// Copyright (c) 2024-2026, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//paired header
#include "key_image_device_composed.h"

//local headers
#include "address_utils.h"
#include "carrot_core/exceptions.h"
#include "misc_log_ex.h"

//third party headers

//standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "carrot_impl.device"

namespace
{
struct make_local_device_error
{
    int code;
    std::string func;

    make_local_device_error(int code, std::string func): code(code), func(std::move(func)) {}

    carrot::device_error operator()(std::string msg)
    {
        return carrot::device_error("Default", "key_image_device_composed", std::move(func), std::move(msg), code);
    }
};
} //anonymous namespace

namespace carrot
{
//-------------------------------------------------------------------------------------------------------------------
key_image_device_composed::key_image_device_composed(std::shared_ptr<generate_image_key_device> k_generate_image_dev,
    std::shared_ptr<address_device> addr_dev,
    std::shared_ptr<view_balance_secret_device> s_view_balance_dev,
    std::shared_ptr<view_incoming_key_device> k_view_incoming_dev):
        m_legacy_k_generate_image_dev(s_view_balance_dev ?
            std::shared_ptr<generate_image_key_device>{} : std::move(k_generate_image_dev)),
        m_carrot_k_generate_image_dev(s_view_balance_dev
            ? std::move(k_generate_image_dev) : std::shared_ptr<generate_image_key_device>{}),
        m_addr_dev(std::move(addr_dev)),
        m_s_view_balance_dev(std::move(s_view_balance_dev)),
        m_k_view_incoming_dev(std::move(k_view_incoming_dev))
{}
//-------------------------------------------------------------------------------------------------------------------
key_image_device_composed::key_image_device_composed(
    std::shared_ptr<generate_image_key_device> legacy_k_generate_image_dev,
    std::shared_ptr<generate_image_key_device> carrot_k_generate_image_dev,
    std::shared_ptr<address_device> addr_dev,
    std::shared_ptr<view_balance_secret_device> s_view_balance_dev,
    std::shared_ptr<view_incoming_key_device> k_view_incoming_dev):
        m_legacy_k_generate_image_dev(std::move(legacy_k_generate_image_dev)),
        m_carrot_k_generate_image_dev(std::move(carrot_k_generate_image_dev)),
        m_addr_dev(std::move(addr_dev)),
        m_s_view_balance_dev(std::move(s_view_balance_dev)),
        m_k_view_incoming_dev(std::move(k_view_incoming_dev))
{}
//-------------------------------------------------------------------------------------------------------------------
crypto::key_image key_image_device_composed::derive_key_image(const OutputOpeningHintVariant &opening_hint) const
{
    // get k^g_o, k^t_o
    crypto::secret_key sender_extension_g;
    crypto::secret_key sender_extension_t;
    if (!try_scan_opening_hint_sender_extensions(opening_hint,
        *m_addr_dev,
        m_s_view_balance_dev.get(),
        m_k_view_incoming_dev.get(),
        sender_extension_g,
        sender_extension_t))
    {
        throw make_local_device_error{-3, "derive_key_image"}("enote scan failed");
    }

    return this->derive_key_image_prescanned(sender_extension_g,
        onetime_address_ref(opening_hint),
        subaddress_index_ref(opening_hint),
        use_biased_hash_to_point(opening_hint));
}
//-------------------------------------------------------------------------------------------------------------------
crypto::key_image key_image_device_composed::derive_key_image_prescanned(const crypto::secret_key &sender_extension_g,
    const crypto::public_key &onetime_address,
    const subaddress_index_extended &subaddr_index,
    const bool use_biased) const
{
    // resolve generate-image device
    const generate_image_key_device *used_k_generate_image_dev = nullptr;
    switch (subaddr_index.derive_type)
    {
    case AddressDeriveType::Auto:
        CARROT_THROW(make_local_device_error(-11, "derive_key_image_prescanned"),
            "Cannot use Auto derive type for opening key images");
        break;
    case AddressDeriveType::PreCarrot:
        used_k_generate_image_dev = m_legacy_k_generate_image_dev.get();
        break;
    case AddressDeriveType::Carrot:
        used_k_generate_image_dev = m_carrot_k_generate_image_dev.get();
        break;
    default:
        CARROT_THROW(make_local_device_error(-9, "derive_key_image_prescanned"),
            "Unrecognized subaddress index derive type");
    }
    CARROT_CHECK_AND_THROW(used_k_generate_image_dev != nullptr,
        make_local_device_error(-10, "derive_key_image_prescanned"),
        "No generate-image device present for given subaddress index type");

    // [legacy] L_partial = k_s Hp(K_o)
    // [carrot] L_partial = k_gi Hp(K_o)
    crypto::ec_point partial_key_image
        = used_k_generate_image_dev->generate_image_scalar_mult_hash_to_point(onetime_address, use_biased);

    // I = Hp(K_o)
    crypto::ec_point key_image_generator;
    crypto::derive_key_image_generator(onetime_address, use_biased, key_image_generator);

    // get k^j_subscal, k^j_subext
    crypto::secret_key subaddr_extension_g;
    crypto::secret_key carrot_subaddr_scalar;
    m_addr_dev->get_address_openings(subaddr_index, subaddr_extension_g, carrot_subaddr_scalar);

    // L_partial = k^j_subscal L_partial
    ge_p3 tmp1;
    int r = ge_frombytes_vartime(&tmp1, to_bytes(partial_key_image));
    CARROT_CHECK_AND_THROW(0 == r, invalid_point, "generate_image_key_device device returned invalid point");
    ge_scalarmult_p3(&tmp1, to_bytes(carrot_subaddr_scalar), &tmp1);
    ge_cached tmp2;
    ge_p3_to_cached(&tmp2, &tmp1);

    // L_partial = k^j_subext I + L_partial
    r = ge_frombytes_vartime(&tmp1, to_bytes(key_image_generator));
    CARROT_CHECK_AND_THROW(0 == r, invalid_point, "derive_key_image_generator device returned invalid point");
    ge_p3 tmp3;
    ge_scalarmult_p3(&tmp3, to_bytes(subaddr_extension_g), &tmp1);
    ge_p1p1 tmp4;
    ge_add(&tmp4, &tmp3, &tmp2);
    ge_p1p1_to_p3(&tmp3, &tmp4);
    ge_p3_to_cached(&tmp2, &tmp3);

    // L = k^g_o I + L_partial
    ge_scalarmult_p3(&tmp1, to_bytes(sender_extension_g), &tmp1);
    ge_add(&tmp4, &tmp1, &tmp2);
    ge_p2 tmp5;
    ge_p1p1_to_p2(&tmp5, &tmp4);
    crypto::key_image ki;
    ge_tobytes(to_bytes(ki), &tmp5);
    return ki;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace carrot
