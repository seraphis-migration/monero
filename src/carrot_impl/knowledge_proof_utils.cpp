// Copyright (c) 2026, The Monero Project
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
#include "knowledge_proof_utils.h"

//local headers
#include "carrot_core/config.h"
#include "carrot_core/exceptions.h"
#include "carrot_core/hash_functions.h"
#include "carrot_core/transcript_fixed.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "fcmp_pp/prove.h"
#include "misc_log_ex.h"
#include "string_tools.h"
#include "tx_builder_inputs.h"

//third party headers

//standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "carrot_impl.knowledge"

namespace carrot
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static crypto::hash ki2hash(const crypto::key_image &ki)
{
    crypto::hash res;
    memcpy(res.data, ki.data, sizeof(res));
    return res;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static crypto::hash make_new_key_image_proof_prefix(const crypto::public_key &onetime_address,
    const bool use_biased_hash_to_point,
    const crypto::key_image &key_image)
{
    const auto transcript = make_fixed_transcript<KNOWLEDGE_DOMAIN_SEP_KEY_IMAGE_PROOF>(onetime_address,
        static_cast<unsigned char>(use_biased_hash_to_point), key_image);
    crypto::hash res;
    derive_bytes_32(transcript.data(), transcript.size(), nullptr, res.data);
    return res;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static FcmpRerandomizedOutputCompressed ota_to_ki_proof_rerand_out(const crypto::public_key &onetime_address,
    const bool use_biased_hash_to_point)
{
    static constexpr crypto::ec_point identity = {{1}};

    // I = Hp(O)
    crypto::ec_point I;
    crypto::derive_key_image_generator(onetime_address, use_biased_hash_to_point, I);

    // r_o = r_i = r_r_i = r_c = 0
    FcmpRerandomizedOutputCompressed o{};
    // O~ = O
    memcpy(o.input.O_tilde, onetime_address.data, sizeof(o.input.O_tilde));
    // I~ = I
    memcpy(o.input.I_tilde, I.data, sizeof(o.input.I_tilde));
    // R = 0
    memcpy(o.input.R, identity.data, sizeof(o.input.R));
    // C~ = 0
    memcpy(o.input.C_tilde, identity.data, sizeof(o.input.C_tilde));
    return o;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void prove_ring_signature_key_image_proof(const crypto::secret_key &x,
    crypto::signature &ki_proof_out,
    crypto::key_image &key_image_out)
{
    // O = x G
    crypto::public_key onetime_address;
    crypto::secret_key_to_public_key(x, onetime_address);

    // L = x Hp(O)
    crypto::generate_key_image(onetime_address, x, key_image_out);

    crypto::generate_ring_signature(ki2hash(key_image_out), key_image_out, {&onetime_address}, x, 0, &ki_proof_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void prove_fcmp_sal_key_image_proof(const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::public_key &onetime_address,
    const bool use_biased_hash_to_point,
    fcmp_pp::FcmpPpSalProof &ki_proof_out,
    crypto::key_image &key_image_out)
{
    // Hp(O)
    crypto::derive_key_image_generator(onetime_address, use_biased_hash_to_point, key_image_out);

    // L = x Hp(O)
    ge_p3 tmp1;
    [[maybe_unused]] int r = ge_frombytes_vartime(&tmp1, to_bytes(key_image_out));
    assert(0 == r); // otherwise crypto::derive_key_image_generator() made an invalid point
    ge_scalarmult_p3(&tmp1, to_bytes(x), &tmp1);
    ge_p3_tobytes(to_bytes(key_image_out), &tmp1);

    // make proof prefix
    const crypto::hash prefix = make_new_key_image_proof_prefix(onetime_address, use_biased_hash_to_point,
        key_image_out);

    std::tie(ki_proof_out, key_image_out) = fcmp_pp::prove_sal(prefix,
        x, y, ota_to_ki_proof_rerand_out(onetime_address, use_biased_hash_to_point));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void prove_key_image_proof(const OutputOpeningHintVariant &opening_hint,
    const address_device &addr_dev,
    const view_balance_secret_device *s_view_balance_dev,
    const view_incoming_key_device &k_view_incoming_dev,
    const crypto::secret_key &account_privkey_g,
    const crypto::secret_key &account_privkey_t,
    KeyImageProofVariant &ki_proof_out,
    crypto::key_image &key_image_out)
{
    crypto::secret_key x;
    crypto::secret_key y;
    get_onetime_address_full_openings(opening_hint, addr_dev, s_view_balance_dev,
        k_view_incoming_dev, account_privkey_g, account_privkey_t, x, y);

    // do the proving with the openings
    const bool is_univariate = y == crypto::null_skey;
    bool use_biased_hash_to_point_ = false;
    if (is_univariate)
    {
        use_biased_hash_to_point_ = true;
        crypto::signature ki_proof;
        prove_ring_signature_key_image_proof(x, ki_proof, key_image_out);
        ki_proof_out = ki_proof;
    }
    else
    {
        use_biased_hash_to_point_ = use_biased_hash_to_point(opening_hint);
        fcmp_pp::FcmpPpSalProof ki_proof;
        prove_fcmp_sal_key_image_proof(x,
            y,
            onetime_address_ref(opening_hint),
            use_biased_hash_to_point_,
            ki_proof,
            key_image_out);
        ki_proof_out = ki_proof;
    }

    // validate proof
    const bool ver = validate_key_image_proof(onetime_address_ref(opening_hint),
    use_biased_hash_to_point_, key_image_out, ki_proof_out);
    CARROT_CHECK_AND_THROW(ver, unexpected_scan_failure,
        std::string("key image proof immediately failed verification")
        + ": one-time address " + epee::string_tools::pod_to_hex(onetime_address_ref(opening_hint))
        + ", key image " + epee::string_tools::pod_to_hex(key_image_out)
        + ", signature " + key_image_proof_to_readable_string(ki_proof_out)
        + ", univariate " + std::to_string(is_univariate)
        + ", subaddress " + std::to_string(subaddress_index_ref(opening_hint).index.is_subaddress()));

    MDEBUG("Proved key image " << epee::string_tools::pod_to_hex(key_image_out) << " is associated to one-time address"
        << epee::string_tools::pod_to_hex(onetime_address_ref(opening_hint)));
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_ring_signature_key_image_proof(const crypto::public_key &onetime_address,
    const crypto::key_image &key_image,
    const crypto::signature &ki_proof)
{
    MDEBUG("Validating key image " << epee::string_tools::pod_to_hex(key_image) << " association to one-time address "
        << epee::string_tools::pod_to_hex(onetime_address) << " using bLSAG signature");

    //! @WARNING:: only safe after #11155 is merged, since we don't check KI validity as caller
    return crypto::check_ring_signature(ki2hash(key_image),
        key_image,
        {&onetime_address},
        &ki_proof);
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_fcmp_pp_sal_key_image_proof(const crypto::public_key &onetime_address,
    const bool use_biased_hash_to_point,
    const crypto::key_image &key_image,
    const fcmp_pp::FcmpPpSalProof &ki_proof)
{
    MDEBUG("Validating key image " << epee::string_tools::pod_to_hex(key_image) << " association to one-time address "
        << epee::string_tools::pod_to_hex(onetime_address) << " using FCMP++ SA/L signature");

    // make proof prefix
    const crypto::hash prefix = make_new_key_image_proof_prefix(onetime_address, use_biased_hash_to_point, key_image);

    //! @WARNING: check code of fcmp_pp::verify_sal() to determine whether it validates KI domain
    return fcmp_pp::verify_sal(prefix,
        ota_to_ki_proof_rerand_out(onetime_address, use_biased_hash_to_point).input,
        key_image,
        ki_proof);
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_key_image_proof(const crypto::public_key &onetime_address,
    const bool use_biased_hash_to_point,
    const crypto::key_image &key_image,
    const KeyImageProofVariant &ki_proof)
{
    struct validate_key_image_proof_visitor
    {
        bool operator()(const crypto::signature &p) const
        {
            if (!use_biased_hash_to_point) return false;
            return validate_ring_signature_key_image_proof(onetime_address, key_image, p);
        }
        bool operator()(const fcmp_pp::FcmpPpSalProof &p) const
        { return validate_fcmp_pp_sal_key_image_proof(onetime_address, use_biased_hash_to_point, key_image, p);}

        const crypto::public_key &onetime_address;
        const bool use_biased_hash_to_point;
        const crypto::key_image &key_image;
    };

    return std::visit(
        validate_key_image_proof_visitor{onetime_address, use_biased_hash_to_point, key_image},
        ki_proof);
}
//-------------------------------------------------------------------------------------------------------------------
std::string key_image_proof_to_readable_string(const KeyImageProofVariant &ki_proof)
{
    struct key_image_proof_to_readable_string_visitor
    {
        std::string operator()(const crypto::signature &s) const
        { return epee::string_tools::pod_to_hex(s); }
        std::string operator()(const fcmp_pp::FcmpPpSalProof &s) const
        { return epee::to_hex::string(epee::to_span(s) ); }
    };
    return std::visit(key_image_proof_to_readable_string_visitor{}, ki_proof);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_key_image_proof_from_readable_string(const std::string &str, KeyImageProofVariant &ki_proof_out)
{
    constexpr std::size_t max_byte_size = FCMP_PP_SAL_PROOF_SIZE_V1;

    if (str.size() > max_byte_size * 2 || str.size() % 2 == 1)
        return false;

    // decode hex into bytes
    std::vector<std::uint8_t> bytes;
    bytes.resize(str.size() / 2);
    if (!epee::from_hex::to_buffer(epee::to_mut_span(bytes), str))
        return false;

    // depending on size of bytes, set variant
    switch (bytes.size())
    {
    case sizeof(crypto::signature):
        memcpy(&ki_proof_out.emplace<crypto::signature>(), bytes.data(), sizeof(crypto::signature));
        break;
    case FCMP_PP_SAL_PROOF_SIZE_V1:
        ki_proof_out = std::move(bytes);
        break;
    default:
        return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------

} //namespace carrot
