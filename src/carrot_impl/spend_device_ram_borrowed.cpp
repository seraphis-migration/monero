// Copyright (c) 2025, The Monero Project
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
#include "spend_device_ram_borrowed.h"

//local headers
#include "address_device_ram_borrowed.h"
#include "carrot_core/account_secrets.h"
#include "carrot_core/device_ram_borrowed.h"
#include "carrot_core/exceptions.h"
#include "carrot_impl/output_opening_types.h"
#include "crypto/generators.h"
#include "key_image_device_composed.h"
#include "misc_log_ex.h"
#include "tx_builder_inputs.h"
#include "tx_builder_outputs.h"

//third party headers

//standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "carrot_impl"

namespace
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::shared_ptr<carrot::key_image_device> compose_key_image_device(
    const crypto::secret_key &privkey_g,
    std::shared_ptr<carrot::view_incoming_key_device> k_view_incoming_dev,
    std::shared_ptr<carrot::view_balance_secret_device> s_view_balance_dev,
    std::shared_ptr<carrot::address_device> address_dev)
{
    std::shared_ptr<carrot::generate_image_key_device> legacy_k_generate_image_dev;
    std::shared_ptr<carrot::generate_image_key_device> carrot_k_generate_image_dev(
        new carrot::generate_image_key_ram_borrowed_device(privkey_g));
    if (!s_view_balance_dev)
        std::swap(legacy_k_generate_image_dev, carrot_k_generate_image_dev);
    return std::make_shared<carrot::key_image_device_composed>(
        std::move(legacy_k_generate_image_dev),
        std::move(carrot_k_generate_image_dev),
        address_dev,
        s_view_balance_dev,
        k_view_incoming_dev);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::shared_ptr<carrot::address_device> compose_legacy_address_device(
    std::shared_ptr<carrot::cryptonote_view_incoming_key_device> k_view_incoming_dev,
    const crypto::secret_key &privkey_g)
{
    // K_s = k_s G
    crypto::public_key cryptonote_account_spend_pubkey;
    crypto::secret_key_to_public_key(privkey_g, cryptonote_account_spend_pubkey);

    return std::shared_ptr<carrot::address_device>(new carrot::cryptonote_hierarchy_address_device(
        std::move(k_view_incoming_dev),
        cryptonote_account_spend_pubkey));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
} //anonymous namespace

namespace carrot
{
//-------------------------------------------------------------------------------------------------------------------
spend_device_ram_borrowed::spend_device_ram_borrowed(
    std::shared_ptr<view_incoming_key_device> k_view_incoming_dev,
    std::shared_ptr<view_balance_secret_device> s_view_balance_dev,
    std::shared_ptr<address_device> address_dev,
    const crypto::secret_key &privkey_g,
    const crypto::secret_key &privkey_t)
:
    m_k_view_incoming_dev(k_view_incoming_dev),
    m_s_view_balance_dev(s_view_balance_dev),
    m_address_dev(address_dev),
    m_key_image_dev(compose_key_image_device(privkey_g, k_view_incoming_dev, s_view_balance_dev, address_dev)),
    m_privkey_g(privkey_g),
    m_privkey_t(privkey_t)
{
    assert(this->m_k_view_incoming_dev);
}
//-------------------------------------------------------------------------------------------------------------------
spend_device_ram_borrowed::spend_device_ram_borrowed(
    const crypto::secret_key &k_spend,
    const crypto::secret_key &k_view)
: 
    spend_device_ram_borrowed(k_spend, std::make_shared<cryptonote_view_incoming_key_ram_borrowed_device>(k_view))
{}
//-------------------------------------------------------------------------------------------------------------------
bool spend_device_ram_borrowed::try_sign_carrot_transaction_proposal_v1(
    const CarrotTransactionProposalV1 &tx_proposal,
    const std::vector<FcmpRerandomizedOutputCompressed> &rerandomized_outputs,
    crypto::hash &signable_tx_hash_out,
    signed_input_set_t &signed_inputs_out) const
{
    signable_tx_hash_out = crypto::null_hash;
    signed_inputs_out.clear();

    // get sorted tx key images and insert into `signed_inputs_out`
    std::vector<crypto::key_image> sorted_input_key_images;
    std::vector<std::size_t> key_image_order;
    carrot::get_sorted_input_key_images_from_proposal_v1(tx_proposal,
        *m_key_image_dev,
        sorted_input_key_images,
        &key_image_order);
    for (std::size_t tx_input_idx = 0; tx_input_idx < sorted_input_key_images.size(); ++tx_input_idx)
    {
        const std::size_t input_proposal_idx = key_image_order.at(tx_input_idx);
        const crypto::public_key ota = onetime_address_ref(tx_proposal.input_proposals.at(input_proposal_idx));
        const crypto::key_image &ki = sorted_input_key_images.at(tx_input_idx);
        signed_inputs_out[ki].first = ota;
    }

    // calculate signable tx hash
    make_signable_tx_hash_from_proposal_v1(tx_proposal,
        /*s_view_balance_dev=*/nullptr,
        this->m_k_view_incoming_dev.get(),
        sorted_input_key_images,
        signable_tx_hash_out);

    // prove SA/L
    this->sign_raw_v1(signable_tx_hash_out,
        epee::to_span(rerandomized_outputs),
        epee::to_span(tx_proposal.input_proposals),
        signed_inputs_out);

    // check key images in signed image set vs set used to hash signable tx hash
    CARROT_CHECK_AND_THROW(sorted_input_key_images.size() == signed_inputs_out.size(),
        carrot_logic_error, "Mismatch in signed input set size with sorted key image set size");
    std::size_t ki_idx = 0;
    for (const auto &signed_input : signed_inputs_out)
    {
        CARROT_CHECK_AND_THROW(signed_input.first == sorted_input_key_images.at(ki_idx),
            carrot_logic_error, "Mismatch of key image in signed input set");
        ++ki_idx;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
crypto::key_image spend_device_ram_borrowed::derive_key_image(const OutputOpeningHintVariant &opening_hint) const
{
    return m_key_image_dev->derive_key_image(opening_hint);
}
//-------------------------------------------------------------------------------------------------------------------
crypto::key_image spend_device_ram_borrowed::derive_key_image_prescanned(
    const crypto::secret_key &sender_extension_g,
    const crypto::public_key &onetime_address,
    const subaddress_index_extended &subaddr_index,
    const bool use_biased) const
{
    return m_key_image_dev->derive_key_image_prescanned(sender_extension_g,
        onetime_address,
        subaddr_index,
        use_biased);
}
//-------------------------------------------------------------------------------------------------------------------
void spend_device_ram_borrowed::sign_raw_v1(const crypto::hash &prefix_hash,
    const epee::span<const FcmpRerandomizedOutputCompressed> rerandomized_outputs,
    const epee::span<const OutputOpeningHintVariant> opening_hints,
    signed_input_set_t &signed_inputs_out) const
{
    signed_inputs_out.clear();

    const std::size_t n_inputs = rerandomized_outputs.size();
    CARROT_CHECK_AND_THROW(rerandomized_outputs.size() == n_inputs,
        carrot_logic_error, "Mismatch in rerandomized outputs / opening hints size");

    for (std::size_t i = 0; i < n_inputs; ++i)
    {
        const FcmpRerandomizedOutputCompressed &rerandomized_output = rerandomized_outputs[i];
        const OutputOpeningHintVariant &opening_hint = opening_hints[i];
        const crypto::public_key onetime_address = onetime_address_ref(opening_hint);
        const rct::key amount_commitment = amount_commitment_ref(opening_hint);
        const bool ver = verify_rerandomized_output_basic(rerandomized_output,
            onetime_address,
            amount_commitment,
            use_biased_hash_to_point(opening_hint));
        CARROT_CHECK_AND_THROW(ver,
            carrot_logic_error, "Given opening hint does not correspond to given rerandomized output");

        fcmp_pp::FcmpPpSalProof sal_proof;
        crypto::key_image ki;
        carrot::make_sal_proof_any_to_hybrid_v1(prefix_hash,
            rerandomized_output,
            opening_hint,
            this->m_privkey_g,
            this->m_privkey_t,
            this->m_s_view_balance_dev.get(),
            *this->m_k_view_incoming_dev,
            *this->m_address_dev,
            sal_proof,
            ki);

        signed_inputs_out[ki] = {onetime_address, std::move(sal_proof)};
    }

    CARROT_CHECK_AND_THROW(signed_inputs_out.size() == n_inputs,
        carrot_logic_error, "Resultant signed input set is the wrong size");
}
//-------------------------------------------------------------------------------------------------------------------
spend_device_ram_borrowed::spend_device_ram_borrowed(const crypto::secret_key &k_spend,
    std::shared_ptr<cryptonote_view_incoming_key_device> k_view_incoming_dev)
:
    m_k_view_incoming_dev(k_view_incoming_dev),
    m_s_view_balance_dev(),
    m_address_dev(compose_legacy_address_device(k_view_incoming_dev, k_spend)),
    m_key_image_dev(compose_key_image_device(k_spend, m_k_view_incoming_dev, nullptr, m_address_dev)),
    m_privkey_g(k_spend),
    m_privkey_t(crypto::null_skey)
{
    assert(m_k_view_incoming_dev);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace carrot
