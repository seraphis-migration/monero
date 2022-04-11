// Copyright (c) 2021, The Monero Project
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

// NOT FOR PRODUCTION

//paired header
#include "tx_validators.h"

//local headers
#include "concise_grootle.h"
#include "crypto/crypto.h"
#include "ledger_context.h"
#include "ringct/bulletproofs_plus.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_composition_proof.h"
#include "sp_crypto_utils.h"
#include "tx_builders_inputs.h"
#include "tx_component_types.h"
#include "tx_extra.h"
#include "tx_misc_utils.h"

//third party headers

//standard headers
#include <algorithm>
#include <memory>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
// helper for validating v1 balance proofs (balance equality check)
//-------------------------------------------------------------------------------------------------------------------
static bool validate_sp_amount_balance_equality_check_v1(const std::vector<SpEnoteImageV1> &input_images,
    const std::vector<SpEnoteV1> &outputs,
    const rct::xmr_amount transaction_fee,
    const rct::key &remainder_blinding_factor)
{
    rct::keyV input_image_amount_commitments;
    rct::keyV output_commitments;
    input_image_amount_commitments.reserve(input_images.size());
    output_commitments.reserve(outputs.size() + 1 +
        (remainder_blinding_factor == rct::zero() ? 0 : 1));

    for (const auto &input_image : input_images)
        input_image_amount_commitments.emplace_back(input_image.m_core.m_masked_commitment);

    for (const auto &output : outputs)
        output_commitments.emplace_back(output.m_core.m_amount_commitment);

    output_commitments.emplace_back(rct::commit(transaction_fee, rct::zero()));

    if (!(remainder_blinding_factor == rct::zero()))
        output_commitments.emplace_back(rct::scalarmultBase(remainder_blinding_factor));

    // sum(input masked commitments) ?= sum(output commitments) + transaction_fee*H + remainder_blinding_factor*G
    return balance_check_equality(input_image_amount_commitments, output_commitments);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
bool validate_sp_semantics_component_counts_v1(const SemanticConfigComponentCountsV1 &config,
    const std::size_t num_input_images,
    const std::size_t num_membership_proofs,
    const std::size_t num_image_proofs,
    const std::size_t num_outputs,
    const std::size_t num_enote_pubkeys,
    const std::size_t num_range_proofs)
{
    // input count
    if (num_input_images < config.m_min_inputs ||
        num_input_images > config.m_max_inputs)
        return false;

    // input images and image proofs should be 1:1
    if (num_input_images != num_image_proofs)
        return false;

    // input images and membership proofs should be 1:1
    if (num_input_images != num_membership_proofs)
        return false;

    // output count
    if (num_outputs < config.m_min_outputs ||
        num_outputs > config.m_max_outputs)
        return false;

    // range proofs should be 1:1 with input image amount commitments and outputs
    if (num_range_proofs != num_input_images + num_outputs)
        return false;

    // outputs and enote pubkeys should be 1:1
    // - except for 2-out txs, which should have only one enote pubkey
    if (num_outputs == 2)
    {
        if (num_enote_pubkeys != 1)
            return false;
    }
    else if (num_outputs != num_enote_pubkeys)
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_sp_semantics_ref_set_size_v1(const SemanticConfigRefSetSizeV1 &config,
    const std::vector<SpMembershipProofV1> &membership_proofs)
{
    // sanity check
    if (membership_proofs.size() == 0)
        return false;

    // check ref set decomp
    std::size_t ref_set_decomp_n{membership_proofs[0].m_ref_set_decomp_n};
    std::size_t ref_set_decomp_m{membership_proofs[0].m_ref_set_decomp_m};

    if (ref_set_decomp_n < config.m_decom_n_min ||
        ref_set_decomp_n > config.m_decom_n_max)
        return false;

    if (ref_set_decomp_m < config.m_decom_m_min ||
        ref_set_decomp_m > config.m_decom_m_max)
        return false;

    // check membership proofs
    for (const auto &proof : membership_proofs)
    {
        // proof ref set decomposition (n^m) should match number of referenced enotes
        std::size_t ref_set_size{ref_set_size_from_decomp(proof.m_ref_set_decomp_n, proof.m_ref_set_decomp_m)};

        if (ref_set_size != proof.m_ledger_enote_indices.size())
            return false;

        // all proofs should have same ref set decomp (and implicitly: same ref set size)
        if (proof.m_ref_set_decomp_n != ref_set_decomp_n)
            return false;
        if (proof.m_ref_set_decomp_m != ref_set_decomp_m)
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_sp_semantics_input_images_v1(const std::vector<SpEnoteImageV1> &input_images)
{
    for (const auto &image : input_images)
    {
        // input linking tags must be in the prime subgroup: l*KI = identity
        if (!sp::key_domain_is_prime_subgroup(rct::ki2rct(image.m_core.m_key_image)))
            return false;

        // image parts must not be identity
        if (rct::ki2rct(image.m_core.m_key_image) == rct::identity())
            return false;
        if (image.m_core.m_masked_address == rct::identity())
            return false;
        if (image.m_core.m_masked_commitment == rct::identity())
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_sp_semantics_sorting_v1(const std::vector<SpMembershipProofV1> &membership_proofs,
    const std::vector<SpEnoteImageV1> &input_images,
    const std::vector<SpEnoteV1> &outputs,
    const TxExtra &tx_extra)
{
    // membership proof referenced enote indices should be sorted (ascending)
    // note: duplicate references are allowed
    for (const auto &proof : membership_proofs)
    {
        if (!std::is_sorted(proof.m_ledger_enote_indices.begin(), proof.m_ledger_enote_indices.end()))
            return false;
    }

    // input images should be sorted by key image with byte-wise comparisons (ascending), and unique
    if (!std::is_sorted(input_images.begin(), input_images.end()))
        return false;
    if (std::adjacent_find(input_images.begin(), input_images.end(), equals_from_less{}) != input_images.end())
        return false;

    // output enotes should be sorted by onetime address with byte-wise comparisons (ascending), and unique
    if (!std::is_sorted(outputs.begin(), outputs.end()))
        return false;
    if (std::adjacent_find(outputs.begin(), outputs.end(), equals_from_less{}) != outputs.end())
        return false;

    // tx extra fields should be in sorted TLV (Type-Length-Value) format
    std::vector<ExtraFieldElement> extra_field_elements;
    if (!try_get_extra_field_elements(tx_extra, extra_field_elements))
        return false;
    if (!std::is_sorted(extra_field_elements.begin(), extra_field_elements.end()))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_sp_linking_tags_v1(const std::vector<SpEnoteImageV1> &input_images, const LedgerContext &ledger_context)
{
    // check no duplicates in ledger context
    for (std::size_t input_index{0}; input_index < input_images.size(); ++input_index)
    {
        if (ledger_context.linking_tag_exists_v1(input_images[input_index].m_core.m_key_image))
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_sp_amount_balance_v1(const std::vector<SpEnoteImageV1> &input_images,
    const std::vector<SpEnoteV1> &outputs,
    const rct::xmr_amount transaction_fee,
    const SpBalanceProofV1 &balance_proof,
    const bool defer_batchable)
{
    const rct::BulletproofPlus &range_proofs = balance_proof.m_bpp_proof;

    // sanity check
    if (range_proofs.V.size() == 0)
        return false;

    // check that amount commitments balance
    if (!validate_sp_amount_balance_equality_check_v1(input_images,
            outputs,
            transaction_fee,
            balance_proof.m_remainder_blinding_factor))
        return false;

    // check that commitments in range proofs line up with input image and output commitments
    if (input_images.size() + outputs.size() != range_proofs.V.size())
        return false;

    for (std::size_t input_commitment_index{0}; input_commitment_index < input_images.size(); ++input_commitment_index)
    {
        // the two stored copies of input image commitments must match
        if (input_images[input_commitment_index].m_core.m_masked_commitment !=
                rct::rct2pk(rct::scalarmult8(range_proofs.V[input_commitment_index])))
            return false;
    }

    for (std::size_t output_commitment_index{0}; output_commitment_index < outputs.size(); ++output_commitment_index)
    {
        // the two stored copies of output commitments must match
        if (outputs[output_commitment_index].m_core.m_amount_commitment !=
                rct::rct2pk(rct::scalarmult8(range_proofs.V[input_images.size() + output_commitment_index])))
            return false;
    }

    // range proofs must be valid
    if (!defer_batchable)
    {
        std::vector<const rct::BulletproofPlus*> range_proof_ptrs;
        range_proof_ptrs.emplace_back(&range_proofs);  //note: there is only one range proofs aggregate per tx

        if (!rct::bulletproof_plus_VERIFY(range_proof_ptrs))
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_sp_membership_proofs_v1_validation_data(const std::vector<const SpMembershipProofV1*> &membership_proofs,
    const std::vector<const SpEnoteImage*> &input_images,
    const LedgerContext &ledger_context,
    rct::pippenger_prep_data &validation_data_out)
{
    std::size_t num_proofs{membership_proofs.size()};

    // sanity check
    if (num_proofs != input_images.size() ||
        num_proofs == 0)
        return false;

    // get batched validation data
    std::vector<const sp::ConciseGrootleProof*> proofs;
    std::vector<rct::keyM> membership_proof_keys;
    rct::keyM offsets;
    rct::keyV messages;
    proofs.reserve(num_proofs);
    membership_proof_keys.resize(num_proofs);
    offsets.resize(num_proofs, rct::keyV(1));
    messages.reserve(num_proofs);

    for (std::size_t proof_index{0}; proof_index < num_proofs; ++proof_index)
    {
        // sanity check
        if (!membership_proofs[proof_index] ||
            !input_images[proof_index])
            return false;

        proofs.emplace_back(&(membership_proofs[proof_index]->m_concise_grootle_proof));

        // get proof keys from enotes stored in the ledger
        ledger_context.get_reference_set_proof_elements_v1(membership_proofs[proof_index]->m_ledger_enote_indices,
            membership_proof_keys[proof_index]);

        // offset (input image masked keys squashed: Q' = Ko' + C')
        rct::addKeys(offsets[proof_index][0],
            input_images[proof_index]->m_masked_address,
            input_images[proof_index]->m_masked_commitment);

        // proof message
        messages.emplace_back();
        make_tx_membership_proof_message_v1(membership_proofs[proof_index]->m_ledger_enote_indices, messages.back());
    }

    // get verification data
    validation_data_out = sp::get_concise_grootle_verification_data(proofs,
        membership_proof_keys,
        offsets,
        membership_proofs[0]->m_ref_set_decomp_n,
        membership_proofs[0]->m_ref_set_decomp_m,
        messages);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_sp_membership_proofs_v1(const std::vector<const SpMembershipProofV1*> &membership_proofs,
    const std::vector<const SpEnoteImage*> &input_images,
    const LedgerContext &ledger_context)
{
    // get multiexponentiation data set representing all the membership proofs
    rct::pippenger_prep_data validation_data;
    if (!try_get_sp_membership_proofs_v1_validation_data(membership_proofs, input_images, ledger_context, validation_data))
        return false;

    // check that the membership proof multiexp data resolves to the identity element
    return multiexp_is_identity(std::move(validation_data));
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_sp_composition_proofs_v1(const std::vector<SpImageProofV1> &image_proofs,
    const std::vector<SpEnoteImageV1> &input_images,
    const rct::key &image_proofs_message)
{
    // sanity check
    if (image_proofs.size() != input_images.size())
        return false;

    // validate each composition proof
    for (std::size_t input_index{0}; input_index < input_images.size(); ++input_index)
    {
        if (!sp::sp_composition_verify(image_proofs[input_index].m_composition_proof,
                image_proofs_message,
                input_images[input_index].m_core.m_masked_address,
                input_images[input_index].m_core.m_key_image))
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
