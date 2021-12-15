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
#include "mock_sp_validators.h"

//local headers
#include "crypto/crypto.h"
#include "grootle.h"
#include "ledger_context.h"
#include "mock_sp_transaction_component_types.h"
#include "mock_sp_transaction_utils.h"
#include "mock_tx_utils.h"
#include "ringct/bulletproofs_plus.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_composition_proof.h"
#include "seraphis_crypto_utils.h"

//third party headers

//standard headers
#include <memory>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "mock_tx"

namespace mock_tx
{
//-------------------------------------------------------------------------------------------------------------------
// helper for validating v1, v2, v3 balance proofs (balance equality check)
//-------------------------------------------------------------------------------------------------------------------
static bool validate_mock_tx_sp_amount_balance_equality_check_v1_v2_v3(const std::vector<MockENoteImageSpV1> &input_images,
    const std::vector<MockENoteSpV1> &outputs,
    const rct::key &remainder_blinding_factor)
{
    rct::keyV input_image_amount_commitments;
    rct::keyV output_commitments;
    input_image_amount_commitments.reserve(input_images.size());
    output_commitments.reserve(outputs.size() +
        (remainder_blinding_factor == rct::zero() ? 0 : 1));

    for (const auto &input_image : input_images)
        input_image_amount_commitments.emplace_back(input_image.m_masked_commitment);

    for (const auto &output : outputs)
        output_commitments.emplace_back(output.m_amount_commitment);

    if (!(remainder_blinding_factor == rct::zero()))
        output_commitments.emplace_back(rct::scalarmultBase(remainder_blinding_factor));

    // sum(input masked commitments) ?= sum(output commitments) + remainder_blinding_factor*G
    if (!balance_check_equality(input_image_amount_commitments, output_commitments))
    {
        return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
// helper for validating v1 and v2 balance proofs
// - the only difference between them is the presence of a 'remainder blinding factor' in v1 proofs
//-------------------------------------------------------------------------------------------------------------------
static bool validate_mock_tx_sp_amount_balance_v1_v2(const std::vector<MockENoteImageSpV1> &input_images,
    const std::vector<MockENoteSpV1> &outputs,
    const std::vector<rct::BulletproofPlus> &range_proofs,
    const rct::key &remainder_blinding_factor,
    const bool defer_batchable)
{
    // sanity check
    if (range_proofs.size() == 0)
        return false;

    // check that amount commitments balance
    if (!validate_mock_tx_sp_amount_balance_equality_check_v1_v2_v3(input_images,
            outputs,
            remainder_blinding_factor))
        return false;

    // check that commitments in range proofs line up with output commitments
    std::size_t range_proof_index{0};
    std::size_t range_proof_grouping_size = range_proofs[0].V.size();

    for (std::size_t output_index{0}; output_index < outputs.size(); ++output_index)
    {
        // assume range proofs are partitioned into groups of size 'range_proof_grouping_size' (except last one)
        if (range_proofs[range_proof_index].V.size() == output_index - range_proof_index*range_proof_grouping_size)
            ++range_proof_index;

        // sanity checks
        if (range_proofs.size() <= range_proof_index)
            return false;
        if (range_proofs[range_proof_index].V.size() <= output_index - range_proof_index*range_proof_grouping_size)
            return false;

        // double check that the two stored copies of output commitments match
        // TODO? don't store commitments in BP+ structure
        if (outputs[output_index].m_amount_commitment !=
                rct::rct2pk(rct::scalarmult8(range_proofs[range_proof_index].V[output_index -
                    range_proof_index*range_proof_grouping_size])))
            return false;
    }

    // range proofs must be valid
    if (!defer_batchable)
    {
        std::vector<const rct::BulletproofPlus*> range_proof_ptrs;
        range_proof_ptrs.reserve(range_proofs.size());

        for (const auto &range_proof : range_proofs)
            range_proof_ptrs.push_back(&range_proof);

        if (!rct::bulletproof_plus_VERIFY(range_proof_ptrs))
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
bool validate_mock_tx_sp_semantics_component_counts_v1(const std::size_t num_input_images,
    const std::size_t num_membership_proofs,
    const std::size_t num_image_proofs,
    const std::size_t num_outputs,
    const std::size_t num_enote_pubkeys,
    const std::shared_ptr<const MockBalanceProofSpV1> balance_proof)
{
    // need at least one input
    if (num_input_images < 1)
        return false;

    // input images and image proofs should be 1:1
    if (num_input_images != num_image_proofs)
        return false;

    // input images and membership proofs should be 1:1
    if (num_input_images != num_membership_proofs)
        return false;

    // need at least 1 output
    if (num_outputs < 1)
        return false;

    // should be a balance proof
    if (balance_proof.get() == nullptr)
        return false;

    // range proofs and outputs should be 1:1
    std::size_t num_range_proofs{0};
    for (const auto &proof : balance_proof->m_bpp_proofs)
        num_range_proofs += proof.V.size();

    if (num_range_proofs != num_outputs)
        return false;

    // outputs and enote pubkeys should be 1:1
    // TODO: if (num(outputs) == 2), num(enote pubkeys) ?= 1
    if (num_outputs != num_enote_pubkeys)
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_mock_tx_sp_semantics_component_counts_v2(const std::size_t num_input_images,
    const std::size_t num_membership_proofs,
    const std::size_t num_outputs,
    const std::size_t num_enote_pubkeys,
    const MockImageProofSpV1 &image_proof_merged,
    const std::shared_ptr<const MockBalanceProofSpV2> balance_proof)
{
    // need at least one input
    if (num_input_images < 1)
        return false;

    // input images and image proofs should be 1:1
    // note: merged composition proofs have proof components that must be 1:1 with input images
    if (num_input_images != image_proof_merged.m_composition_proof.r_i.size() ||
        num_input_images != image_proof_merged.m_composition_proof.K_t1.size())
        return false;

    // input images and membership proofs should be 1:1
    if (num_input_images != num_membership_proofs)
        return false;

    // need at least 1 output
    if (num_outputs < 1)
        return false;

    // should be a balance proof
    if (balance_proof.get() == nullptr)
        return false;

    // range proofs and outputs should be 1:1
    std::size_t num_range_proofs{0};
    for (const auto &proof : balance_proof->m_bpp_proofs)
        num_range_proofs += proof.V.size();

    if (num_range_proofs != num_outputs)
        return false;

    // outputs and enote pubkeys should be 1:1
    // TODO: if (num(outputs) == 2), num(enote pubkeys) ?= 1
    if (num_outputs != num_enote_pubkeys)
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_mock_tx_sp_semantics_component_counts_v3(const std::size_t num_input_images,
    const std::size_t num_membership_proofs,
    const std::size_t num_image_proofs,
    const std::size_t num_outputs,
    const std::size_t num_enote_pubkeys,
    const std::shared_ptr<const MockBalanceProofSpV1> balance_proof)
{
    // need at least one input
    if (num_input_images < 1)
        return false;

    // input images and image proofs should be 1:1
    if (num_input_images != num_image_proofs)
        return false;

    // input images and membership proofs should be 1:1
    if (num_input_images != num_membership_proofs)
        return false;

    // need at least 1 output
    if (num_outputs < 1)
        return false;

    // should be a balance proof
    if (balance_proof.get() == nullptr)
        return false;

    // range proofs should be 1:1 with input image amount commitments and outputs
    std::size_t num_range_proofs{0};
    for (const auto &proof : balance_proof->m_bpp_proofs)
        num_range_proofs += proof.V.size();

    if (num_range_proofs != num_input_images + num_outputs)
        return false;

    // outputs and enote pubkeys should be 1:1
    // TODO: if (num(outputs) == 2), num(enote pubkeys) ?= 1
    if (num_outputs != num_enote_pubkeys)
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_mock_tx_sp_semantics_ref_set_size_v1(const std::vector<MockMembershipProofSpV1> &membership_proofs)
{
    // sanity check
    if (membership_proofs.size() == 0)
        return false;

    // TODO: validate ref set decomp equals a versioned config setting
    std::size_t ref_set_decomp_n{membership_proofs[0].m_ref_set_decomp_n};
    std::size_t ref_set_decomp_m{membership_proofs[0].m_ref_set_decomp_m};

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
bool validate_mock_tx_sp_semantics_input_images_v1(const std::vector<MockENoteImageSpV1> &input_images)
{
    for (const auto &image : input_images)
    {
        // input linking tags must be in the prime subgroup: l*KI = identity
        if (!sp::key_domain_is_prime_subgroup(rct::ki2rct(image.m_key_image)))
            return false;

        // image parts must not be identity
        if (rct::ki2rct(image.m_key_image) == rct::identity())
            return false;
        if (image.m_masked_address == rct::identity())
            return false;
        if (image.m_masked_commitment == rct::identity())
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_mock_tx_sp_semantics_sorting_v1(const std::vector<MockMembershipProofSpV1> &membership_proofs,
    const std::vector<MockENoteImageSpV1> &input_images)
{
    // membership proof referenced enote indices should be sorted (ascending)
    // note: duplicate references are allowed
    for (const auto &proof : membership_proofs)
    {
        for (std::size_t reference_index{1}; reference_index < proof.m_ledger_enote_indices.size(); ++ reference_index)
        {
            if (proof.m_ledger_enote_indices[reference_index - 1] > proof.m_ledger_enote_indices[reference_index])
                return false;
        }
    }

    // input images should be sorted by key image with byte-wise comparisons (ascending)
    for (std::size_t input_index{1}; input_index < input_images.size(); ++input_index)
    {
        if (memcmp(&(input_images[input_index - 1].m_key_image),
                    &(input_images[input_index].m_key_image),
                    sizeof(crypto::key_image)) > 0)
        {
            return false;
        }
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_mock_tx_sp_linking_tags_v1(const std::vector<MockENoteImageSpV1> &input_images,
    const std::shared_ptr<const LedgerContext> ledger_context)
{
    // sanity check
    if (ledger_context.get() == nullptr)
        return false;

    for (std::size_t input_index{0}; input_index < input_images.size(); ++input_index)
    {
        // check no duplicates in tx
        if (input_index > 0)
        {
            if (input_images[input_index - 1].m_key_image == input_images[input_index].m_key_image)
                return false;
        }

        // check no duplicates in ledger context
        if (ledger_context->linking_tag_exists_sp_v1(input_images[input_index].m_key_image))
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_mock_tx_sp_amount_balance_v1(const std::vector<MockENoteImageSpV1> &input_images,
    const std::vector<MockENoteSpV1> &outputs,
    const std::shared_ptr<const MockBalanceProofSpV1> balance_proof,
    const bool defer_batchable)
{
    // sanity check
    if (balance_proof.get() == nullptr)
        return false;

    return validate_mock_tx_sp_amount_balance_v1_v2(input_images,
        outputs,
        balance_proof->m_bpp_proofs,
        balance_proof->m_remainder_blinding_factor,
        defer_batchable);
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_mock_tx_sp_amount_balance_v2(const std::vector<MockENoteImageSpV1> &input_images,
    const std::vector<MockENoteSpV1> &outputs,
    const std::shared_ptr<const MockBalanceProofSpV2> balance_proof,
    const bool defer_batchable)
{
    // sanity check
    if (balance_proof.get() == nullptr)
        return false;

    rct::key remainder_blinding_factor{rct::zero()};  // no remainder in this balance proof type

    return validate_mock_tx_sp_amount_balance_v1_v2(input_images,
        outputs,
        balance_proof->m_bpp_proofs,
        remainder_blinding_factor,
        defer_batchable);
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_mock_tx_sp_amount_balance_v3(const std::vector<MockENoteImageSpV1> &input_images,
    const std::vector<MockENoteSpV1> &outputs,
    const std::shared_ptr<const MockBalanceProofSpV1> balance_proof,
    const bool defer_batchable)
{
    // sanity check
    if (balance_proof.get() == nullptr)
        return false;

    const std::vector<rct::BulletproofPlus> &range_proofs = balance_proof->m_bpp_proofs;

    // sanity check
    if (range_proofs.size() == 0)
        return false;

    // check that amount commitments balance
    if (!validate_mock_tx_sp_amount_balance_equality_check_v1_v2_v3(input_images,
        outputs,
        balance_proof->m_remainder_blinding_factor))
        return false;

    // check that commitments in range proofs line up with input image and output commitments
    std::size_t range_proof_index{0};
    std::size_t range_proof_grouping_size = range_proofs[0].V.size();

    for (std::size_t commitment_index{0}; commitment_index < input_images.size() + outputs.size(); ++commitment_index)
    {
        // assume range proofs are partitioned into groups of size 'range_proof_grouping_size' (except last one)
        if (range_proofs[range_proof_index].V.size() == commitment_index - range_proof_index*range_proof_grouping_size)
            ++range_proof_index;

        // sanity checks
        if (range_proofs.size() <= range_proof_index)
            return false;
        if (range_proofs[range_proof_index].V.size() <= commitment_index - range_proof_index*range_proof_grouping_size)
            return false;

        // double check that the two stored copies of output commitments match
        // TODO? don't store commitments in BP+ structure
        if (commitment_index < input_images.size())
        {
            // input image amount commitments are range proofed first
            if (input_images[commitment_index].m_masked_commitment !=
                    rct::rct2pk(rct::scalarmult8(range_proofs[range_proof_index].V[commitment_index -
                        range_proof_index*range_proof_grouping_size])))
            {
                return false;
            }
        }
        else
        {
            // output commitments are range proofed last
            if (outputs[commitment_index - input_images.size()].m_amount_commitment !=
                    rct::rct2pk(rct::scalarmult8(range_proofs[range_proof_index].V[commitment_index -
                        range_proof_index*range_proof_grouping_size])))
            {
                return false;
            }
        }
    }

    // range proofs must be valid
    if (!defer_batchable)
    {
        std::vector<const rct::BulletproofPlus*> range_proof_ptrs;
        range_proof_ptrs.reserve(range_proofs.size());

        for (const auto &range_proof : range_proofs)
            range_proof_ptrs.push_back(&range_proof);

        if (!rct::bulletproof_plus_VERIFY(range_proof_ptrs))
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_mock_tx_sp_membership_proofs_v1(const std::vector<MockMembershipProofSpV1> &membership_proofs,
    const std::vector<MockENoteImageSpV1> &input_images,
    const std::shared_ptr<const LedgerContext> ledger_context)
{
    // sanity check
    if (membership_proofs.size() != input_images.size())
        return false;

    // validate one proof at a time (no batching - i.e. cannot assume a shared reference set between proofs)
    std::vector<const sp::ConciseGrootleProof*> proof;
    rct::keyM membership_proof_keys;
    rct::keyM offsets;
    rct::keyV message;

    for (std::size_t input_index{0}; input_index < input_images.size(); ++input_index)
    {
        proof = {&(membership_proofs[input_index].m_concise_grootle_proof)};

        // get proof keys from enotes stored in the ledger
        ledger_context->get_reference_set_components_sp_v1(membership_proofs[input_index].m_ledger_enote_indices,
            membership_proof_keys);

        // offsets (input image masked keys)
        offsets = {{input_images[input_index].m_masked_address, input_images[input_index].m_masked_commitment}};

        // proof message
        message = {get_tx_membership_proof_message_sp_v1(membership_proofs[input_index].m_ledger_enote_indices)};

        if (!sp::concise_grootle_verify(proof,
            membership_proof_keys,
            offsets,
            membership_proofs[input_index].m_ref_set_decomp_n,
            membership_proofs[input_index].m_ref_set_decomp_m,
            message))
        {
            return false;
        }
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_mock_tx_sp_membership_proofs_v2(const std::vector<MockMembershipProofSpV1> &membership_proofs,
    const std::vector<MockENoteImageSpV1> &input_images,
    const std::shared_ptr<const LedgerContext> ledger_context)
{
    // sanity check
    if (membership_proofs.size() != input_images.size())
        return false;

    // validate one proof at a time (no batching - i.e. cannot assume a shared reference set between proofs)
    std::vector<const sp::ConciseGrootleProof*> proof;
    rct::keyM membership_proof_keys;
    rct::keyM offsets;
    rct::keyV message;
    offsets.resize(1, rct::keyV(1));

    for (std::size_t input_index{0}; input_index < input_images.size(); ++input_index)
    {
        proof = {&(membership_proofs[input_index].m_concise_grootle_proof)};

        // get proof keys from enotes stored in the ledger
        ledger_context->get_reference_set_components_sp_v2(membership_proofs[input_index].m_ledger_enote_indices,
            membership_proof_keys);

        // offset (input image masked keys squashed: Q' = Ko' + C')
        rct::addKeys(offsets[0][0],
            input_images[input_index].m_masked_address,
            input_images[input_index].m_masked_commitment);

        // proof message
        message = {get_tx_membership_proof_message_sp_v1(membership_proofs[input_index].m_ledger_enote_indices)};

        if (!sp::concise_grootle_verify(proof,
            membership_proof_keys,
            offsets,
            membership_proofs[input_index].m_ref_set_decomp_n,
            membership_proofs[input_index].m_ref_set_decomp_m,
            message))
        {
            return false;
        }
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_mock_tx_sp_composition_proofs_v1(const std::vector<MockImageProofSpV1> &image_proofs,
    const std::vector<MockENoteImageSpV1> &input_images,
    const rct::key &image_proofs_message)
{
    // sanity check
    if (image_proofs.size() != input_images.size())
        return false;

    // validate each composition proof; these proofs are unmerged (one per input)
    rct::keyV K;
    std::vector<crypto::key_image> KI;

    for (std::size_t input_index{0}; input_index < input_images.size(); ++input_index)
    {
        K = {input_images[input_index].m_masked_address};
        KI = {input_images[input_index].m_key_image};

        if (!sp::sp_composition_verify(image_proofs[input_index].m_composition_proof, K, KI, image_proofs_message))
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_mock_tx_sp_composition_proof_merged_v1(const MockImageProofSpV1 &image_proof,
    const std::vector<MockENoteImageSpV1> &input_images,
    const rct::key &image_proofs_message)
{
    // validate the merged composition proof (one proof for all input images)
    rct::keyV K;
    std::vector<crypto::key_image> KI;
    K.reserve(input_images.size());
    KI.reserve(input_images.size());

    for (std::size_t input_index{0}; input_index < input_images.size(); ++input_index)
    {
        K.emplace_back(input_images[input_index].m_masked_address);
        KI.emplace_back(input_images[input_index].m_key_image);
    }

    if (!sp::sp_composition_verify(image_proof.m_composition_proof, K, KI, image_proofs_message))
            return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace mock_tx
