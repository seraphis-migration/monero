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
#include "mock_sp_transaction_utils.h"

//local headers
#include "common/varint.h"
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_config.h"
#include "grootle.h"
#include "misc_log_ex.h"
#include "mock_ledger_context.h"
#include "mock_sp_transaction_builder_types.h"
#include "mock_sp_transaction_component_types.h"
#include "mock_tx_utils.h"
#include "ringct/bulletproofs_plus.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_composition_proof.h"
#include "seraphis_crypto_utils.h"

//third party headers

//standard headers
#include <algorithm>
#include <memory>
#include <string>
#include <vector>


namespace mock_tx
{
//-------------------------------------------------------------------------------------------------------------------
// v_c_last = sum(y_t) - sum_except_last(v_c_j)
//-------------------------------------------------------------------------------------------------------------------
static void get_last_sp_image_amount_blinding_factor_v1(
    const std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors,
    const std::vector<crypto::secret_key> &initial_image_amount_blinding_factors,
    crypto::secret_key &last_image_amount_blinding_factor)
{
    // add together output blinding factors
    last_image_amount_blinding_factor = rct::rct2sk(rct::zero());

    for (const auto &y : output_amount_commitment_blinding_factors)
        sc_add(&last_image_amount_blinding_factor, &last_image_amount_blinding_factor, &y);

    // subtract image blinding factors from sum
    for (const auto &v_c : initial_image_amount_blinding_factors)
        sc_sub(&last_image_amount_blinding_factor, &last_image_amount_blinding_factor, &v_c);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
rct::key get_tx_membership_proof_message_sp_v1(const std::vector<std::size_t> &enote_ledger_indices)
{
    rct::key hash_result;
    std::string hash;
    hash.reserve(sizeof(CRYPTONOTE_NAME) + enote_ledger_indices.size()*((sizeof(std::size_t) * 8 + 6) / 7));
    // project name
    hash = CRYPTONOTE_NAME;
    // all referenced enote ledger indices
    char converted_index[(sizeof(size_t) * 8 + 6) / 7];
    char* end;
    for (const std::size_t index : enote_ledger_indices)
    {
        // TODO: append real ledger references
        end = converted_index;
        tools::write_varint(end, index);
        assert(end <= converted_index + sizeof(converted_index));
        hash.append(converted_index, end - converted_index);
    }

    rct::hash_to_scalar(hash_result, hash.data(), hash.size());

    return hash_result;
}
//-------------------------------------------------------------------------------------------------------------------
void sort_tx_inputs_sp_v1(std::vector<MockENoteImageSpV1> &input_images_inout,
    std::vector<MockImageProofSpV1> &tx_image_proofs_inout,
    std::vector<MockMembershipProofSpV1> &tx_membership_proofs_inout)
{
    CHECK_AND_ASSERT_THROW_MES(input_images_inout.size() == tx_image_proofs_inout.size(), "Input components size mismatch");
    CHECK_AND_ASSERT_THROW_MES(input_images_inout.size() == tx_membership_proofs_inout.size(), "Input components size mismatch");

    std::vector<std::size_t> original_indices;
    original_indices.resize(input_images_inout.size());

    for (std::size_t input_index{0}; input_index < input_images_inout.size(); ++input_index)
        original_indices[input_index] = input_index;

    // sort: key images ascending with byte-wise comparisons
    std::sort(original_indices.begin(), original_indices.end(),
            [&input_images_inout](const std::size_t input_index_1, const std::size_t input_index_2) -> bool
            {
                return memcmp(&(input_images_inout[input_index_1].m_key_image),
                    &(input_images_inout[input_index_2].m_key_image), sizeof(crypto::key_image)) < 0;
            }
        );

    // move all input pieces into sorted positions
    std::vector<MockENoteImageSpV1> input_images_sorted;
    std::vector<MockImageProofSpV1> tx_image_proofs_sorted;
    std::vector<MockMembershipProofSpV1> tx_membership_proofs_sorted;
    input_images_sorted.reserve(input_images_inout.size());
    tx_image_proofs_sorted.reserve(input_images_inout.size());
    tx_membership_proofs_sorted.reserve(input_images_inout.size());

    for (const auto old_index : original_indices)
    {
        input_images_sorted.emplace_back(std::move(input_images_inout[old_index]));
        tx_image_proofs_sorted.emplace_back(std::move(tx_image_proofs_inout[old_index]));
        tx_membership_proofs_sorted.emplace_back(std::move(tx_membership_proofs_inout[old_index]));
    }

    // update inputs
    input_images_inout = std::move(input_images_sorted);
    tx_image_proofs_inout = std::move(tx_image_proofs_sorted);
    tx_membership_proofs_inout = std::move(tx_membership_proofs_sorted);
}
//-------------------------------------------------------------------------------------------------------------------
void sort_v1_tx_membership_proofs_sp_v1(const MockTxPartialSpV1 &partial_tx,
    std::vector<MockMembershipProofSortableSpV1> &tx_membership_proofs_sortable_in,
    std::vector<MockMembershipProofSpV1> &tx_membership_proofs_out)
{
    CHECK_AND_ASSERT_THROW_MES(tx_membership_proofs_sortable_in.size() == partial_tx.m_input_images.size(),
        "Mismatch between sortable membership proof count and partial tx input image count.");

    tx_membership_proofs_out.clear();
    tx_membership_proofs_out.reserve(tx_membership_proofs_sortable_in.size());

    for (std::size_t input_index{0}; input_index < partial_tx.m_input_images.size(); ++input_index)
    {
        // find the membership proof that matches with the input image at this index
        auto ordered_membership_proof{
                std::find_if(tx_membership_proofs_sortable_in.begin(), tx_membership_proofs_sortable_in.end(),
                        [&](const MockMembershipProofSortableSpV1 &sortable_proof) -> bool
                        {
                            return partial_tx.m_input_images[input_index].m_masked_address ==
                                sortable_proof.m_masked_address;
                        }
                    )
            };

        CHECK_AND_ASSERT_THROW_MES(ordered_membership_proof != tx_membership_proofs_sortable_in.end(),
            "Could not find input image to match with a sortable membership proof.");

        tx_membership_proofs_out.emplace_back(std::move(ordered_membership_proof->m_membership_proof));
    }
}
//-------------------------------------------------------------------------------------------------------------------
rct::key get_tx_image_proof_message_sp_v1(const std::string &version_string,
    const std::vector<MockENoteSpV1> &output_enotes,
    const std::shared_ptr<const MockBalanceProofSpV1> &balance_proof,
    const MockSupplementSpV1 &tx_supplement)
{
    CHECK_AND_ASSERT_THROW_MES(balance_proof.get() != nullptr, "Balance proof doesn't exist!");

    rct::key hash_result;
    std::string hash;
    hash.reserve(sizeof(CRYPTONOTE_NAME) +
        version_string.size() +
        output_enotes.size()*MockENoteSpV1::get_size_bytes() +
        balance_proof->get_size_bytes() +
        tx_supplement.m_output_enote_pubkeys.size());
    hash = CRYPTONOTE_NAME;
    hash += version_string;
    for (const auto &output_enote : output_enotes)
    {
        output_enote.append_to_string(hash);
    }
    balance_proof->append_to_string(false, hash);  // don't append amount commitments here (they were appended by enotes)
    for (const auto &enote_pubkey : tx_supplement.m_output_enote_pubkeys)
    {
        hash.append((const char*) enote_pubkey.bytes, sizeof(enote_pubkey));
    }

    rct::hash_to_scalar(hash_result, hash.data(), hash.size());

    return hash_result;
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_outputs_sp_v1(const std::vector<MockDestinationSpV1> &destinations,
    std::vector<MockENoteSpV1> &outputs_out,
    std::vector<rct::xmr_amount> &output_amounts_out,
    std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors_out,
    MockSupplementSpV1 &tx_supplement_inout)
{
    rct::keyV temp_enote_pubkeys;
    temp_enote_pubkeys.resize(destinations.size());
    outputs_out.clear();
    outputs_out.reserve(destinations.size());
    output_amounts_out.clear();
    output_amounts_out.reserve(destinations.size());
    output_amount_commitment_blinding_factors_out.resize(destinations.size());

    for (std::size_t dest_index{0}; dest_index < destinations.size(); ++dest_index)
    {
        // build output set
        outputs_out.emplace_back(destinations[dest_index].to_enote_v1(dest_index, temp_enote_pubkeys[dest_index]));

        // prepare for range proofs
        output_amounts_out.emplace_back(destinations[dest_index].m_amount);
        destinations[dest_index].get_amount_blinding_factor(dest_index,
            output_amount_commitment_blinding_factors_out[dest_index]);
    }

    // copy non-duplicate enote pubkeys to tx supplement
    tx_supplement_inout.m_output_enote_pubkeys.clear();
    tx_supplement_inout.m_output_enote_pubkeys.reserve(destinations.size());

    for (const auto &enote_pubkey : temp_enote_pubkeys)
    {
        if (std::find(tx_supplement_inout.m_output_enote_pubkeys.begin(), tx_supplement_inout.m_output_enote_pubkeys.end(),
            enote_pubkey) == tx_supplement_inout.m_output_enote_pubkeys.end())
        {
            tx_supplement_inout.m_output_enote_pubkeys.emplace_back(enote_pubkey);
        }
    }

    // should be either 1 enote pubkey for entire destination set, or 1:1 per destination
    CHECK_AND_ASSERT_THROW_MES(tx_supplement_inout.m_output_enote_pubkeys.size() == 1 ||
        tx_supplement_inout.m_output_enote_pubkeys.size() == destinations.size(), "Invalid number of enote pubkeys in destination set.");
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_image_sp_v1(const MockInputProposalSpV1 &input_proposal,
    MockENoteImageSpV1 &input_image_out,
    crypto::secret_key &image_address_mask_out,
    crypto::secret_key &image_amount_mask_out)
{
    image_address_mask_out = rct::rct2sk(rct::zero());
    image_amount_mask_out = rct::rct2sk(rct::zero());

    // t_k
    while (image_address_mask_out == rct::rct2sk(rct::zero()))
        image_address_mask_out = rct::rct2sk(rct::skGen());

    // t_c
    while (image_amount_mask_out == rct::rct2sk(rct::zero()))
        image_amount_mask_out = rct::rct2sk(rct::skGen());

    // enote image
    input_proposal.to_enote_image_base(image_address_mask_out, image_amount_mask_out, input_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_image_last_sp_v1(const MockInputProposalSpV1 &input_proposal,
    const std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors,
    const std::vector<crypto::secret_key> &input_amount_blinding_factors,
    MockENoteImageSpV1 &input_image_out,
    crypto::secret_key &image_address_mask_out,
    crypto::secret_key &image_amount_mask_out)
{
    CHECK_AND_ASSERT_THROW_MES(output_amount_commitment_blinding_factors.size() > 0,
        "Tried to finalize tx input image set without any output blinding factors.");

    image_address_mask_out = rct::rct2sk(rct::zero());
    image_amount_mask_out = rct::rct2sk(rct::zero());

    // t_k
    while (image_address_mask_out == rct::rct2sk(rct::zero()))
        image_address_mask_out = rct::rct2sk(rct::skGen());

    // get total blinding factor of last input image masked amount commitment
    // v_c = t_c + x
    crypto::secret_key last_image_amount_blinding_factor;
    get_last_sp_image_amount_blinding_factor_v1(output_amount_commitment_blinding_factors,
        input_amount_blinding_factors,
        last_image_amount_blinding_factor);

    // t_c = v_c - x
    sc_sub(&image_amount_mask_out,
        &last_image_amount_blinding_factor,  // v_c
        &input_proposal.m_amount_blinding_factor);  // x

    // enote image
    input_proposal.to_enote_image_base(image_address_mask_out, image_amount_mask_out, input_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_images_sp_v1(const std::vector<MockInputProposalSpV1> &input_proposals,
    const std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors,
    std::vector<MockENoteImageSpV1> &input_images_out,
    std::vector<crypto::secret_key> &image_address_masks_out,
    std::vector<crypto::secret_key> &image_amount_masks_out)
{
    CHECK_AND_ASSERT_THROW_MES(input_proposals.size() > 0, "Tried to make tx input image set without any inputs.");
    CHECK_AND_ASSERT_THROW_MES(output_amount_commitment_blinding_factors.size() > 0,
        "Tried to make tx input image set without any output blinding factors.");

    std::vector<crypto::secret_key> input_amount_blinding_factors;

    input_images_out.resize(input_proposals.size());
    image_address_masks_out.resize(input_proposals.size());
    image_amount_masks_out.resize(input_proposals.size());
    input_amount_blinding_factors.resize(input_proposals.size() - 1);

    // make initial set of input images (all but last)
    for (std::size_t input_index{0}; input_index < input_proposals.size() - 1; ++input_index)
    {
        make_v1_tx_image_sp_v1(input_proposals[input_index],
            input_images_out[input_index],
            image_address_masks_out[input_index],
            image_amount_masks_out[input_index]);

        // store total blinding factor of input image masked amount commitment
        // v_c = t_c + x
        sc_add(&(input_amount_blinding_factors[input_index]),
            &(image_amount_masks_out[input_index]),  // t_c
            &(input_proposals[input_index].m_amount_blinding_factor));  // x
    }

    // make last input image
    make_v1_tx_image_last_sp_v1(input_proposals.back(),
        output_amount_commitment_blinding_factors,
        input_amount_blinding_factors,
        input_images_out.back(),
        image_address_masks_out.back(),
        image_amount_masks_out.back());
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_image_proof_sp_v1(const MockInputProposalSpV1 &input_proposal,
    const MockENoteImageSpV1 &input_image,
    const crypto::secret_key &image_address_mask,
    const rct::key &message,
    MockImageProofSpV1 &tx_image_proof_out)
{
    // prepare for proof
    rct::keyV proof_K;
    std::vector<crypto::secret_key> x, y, z;

    proof_K.resize(1);
    sp::mask_key(image_address_mask, input_proposal.m_enote.m_onetime_address, proof_K[0]);

    x.emplace_back(image_address_mask);
    y.emplace_back(input_proposal.m_enote_view_privkey);
    z.emplace_back(input_proposal.m_spendbase_privkey);

    // make seraphis composition proof
    tx_image_proof_out.m_composition_proof = sp::sp_composition_prove(proof_K, x, y, z, message);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_image_proofs_sp_v1(const std::vector<MockInputProposalSpV1> &input_proposals,
    const std::vector<MockENoteImageSpV1> &input_images,
    const std::vector<crypto::secret_key> &image_address_masks,
    const rct::key &message,
    std::vector<MockImageProofSpV1> &tx_image_proofs_out)
{
    CHECK_AND_ASSERT_THROW_MES(input_proposals.size() == input_images.size(), "Input components size mismatch");
    CHECK_AND_ASSERT_THROW_MES(input_proposals.size() == image_address_masks.size(), "Input components size mismatch");

    tx_image_proofs_out.resize(input_proposals.size());

    for (std::size_t input_index{0}; input_index < input_proposals.size(); ++input_index)
    {
        make_v1_tx_image_proof_sp_v1(input_proposals[input_index],
            input_images[input_index],
            image_address_masks[input_index],
            message,
            tx_image_proofs_out[input_index]);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_balance_proof_sp_v1(const std::vector<rct::xmr_amount> &output_amounts,
    const std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors,
    const std::size_t max_rangeproof_splits,
    std::shared_ptr<MockBalanceProofSpV1> &balance_proof_out)
{
    if (balance_proof_out.get() == nullptr)
        balance_proof_out = std::make_shared<MockBalanceProofSpV1>();

    // make range proofs
    std::vector<rct::BulletproofPlus> range_proofs;

    rct::keyV amount_commitment_blinding_factors;
    amount_commitment_blinding_factors.reserve(output_amount_commitment_blinding_factors.size());

    for (const auto &factor : output_amount_commitment_blinding_factors)
        amount_commitment_blinding_factors.emplace_back(rct::sk2rct(factor));

    make_bpp_rangeproofs(output_amounts,
        amount_commitment_blinding_factors,
        max_rangeproof_splits,
        range_proofs);

    balance_proof_out->m_bpp_proofs = std::move(range_proofs);

    memwipe(amount_commitment_blinding_factors.data(), amount_commitment_blinding_factors.size()*sizeof(rct::key));
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_membership_proof_sp_v1(const MockMembershipReferenceSetSpV1 &membership_ref_set,
    const crypto::secret_key &image_address_mask,
    const crypto::secret_key &image_amount_mask,
    MockMembershipProofSortableSpV1 &tx_membership_proof_out)
{
    // make the membership proof
    make_v1_tx_membership_proof_sp_v1(membership_ref_set,
        image_address_mask,
        image_amount_mask,
        tx_membership_proof_out.m_membership_proof);

    // save the masked address for later matching the membership proof with its input image
    sp::mask_key(image_address_mask,
        membership_ref_set.m_referenced_enotes[membership_ref_set.m_real_spend_index_in_set].m_onetime_address,
        tx_membership_proof_out.m_masked_address);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_membership_proof_sp_v1(const MockMembershipReferenceSetSpV1 &membership_ref_set,
    const crypto::secret_key &image_address_mask,
    const crypto::secret_key &image_amount_mask,
    MockMembershipProofSpV1 &tx_membership_proof_out)
{
    /// initial checks
    std::size_t ref_set_size{
            ref_set_size_from_decomp(membership_ref_set.m_ref_set_decomp_n, membership_ref_set.m_ref_set_decomp_m)
        };

    CHECK_AND_ASSERT_THROW_MES(membership_ref_set.m_referenced_enotes.size() == ref_set_size,
        "Ref set size doesn't match number of referenced enotes");
    CHECK_AND_ASSERT_THROW_MES(membership_ref_set.m_ledger_enote_indices.size() == ref_set_size,
        "Ref set size doesn't match number of referenced enotes' ledger indices");


    /// miscellaneous components
    tx_membership_proof_out.m_ledger_enote_indices = membership_ref_set.m_ledger_enote_indices;
    tx_membership_proof_out.m_ref_set_decomp_n = membership_ref_set.m_ref_set_decomp_n;
    tx_membership_proof_out.m_ref_set_decomp_m = membership_ref_set.m_ref_set_decomp_m;


    /// prepare to make proof

    // public keys referenced by proof
    rct::keyM referenced_enotes;
    referenced_enotes.resize(ref_set_size, rct::keyV(2));

    for (std::size_t ref_index{0}; ref_index < ref_set_size; ++ref_index)
    {
        referenced_enotes[ref_index][0] = membership_ref_set.m_referenced_enotes[ref_index].m_onetime_address;
        referenced_enotes[ref_index][1] = membership_ref_set.m_referenced_enotes[ref_index].m_amount_commitment;
    }

    // proof offsets
    rct::keyV image_offsets;
    image_offsets.resize(2);

    // K'
    sp::mask_key(image_address_mask, referenced_enotes[membership_ref_set.m_real_spend_index_in_set][0], image_offsets[0]);
    // C'
    sp::mask_key(image_amount_mask, referenced_enotes[membership_ref_set.m_real_spend_index_in_set][1], image_offsets[1]);

    // secret key of (K[l] - K') and (C[l] - C')
    std::vector<crypto::secret_key> image_masks;
    image_masks.reserve(2);
    image_masks.emplace_back(image_address_mask);  // t_k
    image_masks.emplace_back(image_amount_mask);  // t_c
    sc_mul(&(image_masks[0]), &(image_masks[0]), sp::MINUS_ONE.bytes);  // -t_k
    sc_mul(&(image_masks[1]), &(image_masks[1]), sp::MINUS_ONE.bytes);  // -t_k

    // proof message
    rct::key message{get_tx_membership_proof_message_sp_v1(membership_ref_set.m_ledger_enote_indices)};


    /// make concise grootle proof
    tx_membership_proof_out.m_concise_grootle_proof = sp::concise_grootle_prove(referenced_enotes,
        membership_ref_set.m_real_spend_index_in_set,
        image_offsets,
        image_masks,
        membership_ref_set.m_ref_set_decomp_n,
        membership_ref_set.m_ref_set_decomp_m,
        message);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_membership_proofs_sp_v1(const std::vector<MockMembershipReferenceSetSpV1> &membership_ref_sets,
    const std::vector<crypto::secret_key> &image_address_masks,
    const std::vector<crypto::secret_key> &image_amount_masks,
    std::vector<MockMembershipProofSortableSpV1> &tx_membership_proofs_out)
{
    CHECK_AND_ASSERT_THROW_MES(membership_ref_sets.size() == image_address_masks.size(), "Input components size mismatch");
    CHECK_AND_ASSERT_THROW_MES(membership_ref_sets.size() == image_amount_masks.size(), "Input components size mismatch");

    tx_membership_proofs_out.resize(membership_ref_sets.size());

    for (std::size_t input_index{0}; input_index < membership_ref_sets.size(); ++input_index)
    {
        make_v1_tx_membership_proof_sp_v1(membership_ref_sets[input_index],
            image_address_masks[input_index],
            image_amount_masks[input_index],
            tx_membership_proofs_out[input_index]);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_membership_proofs_sp_v1(const std::vector<MockMembershipReferenceSetSpV1> &membership_ref_sets,
    const std::vector<MockTxPartialInputSpV1> &partial_inputs,
    std::vector<MockMembershipProofSortableSpV1> &tx_membership_proofs_out)
{
    CHECK_AND_ASSERT_THROW_MES(membership_ref_sets.size() == partial_inputs.size(), "Input components size mismatch");

    tx_membership_proofs_out.resize(membership_ref_sets.size());

    for (std::size_t input_index{0}; input_index < membership_ref_sets.size(); ++input_index)
    {
        CHECK_AND_ASSERT_THROW_MES(membership_ref_sets[input_index].
                m_referenced_enotes[membership_ref_sets[input_index].m_real_spend_index_in_set].m_onetime_address ==
            partial_inputs[input_index].get_input_enote().m_onetime_address, 
            "Membership ref set real spend doesn't match partial input's enote.");

        make_v1_tx_membership_proof_sp_v1(membership_ref_sets[input_index],
            partial_inputs[input_index].get_image_address_mask(),
            partial_inputs[input_index].get_image_amount_mask(),
            tx_membership_proofs_out[input_index]);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_membership_proofs_sp_v1(const std::vector<MockMembershipReferenceSetSpV1> &membership_ref_sets,
    const MockTxPartialSpV1 &partial_tx,
    std::vector<MockMembershipProofSpV1> &tx_membership_proofs_out)
{
    // note: ref sets are assumed to be pre-sorted, so sortable membership proofs are not needed
    CHECK_AND_ASSERT_THROW_MES(membership_ref_sets.size() == partial_tx.m_image_address_masks.size(),
        "Input components size mismatch");
    CHECK_AND_ASSERT_THROW_MES(membership_ref_sets.size() == partial_tx.m_image_amount_masks.size(),
        "Input components size mismatch");

    tx_membership_proofs_out.resize(membership_ref_sets.size());

    for (std::size_t input_index{0}; input_index < membership_ref_sets.size(); ++input_index)
    {
        make_v1_tx_membership_proof_sp_v1(membership_ref_sets[input_index],
            partial_tx.m_image_address_masks[input_index],
            partial_tx.m_image_amount_masks[input_index],
            tx_membership_proofs_out[input_index]);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_partial_inputs_sp_v1(const std::vector<MockInputProposalSpV1> &input_proposals,
    const rct::key &proposal_prefix,
    const MockTxProposalSpV1 &tx_proposal,
    std::vector<MockTxPartialInputSpV1> &partial_inputs_out)
{
    CHECK_AND_ASSERT_THROW_MES(input_proposals.size() > 0, "Can't make partial tx inputs without any input proposals");

    partial_inputs_out.clear();
    partial_inputs_out.reserve(input_proposals.size());

    // make all but last input
    for (std::size_t input_index{0}; input_index < input_proposals.size() - 1; ++input_index)
        partial_inputs_out.emplace_back(input_proposals[input_index], proposal_prefix);

    // make last input
    partial_inputs_out.emplace_back(input_proposals.back(), proposal_prefix, tx_proposal, partial_inputs_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool balance_check_in_out_amnts_sp_v1(const std::vector<MockInputProposalSpV1> &input_proposals,
    const std::vector<MockDestinationSpV1> &destinations)
{
    std::vector<rct::xmr_amount> in_amounts;
    std::vector<rct::xmr_amount> out_amounts;
    in_amounts.reserve(input_proposals.size());
    out_amounts.reserve(destinations.size());

    for (const auto &input_proposal : input_proposals)
    {
        in_amounts.emplace_back(input_proposal.m_amount);
    }
    for (const auto &destination : destinations)
    {
        out_amounts.emplace_back(destination.m_amount);
    }

    return balance_check_in_out_amnts(in_amounts, out_amounts);
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<MockInputProposalSpV1> gen_mock_sp_input_proposals_v1(const std::vector<rct::xmr_amount> in_amounts)
{
    // generate random inputs
    std::vector<MockInputProposalSpV1> input_proposals;
    input_proposals.resize(in_amounts.size());

    for (std::size_t input_index{0}; input_index < in_amounts.size(); ++input_index)
    {
        input_proposals[input_index].gen(in_amounts[input_index]);
    }

    return input_proposals;
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<MockMembershipReferenceSetSpV1> gen_mock_sp_membership_ref_sets_v1(
    const std::vector<MockInputProposalSpV1> &input_proposals,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    std::shared_ptr<MockLedgerContext> ledger_context_inout)
{
    std::vector<MockENoteSpV1> input_enotes;
    input_enotes.reserve(input_proposals.size());

    for (const auto &input_proposal : input_proposals)
    {
        input_enotes.emplace_back(input_proposal.m_enote);
    }

    return gen_mock_sp_membership_ref_sets_v1(input_enotes, ref_set_decomp_n, ref_set_decomp_m, ledger_context_inout);
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<MockMembershipReferenceSetSpV1> gen_mock_sp_membership_ref_sets_v1(
    const std::vector<MockENoteSpV1> &input_enotes,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    std::shared_ptr<MockLedgerContext> ledger_context_inout)
{
    std::vector<MockMembershipReferenceSetSpV1> reference_sets;
    reference_sets.resize(input_enotes.size());

    std::size_t ref_set_size{ref_set_size_from_decomp(ref_set_decomp_n, ref_set_decomp_m)};  // n^m

    for (std::size_t input_index{0}; input_index < input_enotes.size(); ++input_index)
    {
        reference_sets[input_index].m_ref_set_decomp_n = ref_set_decomp_n;
        reference_sets[input_index].m_ref_set_decomp_m = ref_set_decomp_m;
        reference_sets[input_index].m_real_spend_index_in_set = crypto::rand_idx(ref_set_size);  // pi

        reference_sets[input_index].m_ledger_enote_indices.resize(ref_set_size);
        reference_sets[input_index].m_referenced_enotes.resize(ref_set_size);

        for (std::size_t ref_index{0}; ref_index < ref_set_size; ++ref_index)
        {
            // add real input at pi
            if (ref_index == reference_sets[input_index].m_real_spend_index_in_set)
            {
                reference_sets[input_index].m_referenced_enotes[ref_index] = input_enotes[input_index];
            }
            // add dummy enote
            else
            {
                reference_sets[input_index].m_referenced_enotes[ref_index].gen();
            }

            // insert referenced enote into mock ledger
            // note: in a real context, you would instead 'get' the enote's index from the ledger, and error if not found
            reference_sets[input_index].m_ledger_enote_indices[ref_index] =
                ledger_context_inout->add_enote_sp_v1(reference_sets[input_index].m_referenced_enotes[ref_index]);
        }
    }

    return reference_sets;
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<MockDestinationSpV1> gen_mock_sp_dests_v1(const std::vector<rct::xmr_amount> &out_amounts)
{
    // randomize destination order
    std::vector<rct::xmr_amount> randomized_out_amounts{out_amounts};
    std::shuffle(randomized_out_amounts.begin(), randomized_out_amounts.end(), crypto::random_device{});

    // generate random destinations
    std::vector<MockDestinationSpV1> destinations;
    destinations.resize(randomized_out_amounts.size());

    for (std::size_t dest_index{0}; dest_index < randomized_out_amounts.size(); ++dest_index)
    {
        destinations[dest_index].gen(randomized_out_amounts[dest_index]);
    }

    return destinations;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace mock_tx
