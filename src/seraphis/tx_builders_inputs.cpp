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
#include "tx_builder_inputs.h"

//local headers
#include "common/varint.h"
#include "concise_grootle.h"
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_config.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "mock_ledger_context.h"
#include "ringct/bulletproofs_plus.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_composition_proof.h"
#include "sp_core_enote_utils.h"
#include "sp_crypto_utils.h"
#include "tx_builder_types.h"
#include "tx_component_types.h"
#include "tx_misc_utils.h"

//third party headers

//standard headers
#include <memory>
#include <string>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
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
    char converted_index[(sizeof(std::size_t) * 8 + 6) / 7];
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
void prepare_input_commitment_factors_for_balance_proof_v1(
    const std::vector<SpInputProposalV1> &input_proposals,
    const std::vector<crypto::secret_key> &image_address_masks,
    std::vector<rct::xmr_amount> &input_amounts_out,
    std::vector<crypto::secret_key> &input_image_amount_commitment_blinding_factors_out)
{
    CHECK_AND_ASSERT_THROW_MES(input_proposals.size() == image_address_masks.size(),
        "Mismatch between input proposals and image address masks.");

    input_amounts_out.clear();
    input_image_amount_commitment_blinding_factors_out.clear();
    input_amounts_out.resize(input_proposals.size());
    input_image_amount_commitment_blinding_factors_out.resize(input_proposals.size());

    for (std::size_t input_index{0}; input_index < input_proposals.size(); ++input_index)
    {
        input_amounts_out[input_index] = input_proposals[input_index].m_amount;

        // input image amount commitment blinding factor: t_c + x
        sc_add(&(input_image_amount_commitment_blinding_factors_out[input_index]),
            &(image_address_masks[input_index]),  // t_c
            &(input_proposals[input_index].m_amount_blinding_factor));  // x
    }
}
//-------------------------------------------------------------------------------------------------------------------
void prepare_input_commitment_factors_for_balance_proof_v1(
    const std::vector<SpTxPartialInputV1> &partial_inputs,
    std::vector<crypto::secret_key> &input_image_amount_commitment_blinding_factors_out)
{
    input_image_amount_commitment_blinding_factors_out.clear();
    input_image_amount_commitment_blinding_factors_out.resize(partial_inputs.size());

    for (std::size_t input_index{0}; input_index < partial_inputs.size(); ++input_index)
    {
        // input image amount commitment blinding factor: t_c + x
        sc_add(&(input_image_amount_commitment_blinding_factors_out[input_index]),
            &(partial_inputs[input_index].m_image_commitment_mask),  // t_c
            &(partial_inputs[input_index].m_input_amount_blinding_factor));  // x
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_image_proof_sp_v1(const SpInputProposalV1 &input_proposal,
    const rct::key &masked_address,
    const crypto::secret_key &image_address_mask,
    const rct::key &message,
    SpImageProofV1 &tx_image_proof_out)
{
    // prepare for proof (squashed enote model): y, z
    crypto::secret_key y, z;
    crypto::secret_key squash_prefix;
    make_seraphis_squash_prefix(input_proposal.m_input_enote_core.m_onetime_address,
        input_proposal.m_input_enote_core.m_amount_commitment,
        squash_prefix);  // H(Ko,C)

    sc_mul(&y, &squash_prefix, &(input_proposal.m_enote_view_privkey));  // H(Ko,C) (k_{a, recipient} + k_{a, sender})
    sc_mul(&z, &squash_prefix, &(input_proposal.m_spendbase_privkey));  // H(Ko,C) k_{b, recipient}

    // make seraphis composition proof
    tx_image_proof_out.m_composition_proof =
        sp_composition_prove(message, masked_address, image_address_mask, y, z);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_image_proofs_sp_v1(const std::vector<SpInputProposalV1> &input_proposals,
    const std::vector<SpEnoteImageV1> &input_images,
    const std::vector<crypto::secret_key> &image_address_masks,
    const rct::key &message,
    std::vector<SpImageProofV1> &tx_image_proofs_out)
{
    // for squashed enote model

    CHECK_AND_ASSERT_THROW_MES(input_proposals.size() > 0, "Tried to make image proofs for 0 inputs.");
    CHECK_AND_ASSERT_THROW_MES(input_proposals.size() == input_images.size(), "Input components size mismatch");
    CHECK_AND_ASSERT_THROW_MES(input_proposals.size() == image_address_masks.size(), "Input components size mismatch");

    tx_image_proofs_out.clear();
    tx_image_proofs_out.resize(input_proposals.size());

    for (std::size_t input_index{0}; input_index < input_proposals.size(); ++input_index)
    {
        make_v1_tx_image_proof_sp_v1(input_proposals[input_index],
            input_images[input_index].m_enote_image_core.m_masked_address,
            image_address_masks[input_index],
            message,
            tx_image_proofs_out[input_index]);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_membership_proof_sp_v1(const SpMembershipReferenceSetV1 &membership_ref_set,
    const crypto::secret_key &image_address_mask,
    const crypto::secret_key &image_amount_mask,
    SpMembershipProofSortableV1 &tx_membership_proof_out)
{
    // for squashed enote model

    // make the membership proof
    make_v1_tx_membership_proof_sp_v1(membership_ref_set,
        image_address_mask,
        image_amount_mask,
        tx_membership_proof_out.m_membership_proof);

    // save the masked address for later matching the membership proof with its input image
    squash_seraphis_address(
        membership_ref_set.m_referenced_enotes[membership_ref_set.m_real_spend_index_in_set].m_onetime_address,
        membership_ref_set.m_referenced_enotes[membership_ref_set.m_real_spend_index_in_set].m_amount_commitment,
        tx_membership_proof_out.m_masked_address);

    mask_key(image_address_mask,
        tx_membership_proof_out.m_masked_address,
        tx_membership_proof_out.m_masked_address);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_membership_proof_sp_v1(const SpMembershipReferenceSetV1 &membership_ref_set,
    const crypto::secret_key &image_address_mask,
    const crypto::secret_key &image_amount_mask,
    SpMembershipProofV1 &tx_membership_proof_out)
{
    // for squashed enote model

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
    referenced_enotes.resize(ref_set_size, rct::keyV(1));

    for (std::size_t ref_index{0}; ref_index < ref_set_size; ++ref_index)
    {
        // Q_i
        // computing this for every enote for every proof is expensive; TODO: copy Q_i from the node record
        seraphis_squashed_enote_Q(membership_ref_set.m_referenced_enotes[ref_index].m_onetime_address,
            membership_ref_set.m_referenced_enotes[ref_index].m_amount_commitment,
            referenced_enotes[ref_index][0]);
    }

    // proof offsets
    rct::keyV image_offsets;
    image_offsets.resize(1);

    // Q'
    crypto::secret_key q_prime;
    sc_add(&q_prime, &image_address_mask, &image_amount_mask);  // t_k + t_c
    mask_key(q_prime, referenced_enotes[membership_ref_set.m_real_spend_index_in_set][0], image_offsets[0]);  // Q'

    // secret key of (Q[l] - Q')
    std::vector<crypto::secret_key> image_masks;
    image_masks.emplace_back(q_prime);  // t_k + t_c
    sc_mul(&(image_masks[0]), &(image_masks[0]), MINUS_ONE.bytes);  // -(t_k + t_c)

    // proof message
    rct::key message{get_tx_membership_proof_message_sp_v1(membership_ref_set.m_ledger_enote_indices)};


    /// make concise grootle proof
    tx_membership_proof_out.m_concise_grootle_proof = concise_grootle_prove(referenced_enotes,
        membership_ref_set.m_real_spend_index_in_set,
        image_offsets,
        image_masks,
        membership_ref_set.m_ref_set_decomp_n,
        membership_ref_set.m_ref_set_decomp_m,
        message);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_membership_proofs_sp_v1(const std::vector<SpMembershipReferenceSetV1> &membership_ref_sets,
    const std::vector<crypto::secret_key> &image_address_masks,
    const std::vector<crypto::secret_key> &image_amount_masks,
    std::vector<SpMembershipProofSortableV1> &tx_membership_proofs_out)
{
    // for squashed enote model

    CHECK_AND_ASSERT_THROW_MES(membership_ref_sets.size() == image_address_masks.size(), "Input components size mismatch");
    CHECK_AND_ASSERT_THROW_MES(membership_ref_sets.size() == image_amount_masks.size(), "Input components size mismatch");

    tx_membership_proofs_out.clear();
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
void make_v1_tx_membership_proofs_sp_v1(const std::vector<SpMembershipReferenceSetV1> &membership_ref_sets,
    const std::vector<SpTxPartialInputV1> &partial_inputs,
    std::vector<SpMembershipProofSortableV1> &tx_membership_proofs_out)
{
    // for squashed enote model

    CHECK_AND_ASSERT_THROW_MES(membership_ref_sets.size() == partial_inputs.size(), "Input components size mismatch");

    tx_membership_proofs_out.clear();
    tx_membership_proofs_out.resize(membership_ref_sets.size());

    for (std::size_t input_index{0}; input_index < membership_ref_sets.size(); ++input_index)
    {
        CHECK_AND_ASSERT_THROW_MES(membership_ref_sets[input_index].
                m_referenced_enotes[membership_ref_sets[input_index].m_real_spend_index_in_set].m_onetime_address ==
            partial_inputs[input_index].m_input_enote.m_onetime_address, 
            "Membership ref set real spend doesn't match partial input's enote.");

        make_v1_tx_membership_proof_sp_v1(membership_ref_sets[input_index],
            partial_inputs[input_index].m_image_address_mask,
            partial_inputs[input_index].m_image_commitment_mask,
            tx_membership_proofs_out[input_index]);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_membership_proofs_sp_v1(const std::vector<SpMembershipReferenceSetV1> &membership_ref_sets,
    const SpTxPartialV1 &partial_tx,
    std::vector<SpMembershipProofV1> &tx_membership_proofs_out)
{
    // for squashed enote model

    // note: ref sets are assumed to be pre-sorted, so sortable membership proofs are not needed
    CHECK_AND_ASSERT_THROW_MES(membership_ref_sets.size() == partial_tx.m_image_address_masks.size(),
        "Input components size mismatch");
    CHECK_AND_ASSERT_THROW_MES(membership_ref_sets.size() == partial_tx.m_image_commitment_masks.size(),
        "Input components size mismatch");

    tx_membership_proofs_out.clear();
    tx_membership_proofs_out.resize(membership_ref_sets.size());

    for (std::size_t input_index{0}; input_index < membership_ref_sets.size(); ++input_index)
    {
        make_v1_tx_membership_proof_sp_v1(membership_ref_sets[input_index],
            partial_tx.m_image_address_masks[input_index],
            partial_tx.m_image_commitment_masks[input_index],
            tx_membership_proofs_out[input_index]);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_partial_inputs_sp_v1(const std::vector<SpInputProposalV1> &input_proposals,
    const rct::key &proposal_prefix,
    const SpTxProposalV1 &tx_proposal,
    std::vector<SpTxPartialInputV1> &partial_inputs_out)
{
    CHECK_AND_ASSERT_THROW_MES(input_proposals.size() > 0, "Can't make partial tx inputs without any input proposals");

    partial_inputs_out.clear();
    partial_inputs_out.reserve(input_proposals.size());

    // make all inputs
    for (const auto &input_proposal : input_proposals)
        partial_inputs_out.emplace_back(input_proposal, proposal_prefix);
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<SpInputProposalV1> gen_mock_sp_input_proposals_v1(const std::vector<rct::xmr_amount> in_amounts)
{
    // generate random inputs
    std::vector<SpInputProposalV1> input_proposals;
    input_proposals.resize(in_amounts.size());

    for (std::size_t input_index{0}; input_index < in_amounts.size(); ++input_index)
    {
        input_proposals[input_index].gen(in_amounts[input_index]);
    }

    return input_proposals;
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<SpMembershipReferenceSetV1> gen_mock_sp_membership_ref_sets_v1(
    const std::vector<SpInputProposalV1> &input_proposals,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    std::shared_ptr<MockLedgerContext> ledger_context_inout)
{
    // for squashed enote model

    std::vector<SpEnoteV1> input_enotes;
    input_enotes.reserve(input_proposals.size());

    for (const auto &input_proposal : input_proposals)
    {
        input_enotes.emplace_back(input_proposal.m_enote);
    }

    return gen_mock_sp_membership_ref_sets_v1(input_enotes, ref_set_decomp_n, ref_set_decomp_m, ledger_context_inout);
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<SpMembershipReferenceSetV1> gen_mock_sp_membership_ref_sets_v1(
    const std::vector<SpEnoteV1> &input_enotes,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    std::shared_ptr<MockLedgerContext> ledger_context_inout)
{
    // for squashed enote model

    std::vector<SpMembershipReferenceSetV1> reference_sets;
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

            // insert referenced enote into mock ledger (also, record squashed enote)
            // note: in a real context, you would instead 'get' the enote's index from the ledger, and error if not found
            reference_sets[input_index].m_ledger_enote_indices[ref_index] =
                ledger_context_inout->add_enote_sp_v1(reference_sets[input_index].m_referenced_enotes[ref_index]);
        }
    }

    return reference_sets;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
