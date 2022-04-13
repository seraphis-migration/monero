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
#include "tx_builders_inputs.h"

//local headers
#include "common/varint.h"
#include "concise_grootle.h"
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_config.h"
#include "seraphis_config_temp.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "mock_ledger_context.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_composition_proof.h"
#include "sp_core_enote_utils.h"
#include "sp_crypto_utils.h"
#include "tx_builder_types.h"
#include "tx_component_types.h"
#include "tx_misc_utils.h"
#include "tx_record_types.h"
#include "tx_record_utils.h"

//third party headers

//standard headers
#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void align_v1_membership_proofs_v1(const std::vector<SpEnoteImageV1> &input_images,
    std::vector<SpAlignableMembershipProofV1> alignable_membership_proofs,
    std::vector<SpMembershipProofV1> &membership_proofs_out)
{
    CHECK_AND_ASSERT_THROW_MES(alignable_membership_proofs.size() == input_images.size(),
        "Mismatch between alignable membership proof count and partial tx input image count.");

    membership_proofs_out.clear();
    membership_proofs_out.reserve(alignable_membership_proofs.size());

    for (const SpEnoteImageV1 &input_image : input_images)
    {
        // find the membership proof that matches with the input image at this index
        auto membership_proof_match =
            std::find(
                alignable_membership_proofs.begin(),
                alignable_membership_proofs.end(),
                input_image.m_core.m_masked_address
            );

        CHECK_AND_ASSERT_THROW_MES(membership_proof_match != alignable_membership_proofs.end(),
            "Could not find input image to match with an alignable membership proof.");

        membership_proofs_out.emplace_back(std::move(membership_proof_match->m_membership_proof));
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_tx_membership_proof_message_v1(const std::vector<std::size_t> &enote_ledger_indices, rct::key &message_out)
{
    std::string hash;
    hash.reserve(sizeof(CRYPTONOTE_NAME) + enote_ledger_indices.size()*((sizeof(std::size_t) * 8 + 6) / 7));
    // project name
    hash = CRYPTONOTE_NAME;
    // all referenced enote ledger indices
    char converted_index[(sizeof(std::size_t) * 8 + 6) / 7];
    char *end;
    for (const std::size_t index : enote_ledger_indices)
    {
        // TODO: append real ledger references
        end = converted_index;
        tools::write_varint(end, index);
        assert(end <= converted_index + sizeof(converted_index));
        hash.append(converted_index, end - converted_index);
    }

    rct::hash_to_scalar(message_out, hash.data(), hash.size());
}
//-------------------------------------------------------------------------------------------------------------------
void prepare_input_commitment_factors_for_balance_proof_v1(
    const std::vector<SpInputProposalV1> &input_proposals,
    const std::vector<crypto::secret_key> &image_amount_masks,
    std::vector<rct::xmr_amount> &input_amounts_out,
    std::vector<crypto::secret_key> &blinding_factors_out)
{
    // use input proposals and image amount masks to get amounts/blinding factors
    CHECK_AND_ASSERT_THROW_MES(input_proposals.size() == image_amount_masks.size(),
        "Mismatch between input proposals and image address masks.");

    blinding_factors_out.clear();
    input_amounts_out.clear();
    blinding_factors_out.resize(input_proposals.size());
    input_amounts_out.reserve(input_proposals.size());

    for (std::size_t input_index{0}; input_index < input_proposals.size(); ++input_index)
    {
        // input image amount commitment blinding factor: t_c + x
        sc_add(to_bytes(blinding_factors_out[input_index]),
            to_bytes(image_amount_masks[input_index]),  // t_c
            to_bytes(input_proposals[input_index].m_core.m_amount_blinding_factor));  // x

        // input amount: a
        input_amounts_out.emplace_back(input_proposals[input_index].m_core.m_amount);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void prepare_input_commitment_factors_for_balance_proof_v1(
    const std::vector<SpPartialInputV1> &partial_inputs,
    std::vector<rct::xmr_amount> &input_amounts_out,
    std::vector<crypto::secret_key> &blinding_factors_out)
{
    // use partial inputs to get amounts/blinding factors
    blinding_factors_out.clear();
    input_amounts_out.clear();
    blinding_factors_out.resize(partial_inputs.size());
    input_amounts_out.reserve(partial_inputs.size());

    for (std::size_t input_index{0}; input_index < partial_inputs.size(); ++input_index)
    {
        // input image amount commitment blinding factor: t_c + x
        sc_add(to_bytes(blinding_factors_out[input_index]),
            to_bytes(partial_inputs[input_index].m_image_commitment_mask),  // t_c
            to_bytes(partial_inputs[input_index].m_input_amount_blinding_factor));  // x

        // input amount: a
        input_amounts_out.emplace_back(partial_inputs[input_index].m_input_amount);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_input_proposal(const crypto::secret_key &enote_view_privkey,
    const crypto::secret_key &spendbase_privkey,
    const crypto::secret_key &input_amount_blinding_factor,
    const rct::xmr_amount &input_amount,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpInputProposal &proposal_out)
{
    // make an input proposal

    proposal_out.m_enote_view_privkey     = enote_view_privkey;
    proposal_out.m_spendbase_privkey      = spendbase_privkey;
    proposal_out.m_amount_blinding_factor = input_amount_blinding_factor;
    proposal_out.m_amount                 = input_amount;
    proposal_out.m_address_mask           = address_mask;
    proposal_out.m_commitment_mask        = commitment_mask;
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_input_proposal_v1(const SpEnoteRecordV1 &enote_record,
    const crypto::secret_key &spendbase_privkey,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpInputProposalV1 &proposal_out)
{
    // make input proposal from enote record
    make_input_proposal(enote_record.m_enote_view_privkey,
        spendbase_privkey,
        enote_record.m_amount_blinding_factor,
        enote_record.m_amount,
        address_mask,
        commitment_mask,
        proposal_out.m_core);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_make_v1_input_proposal_v1(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const crypto::secret_key &spendbase_privkey,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpInputProposalV1 &proposal_out)
{
    // try to extract info from enote then make an input proposal
    SpEnoteRecordV1 enote_record;
    if (!try_get_enote_record_v1(enote,
            enote_ephemeral_pubkey,
            wallet_spend_pubkey,
            k_view_balance,
            enote_record))
        return false;

    make_v1_input_proposal_v1(enote_record,
        spendbase_privkey,
        address_mask,
        commitment_mask,
        proposal_out);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_image_proof_v1(const SpInputProposal &input_proposal,
    const rct::key &message,
    SpImageProofV1 &image_proof_out)
{
    // make image proof

    // the input enote
    SpEnote input_enote_core;
    input_proposal.get_enote_core(input_enote_core);

    // the input enote image
    SpEnoteImage input_enote_image_core;
    input_proposal.get_enote_image_core(input_enote_image_core);

    // prepare for proof (squashed enote model): y, z
    crypto::secret_key y, z;
    crypto::secret_key squash_prefix;
    make_seraphis_squash_prefix(input_enote_core.m_onetime_address,
        input_enote_core.m_amount_commitment,
        squash_prefix);  // H(Ko,C)

    // H(Ko,C) (k_{a, recipient} + k_{a, sender})
    sc_mul(to_bytes(y), to_bytes(squash_prefix), to_bytes(input_proposal.m_enote_view_privkey));
    // H(Ko,C) k_{b, recipient}
    sc_mul(to_bytes(z), to_bytes(squash_prefix), to_bytes(input_proposal.m_spendbase_privkey));

    // make seraphis composition proof
    image_proof_out.m_composition_proof =
        sp_composition_prove(message, input_enote_image_core.m_masked_address, input_proposal.m_address_mask, y, z);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_image_proofs_v1(const std::vector<SpInputProposalV1> &input_proposals,
    const rct::key &message,
    std::vector<SpImageProofV1> &image_proofs_out)
{
    // make multiple image proofs
    CHECK_AND_ASSERT_THROW_MES(input_proposals.size() > 0, "Tried to make image proofs for 0 inputs.");

    image_proofs_out.clear();
    image_proofs_out.reserve(input_proposals.size());

    for (const SpInputProposalV1 &input_proposal : input_proposals)
    {
        image_proofs_out.emplace_back();
        make_v1_image_proof_v1(input_proposal.m_core, message, image_proofs_out.back());
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_membership_proof_v1(const SpMembershipReferenceSetV1 &membership_ref_set,
    const crypto::secret_key &image_address_mask,
    const crypto::secret_key &image_amount_mask,
    SpMembershipProofV1 &membership_proof_out)
{
    // make membership proof

    /// initial checks
    std::size_t ref_set_size{
            ref_set_size_from_decomp(membership_ref_set.m_ref_set_decomp_n, membership_ref_set.m_ref_set_decomp_m)
        };

    CHECK_AND_ASSERT_THROW_MES(membership_ref_set.m_referenced_enotes.size() == ref_set_size,
        "Ref set size doesn't match number of referenced enotes");
    CHECK_AND_ASSERT_THROW_MES(membership_ref_set.m_ledger_enote_indices.size() == ref_set_size,
        "Ref set size doesn't match number of referenced enotes' ledger indices");


    /// prepare to make proof

    // public keys referenced by proof
    rct::keyM reference_keys;
    reference_keys.resize(ref_set_size, rct::keyV(1));

    for (std::size_t ref_index{0}; ref_index < ref_set_size; ++ref_index)
    {
        // Q_i
        // computing this for every enote for every proof is expensive; TODO: copy Q_i from the node record
        make_seraphis_squashed_enote_Q(membership_ref_set.m_referenced_enotes[ref_index].m_onetime_address,
            membership_ref_set.m_referenced_enotes[ref_index].m_amount_commitment,
            reference_keys[ref_index][0]);
    }

    // proof offsets (only one in the squashed enote model)
    rct::keyV image_offsets;
    image_offsets.resize(1);

    // Q'
    crypto::secret_key squashed_enote_mask;
    sc_add(to_bytes(squashed_enote_mask), to_bytes(image_address_mask), to_bytes(image_amount_mask));  // t_k + t_c
    mask_key(squashed_enote_mask,
        reference_keys[membership_ref_set.m_real_spend_index_in_set][0],
        image_offsets[0]);  // Q'

    // secret key of (Q[l] - Q')
    std::vector<crypto::secret_key> image_masks;
    image_masks.emplace_back(squashed_enote_mask);  // t_k + t_c
    sc_mul(to_bytes(image_masks[0]), to_bytes(image_masks[0]), MINUS_ONE.bytes);  // -(t_k + t_c)

    // proof message
    rct::key message;
    make_tx_membership_proof_message_v1(membership_ref_set.m_ledger_enote_indices, message);


    /// make concise grootle proof
    membership_proof_out.m_concise_grootle_proof = concise_grootle_prove(reference_keys,
        membership_ref_set.m_real_spend_index_in_set,
        image_offsets,
        image_masks,
        membership_ref_set.m_ref_set_decomp_n,
        membership_ref_set.m_ref_set_decomp_m,
        message);


    /// copy miscellaneous components
    membership_proof_out.m_ledger_enote_indices = membership_ref_set.m_ledger_enote_indices;
    membership_proof_out.m_ref_set_decomp_n = membership_ref_set.m_ref_set_decomp_n;
    membership_proof_out.m_ref_set_decomp_m = membership_ref_set.m_ref_set_decomp_m;
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_membership_proof_v1(const SpMembershipReferenceSetV1 &membership_ref_set,
    const crypto::secret_key &image_address_mask,
    const crypto::secret_key &image_amount_mask,
    SpAlignableMembershipProofV1 &alignable_membership_proof_out)
{
    // make alignable membership proof

    // save the masked address to later match the membership proof with its input image
    make_seraphis_squashed_address_key(
        membership_ref_set.m_referenced_enotes[membership_ref_set.m_real_spend_index_in_set].m_onetime_address,
        membership_ref_set.m_referenced_enotes[membership_ref_set.m_real_spend_index_in_set].m_amount_commitment,
        alignable_membership_proof_out.m_masked_address);  //H(Ko,C) Ko

    mask_key(image_address_mask,
        alignable_membership_proof_out.m_masked_address,
        alignable_membership_proof_out.m_masked_address);  //t_k G + H(Ko,C) Ko

    // make the membership proof
    make_v1_membership_proof_v1(membership_ref_set,
        image_address_mask,
        image_amount_mask,
        alignable_membership_proof_out.m_membership_proof);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_membership_proofs_v1(const std::vector<SpMembershipReferenceSetV1> &membership_ref_sets,
    const SpPartialTxV1 &partial_tx,
    std::vector<SpMembershipProofV1> &membership_proofs_out)
{
    // make multiple membership proofs

    // note: ref sets are assumed to be pre-sorted, so alignable membership proofs are not needed
    CHECK_AND_ASSERT_THROW_MES(membership_ref_sets.size() == partial_tx.m_image_address_masks.size(),
        "Input components size mismatch");
    CHECK_AND_ASSERT_THROW_MES(membership_ref_sets.size() == partial_tx.m_image_commitment_masks.size(),
        "Input components size mismatch");

    membership_proofs_out.clear();
    membership_proofs_out.resize(membership_ref_sets.size());

    for (std::size_t input_index{0}; input_index < membership_ref_sets.size(); ++input_index)
    {
        make_v1_membership_proof_v1(membership_ref_sets[input_index],
            partial_tx.m_image_address_masks[input_index],
            partial_tx.m_image_commitment_masks[input_index],
            membership_proofs_out[input_index]);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_membership_proofs_v1(const std::vector<SpMembershipReferenceSetV1> &membership_ref_sets,
    const std::vector<crypto::secret_key> &image_address_masks,
    const std::vector<crypto::secret_key> &image_amount_masks,
    std::vector<SpAlignableMembershipProofV1> &alignable_membership_proofs_out)
{
    // make multiple alignable membership proofs
    CHECK_AND_ASSERT_THROW_MES(membership_ref_sets.size() == image_address_masks.size(), "Input components size mismatch");
    CHECK_AND_ASSERT_THROW_MES(membership_ref_sets.size() == image_amount_masks.size(), "Input components size mismatch");

    alignable_membership_proofs_out.clear();
    alignable_membership_proofs_out.resize(membership_ref_sets.size());

    for (std::size_t input_index{0}; input_index < membership_ref_sets.size(); ++input_index)
    {
        make_v1_membership_proof_v1(membership_ref_sets[input_index],
            image_address_masks[input_index],
            image_amount_masks[input_index],
            alignable_membership_proofs_out[input_index]);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_membership_proofs_v1(const std::vector<SpMembershipReferenceSetV1> &membership_ref_sets,
    const std::vector<SpPartialInputV1> &partial_inputs,
    std::vector<SpAlignableMembershipProofV1> &alignable_membership_proofs_out)
{
    // make multiple alignable membership proofs with partial inputs
    CHECK_AND_ASSERT_THROW_MES(membership_ref_sets.size() == partial_inputs.size(), "Input components size mismatch");

    alignable_membership_proofs_out.clear();
    alignable_membership_proofs_out.resize(membership_ref_sets.size());

    for (std::size_t input_index{0}; input_index < membership_ref_sets.size(); ++input_index)
    {
        CHECK_AND_ASSERT_THROW_MES(membership_ref_sets[input_index].
                m_referenced_enotes[membership_ref_sets[input_index].m_real_spend_index_in_set].m_onetime_address ==
            partial_inputs[input_index].m_input_enote_core.m_onetime_address, 
            "Membership ref set real spend doesn't match partial input's enote.");

        make_v1_membership_proof_v1(membership_ref_sets[input_index],
            partial_inputs[input_index].m_image_address_mask,
            partial_inputs[input_index].m_image_commitment_mask,
            alignable_membership_proofs_out[input_index]);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_partial_input_v1(const SpInputProposalV1 &input_proposal,
    const rct::key &proposal_prefix,
    SpPartialInputV1 &partial_input_out)
{
    // prepare input image
    input_proposal.get_enote_image_v1(partial_input_out.m_input_image);

    // copy misc. proposal info
    partial_input_out.m_image_address_mask           = input_proposal.m_core.m_address_mask;
    partial_input_out.m_image_commitment_mask        = input_proposal.m_core.m_commitment_mask;
    partial_input_out.m_proposal_prefix              = proposal_prefix;
    partial_input_out.m_input_amount                 = input_proposal.m_core.m_amount;
    partial_input_out.m_input_amount_blinding_factor = input_proposal.m_core.m_amount_blinding_factor;
    input_proposal.m_core.get_enote_core(partial_input_out.m_input_enote_core);

    // construct image proof
    make_v1_image_proof_v1(input_proposal.m_core,
        partial_input_out.m_proposal_prefix,
        partial_input_out.m_image_proof);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_partial_inputs_v1(const std::vector<SpInputProposalV1> &input_proposals,
    const rct::key &proposal_prefix,
    std::vector<SpPartialInputV1> &partial_inputs_out)
{
    CHECK_AND_ASSERT_THROW_MES(input_proposals.size() > 0, "Can't make partial tx inputs without any input proposals");

    partial_inputs_out.clear();
    partial_inputs_out.reserve(input_proposals.size());

    // make all inputs
    for (const SpInputProposalV1 &input_proposal : input_proposals)
    {
        partial_inputs_out.emplace_back();
        make_v1_partial_input_v1(input_proposal, proposal_prefix, partial_inputs_out.back());
    }
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<SpInputProposalV1> gen_mock_sp_input_proposals_v1(const std::vector<rct::xmr_amount> in_amounts)
{
    // generate random inputs
    std::vector<SpInputProposalV1> input_proposals;
    input_proposals.reserve(in_amounts.size());

    for (const rct::xmr_amount in_amount : in_amounts)
    {
        input_proposals.emplace_back();
        input_proposals.back().gen(in_amount);
    }

    return input_proposals;
}
//-------------------------------------------------------------------------------------------------------------------
SpMembershipReferenceSetV1 gen_mock_sp_membership_ref_set_v1(
    const SpEnote &input_enote,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    MockLedgerContext &ledger_context_inout)
{
    SpMembershipReferenceSetV1 reference_set;

    std::size_t ref_set_size{ref_set_size_from_decomp(ref_set_decomp_n, ref_set_decomp_m)};  // n^m

    reference_set.m_ref_set_decomp_n = ref_set_decomp_n;
    reference_set.m_ref_set_decomp_m = ref_set_decomp_m;
    reference_set.m_real_spend_index_in_set = crypto::rand_idx(ref_set_size);  // pi

    reference_set.m_ledger_enote_indices.resize(ref_set_size);
    reference_set.m_referenced_enotes.resize(ref_set_size);

    for (std::size_t ref_index{0}; ref_index < ref_set_size; ++ref_index)
    {
        // add real input at pi
        if (ref_index == reference_set.m_real_spend_index_in_set)
        {
            reference_set.m_referenced_enotes[ref_index] = input_enote;
        }
        // add dummy enote
        else
        {
            reference_set.m_referenced_enotes[ref_index].gen();
        }

        // insert referenced enote into mock ledger (also, record squashed enote)
        // note: in a real context, you would instead 'get' the enote's index from the ledger, and error if not found
        SpEnoteV1 temp_enote;
        temp_enote.m_core = reference_set.m_referenced_enotes[ref_index];

        reference_set.m_ledger_enote_indices[ref_index] = ledger_context_inout.add_enote_v1(temp_enote);
    }

    return reference_set;
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<SpMembershipReferenceSetV1> gen_mock_sp_membership_ref_sets_v1(
    const std::vector<SpEnote> &input_enotes,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    MockLedgerContext &ledger_context_inout)
{
    // make mock membership ref sets from input enotes
    std::vector<SpMembershipReferenceSetV1> reference_sets;
    reference_sets.reserve(input_enotes.size());

    for (const SpEnote &input_enote : input_enotes)
    {
        reference_sets.emplace_back(
                gen_mock_sp_membership_ref_set_v1(input_enote, ref_set_decomp_n, ref_set_decomp_m, ledger_context_inout)
            );
    }

    return reference_sets;
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<SpMembershipReferenceSetV1> gen_mock_sp_membership_ref_sets_v1(
    const std::vector<SpInputProposalV1> &input_proposals,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    MockLedgerContext &ledger_context_inout)
{
    // make mock membership ref sets from input proposals
    std::vector<SpEnote> input_enotes;
    input_enotes.reserve(input_proposals.size());

    for (const SpInputProposalV1 &input_proposal : input_proposals)
    {
        input_enotes.emplace_back();
        input_proposal.m_core.get_enote_core(input_enotes.back());
    }

    return gen_mock_sp_membership_ref_sets_v1(input_enotes, ref_set_decomp_n, ref_set_decomp_m, ledger_context_inout);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
