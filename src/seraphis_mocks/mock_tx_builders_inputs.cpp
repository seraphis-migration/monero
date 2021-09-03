// Copyright (c) 2022, The Monero Project
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
#include "mock_tx_builders_inputs.h"

//local headers
#include "common/container_helpers.h"
#include "crypto/crypto.h"
#include "misc_log_ex.h"
#include "mock_ledger_context.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/binned_reference_set.h"
#include "seraphis_core/binned_reference_set_utils.h"
#include "seraphis_core/sp_core_types.h"
#include "seraphis_core/sp_ref_set_index_mapper_flat.h"
#include "seraphis_crypto/math_utils.h"
#include "seraphis_main/tx_builder_types.h"
#include "seraphis_main/tx_builders_inputs.h"
#include "seraphis_main/tx_component_types.h"

//third party headers

//standard headers
#include <algorithm>
#include <unordered_map>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_mocks"

namespace sp
{
namespace mocks
{
//-------------------------------------------------------------------------------------------------------------------
std::vector<SpInputProposalV1> gen_mock_sp_input_proposals_v1(const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_view_balance,
    const std::vector<rct::xmr_amount> &in_amounts)
{
    // generate random inputs
    std::vector<SpInputProposalV1> input_proposals;
    input_proposals.reserve(in_amounts.size());

    for (const rct::xmr_amount in_amount : in_amounts)
        tools::add_element(input_proposals) = gen_sp_input_proposal_v1(sp_spend_privkey, k_view_balance, in_amount);

    return input_proposals;
}
//-------------------------------------------------------------------------------------------------------------------
SpMembershipProofPrepV1 gen_mock_sp_membership_proof_prep_for_enote_at_pos_v1(
    const SpEnoteCoreVariant &real_reference_enote,
    const std::uint64_t &real_reference_index_in_ledger,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    const MockLedgerContext &ledger_context)
{
    // generate a mock membership proof prep

    /// checks and initialization
    const std::size_t ref_set_size{math::uint_pow(ref_set_decomp_n, ref_set_decomp_m)};  // n^m

    CHECK_AND_ASSERT_THROW_MES(validate_bin_config_v1(ref_set_size, bin_config),
        "gen mock membership proof prep: invalid binned reference set config.");


    /// make binned reference set
    SpMembershipProofPrepV1 proof_prep;

    // 1. flat index mapper for mock-up
    const SpRefSetIndexMapperFlat flat_index_mapper{0, ledger_context.max_sp_enote_index()};

    // 2. generator seed
    rct::key generator_seed;
    make_binned_ref_set_generator_seed_v1(onetime_address_ref(real_reference_enote),
        amount_commitment_ref(real_reference_enote),
        address_mask,
        commitment_mask,
        generator_seed);

    // 3. binned reference set
    make_binned_reference_set_v1(flat_index_mapper,
        bin_config,
        generator_seed,
        ref_set_size,
        real_reference_index_in_ledger,
        proof_prep.binned_reference_set);


    /// copy all referenced enotes from the ledger (in squashed enote representation)
    std::vector<std::uint64_t> reference_indices;
    CHECK_AND_ASSERT_THROW_MES(try_get_reference_indices_from_binned_reference_set_v1(proof_prep.binned_reference_set,
            reference_indices),
        "gen mock membership proof prep: could not extract reference indices from binned representation (bug).");

    ledger_context.get_reference_set_proof_elements_v2(reference_indices, proof_prep.referenced_enotes_squashed);


    /// copy misc pieces
    proof_prep.ref_set_decomp_n     = ref_set_decomp_n;
    proof_prep.ref_set_decomp_m     = ref_set_decomp_m;
    proof_prep.real_reference_enote = real_reference_enote;
    proof_prep.address_mask         = address_mask;
    proof_prep.commitment_mask      = commitment_mask;

    return proof_prep;
}
//-------------------------------------------------------------------------------------------------------------------
SpMembershipProofPrepV1 gen_mock_sp_membership_proof_prep_v1(
    const SpEnoteCoreVariant &real_reference_enote,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    MockLedgerContext &ledger_context_inout)
{
    // generate a mock membership proof prep

    /// add fake enotes to the ledger (2x the ref set size), with the real one at a random location

    // 1. make fake enotes
    const std::size_t ref_set_size{math::uint_pow(ref_set_decomp_n, ref_set_decomp_m)};  // n^m
    const std::size_t num_enotes_to_add{ref_set_size * 2};
    const std::size_t add_real_at_pos{crypto::rand_idx(num_enotes_to_add)};
    std::vector<SpEnoteVariant> mock_enotes;
    mock_enotes.reserve(num_enotes_to_add);

    for (std::size_t enote_to_add{0}; enote_to_add < num_enotes_to_add; ++enote_to_add)
    {
        if (enote_to_add == add_real_at_pos)
        {
            if (const SpCoinbaseEnoteCore *enote_ptr = real_reference_enote.try_unwrap<SpCoinbaseEnoteCore>())
                mock_enotes.emplace_back(SpCoinbaseEnoteV1{.core = *enote_ptr});
            else if (const SpEnoteCore *enote_ptr = real_reference_enote.try_unwrap<SpEnoteCore>())
                mock_enotes.emplace_back(SpEnoteV1{.core = *enote_ptr});
            else
                CHECK_AND_ASSERT_THROW_MES(false, "gen mock sp membership proof prep: invalid real reference enote type.");
        }
        else
            mock_enotes.emplace_back(gen_sp_enote_v1());
    }

    // 2. clear any txs lingering unconfirmed
    ledger_context_inout.commit_unconfirmed_txs_v1(rct::pkGen(),
        rct::pkGen(),
        SpTxSupplementV1{},
        std::vector<SpEnoteVariant>{});

    // 3. add mock enotes as the outputs of a mock coinbase tx
    const std::uint64_t real_reference_index_in_ledger{ledger_context_inout.max_sp_enote_index() + add_real_at_pos + 1};
    ledger_context_inout.commit_unconfirmed_txs_v1(rct::pkGen(),
        rct::pkGen(),
        SpTxSupplementV1{},
        std::move(mock_enotes));


    /// finish making the proof prep
    return gen_mock_sp_membership_proof_prep_for_enote_at_pos_v1(real_reference_enote,
        real_reference_index_in_ledger,
        address_mask,
        commitment_mask,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context_inout);
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<SpMembershipProofPrepV1> gen_mock_sp_membership_proof_preps_v1(
    const std::vector<SpEnoteCoreVariant> &real_referenced_enotes,
    const std::vector<crypto::secret_key> &address_masks,
    const std::vector<crypto::secret_key> &commitment_masks,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    MockLedgerContext &ledger_context_inout)
{
    // make mock membership ref sets from input enotes
    CHECK_AND_ASSERT_THROW_MES(real_referenced_enotes.size() == address_masks.size(),
        "gen mock membership proof preps: input enotes don't line up with address masks.");
    CHECK_AND_ASSERT_THROW_MES(real_referenced_enotes.size() == commitment_masks.size(),
        "gen mock membership proof preps: input enotes don't line up with commitment masks.");

    std::vector<SpMembershipProofPrepV1> proof_preps;
    proof_preps.reserve(real_referenced_enotes.size());

    for (std::size_t input_index{0}; input_index < real_referenced_enotes.size(); ++input_index)
    {
        proof_preps.emplace_back(
                gen_mock_sp_membership_proof_prep_v1(real_referenced_enotes[input_index],
                    address_masks[input_index],
                    commitment_masks[input_index],
                    ref_set_decomp_n,
                    ref_set_decomp_m,
                    bin_config,
                    ledger_context_inout)
            );
    }

    return proof_preps;
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<SpMembershipProofPrepV1> gen_mock_sp_membership_proof_preps_v1(
    const std::vector<SpInputProposalV1> &input_proposals,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    MockLedgerContext &ledger_context_inout)
{
    // make mock membership ref sets from input proposals
    std::vector<SpEnoteCoreVariant> input_enotes;
    std::vector<crypto::secret_key> address_masks;
    std::vector<crypto::secret_key> commitment_masks;
    input_enotes.reserve(input_proposals.size());
    address_masks.reserve(input_proposals.size());
    commitment_masks.reserve(input_proposals.size());

    for (const SpInputProposalV1 &input_proposal : input_proposals)
    {
        input_enotes.emplace_back(input_proposal.core.enote_core);
        address_masks.emplace_back(input_proposal.core.address_mask);
        commitment_masks.emplace_back(input_proposal.core.commitment_mask);
    }

    return gen_mock_sp_membership_proof_preps_v1(input_enotes,
        address_masks,
        commitment_masks,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context_inout);
}
//-------------------------------------------------------------------------------------------------------------------
void make_mock_sp_membership_proof_preps_for_inputs_v1(
    const std::unordered_map<crypto::key_image, std::uint64_t> &input_ledger_mappings,
    const std::vector<SpInputProposalV1> &input_proposals,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    const MockLedgerContext &ledger_context,
    std::vector<SpMembershipProofPrepV1> &membership_proof_preps_out)
{
    CHECK_AND_ASSERT_THROW_MES(input_ledger_mappings.size() == input_proposals.size(),
        "make mock membership proof preps: input proposals don't line up with their enotes' ledger indices.");

    membership_proof_preps_out.clear();
    membership_proof_preps_out.reserve(input_proposals.size());

    for (const SpInputProposalV1 &input_proposal : input_proposals)
    {
        CHECK_AND_ASSERT_THROW_MES(
                input_ledger_mappings.find(key_image_ref(input_proposal)) != input_ledger_mappings.end(),
            "make mock membership proof preps: the enote ledger indices map is missing an expected key image.");

        membership_proof_preps_out.emplace_back(
                gen_mock_sp_membership_proof_prep_for_enote_at_pos_v1(input_proposal.core.enote_core,
                        input_ledger_mappings.at(key_image_ref(input_proposal)),
                        input_proposal.core.address_mask,
                        input_proposal.core.commitment_mask,
                        ref_set_decomp_n,
                        ref_set_decomp_m,
                        bin_config,
                        ledger_context)
            );
    }
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace mocks
} //namespace sp
