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

// Seraphis tx-builder/component-builder mockups (tx inputs).

#pragma once

//local headers
#include "crypto/crypto.h"
#include "mock_ledger_context.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/binned_reference_set.h"
#include "seraphis_main/tx_builder_types.h"

//third party headers

//standard headers
#include <unordered_map>
#include <vector>

//forward declarations


namespace sp
{
namespace mocks
{

/**
* brief: gen_mock_sp_input_proposals_v1 - create random mock inputs
* param: sp_spend_privkey -
* param: k_view_balance -
* param: in_amounts -
* return: set of transaction inputs ready to spend
*/
std::vector<SpInputProposalV1> gen_mock_sp_input_proposals_v1(const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_view_balance,
    const std::vector<rct::xmr_amount> &in_amounts);
/**
* brief: gen_mock_sp_membership_proof_prep_v1 - create a random reference set for an enote, with real spend at a
*   random index, and update mock ledger to include all members of the reference set (including squashed enotes)
* param: input_enote -
* param: ref_set_decomp_n -
* param: ref_set_decomp_m -
* inoutparam: ledger_context_inout -
* return: a reference set that can be used to make a membership proof
*/
SpMembershipProofPrepV1 gen_mock_sp_membership_proof_prep_for_enote_at_pos_v1(
    const SpEnoteCoreVariant &real_reference_enote,
    const std::uint64_t &real_reference_index_in_ledger,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    const MockLedgerContext &ledger_context);
SpMembershipProofPrepV1 gen_mock_sp_membership_proof_prep_v1(
    const SpEnoteCoreVariant &real_reference_enote,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    MockLedgerContext &ledger_context_inout);
std::vector<SpMembershipProofPrepV1> gen_mock_sp_membership_proof_preps_v1(
    const std::vector<SpEnoteCoreVariant> &real_referenced_enotes,
    const std::vector<crypto::secret_key> &address_masks,
    const std::vector<crypto::secret_key> &commitment_masks,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    MockLedgerContext &ledger_context_inout);
std::vector<SpMembershipProofPrepV1> gen_mock_sp_membership_proof_preps_v1(
    const std::vector<SpInputProposalV1> &input_proposals,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    MockLedgerContext &ledger_context_inout);
/**
* brief: make_mock_sp_membership_proof_preps_for_inputs_v1 - prepare membership proofs for enotes in a mock ledger
* param: input_ledger_mappings - 
* param: input_proposals -
* param: ref_set_decomp_n -
* param: ref_set_decomp_m -
* param: bin_config -
* param: ledger_context -
* outparam: membership_proof_preps_out -
*/
void make_mock_sp_membership_proof_preps_for_inputs_v1(
    const std::unordered_map<crypto::key_image, std::uint64_t> &input_ledger_mappings,
    const std::vector<SpInputProposalV1> &input_proposals,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    const MockLedgerContext &ledger_context,
    std::vector<SpMembershipProofPrepV1> &membership_proof_preps_out);

} //namespace mocks
} //namespace sp
