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

// Seraphis tx-builder/component-builder mockups (legacy tx inputs).

#pragma once

//local headers
#include "crypto/crypto.h"
#include "mock_ledger_context.h"
#include "ringct/rctTypes.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/tx_builder_types_legacy.h"
#include "seraphis_main/tx_builder_types_multisig.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace sp
{
namespace mocks
{

/// create random mock inputs
std::vector<LegacyInputProposalV1> gen_mock_legacy_input_proposals_v1(const crypto::secret_key &legacy_spend_privkey,
    const std::vector<rct::xmr_amount> &input_amounts);
/// make mock legacy ring signature preps
void gen_mock_legacy_ring_signature_members_for_enote_at_pos_v1(const std::uint64_t real_reference_index_in_ledger,
    const std::uint64_t ring_size,
    const MockLedgerContext &ledger_context,
    std::vector<std::uint64_t> &reference_set_out,
    rct::ctkeyV &referenced_enotes_out,
    std::uint64_t &real_reference_index_out);
LegacyRingSignaturePrepV1 gen_mock_legacy_ring_signature_prep_for_enote_at_pos_v1(const rct::key &tx_proposal_prefix,
    const std::uint64_t real_reference_index_in_ledger,
    const LegacyEnoteImageV2 &real_reference_image,
    const crypto::secret_key &real_reference_view_privkey,
    const crypto::secret_key &commitment_mask,
    const std::uint64_t ring_size,
    const MockLedgerContext &ledger_context);
LegacyRingSignaturePrepV1 gen_mock_legacy_ring_signature_prep_v1(const rct::key &tx_proposal_prefix,
    const rct::ctkey &real_reference_enote,
    const LegacyEnoteImageV2 &real_reference_image,
    const crypto::secret_key &real_reference_view_privkey,
    const crypto::secret_key &commitment_mask,
    const std::uint64_t ring_size,
    MockLedgerContext &ledger_context_inout);
std::vector<LegacyRingSignaturePrepV1> gen_mock_legacy_ring_signature_preps_v1(const rct::key &tx_proposal_prefix,
    const rct::ctkeyV &real_referenced_enotes,
    const std::vector<LegacyEnoteImageV2> &real_reference_images,
    const std::vector<crypto::secret_key> &real_reference_view_privkeys,
    const std::vector<crypto::secret_key> &commitment_masks,
    const std::uint64_t ring_size,
    MockLedgerContext &ledger_context_inout);
std::vector<LegacyRingSignaturePrepV1> gen_mock_legacy_ring_signature_preps_v1(const rct::key &tx_proposal_prefix,
    const std::vector<LegacyInputProposalV1> &input_proposals,
    const std::uint64_t ring_size,
    MockLedgerContext &ledger_context_inout);
/// prepare membership proofs for enotes in a mock ledger
void make_mock_legacy_ring_signature_preps_for_inputs_v1(const rct::key &tx_proposal_prefix,
    const std::unordered_map<crypto::key_image, std::uint64_t> &input_ledger_mappings,
    const std::vector<LegacyInputProposalV1> &input_proposals,
    const std::uint64_t ring_size,
    const MockLedgerContext &ledger_context,
    std::vector<LegacyRingSignaturePrepV1> &ring_signature_preps_out);
bool try_gen_legacy_multisig_ring_signature_preps_v1(const std::vector<LegacyContextualEnoteRecordV1> &contextual_records,
    const std::uint64_t legacy_ring_size,
    const MockLedgerContext &ledger_context,
    std::unordered_map<crypto::key_image, LegacyMultisigRingSignaturePrepV1> &mapped_preps_out);

} //namespace mocks
} //namespace sp
