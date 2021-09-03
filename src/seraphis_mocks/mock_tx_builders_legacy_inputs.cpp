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
#include "mock_tx_builders_legacy_inputs.h"

//local headers
#include "common/container_helpers.h"
#include "crypto/crypto.h"
#include "misc_log_ex.h"
#include "mock_ledger_context.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/legacy_decoy_selector_flat.h"
#include "seraphis_core/legacy_enote_types.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/contextual_enote_record_utils.h"
#include "seraphis_main/tx_builder_types_legacy.h"
#include "seraphis_main/tx_builder_types_multisig.h"
#include "seraphis_main/tx_component_types_legacy.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_mocks"

namespace sp
{
namespace mocks
{
//-------------------------------------------------------------------------------------------------------------------
std::vector<LegacyInputProposalV1> gen_mock_legacy_input_proposals_v1(const crypto::secret_key &legacy_spend_privkey,
    const std::vector<rct::xmr_amount> &input_amounts)
{
    // generate random inputs
    std::vector<LegacyInputProposalV1> input_proposals;
    input_proposals.reserve(input_amounts.size());

    for (const rct::xmr_amount in_amount : input_amounts)
        tools::add_element(input_proposals) = gen_legacy_input_proposal_v1(legacy_spend_privkey, in_amount);

    return input_proposals;
}
//-------------------------------------------------------------------------------------------------------------------
void gen_mock_legacy_ring_signature_members_for_enote_at_pos_v1(const std::uint64_t real_reference_index_in_ledger,
    const std::uint64_t ring_size,
    const MockLedgerContext &ledger_context,
    std::vector<std::uint64_t> &reference_set_out,
    rct::ctkeyV &referenced_enotes_out,
    std::uint64_t &real_reference_index_out)
{
    // generate ring members for a mock legacy ring signature for a legacy enote at a known position in the mock ledger

    /// make reference set
    LegacyRingSignaturePrepV1 proof_prep;

    // 1. flat decoy selector for mock-up
    const LegacyDecoySelectorFlat decoy_selector{0, ledger_context.max_legacy_enote_index()};

    // 2. reference set
    CHECK_AND_ASSERT_THROW_MES(ring_size > 0,
        "gen mock legacy ring signature members (for enote at pos): ring size of 0 is not allowed.");

    decoy_selector.get_ring_members(real_reference_index_in_ledger,
        ring_size,
        reference_set_out,
        real_reference_index_out);

    CHECK_AND_ASSERT_THROW_MES(real_reference_index_out < reference_set_out.size(),
        "gen mock legacy ring signature members (for enote at pos): real reference index is outside of reference set.");


    /// copy all referenced legacy enotes from the ledger
    ledger_context.get_reference_set_proof_elements_v1(reference_set_out, referenced_enotes_out);

    CHECK_AND_ASSERT_THROW_MES(reference_set_out.size() == referenced_enotes_out.size(),
        "gen mock legacy ring signature members (for enote at pos): reference set doesn't line up with reference "
        "enotes.");
}
//-------------------------------------------------------------------------------------------------------------------
LegacyRingSignaturePrepV1 gen_mock_legacy_ring_signature_prep_for_enote_at_pos_v1(const rct::key &tx_proposal_prefix,
    const std::uint64_t real_reference_index_in_ledger,
    const LegacyEnoteImageV2 &real_reference_image,
    const crypto::secret_key &real_reference_view_privkey,
    const crypto::secret_key &commitment_mask,
    const std::uint64_t ring_size,
    const MockLedgerContext &ledger_context)
{
    // generate a mock ring signature prep for a legacy enote at a known position in the mock ledger
    LegacyRingSignaturePrepV1 proof_prep;

    // 1. generate ring members
    gen_mock_legacy_ring_signature_members_for_enote_at_pos_v1(real_reference_index_in_ledger,
        ring_size,
        ledger_context,
        proof_prep.reference_set,
        proof_prep.referenced_enotes,
        proof_prep.real_reference_index);

    // 2. copy misc pieces
    proof_prep.tx_proposal_prefix        = tx_proposal_prefix;
    proof_prep.reference_image           = real_reference_image;
    proof_prep.reference_view_privkey    = real_reference_view_privkey;
    proof_prep.reference_commitment_mask = commitment_mask;

    return proof_prep;
}
//-------------------------------------------------------------------------------------------------------------------
LegacyRingSignaturePrepV1 gen_mock_legacy_ring_signature_prep_v1(const rct::key &tx_proposal_prefix,
    const rct::ctkey &real_reference_enote,
    const LegacyEnoteImageV2 &real_reference_image,
    const crypto::secret_key &real_reference_view_privkey,
    const crypto::secret_key &commitment_mask,
    const std::uint64_t ring_size,
    MockLedgerContext &ledger_context_inout)
{
    // generate a mock ring signature prep

    /// add fake enotes to the ledger (2x the ring size), with the real one at a random location

    // 1. make fake legacy enotes
    const std::size_t num_enotes_to_add{ring_size * 2};
    const std::size_t add_real_at_pos{crypto::rand_idx(num_enotes_to_add)};
    std::vector<LegacyEnoteVariant> mock_enotes;
    mock_enotes.reserve(num_enotes_to_add);

    for (std::size_t enote_to_add{0}; enote_to_add < num_enotes_to_add; ++enote_to_add)
    {
        LegacyEnoteV5 temp{gen_legacy_enote_v5()};

        if (enote_to_add == add_real_at_pos)
        {
            temp.onetime_address   = real_reference_enote.dest;
            temp.amount_commitment = real_reference_enote.mask;
        }

        mock_enotes.emplace_back(temp);
    }

    // 2. add mock legacy enotes as the outputs of a mock legacy coinbase tx
    const std::uint64_t real_reference_index_in_ledger{
            ledger_context_inout.max_legacy_enote_index() + add_real_at_pos + 1
        };
    ledger_context_inout.add_legacy_coinbase(rct::pkGen(), 0, TxExtra{}, {}, std::move(mock_enotes));


    /// finish making the proof prep
    return gen_mock_legacy_ring_signature_prep_for_enote_at_pos_v1(tx_proposal_prefix,
        real_reference_index_in_ledger,
        real_reference_image,
        real_reference_view_privkey,
        commitment_mask,
        ring_size,
        ledger_context_inout);
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<LegacyRingSignaturePrepV1> gen_mock_legacy_ring_signature_preps_v1(const rct::key &tx_proposal_prefix,
    const rct::ctkeyV &real_referenced_enotes,
    const std::vector<LegacyEnoteImageV2> &real_reference_images,
    const std::vector<crypto::secret_key> &real_reference_view_privkeys,
    const std::vector<crypto::secret_key> &commitment_masks,
    const std::uint64_t ring_size,
    MockLedgerContext &ledger_context_inout)
{
    // make mock legacy ring signatures from input enotes
    CHECK_AND_ASSERT_THROW_MES(real_referenced_enotes.size() == real_reference_images.size(),
        "gen mock legacy ring signature preps: input enotes don't line up with input images.");
    CHECK_AND_ASSERT_THROW_MES(real_referenced_enotes.size() == real_reference_view_privkeys.size(),
        "gen mock legacy ring signature preps: input enotes don't line up with input enote view privkeys.");
    CHECK_AND_ASSERT_THROW_MES(real_referenced_enotes.size() == commitment_masks.size(),
        "gen mock legacy ring signature preps: input enotes don't line up with commitment masks.");

    std::vector<LegacyRingSignaturePrepV1> proof_preps;
    proof_preps.reserve(real_referenced_enotes.size());

    for (std::size_t input_index{0}; input_index < real_referenced_enotes.size(); ++input_index)
    {
        proof_preps.emplace_back(
                gen_mock_legacy_ring_signature_prep_v1(tx_proposal_prefix,
                    real_referenced_enotes[input_index],
                    real_reference_images[input_index],
                    real_reference_view_privkeys[input_index],
                    commitment_masks[input_index],
                    ring_size,
                    ledger_context_inout)
            );
    }

    return proof_preps;
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<LegacyRingSignaturePrepV1> gen_mock_legacy_ring_signature_preps_v1(const rct::key &tx_proposal_prefix,
    const std::vector<LegacyInputProposalV1> &input_proposals,
    const std::uint64_t ring_size,
    MockLedgerContext &ledger_context_inout)
{
    // make mock legacy ring signatures from input proposals
    rct::ctkeyV input_enotes;
    std::vector<LegacyEnoteImageV2> input_images;
    std::vector<crypto::secret_key> input_enote_view_extensions;
    std::vector<crypto::secret_key> commitment_masks;
    input_enotes.reserve(input_proposals.size());
    input_images.reserve(input_proposals.size());
    input_enote_view_extensions.reserve(input_proposals.size());
    commitment_masks.reserve(input_proposals.size());

    for (const LegacyInputProposalV1 &input_proposal : input_proposals)
    {
        input_enotes.emplace_back(
                rct::ctkey{ .dest = input_proposal.onetime_address, .mask = input_proposal.amount_commitment}
            );
        input_images.emplace_back();

        input_images.back().key_image = input_proposal.key_image;
        mask_key(input_proposal.commitment_mask,
            input_proposal.amount_commitment,
            input_images.back().masked_commitment);

        input_enote_view_extensions.emplace_back(input_proposal.enote_view_extension);
        commitment_masks.emplace_back(input_proposal.commitment_mask);
    }

    return gen_mock_legacy_ring_signature_preps_v1(tx_proposal_prefix,
        input_enotes,
        input_images,
        input_enote_view_extensions,
        commitment_masks,
        ring_size,
        ledger_context_inout);
}
//-------------------------------------------------------------------------------------------------------------------
void make_mock_legacy_ring_signature_preps_for_inputs_v1(const rct::key &tx_proposal_prefix,
    const std::unordered_map<crypto::key_image, std::uint64_t> &input_ledger_mappings,
    const std::vector<LegacyInputProposalV1> &input_proposals,
    const std::uint64_t ring_size,
    const MockLedgerContext &ledger_context,
    std::vector<LegacyRingSignaturePrepV1> &ring_signature_preps_out)
{
    CHECK_AND_ASSERT_THROW_MES(input_ledger_mappings.size() == input_proposals.size(),
        "make mock legacy ring signature preps: input proposals don't line up with their enotes' ledger indices.");

    ring_signature_preps_out.clear();
    ring_signature_preps_out.reserve(input_proposals.size());

    for (const LegacyInputProposalV1 &input_proposal : input_proposals)
    {
        CHECK_AND_ASSERT_THROW_MES(input_ledger_mappings.find(input_proposal.key_image) != input_ledger_mappings.end(),
            "make mock legacy ring signature preps: the enote ledger indices map is missing an expected key image.");

        rct::key masked_commitment;
        mask_key(input_proposal.commitment_mask, input_proposal.amount_commitment, masked_commitment);

        ring_signature_preps_out.emplace_back(
                gen_mock_legacy_ring_signature_prep_for_enote_at_pos_v1(tx_proposal_prefix,
                        input_ledger_mappings.at(input_proposal.key_image),
                        LegacyEnoteImageV2{masked_commitment, input_proposal.key_image},
                        input_proposal.enote_view_extension,
                        input_proposal.commitment_mask,
                        ring_size,
                        ledger_context)
            );
    }
}
//-------------------------------------------------------------------------------------------------------------------
bool try_gen_legacy_multisig_ring_signature_preps_v1(const std::vector<LegacyContextualEnoteRecordV1> &contextual_records,
    const std::uint64_t legacy_ring_size,
    const MockLedgerContext &ledger_context,
    std::unordered_map<crypto::key_image, LegacyMultisigRingSignaturePrepV1> &mapped_preps_out)
{
    // 1. extract map [ legacy KI : enote ledger index ] from contextual records
    std::unordered_map<crypto::key_image, std::uint64_t> enote_ledger_mappings;

    if (!try_get_membership_proof_real_reference_mappings(contextual_records, enote_ledger_mappings))
        return false;

    // 2. generate legacy multisig ring signature preps for each legacy enote requested
    for (const auto &enote_ledger_mapping : enote_ledger_mappings)
    {
        LegacyMultisigRingSignaturePrepV1 &prep = mapped_preps_out[enote_ledger_mapping.first];
        prep.key_image = enote_ledger_mapping.first;

        gen_mock_legacy_ring_signature_members_for_enote_at_pos_v1(enote_ledger_mapping.second,
            legacy_ring_size,
            ledger_context,
            prep.reference_set,
            prep.referenced_enotes,
            prep.real_reference_index);
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace mocks
} //namespace sp
