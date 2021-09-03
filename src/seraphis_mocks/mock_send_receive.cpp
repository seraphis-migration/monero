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
#include "mock_send_receive.h"

//local headers
#include "common/container_helpers.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/subaddress_index.h"
#include "enote_finding_context_mocks.h"
#include "misc_log_ex.h"
#include "mock_ledger_context.h"
#include "mock_tx_builders_inputs.h"
#include "mock_tx_builders_legacy_inputs.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "scan_chunk_consumer_mocks.h"
#include "seraphis_core/binned_reference_set.h"
#include "seraphis_core/binned_reference_set_utils.h"
#include "seraphis_core/legacy_core_utils.h"
#include "seraphis_core/legacy_enote_utils.h"
#include "seraphis_core/sp_core_types.h"
#include "seraphis_impl/scan_context_simple.h"
#include "seraphis_impl/scan_process_basic.h"
#include "seraphis_impl/tx_builder_utils.h"
#include "seraphis_main/contextual_enote_record_utils.h"
#include "seraphis_main/scan_machine_types.h"
#include "seraphis_main/tx_builder_types.h"
#include "seraphis_main/tx_builders_inputs.h"
#include "seraphis_main/tx_builders_mixed.h"
#include "seraphis_main/tx_component_types.h"
#include "seraphis_main/txtype_coinbase_v1.h"
#include "seraphis_main/txtype_squashed_v1.h"
#include "tx_validation_context_mock.h"

//third party headers

//standard headers
#include <algorithm>
#include <tuple>
#include <unordered_map>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_mocks"

namespace sp
{
namespace mocks
{
//-------------------------------------------------------------------------------------------------------------------
void convert_outlay_to_payment_proposal(const rct::xmr_amount outlay_amount,
    const jamtis::JamtisDestinationV1 &destination,
    const TxExtra &partial_memo_for_destination,
    jamtis::JamtisPaymentProposalV1 &payment_proposal_out)
{
    payment_proposal_out = jamtis::JamtisPaymentProposalV1{
            .destination             = destination,
            .amount                  = outlay_amount,
            .enote_ephemeral_privkey = crypto::x25519_secret_key_gen(),
            .partial_memo            = partial_memo_for_destination
        };
}
//-------------------------------------------------------------------------------------------------------------------
void send_legacy_coinbase_amounts_to_user(const std::vector<rct::xmr_amount> &coinbase_amounts,
    const rct::key &destination_subaddr_spend_pubkey,
    const rct::key &destination_subaddr_view_pubkey,
    MockLedgerContext &ledger_context_inout)
{
    // 1. prepare mock coinbase enotes
    std::vector<LegacyEnoteVariant> coinbase_enotes;
    std::vector<rct::key> collected_enote_ephemeral_pubkeys;
    TxExtra tx_extra;
    coinbase_enotes.reserve(coinbase_amounts.size());
    coinbase_enotes.reserve(coinbase_amounts.size());

    LegacyEnoteV5 enote_temp;

    for (std::size_t amount_index{0}; amount_index < coinbase_amounts.size(); ++amount_index)
    {
        // a. legacy enote ephemeral pubkey
        const crypto::secret_key enote_ephemeral_privkey{rct::rct2sk(rct::skGen())};
        collected_enote_ephemeral_pubkeys.emplace_back(
                rct::scalarmultKey(destination_subaddr_spend_pubkey, rct::sk2rct(enote_ephemeral_privkey))
            );

        // b. make legacy coinbase enote
        make_legacy_enote_v5(destination_subaddr_spend_pubkey,
            destination_subaddr_view_pubkey,
            coinbase_amounts[amount_index],
            amount_index,
            enote_ephemeral_privkey,
            enote_temp);

        coinbase_enotes.emplace_back(enote_temp);
    }

    // 2. set tx extra
    CHECK_AND_ASSERT_THROW_MES(try_append_legacy_enote_ephemeral_pubkeys_to_tx_extra(collected_enote_ephemeral_pubkeys,
            tx_extra),
        "send legacy coinbase amounts to user: appending enote ephemeral pubkeys to tx extra failed.");

    // 3. commit coinbase enotes as new block
    ledger_context_inout.add_legacy_coinbase(rct::pkGen(), 0, std::move(tx_extra), {}, std::move(coinbase_enotes));
}
//-------------------------------------------------------------------------------------------------------------------
void send_sp_coinbase_amounts_to_user(const std::vector<rct::xmr_amount> &coinbase_amounts,
    const jamtis::JamtisDestinationV1 &user_address,
    MockLedgerContext &ledger_context_inout)
{
    // 1. prepare payment proposals
    std::vector<jamtis::JamtisPaymentProposalV1> payment_proposals;
    payment_proposals.reserve(coinbase_amounts.size());
    rct::xmr_amount block_reward{0};

    for (const rct::xmr_amount coinbase_amount : coinbase_amounts)
    {
        // a. make payment proposal
        convert_outlay_to_payment_proposal(coinbase_amount,
        user_address,
        TxExtra{},
        tools::add_element(payment_proposals));

        // b. accumulate the block reward
        block_reward += coinbase_amount;
    }

    // 2. make a coinbase tx
    SpTxCoinbaseV1 coinbase_tx;
    make_seraphis_tx_coinbase_v1(SpTxCoinbaseV1::SemanticRulesVersion::MOCK,
        ledger_context_inout.chain_height() + 1,
        block_reward,
        std::move(payment_proposals),
        {},
        coinbase_tx);

    // 3. validate the coinbase tx
    const TxValidationContextMock tx_validation_context{ledger_context_inout};
    CHECK_AND_ASSERT_THROW_MES(validate_tx(coinbase_tx, tx_validation_context),
        "send sp coinbase amounts to user (mock): failed to validate coinbase tx.");

    // 4. commit coinbase tx as new block
    ledger_context_inout.commit_unconfirmed_txs_v1(coinbase_tx);
}
//-------------------------------------------------------------------------------------------------------------------
void send_sp_coinbase_amounts_to_users(const std::vector<std::vector<rct::xmr_amount>> &coinbase_amounts_per_user,
    const std::vector<jamtis::JamtisDestinationV1> &user_addresses,
    MockLedgerContext &ledger_context_inout)
{
    CHECK_AND_ASSERT_THROW_MES(coinbase_amounts_per_user.size() == user_addresses.size(),
        "send sp coinbase amounts to users (mock): amount : address mismatch.");

    // 1. prepare payment proposals
    std::vector<jamtis::JamtisPaymentProposalV1> payment_proposals;
    payment_proposals.reserve(coinbase_amounts_per_user.size());
    rct::xmr_amount block_reward{0};

    for (std::size_t user_index{0}; user_index < user_addresses.size(); ++user_index)
    {
        for (const rct::xmr_amount user_amount : coinbase_amounts_per_user[user_index])
        {
            // a .make payment proposal
            convert_outlay_to_payment_proposal(user_amount,
                user_addresses[user_index],
                TxExtra{},
                tools::add_element(payment_proposals));

            // b. accumulate the block reward
            block_reward += user_amount;
        }
    }

    // 2. make a coinbase tx
    SpTxCoinbaseV1 coinbase_tx;
    make_seraphis_tx_coinbase_v1(SpTxCoinbaseV1::SemanticRulesVersion::MOCK,
        ledger_context_inout.chain_height() + 1,
        block_reward,
        std::move(payment_proposals),
        {},
        coinbase_tx);

    // 3. validate the coinbase tx
    const TxValidationContextMock tx_validation_context{ledger_context_inout};
    CHECK_AND_ASSERT_THROW_MES(validate_tx(coinbase_tx, tx_validation_context),
        "send sp coinbase amounts to user (mock): failed to validate coinbase tx.");

    // 4. commit coinbase tx as new block
    ledger_context_inout.commit_unconfirmed_txs_v1(coinbase_tx);
}
//-------------------------------------------------------------------------------------------------------------------
void construct_tx_for_mock_ledger_v1(const legacy_mock_keys &local_user_legacy_keys,
    const jamtis::mocks::jamtis_mock_keys &local_user_sp_keys,
    const InputSelectorV1 &local_user_input_selector,
    const FeeCalculator &tx_fee_calculator,
    const rct::xmr_amount fee_per_tx_weight,
    const std::size_t max_inputs,
    const std::vector<std::tuple<rct::xmr_amount, jamtis::JamtisDestinationV1, TxExtra>> &outlays,
    const std::size_t legacy_ring_size,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    const MockLedgerContext &ledger_context,
    SpTxSquashedV1 &tx_out)
{
    /// build transaction

    // 1. prepare dummy and change addresses
    jamtis::JamtisDestinationV1 change_address;
    jamtis::JamtisDestinationV1 dummy_address;
    make_random_address_for_user(local_user_sp_keys, change_address);
    make_random_address_for_user(local_user_sp_keys, dummy_address);

    // 2. convert outlays to normal payment proposals
    std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals;
    normal_payment_proposals.reserve(outlays.size());

    for (const auto &outlay : outlays)
    {
        convert_outlay_to_payment_proposal(std::get<rct::xmr_amount>(outlay),
            std::get<jamtis::JamtisDestinationV1>(outlay),
            std::get<TxExtra>(outlay),
            tools::add_element(normal_payment_proposals));
    }

    // 3. prepare inputs and finalize outputs
    std::vector<LegacyContextualEnoteRecordV1> legacy_contextual_inputs;
    std::vector<SpContextualEnoteRecordV1> sp_contextual_inputs;
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals;  //note: no user-defined selfsends
    DiscretizedFee discretized_transaction_fee;
    CHECK_AND_ASSERT_THROW_MES(try_prepare_inputs_and_outputs_for_transfer_v1(change_address,
            dummy_address,
            local_user_input_selector,
            tx_fee_calculator,
            fee_per_tx_weight,
            max_inputs,
            std::move(normal_payment_proposals),
            std::move(selfsend_payment_proposals),
            local_user_sp_keys.k_vb,
            legacy_contextual_inputs,
            sp_contextual_inputs,
            normal_payment_proposals,
            selfsend_payment_proposals,
            discretized_transaction_fee),
        "construct tx for mock ledger (v1): preparing inputs and outputs failed.");

    // 4. tx proposal
    SpTxProposalV1 tx_proposal;
    make_v1_tx_proposal_v1(legacy_contextual_inputs,
        sp_contextual_inputs,
        std::move(normal_payment_proposals),
        std::move(selfsend_payment_proposals),
        discretized_transaction_fee,
        TxExtra{},
        tx_proposal);

    // 5. tx proposal prefix
    const tx_version_t tx_version{tx_version_from(SpTxSquashedV1::SemanticRulesVersion::MOCK)};

    rct::key tx_proposal_prefix;
    get_tx_proposal_prefix_v1(tx_proposal, tx_version, local_user_sp_keys.k_vb, tx_proposal_prefix);

    // 6. get ledger mappings for the input membership proofs
    // note: do this after making the tx proposal to demo that inputs don't have to be on-chain when proposing a tx
    std::unordered_map<crypto::key_image, std::uint64_t> legacy_input_ledger_mappings;
    std::unordered_map<crypto::key_image, std::uint64_t> sp_input_ledger_mappings;
    try_get_membership_proof_real_reference_mappings(legacy_contextual_inputs, legacy_input_ledger_mappings);
    try_get_membership_proof_real_reference_mappings(sp_contextual_inputs, sp_input_ledger_mappings);

    // 7. prepare for legacy ring signatures
    std::vector<LegacyRingSignaturePrepV1> legacy_ring_signature_preps;
    make_mock_legacy_ring_signature_preps_for_inputs_v1(tx_proposal_prefix,
        legacy_input_ledger_mappings,
        tx_proposal.legacy_input_proposals,
        legacy_ring_size,
        ledger_context,
        legacy_ring_signature_preps);

    // 8. prepare for membership proofs
    std::vector<SpMembershipProofPrepV1> sp_membership_proof_preps;
    make_mock_sp_membership_proof_preps_for_inputs_v1(sp_input_ledger_mappings,
        tx_proposal.sp_input_proposals,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context,
        sp_membership_proof_preps);

    // 9. complete tx
    make_seraphis_tx_squashed_v1(SpTxSquashedV1::SemanticRulesVersion::MOCK,
        tx_proposal,
        std::move(legacy_ring_signature_preps),
        std::move(sp_membership_proof_preps),
        local_user_legacy_keys.k_s,
        local_user_sp_keys.k_m,
        local_user_sp_keys.k_vb,
        hw::get_device("default"),
        tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
void transfer_funds_single_mock_v1_unconfirmed_sp_only(const jamtis::mocks::jamtis_mock_keys &local_user_sp_keys,
    const InputSelectorV1 &local_user_input_selector,
    const FeeCalculator &tx_fee_calculator,
    const rct::xmr_amount fee_per_tx_weight,
    const std::size_t max_inputs,
    const std::vector<std::tuple<rct::xmr_amount, jamtis::JamtisDestinationV1, TxExtra>> &outlays,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    MockLedgerContext &ledger_context_inout)
{
    // 1. make one tx
    SpTxSquashedV1 single_tx;
    construct_tx_for_mock_ledger_v1(legacy_mock_keys{},  //no legacy inputs
        local_user_sp_keys,
        local_user_input_selector,
        tx_fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        outlays,
        0,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context_inout,
        single_tx);

    // 2. validate and submit to the mock ledger
    const TxValidationContextMock tx_validation_context{ledger_context_inout};
    CHECK_AND_ASSERT_THROW_MES(validate_tx(single_tx, tx_validation_context),
        "transfer funds single mock unconfirmed: validating tx failed.");
    CHECK_AND_ASSERT_THROW_MES(ledger_context_inout.try_add_unconfirmed_tx_v1(single_tx),
        "transfer funds single mock unconfirmed: adding unconfirmed tx to mock ledger failed.");
}
//-------------------------------------------------------------------------------------------------------------------
void transfer_funds_single_mock_v1_unconfirmed(const legacy_mock_keys &local_user_legacy_keys,
    const jamtis::mocks::jamtis_mock_keys &local_user_sp_keys,
    const InputSelectorV1 &local_user_input_selector,
    const FeeCalculator &tx_fee_calculator,
    const rct::xmr_amount fee_per_tx_weight,
    const std::size_t max_inputs,
    const std::vector<std::tuple<rct::xmr_amount, jamtis::JamtisDestinationV1, TxExtra>> &outlays,
    const std::size_t legacy_ring_size,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    MockLedgerContext &ledger_context_inout)
{
    // 1. make one tx
    SpTxSquashedV1 single_tx;
    construct_tx_for_mock_ledger_v1(local_user_legacy_keys,
        local_user_sp_keys,
        local_user_input_selector,
        tx_fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        outlays,
        legacy_ring_size,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context_inout,
        single_tx);

    // 2. validate and submit to the mock ledger
    const TxValidationContextMock tx_validation_context{ledger_context_inout};
    CHECK_AND_ASSERT_THROW_MES(validate_tx(single_tx, tx_validation_context),
        "transfer funds single mock unconfirmed sp only: validating tx failed.");
    CHECK_AND_ASSERT_THROW_MES(ledger_context_inout.try_add_unconfirmed_tx_v1(single_tx),
        "transfer funds single mock unconfirmed sp only: validating tx failed.");
}
//-------------------------------------------------------------------------------------------------------------------
void transfer_funds_single_mock_v1(const legacy_mock_keys &local_user_legacy_keys,
    const jamtis::mocks::jamtis_mock_keys &local_user_sp_keys,
    const InputSelectorV1 &local_user_input_selector,
    const FeeCalculator &tx_fee_calculator,
    const rct::xmr_amount fee_per_tx_weight,
    const std::size_t max_inputs,
    const std::vector<std::tuple<rct::xmr_amount, jamtis::JamtisDestinationV1, TxExtra>> &outlays,
    const std::size_t legacy_ring_size,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    MockLedgerContext &ledger_context_inout)
{
    // 1. make one tx
    SpTxSquashedV1 single_tx;
    construct_tx_for_mock_ledger_v1(local_user_legacy_keys,
        local_user_sp_keys,
        local_user_input_selector,
        tx_fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        outlays,
        legacy_ring_size,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context_inout,
        single_tx);

    // 2, validate and submit to the mock ledger
    const TxValidationContextMock tx_validation_context{ledger_context_inout};
    CHECK_AND_ASSERT_THROW_MES(validate_tx(single_tx, tx_validation_context),
        "transfer funds single mock: validating tx failed.");
    CHECK_AND_ASSERT_THROW_MES(try_add_tx_to_ledger(single_tx, ledger_context_inout),
        "transfer funds single mock: adding tx to mock ledger failed.");
}
//-------------------------------------------------------------------------------------------------------------------
void refresh_user_enote_store_legacy_intermediate(const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const LegacyScanMode legacy_scan_mode,
    const scanning::ScanMachineConfig &refresh_config,
    const MockLedgerContext &ledger_context,
    SpEnoteStore &user_enote_store_inout)
{
    const EnoteFindingContextLedgerMockLegacy enote_finding_context{
            ledger_context,
            legacy_base_spend_pubkey,
            legacy_subaddress_map,
            legacy_view_privkey,
            legacy_scan_mode
        };
    scanning::ScanContextNonLedgerDummy scan_context_nonledger{};
    scanning::ScanContextLedgerSimple scan_context_ledger{enote_finding_context};
    ChunkConsumerMockLegacyIntermediate chunk_consumer{
            legacy_base_spend_pubkey,
            legacy_view_privkey,
            legacy_scan_mode,
            user_enote_store_inout
        };

    sp::refresh_enote_store(refresh_config,
        scan_context_nonledger,
        scan_context_ledger,
        chunk_consumer);
}
//-------------------------------------------------------------------------------------------------------------------
void refresh_user_enote_store_legacy_full(const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_spend_privkey,
    const crypto::secret_key &legacy_view_privkey,
    const scanning::ScanMachineConfig &refresh_config,
    const MockLedgerContext &ledger_context,
    SpEnoteStore &user_enote_store_inout)
{
    const EnoteFindingContextLedgerMockLegacy enote_finding_context{
            ledger_context,
            legacy_base_spend_pubkey,
            legacy_subaddress_map,
            legacy_view_privkey,
            LegacyScanMode::SCAN
        };
    scanning::ScanContextNonLedgerDummy scan_context_nonledger{};
    scanning::ScanContextLedgerSimple scan_context_ledger{enote_finding_context};
    ChunkConsumerMockLegacy chunk_consumer{
            legacy_base_spend_pubkey,
            legacy_spend_privkey,
            legacy_view_privkey,
            user_enote_store_inout
        };

    sp::refresh_enote_store(refresh_config,
        scan_context_nonledger,
        scan_context_ledger,
        chunk_consumer);
}
//-------------------------------------------------------------------------------------------------------------------
void refresh_user_enote_store_PV(const jamtis::mocks::jamtis_mock_keys &user_keys,
    const scanning::ScanMachineConfig &refresh_config,
    const MockLedgerContext &ledger_context,
    SpEnoteStorePaymentValidator &user_enote_store_inout)
{
    const EnoteFindingContextUnconfirmedMockSp enote_finding_context_unconfirmed{ledger_context, user_keys.xk_fr};
    const EnoteFindingContextLedgerMockSp enote_finding_context_ledger{ledger_context, user_keys.xk_fr};
    scanning::ScanContextNonLedgerSimple scan_context_unconfirmed{enote_finding_context_unconfirmed};
    scanning::ScanContextLedgerSimple scan_context_ledger{enote_finding_context_ledger};
    ChunkConsumerMockSpIntermediate chunk_consumer{
            user_keys.K_1_base,
            user_keys.xk_ua,
            user_keys.xk_fr,
            user_keys.s_ga,
            user_enote_store_inout
        };

    sp::refresh_enote_store(refresh_config,
        scan_context_unconfirmed,
        scan_context_ledger,
        chunk_consumer);
}
//-------------------------------------------------------------------------------------------------------------------
void refresh_user_enote_store(const jamtis::mocks::jamtis_mock_keys &user_keys,
    const scanning::ScanMachineConfig &refresh_config,
    const MockLedgerContext &ledger_context,
    SpEnoteStore &user_enote_store_inout)
{
    const EnoteFindingContextUnconfirmedMockSp enote_finding_context_unconfirmed{ledger_context, user_keys.xk_fr};
    const EnoteFindingContextLedgerMockSp enote_finding_context_ledger{ledger_context, user_keys.xk_fr};
    scanning::ScanContextNonLedgerSimple scan_context_unconfirmed{enote_finding_context_unconfirmed};
    scanning::ScanContextLedgerSimple scan_context_ledger{enote_finding_context_ledger};
    ChunkConsumerMockSp chunk_consumer{user_keys.K_1_base, user_keys.k_vb, user_enote_store_inout};

    sp::refresh_enote_store(refresh_config,
        scan_context_unconfirmed,
        scan_context_ledger,
        chunk_consumer);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace mocks
} //namespace sp
