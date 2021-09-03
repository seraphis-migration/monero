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

#include "common/container_helpers.h"
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "crypto/generators.h"
#include "cryptonote_basic/account_generators.h"
#include "cryptonote_basic/subaddress_index.h"
#include "device/device.hpp"
#include "multisig/multisig.h"
#include "multisig/multisig_account.h"
#include "multisig/multisig_mocks.h"
#include "multisig/multisig_nonce_cache.h"
#include "multisig/multisig_signer_set_filter.h"
#include "multisig/multisig_signing_errors.h"
#include "multisig/multisig_signing_helper_types.h"
#include "multisig/multisig_sp_composition_proof.h"
#include "ringct/rctOps.h"
#include "ringct/rctSigs.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/binned_reference_set.h"
#include "seraphis_core/binned_reference_set_utils.h"
#include "seraphis_core/discretized_fee.h"
#include "seraphis_core/jamtis_core_utils.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_core/jamtis_payment_proposal.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_core/legacy_core_utils.h"
#include "seraphis_core/legacy_enote_utils.h"
#include "seraphis_core/sp_core_enote_utils.h"
#include "seraphis_core/tx_extra.h"
#include "seraphis_crypto/sp_composition_proof.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_impl/enote_store_utils.h"
#include "seraphis_impl/legacy_ki_import_tool.h"
#include "seraphis_impl/tx_builder_utils.h"
#include "seraphis_impl/tx_input_selection_output_context_v1.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/contextual_enote_record_utils.h"
#include "seraphis_main/enote_record_types.h"
#include "seraphis_main/enote_record_utils.h"
#include "seraphis_main/scan_machine_types.h"
#include "seraphis_main/tx_builder_types.h"
#include "seraphis_main/tx_builder_types_multisig.h"
#include "seraphis_main/tx_builders_inputs.h"
#include "seraphis_main/tx_builders_mixed.h"
#include "seraphis_main/tx_builders_multisig.h"
#include "seraphis_main/tx_builders_outputs.h"
#include "seraphis_main/tx_component_types.h"
#include "seraphis_main/tx_input_selection.h"
#include "seraphis_main/txtype_base.h"
#include "seraphis_main/txtype_squashed_v1.h"
#include "seraphis_mocks/seraphis_mocks.h"

#include "gtest/gtest.h"

#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace sp;
using namespace jamtis;
using namespace sp::mocks;
using namespace jamtis::mocks;

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_multisig_jamtis_mock_keys(const multisig::multisig_account &account,
    jamtis_mock_keys &keys_out)
{
    keys_out.k_m = rct::rct2sk(rct::Z); //master key is not known in multisig
    keys_out.k_vb = account.get_common_privkey();
    make_jamtis_unlockamounts_key(keys_out.k_vb, keys_out.xk_ua);
    make_jamtis_findreceived_key(keys_out.k_vb, keys_out.xk_fr);
    make_jamtis_generateaddress_secret(keys_out.k_vb, keys_out.s_ga);
    make_jamtis_ciphertag_secret(keys_out.s_ga, keys_out.s_ct);
    keys_out.K_1_base = rct::pk2rct(account.get_multisig_pubkey());
    extend_seraphis_spendkey_x(keys_out.k_vb, keys_out.K_1_base);
    make_jamtis_unlockamounts_pubkey(keys_out.xk_ua, keys_out.xK_ua);
    make_jamtis_findreceived_pubkey(keys_out.xk_fr, keys_out.xK_ua, keys_out.xK_fr);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void refresh_user_enote_store_legacy_multisig(const std::vector<multisig::multisig_account> &accounts,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const scanning::ScanMachineConfig &refresh_config,
    const MockLedgerContext &ledger_context,
    SpEnoteStore &enote_store_inout)
{
    ASSERT_TRUE(accounts.size() > 0);

    // 1. legacy view-only scan
    refresh_user_enote_store_legacy_intermediate(rct::pk2rct(accounts[0].get_multisig_pubkey()),
        legacy_subaddress_map,
        accounts[0].get_common_privkey(),
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store_inout);

    // 2. start key image import cycle
    LegacyKIImportCheckpoint import_cycle_checkpoint;
    ASSERT_NO_THROW(make_legacy_ki_import_checkpoint(enote_store_inout, import_cycle_checkpoint));

    // 3. extract view-key secret keys of the intermediate records in this cycle
    std::unordered_map<crypto::public_key, crypto::secret_key> saved_key_components;

    for (const auto &intermediate_record : import_cycle_checkpoint.legacy_intermediate_records)
    {
        saved_key_components[rct::rct2pk(onetime_address_ref(intermediate_record.second))] =
            intermediate_record.second.record.enote_view_extension;
    }

    // 4. recover key images (multisig KI ceremony)
    std::unordered_map<crypto::public_key, crypto::key_image> recovered_key_images;
    EXPECT_NO_THROW(multisig::mocks::mock_multisig_cn_key_image_recovery(accounts,
        saved_key_components,
        recovered_key_images));

    // 5. import acquired key images
    std::list<EnoteStoreEvent> events;
    ASSERT_NO_THROW(import_legacy_key_images(recovered_key_images, enote_store_inout, events));

    // 6. legacy key-image-refresh scan
    refresh_user_enote_store_legacy_intermediate(rct::pk2rct(accounts[0].get_multisig_pubkey()),
        legacy_subaddress_map,
        accounts[0].get_common_privkey(),
        LegacyScanMode::KEY_IMAGES_ONLY,
        refresh_config,
        ledger_context,
        enote_store_inout);

    // 7. check results of key image refresh scan
    ASSERT_TRUE(enote_store_inout.legacy_intermediate_records().size() == 0);

    // 8. update the legacy fullscan index to account for a complete view-only scan cycle with key image recovery
    ASSERT_NO_THROW(finish_legacy_ki_import_cycle(import_cycle_checkpoint, enote_store_inout));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool legacy_multisig_input_is_ready_to_spend(const LegacyMultisigInputProposalV1 &input_proposal,
    const SpEnoteStore &enote_store,
    const std::uint64_t top_block_index)
{
    // 1. get the legacy enote from the enote store
    LegacyContextualEnoteRecordV1 contextual_record;
    if (!enote_store.try_get_legacy_enote_record(input_proposal.key_image, contextual_record))
        return false;

    // 2. expect the record obtained matches with the input proposal
    if (!matches_with(input_proposal, contextual_record.record))
        return false;

    // 3. expect that the enote is unspent
    if (contextual_record.spent_context.spent_status != SpEnoteSpentStatus::UNSPENT)
        return false;

    // 4. expect the enote is spendable within the index specified
    if (onchain_legacy_enote_is_locked(contextual_record.origin_context.block_index,
            contextual_record.record.unlock_time,
            top_block_index,
            0,  //default spendable age: configurable
            0)) //current time: use system call
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool sp_multisig_input_is_ready_to_spend(const SpMultisigInputProposalV1 &multisig_input_proposal,
    const SpEnoteStore &enote_store,
    const std::unordered_set<SpEnoteOriginStatus> &origin_statuses,
    const std::uint64_t top_block_index,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance)
{
    // 1. convert to a normal input proposal so the key image is available
    SpInputProposalV1 input_proposal;
    get_sp_input_proposal_v1(multisig_input_proposal, jamtis_spend_pubkey, k_view_balance, input_proposal);

    // 2. get the legacy enote from the enote store
    SpContextualEnoteRecordV1 contextual_record;
    if (!enote_store.try_get_sp_enote_record(key_image_ref(input_proposal), contextual_record))
        return false;

    // 3. expect the record obtained matches with the input proposal
    if (!matches_with(multisig_input_proposal, contextual_record.record))
        return false;

    // 4. expect that the enote has an allowed origin
    if (origin_statuses.find(contextual_record.origin_context.origin_status) == origin_statuses.end())
        return false;

    // 5. expect that the enote is unspent
    if (contextual_record.spent_context.spent_status != SpEnoteSpentStatus::UNSPENT)
        return false;

    // 6. expect the enote is spendable within the index specified (only check when only onchain enotes are permitted)
    if (origin_statuses.size() == 1 &&
        origin_statuses.find(SpEnoteOriginStatus::ONCHAIN) != origin_statuses.end() &&
        onchain_sp_enote_is_locked(contextual_record.origin_context.block_index,
            top_block_index,
            0))  //default spendable age: configurable
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool legacy_ring_members_are_ready_to_spend(const std::vector<std::uint64_t> &reference_set,
    const rct::ctkeyV &legacy_ring_members,
    const MockLedgerContext &ledger_context)
{
    // 1. 'zero ring members' are always ready to spend
    if (reference_set.size() == 0)
        return true;

    // 2. consistency sanity check
    if (reference_set.size() != legacy_ring_members.size())
        return false;

    // 3. try to obtain copies of the ring members from the ledger
    // note: this should NOT succeed for ring members that are locked on-chain (the mock ledger context does not implement
    //       that)
    rct::ctkeyV proof_elements_recovered;
    try { ledger_context.get_reference_set_proof_elements_v1(reference_set, proof_elements_recovered); }
    catch (...) { return false;}

    // 4. expect the recovered proof elements to match the expected ring members
    if (legacy_ring_members.size() != proof_elements_recovered.size())
        return false;

    for (std::size_t ring_member_index{0}; ring_member_index < legacy_ring_members.size(); ++ring_member_index)
    {
        if (!(legacy_ring_members[ring_member_index].dest == proof_elements_recovered[ring_member_index].dest))
            return false;
        if (!(legacy_ring_members[ring_member_index].mask == proof_elements_recovered[ring_member_index].mask))
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void validate_multisig_tx_proposal(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    const std::uint32_t threshold,
    const std::size_t num_signers,
    const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const SpEnoteStore &enote_store,
    const MockLedgerContext &ledger_context)
{
    // 1. check that the multisig tx proposal is well-formed
    ASSERT_TRUE(try_simulate_tx_from_multisig_tx_proposal_v1(multisig_tx_proposal,
        semantic_rules_version,
        threshold,
        num_signers,
        legacy_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        jamtis_spend_pubkey,
        k_view_balance,
        hw::get_device("default")));

    // 2. check that the proposal inputs are known by our enote store, are unspent, and will be unlocked by a specified
    //    block index
    // note: could also check if the proposed inputs have been confirmed up to N blocks
    // note2: these checks are only 'temporary' because the specified enotes may be spent at any time (or be reorged)
    for (const LegacyMultisigInputProposalV1 &legacy_multisig_input_proposal :
        multisig_tx_proposal.legacy_multisig_input_proposals)
    {
        ASSERT_TRUE(legacy_multisig_input_is_ready_to_spend(legacy_multisig_input_proposal,
            enote_store,
            enote_store.top_block_index()));
    }

    for (const SpMultisigInputProposalV1 &sp_multisig_input_proposal :
        multisig_tx_proposal.sp_multisig_input_proposals)
    {
        ASSERT_TRUE(sp_multisig_input_is_ready_to_spend(sp_multisig_input_proposal,
            enote_store,
            {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED, SpEnoteOriginStatus::OFFCHAIN},
            enote_store.top_block_index(),
            jamtis_spend_pubkey,
            k_view_balance));
    }

    // 3. check that the legacy inputs' ring members are valid references from the ledger
    // note: a reorg can invalidate the result of these checks
    ASSERT_TRUE(multisig_tx_proposal.legacy_multisig_input_proposals.size() ==
        multisig_tx_proposal.legacy_input_proof_proposals.size());

    for (std::size_t legacy_input_index{0};
        legacy_input_index < multisig_tx_proposal.legacy_multisig_input_proposals.size();
        ++legacy_input_index)
    {
        ASSERT_TRUE(legacy_ring_members_are_ready_to_spend(
            multisig_tx_proposal.legacy_multisig_input_proposals[legacy_input_index].reference_set,
            multisig_tx_proposal.legacy_input_proof_proposals[legacy_input_index].ring_members,
            ledger_context));
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void print_multisig_errors(const std::list<multisig::MultisigSigningErrorVariant> &multisig_errors)
{
    for (const multisig::MultisigSigningErrorVariant &error : multisig_errors)
        std::cout << "Multisig Signing Error: " << error_message_ref(error) << '\n';
}
//-------------------------------------------------------------------------------------------------------------------
// v1: SpTxSquashedV1
//-------------------------------------------------------------------------------------------------------------------
static void seraphis_multisig_tx_v1_test(const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const std::vector<std::uint32_t> &requested_signers,
    const std::vector<rct::xmr_amount> &legacy_in_amounts,
    const std::vector<rct::xmr_amount> &sp_in_amounts,
    const std::vector<rct::xmr_amount> &out_amounts_normal,
    const std::vector<rct::xmr_amount> &out_amounts_selfsend,
    const DiscretizedFee fee,
    const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version)
{
    ASSERT_TRUE(num_signers > 0);
    ASSERT_TRUE(requested_signers.size() >= threshold);
    ASSERT_TRUE(requested_signers.size() <= num_signers);
    for (const std::uint32_t requested_signer : requested_signers)
        ASSERT_TRUE(requested_signer < num_signers);

    // config
    const std::size_t max_inputs{10000};
    rct::xmr_amount specified_fee;
    ASSERT_TRUE(try_get_fee_value(fee, specified_fee));
    const std::size_t fee_per_tx_weight{specified_fee};
    const std::size_t legacy_ring_size{2};
    const std::size_t ref_set_decomp_m{2};
    const std::size_t ref_set_decomp_n{2};
    const std::size_t bin_radius{1};
    const std::size_t num_bin_members{2};

    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 0
        };

    const SpBinnedReferenceSetConfigV1 bin_config{
            .bin_radius = bin_radius,
            .num_bin_members = num_bin_members
        };

    // global
    MockLedgerContext ledger_context{0, 10000};

    const tx_version_t tx_version{tx_version_from(semantic_rules_version)};


    /// 1) setup multisig accounts

    // a) make accounts
    std::vector<multisig::multisig_account> legacy_accounts;
    ASSERT_NO_THROW(multisig::mocks::make_multisig_mock_accounts(cryptonote::account_generator_era::cryptonote,
        threshold,
        num_signers,
        legacy_accounts));
    std::vector<multisig::multisig_account> seraphis_accounts{legacy_accounts};
    ASSERT_NO_THROW(multisig::mocks::mock_convert_multisig_accounts(cryptonote::account_generator_era::seraphis,
        seraphis_accounts));
    ASSERT_TRUE(legacy_accounts.size() == num_signers);
    ASSERT_TRUE(seraphis_accounts.size() == num_signers);
    ASSERT_TRUE(legacy_accounts[0].get_base_pubkey() == seraphis_accounts[0].get_base_pubkey());

    // b) get shared seraphis multisig wallet keys
    jamtis_mock_keys shared_sp_keys;
    ASSERT_NO_THROW(make_multisig_jamtis_mock_keys(seraphis_accounts[0], shared_sp_keys));

    // c) make an enote store for the multisig group
    SpEnoteStore enote_store{0, 0, 0};


    /// 2) fund the multisig address

    // a) make a legacy user address to receive funds
    rct::key legacy_subaddr_spendkey;
    rct::key legacy_subaddr_viewkey;
    cryptonote::subaddress_index legacy_subaddr_index;
    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;

    gen_legacy_subaddress(rct::pk2rct(legacy_accounts[0].get_multisig_pubkey()),
        legacy_accounts[0].get_common_privkey(),
        legacy_subaddr_spendkey,
        legacy_subaddr_viewkey,
        legacy_subaddr_index);

    legacy_subaddress_map[legacy_subaddr_spendkey] = legacy_subaddr_index;

    // b) make a seraphis user address to receive funds
    address_index_t j;
    j = sp::jamtis::gen_address_index();
    JamtisDestinationV1 sp_user_address;

    ASSERT_NO_THROW(make_jamtis_destination_v1(shared_sp_keys.K_1_base,
        shared_sp_keys.xK_ua,
        shared_sp_keys.xK_fr,
        shared_sp_keys.s_ga,
        j,
        sp_user_address));

    // c) send legacy coinbase enotes to the address, padded so there are enough for legacy ring signatures
    std::vector<rct::xmr_amount> legacy_in_amounts_padded{legacy_in_amounts};

    if (legacy_in_amounts_padded.size() < legacy_ring_size)
        legacy_in_amounts_padded.resize(legacy_ring_size, 0);

    send_legacy_coinbase_amounts_to_user(legacy_in_amounts_padded,
        legacy_subaddr_spendkey,
        legacy_subaddr_viewkey,
        ledger_context);

    // d) send coinbase enotes to the address, padded so there are enough for seraphis membership proofs
    std::vector<rct::xmr_amount> sp_in_amounts_padded{sp_in_amounts};

    if (sp_in_amounts_padded.size() < compute_bin_width(bin_radius))
        sp_in_amounts_padded.resize(compute_bin_width(bin_radius), 0);

    send_sp_coinbase_amounts_to_user(sp_in_amounts_padded, sp_user_address, ledger_context);

    // e) recover balance
    refresh_user_enote_store_legacy_multisig(legacy_accounts,
        legacy_subaddress_map,
        refresh_config,
        ledger_context,
        enote_store);
    refresh_user_enote_store(shared_sp_keys, refresh_config, ledger_context, enote_store);

    // f) compute expected received amount
    boost::multiprecision::uint128_t total_input_amount{0};

    for (const rct::xmr_amount legacy_in_amount : legacy_in_amounts_padded)
        total_input_amount += legacy_in_amount;
    for (const rct::xmr_amount sp_in_amount : sp_in_amounts_padded)
        total_input_amount += sp_in_amount;

    // g) balance check
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == total_input_amount);


    /// 3) propose tx

    // a) prepare outputs

    // - normal payments
    std::vector<JamtisPaymentProposalV1> normal_payment_proposals;
    normal_payment_proposals.reserve(out_amounts_normal.size());

    for (const rct::xmr_amount out_amount : out_amounts_normal)
        tools::add_element(normal_payment_proposals) = gen_jamtis_payment_proposal_v1(out_amount, 0);

    // - self-send payments
    std::vector<JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals;
    selfsend_payment_proposals.reserve(out_amounts_selfsend.size());

    for (const rct::xmr_amount out_amount : out_amounts_selfsend)
    {
        selfsend_payment_proposals.emplace_back(
                JamtisPaymentProposalSelfSendV1{
                    .destination             = sp_user_address,
                    .amount                  = out_amount,
                    .type                    = JamtisSelfSendType::SELF_SPEND,
                    .enote_ephemeral_privkey = crypto::x25519_secret_key_gen(),
                    .partial_memo            = TxExtra{}
                }
            );
    }

    // b) set requested signers filter
    std::vector<crypto::public_key> requested_signers_ids;
    requested_signers_ids.reserve(requested_signers.size());

    for (std::size_t signer_index{0}; signer_index < seraphis_accounts.size(); ++signer_index)
    {
        if (std::find(requested_signers.begin(), requested_signers.end(), signer_index) != requested_signers.end())
            requested_signers_ids.emplace_back(seraphis_accounts[signer_index].get_base_pubkey());
    }

    multisig::signer_set_filter aggregate_filter_of_requested_multisig_signers;
    multisig::multisig_signers_to_filter(requested_signers_ids,
        seraphis_accounts[0].get_signers(),
        aggregate_filter_of_requested_multisig_signers);

    // c) prepare inputs and finalize outputs
    const InputSelectorMockV1 input_selector{enote_store};
    const FeeCalculatorMockTrivial tx_fee_calculator;  //trivial fee calculator so we can use specified input fee

    std::vector<LegacyContextualEnoteRecordV1> legacy_contextual_inputs;
    std::vector<SpContextualEnoteRecordV1> sp_contextual_inputs;
    DiscretizedFee discretized_transaction_fee;
    ASSERT_NO_THROW(ASSERT_TRUE(try_prepare_inputs_and_outputs_for_transfer_v1(sp_user_address,
        sp_user_address,
        input_selector,
        tx_fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        std::move(normal_payment_proposals),
        std::move(selfsend_payment_proposals),
        shared_sp_keys.k_vb,
        legacy_contextual_inputs,
        sp_contextual_inputs,
        normal_payment_proposals,
        selfsend_payment_proposals,
        discretized_transaction_fee)));

    // d) prepare for legacy input proofs
    // note: need legacy ring signature preps here because legacy multisig proofs include ledger references (the ring
    //       signature decoys must be taken from the chain); however, seraphis ledger mappings are NOT needed because
    //       seraphis multisig proofs only operate on seraphis enote images, which don't require ledger references
    std::unordered_map<crypto::key_image, LegacyMultisigRingSignaturePrepV1> mapped_legacy_multisig_ring_signature_preps;
    ASSERT_NO_THROW(ASSERT_TRUE(try_gen_legacy_multisig_ring_signature_preps_v1(legacy_contextual_inputs,
        legacy_ring_size,
        ledger_context,
        mapped_legacy_multisig_ring_signature_preps)));

    // e) make multisig tx proposal
    SpMultisigTxProposalV1 multisig_tx_proposal;
    ASSERT_NO_THROW(make_v1_multisig_tx_proposal_v1(legacy_contextual_inputs,
        sp_contextual_inputs,
        std::move(mapped_legacy_multisig_ring_signature_preps),
        aggregate_filter_of_requested_multisig_signers,
        std::move(normal_payment_proposals),
        std::move(selfsend_payment_proposals),
        discretized_transaction_fee,
        TxExtra{},
        tx_version,
        rct::pk2rct(legacy_accounts[0].get_multisig_pubkey()),
        legacy_subaddress_map,
        legacy_accounts[0].get_common_privkey(),
        shared_sp_keys.K_1_base,
        shared_sp_keys.k_vb,
        multisig_tx_proposal));

    ASSERT_TRUE(multisig_tx_proposal.tx_fee == fee);

    // f) prove the multisig tx proposal is valid (this should be done by every signer who receives a multisig tx proposal
    //    from another group member)
    validate_multisig_tx_proposal(multisig_tx_proposal,
        semantic_rules_version,
        seraphis_accounts[0].get_threshold(),
        seraphis_accounts[0].get_signers().size(),
        rct::pk2rct(legacy_accounts[0].get_multisig_pubkey()),
        legacy_subaddress_map,
        legacy_accounts[0].get_common_privkey(),
        shared_sp_keys.K_1_base,
        shared_sp_keys.k_vb,
        enote_store,
        ledger_context);


    /// 4) get seraphis input proof inits from all requested signers
    std::vector<multisig::MultisigNonceCache> signer_nonce_records;
    std::unordered_map<crypto::public_key, std::unordered_map<rct::key, multisig::MultisigProofInitSetV1>>
        legacy_input_init_collections_per_signer;
    std::unordered_map<crypto::public_key, std::unordered_map<rct::key, multisig::MultisigProofInitSetV1>>
        sp_input_init_collections_per_signer;
    //signer_nonce_records.reserve(seraphis_accounts.size());  //nonce records are non-copyable, so .reserve() doesn't work

    for (std::size_t signer_index{0}; signer_index < seraphis_accounts.size(); ++signer_index)
    {
        signer_nonce_records.emplace_back();

        if (std::find(requested_signers.begin(), requested_signers.end(), signer_index) != requested_signers.end())
        {
            ASSERT_NO_THROW(make_v1_multisig_init_sets_for_inputs_v1(seraphis_accounts[signer_index].get_base_pubkey(),
                seraphis_accounts[signer_index].get_threshold(),
                seraphis_accounts[signer_index].get_signers(),
                multisig_tx_proposal,
                tx_version,
                rct::pk2rct(legacy_accounts[0].get_multisig_pubkey()),
                legacy_subaddress_map,
                legacy_accounts[0].get_common_privkey(),
                shared_sp_keys.K_1_base,
                shared_sp_keys.k_vb,
                signer_nonce_records.back(),
                legacy_input_init_collections_per_signer[seraphis_accounts[signer_index].get_base_pubkey()],
                sp_input_init_collections_per_signer[seraphis_accounts[signer_index].get_base_pubkey()]));
        }
        else
        {
            ASSERT_ANY_THROW(make_v1_multisig_init_sets_for_inputs_v1(seraphis_accounts[signer_index].get_base_pubkey(),
                seraphis_accounts[signer_index].get_threshold(),
                seraphis_accounts[signer_index].get_signers(),
                multisig_tx_proposal,
                tx_version,
                rct::pk2rct(legacy_accounts[0].get_multisig_pubkey()),
                legacy_subaddress_map,
                legacy_accounts[0].get_common_privkey(),
                shared_sp_keys.K_1_base,
                shared_sp_keys.k_vb,
                signer_nonce_records.back(),
                legacy_input_init_collections_per_signer[seraphis_accounts[signer_index].get_base_pubkey()],
                sp_input_init_collections_per_signer[seraphis_accounts[signer_index].get_base_pubkey()]));
        }
    }


    /// 5) get partial signatures from all requested signers
    std::unordered_map<crypto::public_key, std::vector<multisig::MultisigPartialSigSetV1>>
        legacy_input_partial_sigs_per_signer;
    std::unordered_map<crypto::public_key, std::vector<multisig::MultisigPartialSigSetV1>>
        sp_input_partial_sigs_per_signer;
    std::list<multisig::MultisigSigningErrorVariant> multisig_make_partial_sig_errors;

    for (std::size_t signer_index{0}; signer_index < seraphis_accounts.size(); ++signer_index)
    {
        multisig_make_partial_sig_errors.clear();

        if (std::find(requested_signers.begin(), requested_signers.end(), signer_index) != requested_signers.end())
        {
            ASSERT_NO_THROW(ASSERT_TRUE(try_make_v1_multisig_partial_sig_sets_for_legacy_inputs_v1(
                legacy_accounts[signer_index],
                multisig_tx_proposal,
                legacy_subaddress_map,
                shared_sp_keys.K_1_base,
                shared_sp_keys.k_vb,
                tx_version,
                legacy_input_init_collections_per_signer[legacy_accounts[signer_index].get_base_pubkey()],
                //don't need to remove the local init (will be filtered out internally)
                legacy_input_init_collections_per_signer,
                multisig_make_partial_sig_errors,
                signer_nonce_records[signer_index],
                legacy_input_partial_sigs_per_signer[legacy_accounts[signer_index].get_base_pubkey()])));

            ASSERT_NO_THROW(ASSERT_TRUE(try_make_v1_multisig_partial_sig_sets_for_sp_inputs_v1(
                seraphis_accounts[signer_index],
                multisig_tx_proposal,
                rct::pk2rct(legacy_accounts[0].get_multisig_pubkey()),
                legacy_subaddress_map,
                legacy_accounts[0].get_common_privkey(),
                tx_version,
                sp_input_init_collections_per_signer[seraphis_accounts[signer_index].get_base_pubkey()],
                //don't need to remove the local init (will be filtered out internally)
                sp_input_init_collections_per_signer,
                multisig_make_partial_sig_errors,
                signer_nonce_records[signer_index],
                sp_input_partial_sigs_per_signer[seraphis_accounts[signer_index].get_base_pubkey()])));

            print_multisig_errors(multisig_make_partial_sig_errors);
        }
        else
        {
            ASSERT_ANY_THROW(
                    try_make_v1_multisig_partial_sig_sets_for_legacy_inputs_v1(legacy_accounts[signer_index],
                        multisig_tx_proposal,
                        legacy_subaddress_map,
                        shared_sp_keys.K_1_base,
                        shared_sp_keys.k_vb,
                        tx_version,
                        legacy_input_init_collections_per_signer[legacy_accounts[signer_index].get_base_pubkey()],
                        //don't need to remove the local init (will be filtered out internally)
                        legacy_input_init_collections_per_signer,
                        multisig_make_partial_sig_errors,
                        signer_nonce_records[signer_index],
                        legacy_input_partial_sigs_per_signer[legacy_accounts[signer_index].get_base_pubkey()])
                    &&
                    try_make_v1_multisig_partial_sig_sets_for_sp_inputs_v1(seraphis_accounts[signer_index],
                        multisig_tx_proposal,
                        rct::pk2rct(legacy_accounts[0].get_multisig_pubkey()),
                        legacy_subaddress_map,
                        legacy_accounts[0].get_common_privkey(),
                        tx_version,
                        sp_input_init_collections_per_signer[seraphis_accounts[signer_index].get_base_pubkey()],
                        //don't need to remove the local init (will be filtered out internally)
                        sp_input_init_collections_per_signer,
                        multisig_make_partial_sig_errors,
                        signer_nonce_records[signer_index],
                        sp_input_partial_sigs_per_signer[seraphis_accounts[signer_index].get_base_pubkey()])
                );

            print_multisig_errors(multisig_make_partial_sig_errors);
        }
    }


    /// 6) any signer (or even a non-signer) can assemble partial signatures and complete txs
    /// note: even signers who didn't participate in making partial sigs can complete txs here

    // a) get legacy inputs and seraphis partial inputs
    std::vector<LegacyInputV1> legacy_inputs;
    std::vector<SpPartialInputV1> sp_partial_inputs;
    std::list<multisig::MultisigSigningErrorVariant> multisig_make_inputs_errors;

    ASSERT_NO_THROW(
            ASSERT_TRUE(try_make_inputs_for_multisig_v1(multisig_tx_proposal,
                seraphis_accounts[0].get_signers(),
                rct::pk2rct(legacy_accounts[0].get_multisig_pubkey()),
                legacy_subaddress_map,
                legacy_accounts[0].get_common_privkey(),
                shared_sp_keys.K_1_base,
                shared_sp_keys.k_vb,
                legacy_input_partial_sigs_per_signer,
                sp_input_partial_sigs_per_signer,
                multisig_make_inputs_errors,
                legacy_inputs,
                sp_partial_inputs))
        );
    print_multisig_errors(multisig_make_inputs_errors);

    // b) build partial tx
    SpTxProposalV1 tx_proposal;
    get_v1_tx_proposal_v1(multisig_tx_proposal,
        rct::pk2rct(legacy_accounts[0].get_multisig_pubkey()),
        legacy_subaddress_map,
        legacy_accounts[0].get_common_privkey(),
        shared_sp_keys.K_1_base,
        shared_sp_keys.k_vb,
        tx_proposal);

    SpPartialTxV1 partial_tx;
    ASSERT_NO_THROW(make_v1_partial_tx_v1(tx_proposal,
        std::move(legacy_inputs),
        std::move(sp_partial_inputs),
        tx_version,
        rct::pk2rct(legacy_accounts[0].get_multisig_pubkey()),
        shared_sp_keys.K_1_base,
        shared_sp_keys.k_vb,
        partial_tx));

    // c) get ledger mappings for the seraphis input membership proofs
    // note: do this after making the partial tx to demo that seraphis inputs don't have to be on-chain until this point
    std::unordered_map<crypto::key_image, std::uint64_t> sp_input_ledger_mappings;
    ASSERT_TRUE(try_get_membership_proof_real_reference_mappings(sp_contextual_inputs, sp_input_ledger_mappings));

    // d) prepare for membership proofs
    // note: use ring size 2^2 = 4 for speed
    std::vector<SpMembershipProofPrepV1> membership_proof_preps;
    ASSERT_NO_THROW(make_mock_sp_membership_proof_preps_for_inputs_v1(sp_input_ledger_mappings,
        tx_proposal.sp_input_proposals,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context,
        membership_proof_preps));

    // e) make membership proofs
    std::vector<SpAlignableMembershipProofV1> alignable_membership_proofs;

    ASSERT_NO_THROW(make_v1_alignable_membership_proofs_v1(std::move(membership_proof_preps),
        alignable_membership_proofs));

    // f) complete tx
    SpTxSquashedV1 completed_tx;

    ASSERT_NO_THROW(make_seraphis_tx_squashed_v1(semantic_rules_version,
        partial_tx,
        std::move(alignable_membership_proofs),
        completed_tx));

    // - sanity check fee (should do this in production use-case, but can't do it here with the trivial fee calculator)
    //ASSERT_TRUE(completed_tx.tx_fee == tx_fee_calculator.compute_fee(fee_per_tx_weight, completed_tx));

    // g) verify tx
    const TxValidationContextMock tx_validation_context{ledger_context};
    ASSERT_NO_THROW(ASSERT_TRUE(validate_tx(completed_tx, tx_validation_context)));

    // h) add tx to mock ledger
    ASSERT_NO_THROW(ASSERT_TRUE(try_add_tx_to_ledger(completed_tx, ledger_context)));


    /// 7) scan outputs for post-tx balance check

    // a) refresh enote store
    refresh_user_enote_store_legacy_multisig(legacy_accounts,
        legacy_subaddress_map,
        refresh_config,
        ledger_context,
        enote_store);
    refresh_user_enote_store(shared_sp_keys, refresh_config, ledger_context, enote_store);

    // b) compute expected spent amount
    boost::multiprecision::uint128_t total_spent_amount{0};

    for (const rct::xmr_amount out_amount : out_amounts_normal)
        total_spent_amount += out_amount;

    // c) balance check
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == total_input_amount - total_spent_amount - specified_fee);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_multisig, txtype_squashed_v1)
{
    // parameters: threshold | num_signers | {requested_signers} | {legacy in amnts} | {sp in amnts} | {out amnts normal} |
    // {out amnts selfsend} | fee | semantic_rules_version

    const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version{
            SpTxSquashedV1::SemanticRulesVersion::MOCK
        };

    // prepare fees to use (these should discretize perfectly)
    const DiscretizedFee fee_zero{discretize_fee(0)};
    const DiscretizedFee fee_one{discretize_fee(1)};
    EXPECT_TRUE(fee_zero == rct::xmr_amount{0});
    EXPECT_TRUE(fee_one == rct::xmr_amount{1});


    /// legacy inputs only

    // test M-of-N combos (and combinations of requested signers)
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(2, 2, {0,1},     {2}, {}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 3, {0},       {2}, {}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 3, {1},       {2}, {}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(2, 3, {0,2},     {2}, {}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(3, 3, {0,1,2},   {2}, {}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(2, 4, {1,3},     {2}, {}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(2, 4, {0,1,2,3}, {2}, {}, {1}, {}, fee_one, semantic_rules_version));

    // test various combinations of inputs/outputs
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {2},   {}, {1},   { },   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {2},   {}, {1},   { },   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {2},   {}, {1},   {0},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {2},   {}, { },   {1},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {2},   {}, {2},   { },   fee_zero, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {2},   {}, {2},   { },   fee_zero, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {2},   {}, {2},   {0},   fee_zero, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {2},   {}, {1},   {0},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {3},   {}, {1},   { },   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {3},   {}, {1},   {1},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {4},   {}, {1},   {1},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {4},   {}, {1},   {1},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {4},   {}, {1},   {0},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {4,4}, {}, {1,1}, {1,1}, fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {2,2,2}, {}, {1,1}, {1,1}, fee_one,  semantic_rules_version));


    /// seraphis inputs only

    // test M-of-N combos (and combinations of requested signers)
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(2, 2, {0,1},     {}, {2}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 3, {0},       {}, {2}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 3, {1},       {}, {2}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(2, 3, {0,2},     {}, {2}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(3, 3, {0,1,2},   {}, {2}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(2, 4, {1,3},     {}, {2}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(2, 4, {0,1,2,3}, {}, {2}, {1}, {}, fee_one, semantic_rules_version));

    // test various combinations of inputs/outputs
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {}, {2},   {1},   { },   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {}, {2},   {1},   { },   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {}, {2},   {1},   {0},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {}, {2},   { },   {1},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {}, {2},   {2},   { },   fee_zero, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {}, {2},   {2},   { },   fee_zero, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {}, {2},   {2},   {0},   fee_zero, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {}, {2},   {1},   {0},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {}, {3},   {1},   { },   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {}, {3},   {1},   {1},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {}, {4},   {1},   {1},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {}, {4},   {1},   {1},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {}, {4},   {1},   {0},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {}, {4,4}, {1,1}, {1,1}, fee_one,  semantic_rules_version));


    /// both seraphis and legacy inputs

    // test M-of-N combos (and combinations of requested signers)
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(2, 2, {0,1},     {1}, {1}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 3, {0},       {1}, {1}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 3, {1},       {1}, {1}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(2, 3, {0,2},     {1}, {1}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(3, 3, {0,1,2},   {1}, {1}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(2, 4, {1,3},     {1}, {1}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(2, 4, {0,1,2,3}, {1}, {1}, {1}, {}, fee_one, semantic_rules_version));

    // test various combinations of inputs/outputs
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {1},   {1},   {1},   { },   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {1},   {1},   {1},   { },   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {1},   {1},   {1},   {0},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {1},   {1},   { },   {1},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {1},   {1},   {2},   { },   fee_zero, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {1},   {1},   {2},   { },   fee_zero, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {1},   {1},   {2},   {0},   fee_zero, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {1},   {1},   {1},   {0},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {1},   {2},   {1},   { },   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {1},   {2},   {1},   {1},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {1},   {3},   {1},   {1},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {1},   {3},   {1},   {1},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {1},   {3},   {1},   {0},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {1,1}, {2,2}, {1,1}, {1,1}, fee_one,  semantic_rules_version));
}
//-------------------------------------------------------------------------------------------------------------------
