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

#include "crypto/crypto.h"
#include "misc_language.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis/jamtis_address_tag_utils.h"
#include "seraphis/jamtis_address_utils.h"
#include "seraphis/jamtis_core_utils.h"
#include "seraphis/jamtis_destination.h"
#include "seraphis/jamtis_enote_utils.h"
#include "seraphis/jamtis_payment_proposal.h"
#include "seraphis/jamtis_support_types.h"
#include "seraphis/mock_ledger_context.h"
#include "seraphis/sp_composition_proof.h"
#include "seraphis/sp_core_enote_utils.h"
#include "seraphis/sp_core_types.h"
#include "seraphis/sp_crypto_utils.h"
#include "seraphis/tx_base.h"
#include "seraphis/tx_binned_reference_set.h"
#include "seraphis/tx_builder_types.h"
#include "seraphis/tx_builders_inputs.h"
#include "seraphis/tx_builders_mixed.h"
#include "seraphis/tx_builders_outputs.h"
#include "seraphis/tx_component_types.h"
#include "seraphis/tx_discretized_fee.h"
#include "seraphis/tx_enote_finding_context_mocks.h"
#include "seraphis/tx_enote_record_types.h"
#include "seraphis/tx_enote_record_utils.h"
#include "seraphis/tx_enote_scanning.h"
#include "seraphis/tx_enote_scanning_context_simple.h"
#include "seraphis/tx_enote_store_mocks.h"
#include "seraphis/tx_extra.h"
#include "seraphis/tx_fee_calculator_mocks.h"
#include "seraphis/tx_fee_calculator_squashed_v1.h"
#include "seraphis/tx_input_selection.h"
#include "seraphis/tx_input_selection_output_context_v1.h"
#include "seraphis/tx_input_selector_mocks.h"
#include "seraphis/tx_misc_utils.h"
#include "seraphis/tx_validation_context_mock.h"
#include "seraphis/txtype_squashed_v1.h"

#include "boost/multiprecision/cpp_int.hpp"
#include "gtest/gtest.h"


class Invokable
{
public:
    virtual ~Invokable() = default;
    Invokable& operator=(Invokable&&) = delete;
    virtual void invoke() = 0;
};

class DummyInvokable final : public Invokable
{
public:
    void invoke() override {}
};

namespace sp
{

////
// EnoteScanningContextLedgerTEST
// - enote scanning context for injecting behavior into a scanning process
///
class EnoteScanningContextLedgerTEST final : public EnoteScanningContextLedger
{
public:
//constructors
    /// normal constructor
    EnoteScanningContextLedgerTEST(EnoteScanningContextLedgerSimple &core_scanning_context,
        Invokable &invokable_begin_scanning,
        Invokable &invokable_get_onchain_chunk,
        Invokable &invokable_get_unconfirmed_chunk,
        Invokable &invokable_terminate) :
            m_core_scanning_context{core_scanning_context},
            m_invokable_begin_scanning{invokable_begin_scanning},
            m_invokable_get_onchain_chunk{invokable_get_onchain_chunk},
            m_invokable_get_unconfirmed_chunk{invokable_get_unconfirmed_chunk},
            m_invokable_terminate{invokable_terminate}
    {}

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference werapper])
    EnoteScanningContextLedgerTEST& operator=(EnoteScanningContextLedgerTEST&&) = delete;

//member functions
    /// tell the enote finder it can start scanning from a specified block height
    void begin_scanning_from_height(const std::uint64_t initial_start_height,
        const std::uint64_t max_chunk_size) override
    {
        m_invokable_begin_scanning.invoke();
        m_core_scanning_context.begin_scanning_from_height(initial_start_height, max_chunk_size);
    }
    /// get the next available onchain chunk (must be contiguous with the last chunk acquired since starting to scan)
    /// note: if chunk is empty, chunk represents top of current chain
    void get_onchain_chunk(EnoteScanningChunkLedgerV1 &chunk_out) override
    {
        m_invokable_get_onchain_chunk.invoke();
        m_core_scanning_context.get_onchain_chunk(chunk_out);
    }
    /// try to get a scanning chunk for the unconfirmed txs in a ledger
    bool try_get_unconfirmed_chunk(EnoteScanningChunkNonLedgerV1 &chunk_out) override
    {
        m_invokable_get_unconfirmed_chunk.invoke();
        return m_core_scanning_context.try_get_unconfirmed_chunk(chunk_out);
    }
    /// tell the enote finder to stop its scanning process (should be no-throw no-fail)
    void terminate_scanning() override
    {
        m_invokable_terminate.invoke();
        m_core_scanning_context.terminate_scanning();
    }

private:
    /// enote scanning context that this test context wraps
    EnoteScanningContextLedgerSimple &m_core_scanning_context;

    /// injected invokable objects
    Invokable &m_invokable_begin_scanning;
    Invokable &m_invokable_get_onchain_chunk;
    Invokable &m_invokable_get_unconfirmed_chunk;
    Invokable &m_invokable_terminate;
};

} //namespace sp


//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static crypto::secret_key make_secret_key()
{
    return rct::rct2sk(rct::skGen());
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_random_address_for_user(const sp::jamtis::jamtis_mock_keys &user_keys,
    sp::jamtis::JamtisDestinationV1 &user_address_out)
{
    using namespace sp;
    using namespace jamtis;

    address_index_t address_index;
    address_index.gen();

    ASSERT_NO_THROW(make_jamtis_destination_v1(user_keys.K_1_base,
        user_keys.K_ua,
        user_keys.K_fr,
        user_keys.s_ga,
        address_index,
        user_address_out));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void convert_outlay_to_payment_proposal(const rct::xmr_amount outlay_amount,
    const sp::jamtis::JamtisDestinationV1 &destination,
    const sp::TxExtra &partial_memo_for_destination,
    sp::jamtis::JamtisPaymentProposalV1 &payment_proposal_out)
{
    using namespace sp;
    using namespace jamtis;

    payment_proposal_out = JamtisPaymentProposalV1{
            .m_destination = destination,
            .m_amount = outlay_amount,
            .m_enote_ephemeral_privkey = make_secret_key(),
            .m_partial_memo = partial_memo_for_destination
        };
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void add_coinbase_enotes_for_user(const rct::key &mock_input_context,
    const std::vector<rct::xmr_amount> &coinbase_amounts,
    const sp::jamtis::JamtisDestinationV1 &user_address,
    std::vector<sp::SpEnoteV1> &coinbase_enotes_inout,
    sp::SpTxSupplementV1 &tx_supplement_inout)
{
    using namespace sp;
    using namespace jamtis;

    // prepare mock coinbase enotes
    JamtisPaymentProposalV1 payment_proposal_temp;
    coinbase_enotes_inout.reserve(coinbase_enotes_inout.size() + coinbase_amounts.size());
    tx_supplement_inout.m_output_enote_ephemeral_pubkeys.reserve(
        tx_supplement_inout.m_output_enote_ephemeral_pubkeys.size() + coinbase_amounts.size());

    for (const rct::xmr_amount coinbase_amount : coinbase_amounts)
    {
        // make payment proposal
        convert_outlay_to_payment_proposal(coinbase_amount, user_address, TxExtra{}, payment_proposal_temp);

        // get output proposal
        SpOutputProposalV1 output_proposal;
        payment_proposal_temp.get_output_proposal_v1(mock_input_context, output_proposal);

        // save enote and ephemeral pubkey
        coinbase_enotes_inout.emplace_back();
        output_proposal.get_enote_v1(coinbase_enotes_inout.back());
        tx_supplement_inout.m_output_enote_ephemeral_pubkeys.emplace_back(output_proposal.m_enote_ephemeral_pubkey);
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void send_coinbase_amounts_to_users(const std::vector<std::vector<rct::xmr_amount>> &coinbase_amounts_per_user,
    const std::vector<sp::jamtis::JamtisDestinationV1> &user_addresses,
    sp::MockLedgerContext &ledger_context_inout)
{
    ASSERT_TRUE(coinbase_amounts_per_user.size() == user_addresses.size());

    using namespace sp;
    using namespace jamtis;

    // prepare mock coinbase enotes
    const rct::key mock_input_context{rct::pkGen()};
    std::vector<SpEnoteV1> coinbase_enotes;
    SpTxSupplementV1 tx_supplement;

    for (std::size_t user_index{0}; user_index < user_addresses.size(); ++user_index)
    {
        add_coinbase_enotes_for_user(mock_input_context,
            coinbase_amounts_per_user[user_index],
            user_addresses[user_index],
            coinbase_enotes,
            tx_supplement);
    }

    // commit coinbase enotes as new block
    ASSERT_NO_THROW(ledger_context_inout.commit_unconfirmed_txs_v1(mock_input_context,
        std::move(tx_supplement),
        std::move(coinbase_enotes)));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void refresh_user_enote_store(const sp::jamtis::jamtis_mock_keys &user_keys,
    const sp::RefreshLedgerEnoteStoreConfig &refresh_config,
    const sp::MockLedgerContext &ledger_context,
    sp::SpEnoteStoreV1 &user_enote_store_inout)
{
    using namespace sp;
    using namespace jamtis;

    const EnoteFindingContextLedgerMock enote_finding_context{ledger_context, user_keys.k_fr};
    EnoteScanningContextLedgerSimple enote_scanning_context{enote_finding_context};

    ASSERT_NO_THROW(refresh_enote_store_ledger(refresh_config,
        user_keys.K_1_base,
        user_keys.k_vb,
        enote_scanning_context,
        user_enote_store_inout));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void construct_tx_for_mock_ledger_v1(const sp::jamtis::jamtis_mock_keys &local_user_keys,
    const sp::InputSelectorV1 &local_user_input_selector,
    const sp::FeeCalculator &tx_fee_calculator,
    const rct::xmr_amount fee_per_tx_weight,
    const std::size_t max_inputs,
    const std::vector<std::tuple<rct::xmr_amount, sp::jamtis::JamtisDestinationV1, sp::TxExtra>> &outlays,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const sp::SpBinnedReferenceSetConfigV1 &bin_config,
    sp::MockLedgerContext &ledger_context_inout,
    sp::SpTxSquashedV1 &tx_out)
{
    using namespace sp;
    using namespace jamtis;

    /// build transaction

    // 1. prepare dummy and change addresses
    JamtisDestinationV1 change_address;
    JamtisDestinationV1 dummy_address;
    make_random_address_for_user(local_user_keys, change_address);
    make_random_address_for_user(local_user_keys, dummy_address);

    // 2. convert outlays to normal payment proposals
    std::vector<JamtisPaymentProposalV1> normal_payment_proposals;
    normal_payment_proposals.reserve(outlays.size());

    for (const auto &outlay : outlays)
    {
        normal_payment_proposals.emplace_back();

        convert_outlay_to_payment_proposal(std::get<rct::xmr_amount>(outlay),
            std::get<JamtisDestinationV1>(outlay),
            std::get<TxExtra>(outlay),
            normal_payment_proposals.back());
    }

    // 2. tx proposal
    SpTxProposalV1 tx_proposal;
    std::unordered_map<crypto::key_image, std::uint64_t> input_ledger_mappings;
    ASSERT_NO_THROW(ASSERT_TRUE(try_make_v1_tx_proposal_for_transfer_v1(local_user_keys.k_vb,
        change_address,
        dummy_address,
        local_user_input_selector,
        tx_fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        std::move(normal_payment_proposals),
        TxExtra{},
        tx_proposal,
        input_ledger_mappings)));

    // 3. prepare for membership proofs
    std::vector<SpMembershipProofPrepV1> membership_proof_preps;
    ASSERT_NO_THROW(make_mock_sp_membership_proof_preps_for_inputs_v1(input_ledger_mappings,
        tx_proposal.m_input_proposals,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context_inout,
        membership_proof_preps));

    // 4. complete tx
    ASSERT_NO_THROW(make_seraphis_tx_squashed_v1(tx_proposal,
        std::move(membership_proof_preps),
        SpTxSquashedV1::SemanticRulesVersion::MOCK,
        local_user_keys.k_m,
        local_user_keys.k_vb,
        tx_out));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void transfer_funds_single_mock_v1_unconfirmed(const sp::jamtis::jamtis_mock_keys &local_user_keys,
    const sp::InputSelectorV1 &local_user_input_selector,
    const sp::FeeCalculator &tx_fee_calculator,
    const rct::xmr_amount fee_per_tx_weight,
    const std::size_t max_inputs,
    const std::vector<std::tuple<rct::xmr_amount, sp::jamtis::JamtisDestinationV1, sp::TxExtra>> &outlays,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const sp::SpBinnedReferenceSetConfigV1 &bin_config,
    sp::MockLedgerContext &ledger_context_inout)
{
    using namespace sp;
    using namespace jamtis;

    // make one tx
    SpTxSquashedV1 single_tx;
    construct_tx_for_mock_ledger_v1(local_user_keys,
        local_user_input_selector,
        tx_fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        outlays,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context_inout,
        single_tx);

    // validate and submit to the mock ledger
    const sp::TxValidationContextMock tx_validation_context{ledger_context_inout};
    ASSERT_TRUE(validate_tx(single_tx, tx_validation_context));
    ASSERT_TRUE(ledger_context_inout.try_add_unconfirmed_tx_v1(single_tx));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, trivial_ledger)
{
    using namespace sp;
    using namespace jamtis;

    // make user keys
    jamtis_mock_keys user_keys;
    make_jamtis_mock_keys(user_keys);

    // make user address
    address_index_t j;
    j.gen();
    JamtisDestinationV1 user_address;

    ASSERT_NO_THROW(make_jamtis_destination_v1(user_keys.K_1_base,
        user_keys.K_ua,
        user_keys.K_fr,
        user_keys.s_ga,
        j,
        user_address));

    // make enote for user
    const rct::xmr_amount enote_amount{1};
    const rct::key mock_input_context{rct::skGen()};
    SpTxSupplementV1 mock_tx_supplement{};

    const JamtisPaymentProposalV1 payment_proposal{
            .m_destination = user_address,
            .m_amount = enote_amount,
            .m_enote_ephemeral_privkey = make_secret_key(),
            .m_partial_memo = mock_tx_supplement.m_tx_extra
        };
    SpOutputProposalV1 output_proposal;
    payment_proposal.get_output_proposal_v1(mock_input_context, output_proposal);

    SpEnoteV1 single_enote;
    output_proposal.get_enote_v1(single_enote);
    mock_tx_supplement.m_output_enote_ephemeral_pubkeys.emplace_back(output_proposal.m_enote_ephemeral_pubkey);

    // add enote to mock ledger context as a coinbase enote
    MockLedgerContext ledger_context;
    ASSERT_NO_THROW(ledger_context.commit_unconfirmed_txs_v1(mock_input_context, mock_tx_supplement, {single_enote}));

    // make and refresh enote store with mock ledger context
    SpEnoteStoreMockV1 user_enote_store{0};
    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };
    const EnoteFindingContextLedgerMock enote_finding_context{ledger_context, user_keys.k_fr};
    EnoteScanningContextLedgerSimple enote_scanning_context{enote_finding_context};

    ASSERT_NO_THROW(refresh_enote_store_ledger(refresh_config,
        user_keys.K_1_base,
        user_keys.k_vb,
        enote_scanning_context,
        user_enote_store));

    // make a copy of the expected enote record
    SpEnoteRecordV1 single_enote_record;

    ASSERT_TRUE(try_get_enote_record_v1(single_enote,
        output_proposal.m_enote_ephemeral_pubkey,
        mock_input_context,
        user_keys.K_1_base,
        user_keys.k_vb,
        single_enote_record));

    // expect the enote to be found
    ASSERT_TRUE(user_enote_store.has_enote_with_key_image(single_enote_record.m_key_image));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, simple_ledger)
{
    using namespace sp;
    using namespace jamtis;

    /// setup

    // 1. config
    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 0,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };

    // 2. user keys
    jamtis_mock_keys user_keys_A;
    jamtis_mock_keys user_keys_B;
    make_jamtis_mock_keys(user_keys_A);
    make_jamtis_mock_keys(user_keys_B);

    // 3. user addresses
    JamtisDestinationV1 destination_A;
    JamtisDestinationV1 destination_B;
    make_random_address_for_user(user_keys_A, destination_A);
    make_random_address_for_user(user_keys_B, destination_B);


    /// tests

    // 1. one coinbase to user
    MockLedgerContext ledger_context_test1;
    SpEnoteStoreMockV1 enote_store_A_test1{0};
    send_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context_test1);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context_test1, enote_store_A_test1);

    ASSERT_TRUE(enote_store_A_test1.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test1.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);

    // 2. two coinbase to user (one coinbase tx)
    MockLedgerContext ledger_context_test2;
    SpEnoteStoreMockV1 enote_store_A_test2{0};
    send_coinbase_amounts_to_users({{1, 1}}, {destination_A}, ledger_context_test2);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context_test2, enote_store_A_test2);

    ASSERT_TRUE(enote_store_A_test2.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test2.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);

    // 3. two coinbase owned by different users (one coinbase tx)
    MockLedgerContext ledger_context_test3;
    SpEnoteStoreMockV1 enote_store_A_test3{0};
    SpEnoteStoreMockV1 enote_store_B_test3{0};
    send_coinbase_amounts_to_users({{1}, {2}}, {destination_A, destination_B}, ledger_context_test3);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context_test3, enote_store_A_test3);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context_test3, enote_store_B_test3);

    ASSERT_TRUE(enote_store_A_test3.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test3.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(enote_store_B_test3.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_B_test3.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);

    // 4. two coinbase to user, search between each send (two coinbase txs i.e. two blocks)
    MockLedgerContext ledger_context_test4;
    SpEnoteStoreMockV1 enote_store_A_test4{0};
    send_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context_test4);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context_test4, enote_store_A_test4);

    ASSERT_TRUE(enote_store_A_test4.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test4.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);

    send_coinbase_amounts_to_users({{2}}, {destination_A}, ledger_context_test4);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context_test4, enote_store_A_test4);

    ASSERT_TRUE(enote_store_A_test4.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test4.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);

    // 5. search once, three coinbase to user, search once, pop 2, search again, 1 coinbase to user, search again
    const RefreshLedgerEnoteStoreConfig refresh_config_test5{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };
    MockLedgerContext ledger_context_test5;
    SpEnoteStoreMockV1 enote_store_A_test5{0};
    refresh_user_enote_store(user_keys_A, refresh_config_test5, ledger_context_test5, enote_store_A_test5);
    ASSERT_TRUE(enote_store_A_test5.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test5.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);

    send_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context_test5);
    send_coinbase_amounts_to_users({{2}}, {destination_A}, ledger_context_test5);
    send_coinbase_amounts_to_users({{4}}, {destination_A}, ledger_context_test5);
    refresh_user_enote_store(user_keys_A, refresh_config_test5, ledger_context_test5, enote_store_A_test5);

    ASSERT_TRUE(enote_store_A_test5.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test5.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 7);

    ledger_context_test5.pop_blocks(2);
    refresh_user_enote_store(user_keys_A, refresh_config_test5, ledger_context_test5, enote_store_A_test5);

    ASSERT_TRUE(enote_store_A_test5.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test5.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);

    send_coinbase_amounts_to_users({{8}}, {destination_A}, ledger_context_test5);
    refresh_user_enote_store(user_keys_A, refresh_config_test5, ledger_context_test5, enote_store_A_test5);

    ASSERT_TRUE(enote_store_A_test5.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test5.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 9);

    // 6. search, three coinbase to user, search, pop 2, search, 1 coinbase to user, search, pop 3, search
    // - refresh height 1
    const RefreshLedgerEnoteStoreConfig refresh_config_test6{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };
    MockLedgerContext ledger_context_test6;
    SpEnoteStoreMockV1 enote_store_A_test6{1};
    refresh_user_enote_store(user_keys_A, refresh_config_test6, ledger_context_test6, enote_store_A_test6);

    ASSERT_TRUE(enote_store_A_test6.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test6.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);

    send_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context_test6);
    send_coinbase_amounts_to_users({{2}}, {destination_A}, ledger_context_test6);
    send_coinbase_amounts_to_users({{4}}, {destination_A}, ledger_context_test6);
    refresh_user_enote_store(user_keys_A, refresh_config_test6, ledger_context_test6, enote_store_A_test6);

    ASSERT_TRUE(enote_store_A_test6.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test6.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 6);

    ledger_context_test6.pop_blocks(2);
    refresh_user_enote_store(user_keys_A, refresh_config_test6, ledger_context_test6, enote_store_A_test6);

    ASSERT_TRUE(enote_store_A_test6.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test6.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);

    send_coinbase_amounts_to_users({{8}}, {destination_A}, ledger_context_test6);
    refresh_user_enote_store(user_keys_A, refresh_config_test6, ledger_context_test6, enote_store_A_test6);

    ASSERT_TRUE(enote_store_A_test6.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test6.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 8);

    ledger_context_test6.pop_blocks(3);
    refresh_user_enote_store(user_keys_A, refresh_config_test6, ledger_context_test6, enote_store_A_test6);

    ASSERT_TRUE(enote_store_A_test6.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test6.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, basic_ledger_tx_passing)
{
    using namespace sp;
    using namespace jamtis;

    /// setup

    // 1. config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{0};  // 0 fee here
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator here (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .m_bin_radius = 1,
            .m_num_bin_members = 2
        };

    // 2. user keys
    jamtis_mock_keys user_keys_A;
    jamtis_mock_keys user_keys_B;
    make_jamtis_mock_keys(user_keys_A);
    make_jamtis_mock_keys(user_keys_B);

    // 3. user addresses
    JamtisDestinationV1 destination_A;
    JamtisDestinationV1 destination_B;
    make_random_address_for_user(user_keys_A, destination_A);
    make_random_address_for_user(user_keys_B, destination_B);


    /// tests

    // 1. one unconfirmed tx (no change), then commit it
    MockLedgerContext ledger_context_test1;
    SpEnoteStoreMockV1 enote_store_A_test1{0};
    SpEnoteStoreMockV1 enote_store_B_test1{0};
    const sp::InputSelectorMockV1 input_selector_A_test1{enote_store_A_test1};
    const sp::InputSelectorMockV1 input_selector_B_test1{enote_store_B_test1};
    send_coinbase_amounts_to_users({{1, 1, 1, 1}}, {destination_A}, ledger_context_test1);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context_test1, enote_store_A_test1);

    transfer_funds_single_mock_v1_unconfirmed(user_keys_A,
        input_selector_A_test1,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{2, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context_test1);

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context_test1, enote_store_A_test1);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context_test1, enote_store_B_test1);

    ASSERT_TRUE(enote_store_A_test1.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 4);
    ASSERT_TRUE(enote_store_A_test1.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test1.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 2);
    ASSERT_TRUE(enote_store_B_test1.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_B_test1.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 2);
    ASSERT_TRUE(enote_store_B_test1.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 2);

    ledger_context_test1.commit_unconfirmed_txs_v1(rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteV1>{});
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context_test1, enote_store_A_test1);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context_test1, enote_store_B_test1);

    ASSERT_TRUE(enote_store_A_test1.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);
    ASSERT_TRUE(enote_store_A_test1.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test1.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 2);
    ASSERT_TRUE(enote_store_B_test1.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);
    ASSERT_TRUE(enote_store_B_test1.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_B_test1.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 2);

    // 2. one unconfirmed tx (>0 change), then commit it
    MockLedgerContext ledger_context_test2;
    SpEnoteStoreMockV1 enote_store_A_test2{0};
    SpEnoteStoreMockV1 enote_store_B_test2{0};
    const sp::InputSelectorMockV1 input_selector_A_test2{enote_store_A_test2};
    const sp::InputSelectorMockV1 input_selector_B_test2{enote_store_B_test2};
    send_coinbase_amounts_to_users({{0, 0, 0, 8}}, {destination_A}, ledger_context_test2);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context_test2, enote_store_A_test2);

    transfer_funds_single_mock_v1_unconfirmed(user_keys_A,
        input_selector_A_test2,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{3, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context_test2);

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context_test2, enote_store_A_test2);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context_test2, enote_store_B_test2);

    ASSERT_TRUE(enote_store_A_test2.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 8);
    ASSERT_TRUE(enote_store_A_test2.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test2.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 5);
    ASSERT_TRUE(enote_store_B_test2.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_B_test2.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 3);
    ASSERT_TRUE(enote_store_B_test2.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 3);

    ledger_context_test2.commit_unconfirmed_txs_v1(rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteV1>{});
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context_test2, enote_store_A_test2);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context_test2, enote_store_B_test2);

    ASSERT_TRUE(enote_store_A_test2.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 5);
    ASSERT_TRUE(enote_store_A_test2.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test2.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 5);
    ASSERT_TRUE(enote_store_B_test2.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(enote_store_B_test2.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_B_test2.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 3);

    // 3. one unconfirmed tx (>0 change), then commit it + coinbase to B
    MockLedgerContext ledger_context_test3;
    SpEnoteStoreMockV1 enote_store_A_test3{0};
    SpEnoteStoreMockV1 enote_store_B_test3{0};
    const sp::InputSelectorMockV1 input_selector_A_test3{enote_store_A_test3};
    const sp::InputSelectorMockV1 input_selector_B_test3{enote_store_B_test3};
    send_coinbase_amounts_to_users({{0, 0, 0, 8}}, {destination_A}, ledger_context_test3);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context_test3, enote_store_A_test3);

    transfer_funds_single_mock_v1_unconfirmed(user_keys_A,
        input_selector_A_test3,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{3, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context_test3);

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context_test3, enote_store_A_test3);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context_test3, enote_store_B_test3);

    ASSERT_TRUE(enote_store_A_test3.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 8);
    ASSERT_TRUE(enote_store_A_test3.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test3.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 5);
    ASSERT_TRUE(enote_store_B_test3.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_B_test3.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 3);
    ASSERT_TRUE(enote_store_B_test3.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 3);

    send_coinbase_amounts_to_users({{8}}, {destination_B}, ledger_context_test3);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context_test3, enote_store_A_test3);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context_test3, enote_store_B_test3);

    ASSERT_TRUE(enote_store_A_test3.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 5);
    ASSERT_TRUE(enote_store_A_test3.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test3.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 5);
    ASSERT_TRUE(enote_store_B_test3.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 11);
    ASSERT_TRUE(enote_store_B_test3.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_B_test3.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 11);

    // 4. pass funds around with unconfirmed cache clear
    MockLedgerContext ledger_context_test4;
    SpEnoteStoreMockV1 enote_store_A_test4{0};
    SpEnoteStoreMockV1 enote_store_B_test4{0};
    const sp::InputSelectorMockV1 input_selector_A_test4{enote_store_A_test4};
    const sp::InputSelectorMockV1 input_selector_B_test4{enote_store_B_test4};
    send_coinbase_amounts_to_users({{10, 10, 10, 10}}, {destination_A}, ledger_context_test4);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context_test4, enote_store_A_test4);

    transfer_funds_single_mock_v1_unconfirmed(user_keys_A,
        input_selector_A_test4,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{20, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context_test4);

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context_test4, enote_store_A_test4);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context_test4, enote_store_B_test4);

    ASSERT_TRUE(enote_store_A_test4.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 40);
    ASSERT_TRUE(enote_store_A_test4.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test4.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 20);
    ASSERT_TRUE(enote_store_B_test4.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_B_test4.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 20);
    ASSERT_TRUE(enote_store_B_test4.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 20);

    ledger_context_test4.clear_unconfirmed_cache();
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context_test4, enote_store_A_test4);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context_test4, enote_store_B_test4);

    ASSERT_TRUE(enote_store_A_test4.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 40);
    ASSERT_TRUE(enote_store_A_test4.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test4.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 40);
    ASSERT_TRUE(enote_store_B_test4.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_B_test4.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_B_test4.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);

    transfer_funds_single_mock_v1_unconfirmed(user_keys_A,
        input_selector_A_test4,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{30, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context_test4);

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context_test4, enote_store_A_test4);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context_test4, enote_store_B_test4);

    ASSERT_TRUE(enote_store_A_test4.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 40);
    ASSERT_TRUE(enote_store_A_test4.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test4.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 10);
    ASSERT_TRUE(enote_store_B_test4.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_B_test4.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 30);
    ASSERT_TRUE(enote_store_B_test4.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 30);

    ledger_context_test4.commit_unconfirmed_txs_v1(rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteV1>{});
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context_test4, enote_store_A_test4);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context_test4, enote_store_B_test4);

    ASSERT_TRUE(enote_store_A_test4.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 10);
    ASSERT_TRUE(enote_store_A_test4.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test4.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 10);
    ASSERT_TRUE(enote_store_B_test4.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 30);
    ASSERT_TRUE(enote_store_B_test4.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_B_test4.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 30);

    transfer_funds_single_mock_v1_unconfirmed(user_keys_A,
        input_selector_A_test4,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{3, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context_test4);

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context_test4, enote_store_A_test4);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context_test4, enote_store_B_test4);

    ASSERT_TRUE(enote_store_A_test4.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 10);
    ASSERT_TRUE(enote_store_A_test4.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test4.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 7);
    ASSERT_TRUE(enote_store_B_test4.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 30);
    ASSERT_TRUE(enote_store_B_test4.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 3);
    ASSERT_TRUE(enote_store_B_test4.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 33);

    ledger_context_test4.commit_unconfirmed_txs_v1(rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteV1>{});
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context_test4, enote_store_A_test4);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context_test4, enote_store_B_test4);

    ASSERT_TRUE(enote_store_A_test4.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 7);
    ASSERT_TRUE(enote_store_A_test4.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test4.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 7);
    ASSERT_TRUE(enote_store_B_test4.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 33);
    ASSERT_TRUE(enote_store_B_test4.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_B_test4.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 33);

    // 5. pass funds around with non-zero refresh height and reorging
    MockLedgerContext ledger_context_test5;
    SpEnoteStoreMockV1 enote_store_A_test5{0};
    SpEnoteStoreMockV1 enote_store_B_test5{2};
    const sp::InputSelectorMockV1 input_selector_A_test5{enote_store_A_test5};
    const sp::InputSelectorMockV1 input_selector_B_test5{enote_store_B_test5};
    send_coinbase_amounts_to_users({{10, 10, 10, 10}}, {destination_A}, ledger_context_test5);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context_test5, enote_store_A_test5);

    transfer_funds_single_mock_v1_unconfirmed(user_keys_A,
        input_selector_A_test5,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{11, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context_test5);

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context_test5, enote_store_A_test5);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context_test5, enote_store_B_test5);

    ASSERT_TRUE(enote_store_A_test5.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 40);
    ASSERT_TRUE(enote_store_A_test5.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test5.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 29);
    ASSERT_TRUE(enote_store_B_test5.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_B_test5.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 11);
    ASSERT_TRUE(enote_store_B_test5.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 11);

    ledger_context_test5.commit_unconfirmed_txs_v1(rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteV1>{});
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context_test5, enote_store_A_test5);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context_test5, enote_store_B_test5);

    ASSERT_TRUE(enote_store_A_test5.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 29);
    ASSERT_TRUE(enote_store_A_test5.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test5.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 29);
    ASSERT_TRUE(enote_store_B_test5.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_B_test5.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_B_test5.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);

    transfer_funds_single_mock_v1_unconfirmed(user_keys_A,
        input_selector_A_test5,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{12, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context_test5);

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context_test5, enote_store_A_test5);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context_test5, enote_store_B_test5);

    ASSERT_TRUE(enote_store_A_test5.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 29);
    ASSERT_TRUE(enote_store_A_test5.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test5.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 17);
    ASSERT_TRUE(enote_store_B_test5.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_B_test5.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 12);
    ASSERT_TRUE(enote_store_B_test5.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 12);

    ledger_context_test5.commit_unconfirmed_txs_v1(rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteV1>{});
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context_test5, enote_store_A_test5);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context_test5, enote_store_B_test5);

    ASSERT_TRUE(enote_store_A_test5.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 17);
    ASSERT_TRUE(enote_store_A_test5.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test5.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 17);
    ASSERT_TRUE(enote_store_B_test5.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 12);
    ASSERT_TRUE(enote_store_B_test5.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_B_test5.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 12);

    ledger_context_test5.pop_blocks(1);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context_test5, enote_store_A_test5);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context_test5, enote_store_B_test5);

    ASSERT_TRUE(enote_store_A_test5.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 29);
    ASSERT_TRUE(enote_store_A_test5.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test5.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 29);
    ASSERT_TRUE(enote_store_B_test5.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_B_test5.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_B_test5.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);

    transfer_funds_single_mock_v1_unconfirmed(user_keys_A,
        input_selector_A_test5,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{13, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context_test5);

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context_test5, enote_store_A_test5);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context_test5, enote_store_B_test5);

    ASSERT_TRUE(enote_store_A_test5.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 29);
    ASSERT_TRUE(enote_store_A_test5.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test5.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 16);
    ASSERT_TRUE(enote_store_B_test5.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_B_test5.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 13);
    ASSERT_TRUE(enote_store_B_test5.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 13);

    ledger_context_test5.commit_unconfirmed_txs_v1(rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteV1>{});
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context_test5, enote_store_A_test5);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context_test5, enote_store_B_test5);

    ASSERT_TRUE(enote_store_A_test5.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 16);
    ASSERT_TRUE(enote_store_A_test5.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test5.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 16);
    ASSERT_TRUE(enote_store_B_test5.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 13);
    ASSERT_TRUE(enote_store_B_test5.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_B_test5.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 13);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
class InvokableTest1 final : public Invokable
{
public:
    InvokableTest1(sp::MockLedgerContext &ledger_context) : m_ledger_contex{ledger_context} {}
    InvokableTest1& operator=(InvokableTest1&&) = delete;

    /// invoke: on the third call, pop 2 blocks from the ledger context
    void invoke() override
    {
        ++m_num_calls;

        if (m_num_calls == 3)
            m_ledger_contex.pop_blocks(2);
    }
private:
    sp::MockLedgerContext &m_ledger_contex;
    std::size_t m_num_calls{0};
};
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, reorgs_while_scanning)
{
    using namespace sp;
    using namespace jamtis;

    /// setup
    DummyInvokable dummy_invokable;

    // 1. config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{0};  // 0 fee here
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator here (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .m_bin_radius = 1,
            .m_num_bin_members = 2
        };

    // 2. user keys
    jamtis_mock_keys user_keys_A;
    jamtis_mock_keys user_keys_B;
    make_jamtis_mock_keys(user_keys_A);
    make_jamtis_mock_keys(user_keys_B);

    // 3. user addresses
    JamtisDestinationV1 destination_A;
    JamtisDestinationV1 destination_B;
    make_random_address_for_user(user_keys_A, destination_A);
    make_random_address_for_user(user_keys_B, destination_B);


    /// tests

    // 1. full internal reorg
    const RefreshLedgerEnoteStoreConfig refresh_config_test1{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };
    MockLedgerContext ledger_context_test1;
    SpEnoteStoreMockV1 enote_store_A_test1{0};
    SpEnoteStoreMockV1 enote_store_B_test1{0};
    const sp::InputSelectorMockV1 input_selector_A_test1{enote_store_A_test1};
    const sp::InputSelectorMockV1 input_selector_B_test1{enote_store_B_test1};
    send_coinbase_amounts_to_users({{1, 1, 1, 1}}, {destination_A}, ledger_context_test1);

    // a. refresh once so alignment will begin on block 0 in the test
    refresh_user_enote_store(user_keys_A, refresh_config_test1, ledger_context_test1, enote_store_A_test1);

    // b. send tx A -> B
    transfer_funds_single_mock_v1_unconfirmed(user_keys_A,
        input_selector_A_test1,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{2, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context_test1);
    ledger_context_test1.commit_unconfirmed_txs_v1(rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteV1>{});

    // c. refresh with injected invokable
    // current chain state: {block0[{1, 1, 1, 1} -> A], block1[A -> {2} -> B]}
    // current enote context A: [enotes: block0{1, 1, 1, 1}], [blocks: 0{...}]
    // expected refresh sequence:
    // 1. desired start height = block 1
    // 2. actual start height = block 0 = ([desired start] 1 - [reorg depth] 1)
    // 3. scan process
    //   a. onchain loop
    //     i.   get onchain chunk: block 0  (success: chunk range [0, 1))
    //     ii.  get onchain chunk: block 1  (success: chunk range [1, 2))
    //     iii. get onchain chunk: block 2  (injected: pop 2)  (fail: chunk range [0,0))
    //   b. unconfirmed chunk: get nothing
    //   c. skip follow-up onchain loop (NEED_FULLSCAN)
    // 4. promote NEED_FULLSCAN -> DONE because reorg goes below enote store refresh height (it's 0)
    // 4. refresh enote store of A: completely empty
    const EnoteFindingContextLedgerMock enote_finding_context_A_test1{ledger_context_test1, user_keys_A.k_fr};
    EnoteScanningContextLedgerSimple enote_scanning_context_A_test1{enote_finding_context_A_test1};
    InvokableTest1 invokable_get_onchain_test1{ledger_context_test1};
    EnoteScanningContextLedgerTEST test_scanning_context_A_test1(enote_scanning_context_A_test1,
        dummy_invokable,
        invokable_get_onchain_test1,
        dummy_invokable,
        dummy_invokable);
    ASSERT_NO_THROW(refresh_enote_store_ledger(refresh_config_test1,
        user_keys_A.K_1_base,
        user_keys_A.k_vb,
        test_scanning_context_A_test1,
        enote_store_A_test1));

    // d. after refreshing, both users should have no balance
    refresh_user_enote_store(user_keys_B, refresh_config_test1, ledger_context_test1, enote_store_B_test1);

    ASSERT_TRUE(enote_store_A_test1.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_A_test1.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A_test1.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_B_test1.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_B_test1.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_B_test1.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);


/*
    1. full internal reorg
    - normal scan once so alignment will be at block 0 in the test
    - commit tx 1 A -> B

    - A starts scan process on {blocks: {0, 1}, refresh height: 0, num scanned blocks: 1, chunk size: 1, avoid reorg depth: 1, max partial scans = 1}
    - try get onchain chunk {0} (initial onchain loop)  (should update alignment marker so it equals block 0)
        - get chunk: {0}
    - try get onchain chunk {1}
        - get chunk: {1}
    - try get onchain chunk {2}  (INJECTED STEP)
        - pop 2
        - return false (on trying and failing to get chunk 2, and instead returning empty block representing first block)
    - status: NEED_FULLSCAN  
    - status: converted to DONE since reorg goes to refresh height (note: should incorrectly maintain balance from block 0 on post-process enote store update since alignment marker is on block 0)

    - check onchain balances (standard balance update for B)
        - A: {}
        - B: {}

    2. partial internal reorg
    - commit tx 1 A -> B

    - B starts scan process on {blocks: {0, 1}, refresh height: 0, num scanned blocks: 0, chunk size: 1, avoid reorg depth: 0, max partial scans = 1}
    - try get onchain chunk {0}  (initial onchain loop)
        - get chunk: {0}
    - try get onchain chunk {1}  (INJECTED STEP)
        - pop 1
        - commit tx 2 A -> B
        - get chunk: {1}
    - status: NEED_PARTIALSCAN  (note: should be NEED_FULLSCAN incorrectly on internal first contiguity height check)
    - B starts scan process on {blocks: {0, 1}, refresh height: 0, num scanned blocks: 1, chunk size: 1, avoid reorg depth: 0, max partial scans = 1}
    - try get onchain chunk {1}  (initial onchain loop)
        - get chunk: {1}
    - try get onchain chunk {2}
        - return false
    - try get unconfirmed chunk {}  (unconfirmed chunk)
        - return false
    - try get onchain chunk {2}  (follow-up loop)
        - return false
    - status: DONE

    - check onchain balances (standard balance update for A)
        - A: {0, tx 2}
        - B: {tx 2}

    3. partial internal reorgs to failure
    - commit tx 1 A -> B

    - B starts scan process on {blocks: {0, 1}, refresh height: 0, num scanned blocks: 0, chunk size: 1, avoid reorg depth: 0, max partial scans = 4}
    - try get onchain chunk {0}  (initial onchain loop)
        - get chunk: {0}
    - try get onchain chunk {1}  (INJECTED STEP)
        - pop 1
        - commit tx 2 A -> B
        - commit tx 3 A -> B
        - get chunk: {1}
    - status: NEED_PARTIALSCAN
    - B starts scan process on {blocks: {0, 1, 2}, refresh height: 0, num scanned blocks: 1, chunk size: 1, avoid reorg depth: 0, max partial scans = 4}
    - try get onchain chunk {1}  (initial onchain loop)
        - get chunk: {1}
    - try get onchain chunk {2}  (INJECTED STEP)
        - pop 1
        - commit tx 4 A -> B
        - commit tx 5 A -> B
        - get chunk: {2}
    - status: NEED_PARTIALSCAN
    - etc.
    - EXPECT_ANY_THROW()

    4. sneaky tx found in follow-up loop
    - commit tx 1 A -> B

    - B starts scan process on {blocks: {0, 1}, refresh height: 0, num scanned blocks: 0, chunk size: 1, avoid reorg depth: 0}
    - try get onchain chunk {0}  (initial onchain loop)
        - get chunk: {0}
    - try get onchain chunk {1}
        - get chunk: {1}
    - try get onchain chunk {2}
        - return false
    - try get unconfirmed chunk {}  (unconfirmed chunk)  (INJECTED STEP)
        - submit tx 2 A -> B
        - return true
    - try get onchain chunk {2}  (follow-up loop)  (INJECTED STEP)
        - commit unconfirmed cache
        - get chunk: {2}
    - try get onchain chunk {3}
        - return false
    - status: DONE

    - check onchain balances (standard balance update for A)
        - A: {0, tx 1, tx 2}
        - B: {tx 1, tx 2}
*/
}
//-------------------------------------------------------------------------------------------------------------------
