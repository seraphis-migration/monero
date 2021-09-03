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

#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "cryptonote_basic/subaddress_index.h"
#include "misc_language.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/binned_reference_set.h"
#include "seraphis_core/discretized_fee.h"
#include "seraphis_core/jamtis_address_tag_utils.h"
#include "seraphis_core/jamtis_address_utils.h"
#include "seraphis_core/jamtis_core_utils.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_core/jamtis_enote_utils.h"
#include "seraphis_core/jamtis_payment_proposal.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_core/legacy_core_utils.h"
#include "seraphis_core/legacy_enote_types.h"
#include "seraphis_core/legacy_enote_utils.h"
#include "seraphis_core/sp_core_enote_utils.h"
#include "seraphis_core/sp_core_types.h"
#include "seraphis_core/tx_extra.h"
#include "seraphis_crypto/sp_composition_proof.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_impl/enote_store_utils.h"
#include "seraphis_impl/legacy_ki_import_tool.h"
#include "seraphis_impl/scan_context_simple.h"
#include "seraphis_impl/scan_process_basic.h"
#include "seraphis_impl/tx_fee_calculator_squashed_v1.h"
#include "seraphis_impl/tx_input_selection_output_context_v1.h"
#include "seraphis_main/contextual_enote_record_utils.h"
#include "seraphis_main/enote_record_types.h"
#include "seraphis_main/enote_record_utils.h"
#include "seraphis_main/enote_record_utils_legacy.h"
#include "seraphis_main/scan_machine_types.h"
#include "seraphis_main/tx_builder_types.h"
#include "seraphis_main/tx_builders_inputs.h"
#include "seraphis_main/tx_builders_legacy_inputs.h"
#include "seraphis_main/tx_builders_mixed.h"
#include "seraphis_main/tx_builders_outputs.h"
#include "seraphis_main/tx_component_types.h"
#include "seraphis_main/tx_input_selection.h"
#include "seraphis_main/txtype_base.h"
#include "seraphis_main/txtype_squashed_v1.h"
#include "seraphis_mocks/seraphis_mocks.h"

#include "boost/multiprecision/cpp_int.hpp"
#include "gtest/gtest.h"

using namespace sp;
using namespace jamtis;
using namespace sp::mocks;
using namespace jamtis::mocks;

class Invocable
{
public:
    virtual ~Invocable() = default;
    Invocable& operator=(Invocable&&) = delete;
    virtual void invoke() = 0;
};

class DummyInvocable final : public Invocable
{
public:
    void invoke() override {}
};

namespace sp
{

////
// ScanContextNonLedgerTEST
// - enote scanning context for injecting behavior into the nonledger component of a scanning process
///
class ScanContextNonLedgerTEST final : public scanning::ScanContextNonLedger
{
public:
//constructors
    /// normal constructor
    ScanContextNonLedgerTEST(scanning::ScanContextNonLedgerSimple &core_scan_context,
        Invocable &invocable_get_nonledger_chunk) :
            m_core_scan_context{core_scan_context},
            m_invocable_get_nonledger_chunk{invocable_get_nonledger_chunk}
    {}

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference werapper])
    ScanContextNonLedgerTEST& operator=(ScanContextNonLedgerTEST&&) = delete;

//member functions
    /// try to get a scanning chunk for the unconfirmed txs in a ledger
    void get_nonledger_chunk(scanning::ChunkData &chunk_out) override
    {
        m_invocable_get_nonledger_chunk.invoke();
        m_core_scan_context.get_nonledger_chunk(chunk_out);
    }
    /// check if aborted
    bool is_aborted() const override { return false; }

private:
//member variables
    /// enote scanning context that this test context wraps
    scanning::ScanContextNonLedgerSimple &m_core_scan_context;

    /// injected invocable objects
    Invocable &m_invocable_get_nonledger_chunk;
};

////
// ScanContextLedgerTEST
// - enote scanning context for injecting behavior into the ledger component of a scanning process
///
class ScanContextLedgerTEST final : public scanning::ScanContextLedger
{
public:
//constructors
    /// normal constructor
    ScanContextLedgerTEST(scanning::ScanContextLedgerSimple &core_scan_context,
        Invocable &invocable_begin_scanning,
        Invocable &invocable_get_onchain_chunk,
        Invocable &invocable_terminate) :
            m_core_scan_context{core_scan_context},
            m_invocable_begin_scanning{invocable_begin_scanning},
            m_invocable_get_onchain_chunk{invocable_get_onchain_chunk},
            m_invocable_terminate{invocable_terminate}
    {}

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference werapper])
    ScanContextLedgerTEST& operator=(ScanContextLedgerTEST&&) = delete;

//member functions
    /// tell the enote finder it can start scanning from a specified block index
    void begin_scanning_from_index(const std::uint64_t initial_start_index,
        const std::uint64_t max_chunk_size_hint) override
    {
        m_invocable_begin_scanning.invoke();
        m_core_scan_context.begin_scanning_from_index(initial_start_index, max_chunk_size_hint);
    }
    /// get the next available onchain chunk (must be contiguous with the last chunk acquired since starting to scan)
    /// note: if chunk is empty, chunk represents top of current chain
    std::unique_ptr<scanning::LedgerChunk> get_onchain_chunk() override
    {
        m_invocable_get_onchain_chunk.invoke();
        return m_core_scan_context.get_onchain_chunk();
    }
    /// tell the enote finder to stop its scanning process (should be no-throw no-fail)
    void terminate_scanning() override
    {
        m_invocable_terminate.invoke();
        m_core_scan_context.terminate_scanning();
    }
    /// check if aborted
    bool is_aborted() const override { return false; }

private:
    /// enote scanning context that this test context wraps
    scanning::ScanContextLedgerSimple &m_core_scan_context;

    /// injected invocable objects
    Invocable &m_invocable_begin_scanning;
    Invocable &m_invocable_get_onchain_chunk;
    Invocable &m_invocable_terminate;
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
static void prepare_mock_v5_legacy_enote_for_transfer(const rct::key &destination_subaddr_spendkey,
    const rct::key &destination_subaddr_viewkey,
    const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_spend_privkey,
    const crypto::secret_key &legacy_view_privkey,
    const rct::xmr_amount amount,
    const std::uint64_t tx_output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    LegacyEnoteV5 &legacy_enote_out,
    rct::key &enote_ephemeral_pubkey_out,
    crypto::key_image &key_image_out)
{
    // prepare enote
    enote_ephemeral_pubkey_out = rct::scalarmultKey(destination_subaddr_spendkey, rct::sk2rct(enote_ephemeral_privkey));

    ASSERT_NO_THROW(make_legacy_enote_v5(destination_subaddr_spendkey,
        destination_subaddr_viewkey,
        amount,
        tx_output_index,
        enote_ephemeral_privkey,
        legacy_enote_out));

    // recover key image of enote
    LegacyEnoteRecord full_record_recovered;

    ASSERT_TRUE(try_get_legacy_enote_record(legacy_enote_out,
        enote_ephemeral_pubkey_out,
        tx_output_index,
        0,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        hw::get_device("default"),
        full_record_recovered));

    key_image_out = full_record_recovered.key_image;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, trivial_ledger)
{
    // make user keys
    jamtis_mock_keys user_keys;
    make_jamtis_mock_keys(user_keys);

    // make user address
    address_index_t j;
    j = sp::jamtis::gen_address_index();
    JamtisDestinationV1 user_address;

    ASSERT_NO_THROW(make_jamtis_destination_v1(user_keys.K_1_base,
        user_keys.xK_ua,
        user_keys.xK_fr,
        user_keys.s_ga,
        j,
        user_address));

    // make enote for user
    const rct::xmr_amount enote_amount{1};
    const rct::key mock_input_context{rct::skGen()};
    SpTxSupplementV1 mock_tx_supplement{};

    const JamtisPaymentProposalV1 payment_proposal{
            .destination = user_address,
            .amount = enote_amount,
            .enote_ephemeral_privkey = crypto::x25519_secret_key_gen(),
            .partial_memo = mock_tx_supplement.tx_extra
        };
    SpOutputProposalV1 output_proposal;
    make_v1_output_proposal_v1(payment_proposal, mock_input_context, output_proposal);

    SpEnoteV1 single_enote;
    get_enote_v1(output_proposal, single_enote);
    mock_tx_supplement.output_enote_ephemeral_pubkeys.emplace_back(output_proposal.enote_ephemeral_pubkey);

    // add enote to mock ledger context as a coinbase enote
    MockLedgerContext ledger_context{0, 0};
    ASSERT_NO_THROW(ledger_context.commit_unconfirmed_txs_v1(rct::pkGen(),
        mock_input_context,
        mock_tx_supplement,
        {single_enote}));

    // make and refresh enote store with mock ledger context
    SpEnoteStore user_enote_store{0, 0, 0};
    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 0
        };
    const EnoteFindingContextUnconfirmedMockSp enote_finding_context_unconfirmed{ledger_context, user_keys.xk_fr};
    const EnoteFindingContextLedgerMockSp enote_finding_context_ledger{ledger_context, user_keys.xk_fr};
    scanning::ScanContextNonLedgerSimple scan_context_unconfirmed{enote_finding_context_unconfirmed};
    scanning::ScanContextLedgerSimple scan_context_ledger{enote_finding_context_ledger};
    ChunkConsumerMockSp chunk_consumer{user_keys.K_1_base, user_keys.k_vb, user_enote_store};

    ASSERT_NO_THROW(refresh_enote_store(refresh_config,
        scan_context_unconfirmed,
        scan_context_ledger,
        chunk_consumer));

    // make a copy of the expected enote record
    SpEnoteRecordV1 single_enote_record;

    ASSERT_TRUE(try_get_enote_record_v1(single_enote,
        output_proposal.enote_ephemeral_pubkey,
        mock_input_context,
        user_keys.K_1_base,
        user_keys.k_vb,
        single_enote_record));

    // expect the enote to be found
    ASSERT_TRUE(user_enote_store.has_enote_with_key_image(single_enote_record.key_image));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, simple_ledger_1)
{
    /// setup

    // 1. config
    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 0,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 0
        };

    // 2. user keys
    jamtis_mock_keys user_keys_A;
    make_jamtis_mock_keys(user_keys_A);

    // 3. user addresses
    JamtisDestinationV1 destination_A;
    make_random_address_for_user(user_keys_A, destination_A);


    /// test

    // 1. one coinbase to user
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStore enote_store_A{0, 0, 0};
    send_sp_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, simple_ledger_2)
{
    /// setup

    // 1. config
    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 0,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 0
        };

    // 2. user keys
    jamtis_mock_keys user_keys_A;
    make_jamtis_mock_keys(user_keys_A);

    // 3. user addresses
    JamtisDestinationV1 destination_A;
    make_random_address_for_user(user_keys_A, destination_A);


    /// test

    // 2. two coinbase to user (one coinbase tx)
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStore enote_store_A{0, 0, 0};
    send_sp_coinbase_amounts_to_users({{1, 1}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, simple_ledger_3)
{
    /// setup

    // 1. config
    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 0,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 0
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


    /// test

    // 3. two coinbase owned by different users (one coinbase tx)
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStore enote_store_A{0, 0, 0};
    SpEnoteStore enote_store_B{0, 0, 0};
    send_sp_coinbase_amounts_to_users({{1}, {2}}, {destination_A, destination_B}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, simple_ledger_4)
{
    /// setup

    // 1. config
    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 0,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 0
        };

    // 2. user keys
    jamtis_mock_keys user_keys_A;
    make_jamtis_mock_keys(user_keys_A);

    // 3. user addresses
    JamtisDestinationV1 destination_A;
    make_random_address_for_user(user_keys_A, destination_A);


    /// test

    // 4. two coinbase to user, search between each send (two coinbase txs i.e. two blocks)
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStore enote_store_A{0, 0, 0};
    send_sp_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);

    send_sp_coinbase_amounts_to_users({{2}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, simple_ledger_5)
{
    /// setup

    // 1. config
    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 0
        };

    // 2. user keys
    jamtis_mock_keys user_keys_A;
    make_jamtis_mock_keys(user_keys_A);

    // 3. user addresses
    JamtisDestinationV1 destination_A;
    make_random_address_for_user(user_keys_A, destination_A);


    /// test

    // 5. search once, three coinbase to user, search once, pop 2, search again, 1 coinbase to user, search again
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStore enote_store_A{0, 0, 0};
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);

    send_sp_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);
    send_sp_coinbase_amounts_to_users({{2}}, {destination_A}, ledger_context);
    send_sp_coinbase_amounts_to_users({{4}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 7);

    ledger_context.pop_blocks(2);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);

    send_sp_coinbase_amounts_to_users({{8}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 9);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, simple_ledger_6)
{
    /// setup

    // 1. config
    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 0
        };

    // 2. user keys
    jamtis_mock_keys user_keys_A;
    make_jamtis_mock_keys(user_keys_A);

    // 3. user addresses
    JamtisDestinationV1 destination_A;
    make_random_address_for_user(user_keys_A, destination_A);


    /// test

    // 6. search, three coinbase to user, search, pop 2, search, 1 coinbase to user, search, pop 3, search
    // - refresh index 1
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStore enote_store_A{1, 0, 0};
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);

    send_sp_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);
    send_sp_coinbase_amounts_to_users({{2}}, {destination_A}, ledger_context);
    send_sp_coinbase_amounts_to_users({{4}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 6);

    ledger_context.pop_blocks(2);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);

    send_sp_coinbase_amounts_to_users({{8}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 8);

    ledger_context.pop_blocks(3);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, simple_ledger_7)
{
    // test: reorgs that affect pruned blocks in the enote store's checkpoint cache

    /// setup

    // 1. config
    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 0
        };
    const CheckpointCacheConfig checkpoint_cache_config{
            .num_unprunable = 1,
            .max_separation = 100,
            .density_factor = 1
        };

    // 2. user keys
    jamtis_mock_keys user_keys_A;
    make_jamtis_mock_keys(user_keys_A);

    // 3. user addresses
    JamtisDestinationV1 destination_A;
    make_random_address_for_user(user_keys_A, destination_A);


    /// test
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStore enote_store_A{4, 0, 0, checkpoint_cache_config};
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);

    // send funds: blocks 0 - 12, refresh
    send_sp_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);  //block 0
    send_sp_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);  //block 1
    send_sp_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);  //block 2
    send_sp_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);  //block 3
    send_sp_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);  //block 4
    send_sp_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);  //block 5
    send_sp_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);  //block 6
    send_sp_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);  //block 7
    send_sp_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);  //block 8
    send_sp_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);  //block 9
    send_sp_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);  //block 10
    send_sp_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);  //block 11
    send_sp_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);  //block 12
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 9);

    // pop blocks 8 - 12, refresh
    ledger_context.pop_blocks(5);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 4);

    // send funds: blocks 8 - 12, refresh
    send_sp_coinbase_amounts_to_users({{2}}, {destination_A}, ledger_context);  //block 8
    send_sp_coinbase_amounts_to_users({{2}}, {destination_A}, ledger_context);  //block 9
    send_sp_coinbase_amounts_to_users({{2}}, {destination_A}, ledger_context);  //block 10
    send_sp_coinbase_amounts_to_users({{2}}, {destination_A}, ledger_context);  //block 11
    send_sp_coinbase_amounts_to_users({{2}}, {destination_A}, ledger_context);  //block 12
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 14);

    // pop blocks 2 - 12
    ledger_context.pop_blocks(11);

    // send funds: blocks 2 - 12, refresh
    send_sp_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);  //block 2
    send_sp_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);  //block 3
    send_sp_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);  //block 4
    send_sp_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);  //block 5
    send_sp_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);  //block 6
    send_sp_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);  //block 7
    send_sp_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);  //block 8
    send_sp_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);  //block 9
    send_sp_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);  //block 10
    send_sp_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);  //block 11
    send_sp_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);  //block 12
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 9);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, simple_ledger_locked)
{
    /// setup

    // 1. config
    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 0,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 0
        };

    // 2. user keys
    jamtis_mock_keys user_keys_A;
    make_jamtis_mock_keys(user_keys_A);

    // 3. user addresses
    JamtisDestinationV1 destination_A;
    make_random_address_for_user(user_keys_A, destination_A);


    /// test

    // test locked enotes
    const std::uint64_t default_spendable_age{2};
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStore enote_store_A{0, 0, default_spendable_age};
    SpEnoteStorePaymentValidator enote_store_PV_A{0, default_spendable_age};
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store_PV(user_keys_A, refresh_config, ledger_context, enote_store_PV_A);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 0);
    ASSERT_TRUE(get_received_sum(enote_store_PV_A, {SpEnoteOriginStatus::ONCHAIN}) == 0);
    ASSERT_TRUE(get_received_sum(enote_store_PV_A, {SpEnoteOriginStatus::ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 0);

    send_sp_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store_PV(user_keys_A, refresh_config, ledger_context, enote_store_PV_A);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 0);  //amount 1 locked
    ASSERT_TRUE(get_received_sum(enote_store_PV_A, {SpEnoteOriginStatus::ONCHAIN}) == 1);
    ASSERT_TRUE(get_received_sum(enote_store_PV_A, {SpEnoteOriginStatus::ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 0);  //amount 1 locked

    send_sp_coinbase_amounts_to_users({{2}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store_PV(user_keys_A, refresh_config, ledger_context, enote_store_PV_A);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 1);  //amount 2 locked
    ASSERT_TRUE(get_received_sum(enote_store_PV_A, {SpEnoteOriginStatus::ONCHAIN}) == 3);
    ASSERT_TRUE(get_received_sum(enote_store_PV_A, {SpEnoteOriginStatus::ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 1);  //amount 2 locked

    ledger_context.commit_unconfirmed_txs_v1({}, {}, {}, {});
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store_PV(user_keys_A, refresh_config, ledger_context, enote_store_PV_A);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 3);  //none locked
    ASSERT_TRUE(get_received_sum(enote_store_PV_A, {SpEnoteOriginStatus::ONCHAIN}) == 3);
    ASSERT_TRUE(get_received_sum(enote_store_PV_A, {SpEnoteOriginStatus::ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 3);  //none
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, basic_ledger_tx_passing_1)
{
    /// setup

    // 1. config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{0};  // 0 fee here
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 0
        };

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator here (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .bin_radius = 1,
            .num_bin_members = 2
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


    /// test

    // 1. one unconfirmed tx (no change), then commit it (include payment validator checks)
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStore enote_store_A{0, 0, 0};
    SpEnoteStorePaymentValidator enote_store_PV_A{0, 0};
    SpEnoteStore enote_store_B{0, 0, 0};
    const InputSelectorMockV1 input_selector_A{enote_store_A};
    const InputSelectorMockV1 input_selector_B{enote_store_B};
    send_sp_coinbase_amounts_to_users({{1, 1, 1, 1}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    transfer_funds_single_mock_v1_unconfirmed_sp_only(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{2, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store_PV(user_keys_A, refresh_config, ledger_context, enote_store_PV_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 4);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 2);
    ASSERT_TRUE(get_received_sum(enote_store_PV_A, {SpEnoteOriginStatus::OFFCHAIN,
        SpEnoteOriginStatus::UNCONFIRMED}) == 0);  //can't find change
    ASSERT_TRUE(get_received_sum(enote_store_PV_A, {SpEnoteOriginStatus::ONCHAIN}) == 4);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 2);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 2);

    ledger_context.commit_unconfirmed_txs_v1(rct::pkGen(), rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteVariant>{});
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store_PV(user_keys_A, refresh_config, ledger_context, enote_store_PV_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 2);
    ASSERT_TRUE(get_received_sum(enote_store_PV_A, {SpEnoteOriginStatus::OFFCHAIN,
        SpEnoteOriginStatus::UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_received_sum(enote_store_PV_A, {SpEnoteOriginStatus::ONCHAIN}) == 4); //coinbase + can't find change
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 2);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, basic_ledger_tx_passing_2)
{
    /// setup

    // 1. config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{0};  // 0 fee here
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 0
        };

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator here (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .bin_radius = 1,
            .num_bin_members = 2
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

    /// test

    // 2. one unconfirmed tx (>0 change), then commit it
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStore enote_store_A{0, 0, 0};
    SpEnoteStore enote_store_B{0, 0, 0};
    const InputSelectorMockV1 input_selector_A{enote_store_A};
    const InputSelectorMockV1 input_selector_B{enote_store_B};
    send_sp_coinbase_amounts_to_users({{0, 0, 0, 8}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    transfer_funds_single_mock_v1_unconfirmed_sp_only(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{3, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 8);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 5);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 5);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 3);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 3);

    ledger_context.commit_unconfirmed_txs_v1(rct::pkGen(), rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteVariant>{});
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 5);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 5);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 3);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, basic_ledger_tx_passing_3)
{
    /// setup

    // 1. config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{0};  // 0 fee here
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 0
        };

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator here (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .bin_radius = 1,
            .num_bin_members = 2
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


    /// test

    // 3. one unconfirmed tx (>0 change), then commit it + coinbase to B
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStore enote_store_A{0, 0, 0};
    SpEnoteStore enote_store_B{0, 0, 0};
    const InputSelectorMockV1 input_selector_A{enote_store_A};
    const InputSelectorMockV1 input_selector_B{enote_store_B};
    send_sp_coinbase_amounts_to_users({{0, 0, 0, 8}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    transfer_funds_single_mock_v1_unconfirmed_sp_only(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{3, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 8);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 5);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 5);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 3);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 3);

    send_sp_coinbase_amounts_to_users({{8}}, {destination_B}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 5);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 5);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 11);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 11);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, basic_ledger_tx_passing_4)
{
    /// setup

    // 1. config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{0};  // 0 fee here
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 0
        };

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator here (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .bin_radius = 1,
            .num_bin_members = 2
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


    /// test

    // 4. pass funds around with unconfirmed cache clear
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStore enote_store_A{0, 0, 0};
    SpEnoteStore enote_store_B{0, 0, 0};
    const InputSelectorMockV1 input_selector_A{enote_store_A};
    const InputSelectorMockV1 input_selector_B{enote_store_B};
    send_sp_coinbase_amounts_to_users({{10, 10, 10, 10}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    transfer_funds_single_mock_v1_unconfirmed_sp_only(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{20, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 40);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 20);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 20);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 20);

    ledger_context.clear_unconfirmed_cache();
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 40);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 40);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);

    transfer_funds_single_mock_v1_unconfirmed_sp_only(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{30, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 40);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 10);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 30);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 30);

    ledger_context.commit_unconfirmed_txs_v1(rct::pkGen(), rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteVariant>{});
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 10);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 10);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 30);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 30);

    transfer_funds_single_mock_v1_unconfirmed_sp_only(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{3, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 10);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 7);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 7);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 30);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 3);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 33);

    ledger_context.commit_unconfirmed_txs_v1(rct::pkGen(), rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteVariant>{});
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 7);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 7);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 33);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 33);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, basic_ledger_tx_passing_5)
{
    /// setup

    // 1. config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{0};  // 0 fee here
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 0
        };

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator here (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .bin_radius = 1,
            .num_bin_members = 2
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


    /// test

    // 5. pass funds around with non-zero refresh index and reorging
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStore enote_store_A{0, 0, 0};
    SpEnoteStore enote_store_B{2, 0, 0};
    const InputSelectorMockV1 input_selector_A{enote_store_A};
    const InputSelectorMockV1 input_selector_B{enote_store_B};
    send_sp_coinbase_amounts_to_users({{10, 10, 10, 10}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    transfer_funds_single_mock_v1_unconfirmed_sp_only(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{11, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 40);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 9);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 29);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 11);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 11);

    ledger_context.commit_unconfirmed_txs_v1(rct::pkGen(), rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteVariant>{});
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 29);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 29);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);

    transfer_funds_single_mock_v1_unconfirmed_sp_only(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{12, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 29);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) >= 7);  //can be (10 + 9) - 12 OR (10 + 10) - 12
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 17);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 12);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 12);

    ledger_context.commit_unconfirmed_txs_v1(rct::pkGen(), rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteVariant>{});
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 17);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 17);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 12);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 12);

    ledger_context.pop_blocks(1);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 29);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 29);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);

    transfer_funds_single_mock_v1_unconfirmed_sp_only(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{13, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 29);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) >= 6);  //can be (10 + 9) - 13 OR (10 + 10) - 13
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 16);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 13);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 13);

    ledger_context.commit_unconfirmed_txs_v1(rct::pkGen(), rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteVariant>{});
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 16);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 16);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 13);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 13);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, basic_ledger_tx_passing_6)
{
    /// setup

    // 1. config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{0};  // 0 fee here
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 5,
            .max_partialscan_attempts = 0
        };

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator here (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .bin_radius = 1,
            .num_bin_members = 2
        };

    // 2. user keys
    jamtis_mock_keys user_keys_A;
    make_jamtis_mock_keys(user_keys_A);

    // 3. user addresses
    JamtisDestinationV1 destination_A;
    make_random_address_for_user(user_keys_A, destination_A);


    /// test

    // 6. pass funds back and forth to the same account, with a max chunk size > 1 so multiple self-sends can be sent
    //    and spent within a single chunk
    // NOTE: the run-time of this test varies around 10-20% since the amount of funds transfered in each loop is
    //       random so some runs will have more total tx inputs and outputs than others
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStore enote_store_A{0, 0, 0};
    const InputSelectorMockV1 input_selector_A{enote_store_A};
    send_sp_coinbase_amounts_to_users({{16, 0, 0, 0}}, {destination_A}, ledger_context);

    for (std::size_t iteration{0}; iteration < 12; ++iteration)
    {
        // refresh enote store for input selection
        refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

        ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN}, {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 16);

        // churn some of user A's funds
        rct::xmr_amount amnt1 = crypto::rand_range<rct::xmr_amount>(1, 16);

        transfer_funds_single_mock_v1_unconfirmed_sp_only(user_keys_A,
            input_selector_A,
            fee_calculator,
            fee_per_tx_weight,
            max_inputs,
            {
                {amnt1, destination_A, TxExtra{}}
            },
            ref_set_decomp_n,
            ref_set_decomp_m,
            bin_config,
            ledger_context);
        ledger_context.commit_unconfirmed_txs_v1(rct::pkGen(),
            rct::key{},
            SpTxSupplementV1{},
            std::vector<SpEnoteVariant>{});

        // full refresh of user A
        SpEnoteStore enote_store_A_full_refresh{0, 0, 0};
        refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A_full_refresh);

        ASSERT_TRUE(get_balance(enote_store_A_full_refresh, {SpEnoteOriginStatus::ONCHAIN},
            {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 16);
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
class InvocableTest1 final : public Invocable
{
public:
    InvocableTest1(MockLedgerContext &ledger_context) : m_ledger_contex{ledger_context} {}
    InvocableTest1& operator=(InvocableTest1&&) = delete;

    /// invoke: on the third call, pop 2 blocks from the ledger context
    void invoke() override
    {
        ++m_num_calls;

        if (m_num_calls == 3)
            m_ledger_contex.pop_blocks(2);
    }
private:
    MockLedgerContext &m_ledger_contex;
    std::size_t m_num_calls{0};
};
//-------------------------------------------------------------------------------------------------------------------
class InvocableTest2 final : public Invocable
{
public:
    InvocableTest2(const JamtisDestinationV1 &user_address,
        std::vector<rct::xmr_amount> amounts_per_new_coinbase,
        MockLedgerContext &ledger_context) :
            m_user_address{user_address},
            m_amounts_per_new_coinbase{std::move(amounts_per_new_coinbase)},
            m_ledger_contex{ledger_context}
    {}
    InvocableTest2& operator=(InvocableTest2&&) = delete;

    /// invoke: on the first call, pop 2 blocks then push back N new blocks with one coinbase amount each
    void invoke() override
    {
        ++m_num_calls;

        if (m_num_calls == 1)
        {
            m_ledger_contex.pop_blocks(2);
            for (const rct::xmr_amount new_coinbase_amount : m_amounts_per_new_coinbase)
                send_sp_coinbase_amounts_to_users({{new_coinbase_amount}}, {m_user_address}, m_ledger_contex);
        }
    }
private:
    const JamtisDestinationV1 &m_user_address;
    const std::vector<rct::xmr_amount> m_amounts_per_new_coinbase;
    MockLedgerContext &m_ledger_contex;
    std::size_t m_num_calls{0};
};
//-------------------------------------------------------------------------------------------------------------------
class InvocableTest3 final : public Invocable
{
public:
    InvocableTest3(const JamtisDestinationV1 &user_address,
        std::vector<rct::xmr_amount> amounts_per_new_coinbase,
        MockLedgerContext &ledger_context) :
            m_user_address{user_address},
            m_amounts_per_new_coinbase{std::move(amounts_per_new_coinbase)},
            m_ledger_contex{ledger_context}
    {}
    InvocableTest3& operator=(InvocableTest3&&) = delete;

    /// invoke: on the third call, pop 2 blocks then push back N new blocks with one coinbase amount each
    void invoke() override
    {
        ++m_num_calls;

        if (m_num_calls == 3)
        {
            m_ledger_contex.pop_blocks(2);
            for (const rct::xmr_amount new_coinbase_amount : m_amounts_per_new_coinbase)
                send_sp_coinbase_amounts_to_users({{new_coinbase_amount}}, {m_user_address}, m_ledger_contex);
        }
    }

    /// return number of invocations
    std::size_t num_invocations() const { return m_num_calls; }
private:
    const JamtisDestinationV1 &m_user_address;
    const std::vector<rct::xmr_amount> m_amounts_per_new_coinbase;
    MockLedgerContext &m_ledger_contex;
    std::size_t m_num_calls{0};
};
//-------------------------------------------------------------------------------------------------------------------
class InvocableTest4 final : public Invocable
{
public:
    InvocableTest4(const JamtisDestinationV1 &user_address,
        const rct::xmr_amount amount_new_coinbase,
        MockLedgerContext &ledger_context) :
            m_user_address{user_address},
            m_amount_new_coinbase{amount_new_coinbase},
            m_ledger_contex{ledger_context}
    {}
    InvocableTest4& operator=(InvocableTest4&&) = delete;

    /// invoke: on every third call, pop 1 block then push back 1 new block with one coinbase amount
    void invoke() override
    {
        ++m_num_calls;

        if (m_num_calls % 3 == 0)
        {
            m_ledger_contex.pop_blocks(1);
            send_sp_coinbase_amounts_to_users({{m_amount_new_coinbase}}, {m_user_address}, m_ledger_contex);
        }
    }
private:
    const JamtisDestinationV1 &m_user_address;
    const rct::xmr_amount m_amount_new_coinbase;
    MockLedgerContext &m_ledger_contex;
    std::size_t m_num_calls{0};
};
//-------------------------------------------------------------------------------------------------------------------
class InvocableTest5Submit final : public Invocable
{
public:
    InvocableTest5Submit(SpTxSquashedV1 tx_to_submit,
        MockLedgerContext &ledger_context) :
            m_tx_to_submit{std::move(tx_to_submit)},
            m_ledger_contex{ledger_context}
    {}
    InvocableTest5Submit& operator=(InvocableTest5Submit&&) = delete;

    /// invoke: on the first call, submit prepared tx to the unconfirmed cache of the ledger
    void invoke() override
    {
        ++m_num_calls;

        if (m_num_calls == 1)
        {
            // validate and submit to the mock ledger
            const TxValidationContextMock tx_validation_context{m_ledger_contex};
            ASSERT_TRUE(validate_tx(m_tx_to_submit, tx_validation_context));
            ASSERT_TRUE(m_ledger_contex.try_add_unconfirmed_tx_v1(m_tx_to_submit));
        }
    }
private:
    const SpTxSquashedV1 m_tx_to_submit;
    MockLedgerContext &m_ledger_contex;
    std::size_t m_num_calls{0};
};
//-------------------------------------------------------------------------------------------------------------------
class InvocableTest5Commit final : public Invocable
{
public:
    InvocableTest5Commit(MockLedgerContext &ledger_context) : m_ledger_contex{ledger_context} {}
    InvocableTest5Commit& operator=(InvocableTest5Commit&&) = delete;

    /// invoke: commit any unconfirmed txs in the ledger's unconfirmed chache
    void invoke() override
    {
        m_ledger_contex.commit_unconfirmed_txs_v1(rct::pkGen(),
            rct::key{},
            SpTxSupplementV1{},
            std::vector<SpEnoteVariant>{});
    }
private:
    MockLedgerContext &m_ledger_contex;
};
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, reorgs_while_scanning_1)
{
    /// setup
    DummyInvocable dummy_invocable;

    // 1. config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{0};  // 0 fee here
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator here (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .bin_radius = 1,
            .num_bin_members = 2
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


    /// test

    // 1. full internal reorg
    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 0
        };
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStore enote_store_A{0, 0, 0};
    SpEnoteStore enote_store_B{0, 0, 0};
    const InputSelectorMockV1 input_selector_A{enote_store_A};
    const InputSelectorMockV1 input_selector_B{enote_store_B};
    send_sp_coinbase_amounts_to_users({{1, 1, 1, 1}}, {destination_A}, ledger_context);

    // a. refresh once so alignment will begin on block 0 in the test
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    // b. send tx A -> B
    transfer_funds_single_mock_v1_unconfirmed_sp_only(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{2, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);
    ledger_context.commit_unconfirmed_txs_v1(rct::pkGen(), rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteVariant>{});

    // c. refresh user A with injected invocable
    // current chain state: {block0[{1, 1, 1, 1} -> A], block1[A -> {2} -> B]}
    // current enote context A: [enotes: block0{1, 1, 1, 1}], [blocks: 0{...}]
    // expected refresh sequence:
    // 1. desired start index = block 1
    // 2. actual start index = block 0 = ([desired start] 1 - [reorg depth] 1)
    // 3. scan process
    //   a. onchain loop
    //     i.   get onchain chunk: block 0  (success: chunk range [0, 1))
    //     ii.  get onchain chunk: block 1  (success: chunk range [1, 2))
    //     iii. get onchain chunk: block 2  (injected: pop 2)  (fail: chunk range [0,0) -> NEED_FULLSCAN)
    //   b. skip unconfirmed chunk: (NEED_FULLSCAN)
    // 4. NEED_FULLSCAN: rescan from block 0
    //   a. onchain loop
    //     i.   get onchain chunk: block 0  (success: chunk range [0, 0) -> DONE)
    //   b. unconfirmed chunk: empty
    //   c. follow-up onchain loop: success on block 0 (range [0, 0) -> DONE)
    // 5. DONE: refresh enote store of A
    const EnoteFindingContextUnconfirmedMockSp enote_finding_context_unconfirmed_A{ledger_context, user_keys_A.xk_fr};
    const EnoteFindingContextLedgerMockSp enote_finding_context_ledger_A{ledger_context, user_keys_A.xk_fr};
    scanning::ScanContextNonLedgerSimple scan_context_unconfirmed_A{enote_finding_context_unconfirmed_A};
    scanning::ScanContextLedgerSimple scan_context_ledger_A{enote_finding_context_ledger_A};
    InvocableTest1 invocable_get_onchain{ledger_context};
    ScanContextLedgerTEST test_scan_context_A(scan_context_ledger_A,
        dummy_invocable,
        invocable_get_onchain,
        dummy_invocable);
    ChunkConsumerMockSp chunk_consumer{user_keys_A.K_1_base, user_keys_A.k_vb, enote_store_A};
    ASSERT_NO_THROW(refresh_enote_store(refresh_config,
        scan_context_unconfirmed_A,
        test_scan_context_A,
        chunk_consumer));

    // d. after refreshing, both users should have no balance
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, reorgs_while_scanning_2)
{
    /// setup
    DummyInvocable dummy_invocable;

    // 1. config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{0};  // 0 fee here
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator here (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .bin_radius = 1,
            .num_bin_members = 2
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


    /// test

    // 2. full internal reorg with replacement
    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 0
        };
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStore enote_store_A{0, 0, 0};
    SpEnoteStore enote_store_B{0, 0, 0};
    const InputSelectorMockV1 input_selector_A{enote_store_A};
    const InputSelectorMockV1 input_selector_B{enote_store_B};
    send_sp_coinbase_amounts_to_users({{1, 1, 1, 1}}, {destination_A}, ledger_context);

    // a. refresh A so coinbase funds are available
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    // b. send two tx A -> B in two blocks
    transfer_funds_single_mock_v1_unconfirmed_sp_only(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{1, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);
    ledger_context.commit_unconfirmed_txs_v1(rct::pkGen(), rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteVariant>{});
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    transfer_funds_single_mock_v1_unconfirmed_sp_only(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{2, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);
    ledger_context.commit_unconfirmed_txs_v1(rct::pkGen(), rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteVariant>{});

    // c. refresh A so top block is block 2
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    // d. refresh user A with injected invocable
    // current chain state: {block0[{1, 1, 1, 1} -> A], block1[A -> {1} -> B], block2[A -> {2} -> B]}
    // current enote context A: [enotes: block0{1, 1, 1, 1}, block1{0}, block2{0}], [blocks: 0{...}, 1{...}, 2{...}]
    // expected refresh sequence:
    // 1. desired start index = block 3
    // 2. actual start index = block 2 = ([desired start] 3 - [reorg depth] 1)
    // 3. scan process
    //   a. onchain loop
    //     i.   get onchain chunk: block 2  (injected: pop 2, +2 blocks)  (fail: chunk range [2, 3) -> NEED_FULLSCAN)
    //   b. skip unconfirmed chunk: (NEED_FULLSCAN)
    // 4. NEED_FULLSCAN: rescan from block 1
    //   a. onchain loop
    //     i.   get onchain chunk: block 1  (success: chunk range [1, 2))
    //     ii.  get onchain chunk: block 2  (success: chunk range [2, 3))
    //     iii. get onchain chunk: block 3  (success: chunk range [3, 3) -> DONE)
    //   b. unconfirmed chunk: empty
    //   c. follow-up onchain loop: success on block 3 (range [3, 3) -> DONE)
    // 5. DONE: refresh enote store of A
    const EnoteFindingContextUnconfirmedMockSp enote_finding_context_unconfirmed_A{ledger_context, user_keys_A.xk_fr};
    const EnoteFindingContextLedgerMockSp enote_finding_context_ledger_A{ledger_context, user_keys_A.xk_fr};
    scanning::ScanContextNonLedgerSimple scan_context_unconfirmed_A{enote_finding_context_unconfirmed_A};
    scanning::ScanContextLedgerSimple scan_context_ledger_A{enote_finding_context_ledger_A};
    InvocableTest2 invocable_get_onchain{destination_A, {3, 5}, ledger_context};
    ScanContextLedgerTEST test_scan_context_A(scan_context_ledger_A,
        dummy_invocable,
        invocable_get_onchain,
        dummy_invocable);
    ChunkConsumerMockSp chunk_consumer{user_keys_A.K_1_base, user_keys_A.k_vb, enote_store_A};
    ASSERT_NO_THROW(refresh_enote_store(refresh_config,
        scan_context_unconfirmed_A,
        test_scan_context_A,
        chunk_consumer));

    // d. check balances after refreshing
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 12);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 12);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, reorgs_while_scanning_3)
{
    /// setup
    DummyInvocable dummy_invocable;

    // 1. config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{0};  // 0 fee here
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator here (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .bin_radius = 1,
            .num_bin_members = 2
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


    /// test

    // 3. partial internal reorg with replacement
    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 1
        };
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStore enote_store_A{0, 0, 0};
    SpEnoteStore enote_store_B{0, 0, 0};
    const InputSelectorMockV1 input_selector_A{enote_store_A};
    const InputSelectorMockV1 input_selector_B{enote_store_B};
    send_sp_coinbase_amounts_to_users({{1, 1, 1, 1}}, {destination_A}, ledger_context);

    // a. refresh once so user A can make a tx
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    // b. send two txs A -> B in two blocks
    transfer_funds_single_mock_v1_unconfirmed_sp_only(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{1, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);
    ledger_context.commit_unconfirmed_txs_v1(rct::pkGen(), rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteVariant>{});
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    transfer_funds_single_mock_v1_unconfirmed_sp_only(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{2, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);
    ledger_context.commit_unconfirmed_txs_v1(rct::pkGen(), rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteVariant>{});

    // c. refresh user B with injected invocable
    // current chain state: {block0[{1, 1, 1, 1} -> A], block1[A -> {1} -> B], block2[A -> {2} -> B]}
    // current enote context B: [enotes: none, [blocks: none]
    // expected refresh sequence:
    // 1. desired start index = block 0
    // 2. actual start index = block 0 = round_to_0([desired start] 0 - [reorg depth] 1)
    // 3. scan process
    //   a. onchain loop
    //     i.   get onchain chunk: block 0  (success: chunk range [0, 1))
    //     ii.  get onchain chunk: block 1  (success: chunk range [1, 2))
    //     iii. get onchain chunk: block 2  (injected: pop 2, +2 blocks)  (fail: chunk range [2, 3) -> NEED_PARTIALSCAN)
    //   b. skip unconfirmed chunk: (NEED_PARTIALSCAN)
    // 4. NEED_PARTIALSCAN: rescan from block 1 (desired block: 2, reorg depth: 1)
    //   a. onchain loop
    //     i.   get onchain chunk: block 1  (success: chunk range [1, 2))
    //     ii.  get onchain chunk: block 2  (success: chunk range [2, 3))
    //     iii. get onchain chunk: block 3  (success: chunk range [3, 3) -> DONE)
    //   b. unconfirmed chunk: empty
    //   c. follow-up onchain loop: success on block 3 (range [3, 3) -> DONE)
    // 5. DONE: refresh enote store of B
    const EnoteFindingContextUnconfirmedMockSp enote_finding_context_unconfirmed_B{ledger_context, user_keys_B.xk_fr};
    const EnoteFindingContextLedgerMockSp enote_finding_context_ledger_B{ledger_context, user_keys_B.xk_fr};
    scanning::ScanContextNonLedgerSimple scan_context_unconfirmed_B{enote_finding_context_unconfirmed_B};
    scanning::ScanContextLedgerSimple scan_context_ledger_B{enote_finding_context_ledger_B};
    InvocableTest3 invocable_get_onchain{destination_B, {3, 5}, ledger_context};
    ScanContextLedgerTEST test_scan_context_B(scan_context_ledger_B,
        dummy_invocable,
        invocable_get_onchain,
        dummy_invocable);
    ChunkConsumerMockSp chunk_consumer{user_keys_B.K_1_base, user_keys_B.k_vb, enote_store_B};
    ASSERT_NO_THROW(refresh_enote_store(refresh_config,
        scan_context_unconfirmed_B,
        test_scan_context_B,
        chunk_consumer));

    // d. make sure NEED_FULLSCAN was not triggered on the reorg (would be == 8 here because fullscan will rescan block 0)
    ASSERT_TRUE(invocable_get_onchain.num_invocations() == 7);

    // e. check users' balances
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 4);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 4);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 8);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 8);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, reorgs_while_scanning_4)
{
    /// setup
    DummyInvocable dummy_invocable;

    // 1. config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{0};  // 0 fee here
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator here (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .bin_radius = 1,
            .num_bin_members = 2
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


    /// test

    // 4. partial internal reorgs to failure
    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 2,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 4
        };
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStore enote_store_A{0, 0, 0};
    SpEnoteStore enote_store_B{0, 0, 0};
    const InputSelectorMockV1 input_selector_A{enote_store_A};
    const InputSelectorMockV1 input_selector_B{enote_store_B};
    send_sp_coinbase_amounts_to_users({{1, 1, 1, 1}}, {destination_A}, ledger_context);

    // a. refresh once so user A can make a tx
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    // b. send tx A -> B
    transfer_funds_single_mock_v1_unconfirmed_sp_only(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{1, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);
    ledger_context.commit_unconfirmed_txs_v1(rct::pkGen(), rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteVariant>{});

    // c. refresh user B with injected invocable
    // current chain state: {block0[{1, 1, 1, 1} -> A], block1[A -> {1} -> B]}
    // current enote context B: [enotes: none], [blocks: none]
    // expected refresh sequence:
    // 1. desired start index = block 0
    // 2. actual start index = block 0 = ([desired start] 0 - [reorg depth] 0)
    // 3. scan process
    //   a. onchain loop
    //     i.   get onchain chunk: block 0  (success: chunk range [0, 1))
    //     ii.  get onchain chunk: block 1  (success: chunk range [1, 2))
    //     iii. get onchain chunk: block 2  (inject: pop 1, +1 blocks) (fail: chunk range [2, 2) -> NEED_PARTIALSCAN)
    //   b. skip unconfirmed chunk: (NEED_PARTIALSCAN)
    // 4. NEED_PARTIALSCAN: rescan from block 0
    //   a. onchain loop
    //     i.   get onchain chunk: block 0  (success: chunk range [0, 1))
    //     ii.  get onchain chunk: block 1  (success: chunk range [1, 2))
    //     iii. get onchain chunk: block 2  (inject: pop 1, +1 blocks) (fail: chunk range [2, 2) -> NEED_PARTIALSCAN)
    //   b. skip unconfirmed chunk: (NEED_PARTIALSCAN)
    // 5. ... etc. until partialscan attempts runs out (then throw)
    const EnoteFindingContextUnconfirmedMockSp enote_finding_context_unconfirmed_B{ledger_context, user_keys_B.xk_fr};
    const EnoteFindingContextLedgerMockSp enote_finding_context_ledger_B{ledger_context, user_keys_B.xk_fr};
    scanning::ScanContextNonLedgerSimple scan_context_unconfirmed_B{enote_finding_context_unconfirmed_B};
    scanning::ScanContextLedgerSimple scan_context_ledger_B{enote_finding_context_ledger_B};
    InvocableTest4 invocable_get_onchain{destination_B, 1, ledger_context};
    ScanContextLedgerTEST test_scan_context_B(scan_context_ledger_B,
        dummy_invocable,
        invocable_get_onchain,
        dummy_invocable);
    ChunkConsumerMockSp chunk_consumer{user_keys_B.K_1_base, user_keys_B.k_vb, enote_store_B};
    ASSERT_FALSE(refresh_enote_store(refresh_config,
        scan_context_unconfirmed_B,
        test_scan_context_B,
        chunk_consumer));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, reorgs_while_scanning_5)
{
    /// setup
    DummyInvocable dummy_invocable;

    // 1. config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{0};  // 0 fee here
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator here (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .bin_radius = 1,
            .num_bin_members = 2
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


    /// test

    // 5. sneaky tx found in follow-up loop
    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 4
        };
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStore enote_store_A{0, 0, 0};
    SpEnoteStore enote_store_B{0, 0, 0};
    const InputSelectorMockV1 input_selector_A{enote_store_A};
    const InputSelectorMockV1 input_selector_B{enote_store_B};
    send_sp_coinbase_amounts_to_users({{1, 1, 1, 1}}, {destination_A}, ledger_context);

    // a. refresh once so user A can make a tx
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    // b. send tx A -> B
    transfer_funds_single_mock_v1_unconfirmed_sp_only(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{1, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);
    ledger_context.commit_unconfirmed_txs_v1(rct::pkGen(), rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteVariant>{});
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    // c. prepare sneaky tx to insert while scanning
    SpTxSquashedV1 sneaky_tx;
    construct_tx_for_mock_ledger_v1({}, //legacy keys
        user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{2, destination_B, TxExtra{}}},
        0, //legacy ring size
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context,
        sneaky_tx);

    // c. refresh user B with injected invocable
    // current chain state: {block0[{1, 1, 1, 1} -> A], block1[A -> {1} -> B]}
    // current enote context B: [enotes: none], [blocks: none]
    // expected refresh sequence:
    // 1. desired start index = block 0
    // 2. actual start index = block 0 = ([desired start] 0 - [reorg depth] 0)
    // 3. scan process
    //   a. onchain loop
    //     i.   get onchain chunk: block 0  (success: chunk range [0, 1))
    //     ii.  get onchain chunk: block 1  (success: chunk range [1, 2))
    //     iii. get onchain chunk: block 2  (success: chunk range [2, 2) -> DONE)
    //   b. unconfirmed chunk: (inject: submit A -> {2} -> B)  (success: found {2})
    //   c. follow-up onchain loop
    //     i.   get onchain chunk: block 2  (inject: commit unconfirmed)  (success: chunk range [2, 3])
    //     ii.  get onchain chunk: block 3  (success: chunk range [3, 3) -> DONE)
    // 4. DONE: refresh enote store of B
    const EnoteFindingContextUnconfirmedMockSp enote_finding_context_unconfirmed_B{ledger_context, user_keys_B.xk_fr};
    const EnoteFindingContextLedgerMockSp enote_finding_context_ledger_B{ledger_context, user_keys_B.xk_fr};
    scanning::ScanContextNonLedgerSimple scan_context_unconfirmed_B{enote_finding_context_unconfirmed_B};
    scanning::ScanContextLedgerSimple scan_context_ledger_B{enote_finding_context_ledger_B};
    InvocableTest5Commit invocable_get_unconfirmed{ledger_context};
    InvocableTest5Submit invocable_get_onchain{std::move(sneaky_tx), ledger_context};
    ScanContextNonLedgerTEST test_scan_context_unconfirmed_B(scan_context_unconfirmed_B,
        invocable_get_unconfirmed);
    ScanContextLedgerTEST test_scan_context_ledger_B(scan_context_ledger_B,
        dummy_invocable,
        invocable_get_onchain,
        dummy_invocable);
    ChunkConsumerMockSp chunk_consumer{user_keys_B.K_1_base, user_keys_B.k_vb, enote_store_B};
    ASSERT_NO_THROW(refresh_enote_store(refresh_config,
        test_scan_context_unconfirmed_B,
        test_scan_context_ledger_B,
        chunk_consumer));

    // d. check users' balances
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_A, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 1);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_B, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 3);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, legacy_pre_transition_1)
{
    /// setup

    // 1. config
    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 0
        };

    // 2. user keys
    legacy_mock_keys legacy_keys;
    make_legacy_mock_keys(legacy_keys);

    // 3. user normal address
    const rct::key normal_addr_spendkey{legacy_keys.Ks};
    const rct::key normal_addr_viewkey{rct::scalarmultBase(rct::sk2rct(legacy_keys.k_v))};

    // 4. user subaddress
    rct::key subaddr_spendkey;
    rct::key subaddr_viewkey;
    cryptonote::subaddress_index subaddr_index;

    gen_legacy_subaddress(legacy_keys.Ks, legacy_keys.k_v, subaddr_spendkey, subaddr_viewkey, subaddr_index);

    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;
    legacy_subaddress_map[subaddr_spendkey] = subaddr_index;


    /// test

    // 1. v1-v4 legacy enotes (both normal and subaddress destinations)
    MockLedgerContext ledger_context{10000, 10000};
    SpEnoteStore enote_store{0, 10000, 0};

    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);

    LegacyEnoteV1 enote_v1_1;  //to normal destination
    const crypto::secret_key enote_ephemeral_privkey_1{make_secret_key()};
    const rct::key enote_ephemeral_pubkey_1{
            rct::scalarmultBase(rct::sk2rct(enote_ephemeral_privkey_1))
        };

    ASSERT_NO_THROW(make_legacy_enote_v1(normal_addr_spendkey,
        normal_addr_viewkey,
        1,  //amount
        0,  //index in planned mock coinbase tx
        enote_ephemeral_privkey_1,
        enote_v1_1));

    LegacyEnoteV1 enote_v1_2;  //to subaddress destination
    const crypto::secret_key enote_ephemeral_privkey_2{make_secret_key()};
    const rct::key enote_ephemeral_pubkey_2{
            rct::scalarmultKey(subaddr_spendkey, rct::sk2rct(enote_ephemeral_privkey_2))
        };

    ASSERT_NO_THROW(make_legacy_enote_v1(subaddr_spendkey,
        subaddr_viewkey,
        1,  //amount
        1,  //index in planned mock coinbase tx
        enote_ephemeral_privkey_2,
        enote_v1_2));

    LegacyEnoteV2 enote_v2_1;  //to normal destination
    const crypto::secret_key enote_ephemeral_privkey_3{make_secret_key()};
    const rct::key enote_ephemeral_pubkey_3{
            rct::scalarmultBase(rct::sk2rct(enote_ephemeral_privkey_3))
        };

    ASSERT_NO_THROW(make_legacy_enote_v2(normal_addr_spendkey,
        normal_addr_viewkey,
        1,  //amount
        2,  //index in planned mock coinbase tx
        enote_ephemeral_privkey_3,
        enote_v2_1));

    LegacyEnoteV2 enote_v2_2;  //to subaddress destination
    const crypto::secret_key enote_ephemeral_privkey_4{make_secret_key()};
    const rct::key enote_ephemeral_pubkey_4{
            rct::scalarmultKey(subaddr_spendkey, rct::sk2rct(enote_ephemeral_privkey_4))
        };

    ASSERT_NO_THROW(make_legacy_enote_v2(subaddr_spendkey,
        subaddr_viewkey,
        1,  //amount
        3,  //index in planned mock coinbase tx
        enote_ephemeral_privkey_4,
        enote_v2_2));

    LegacyEnoteV3 enote_v3_1;  //to normal destination
    const crypto::secret_key enote_ephemeral_privkey_5{make_secret_key()};
    const rct::key enote_ephemeral_pubkey_5{
            rct::scalarmultBase(rct::sk2rct(enote_ephemeral_privkey_5))
        };

    ASSERT_NO_THROW(make_legacy_enote_v3(normal_addr_spendkey,
        normal_addr_viewkey,
        1,  //amount
        4,  //index in planned mock coinbase tx
        enote_ephemeral_privkey_5,
        enote_v3_1));

    LegacyEnoteV3 enote_v3_2;  //to subaddress destination
    const crypto::secret_key enote_ephemeral_privkey_6{make_secret_key()};
    const rct::key enote_ephemeral_pubkey_6{
            rct::scalarmultKey(subaddr_spendkey, rct::sk2rct(enote_ephemeral_privkey_6))
        };

    ASSERT_NO_THROW(make_legacy_enote_v3(subaddr_spendkey,
        subaddr_viewkey,
        1,  //amount
        5,  //index in planned mock coinbase tx
        enote_ephemeral_privkey_6,
        enote_v3_2));

    LegacyEnoteV5 enote_v4_1;  //to normal destination
    const crypto::secret_key enote_ephemeral_privkey_7{make_secret_key()};
    const rct::key enote_ephemeral_pubkey_7{
            rct::scalarmultBase(rct::sk2rct(enote_ephemeral_privkey_7))
        };

    ASSERT_NO_THROW(make_legacy_enote_v5(normal_addr_spendkey,
        normal_addr_viewkey,
        1,  //amount
        6,  //index in planned mock coinbase tx
        enote_ephemeral_privkey_7,
        enote_v4_1));

    LegacyEnoteV5 enote_v4_2;  //to subaddress destination
    const crypto::secret_key enote_ephemeral_privkey_8{make_secret_key()};
    const rct::key enote_ephemeral_pubkey_8{
            rct::scalarmultKey(subaddr_spendkey, rct::sk2rct(enote_ephemeral_privkey_8))
        };

    ASSERT_NO_THROW(make_legacy_enote_v5(subaddr_spendkey,
        subaddr_viewkey,
        1,  //amount
        7,  //index in planned mock coinbase tx
        enote_ephemeral_privkey_8,
        enote_v4_2));

    TxExtra tx_extra_1;
    ASSERT_TRUE(try_append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                enote_ephemeral_pubkey_1,
                enote_ephemeral_pubkey_2,
                enote_ephemeral_pubkey_3,
                enote_ephemeral_pubkey_4,
                enote_ephemeral_pubkey_5,
                enote_ephemeral_pubkey_6,
                enote_ephemeral_pubkey_7,
                enote_ephemeral_pubkey_8
            },
            tx_extra_1
        ));
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_1,
            {},
            {
                enote_v1_1,
                enote_v1_2,
                enote_v2_1,
                enote_v2_2,
                enote_v3_1,
                enote_v3_2,
                enote_v4_1,
                enote_v4_2
            }
        ));

    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 8);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 8);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, legacy_pre_transition_2)
{
    /// setup

    // 1. config
    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 0
        };

    // 2. user keys
    legacy_mock_keys legacy_keys;
    make_legacy_mock_keys(legacy_keys);

    // 3. user normal address
    //const rct::key normal_addr_spendkey{legacy_keys.Ks};
    //const rct::key normal_addr_viewkey{rct::scalarmultBase(rct::sk2rct(legacy_keys.k_v))};

    // 4. user subaddress
    rct::key subaddr_spendkey;
    rct::key subaddr_viewkey;
    cryptonote::subaddress_index subaddr_index;

    gen_legacy_subaddress(legacy_keys.Ks, legacy_keys.k_v, subaddr_spendkey, subaddr_viewkey, subaddr_index);

    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;
    legacy_subaddress_map[subaddr_spendkey] = subaddr_index;

    // 5. events cache
    std::list<EnoteStoreEvent> events;


    /// test

    // 2. manual scanning with key image imports: test 1
    MockLedgerContext ledger_context{10000, 10000};
    SpEnoteStore enote_store{0, 0, 0};

    //make enote for test
    LegacyEnoteV5 enote_1;
    rct::key enote_ephemeral_pubkey_1;
    crypto::key_image key_image;

    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        1,  //amount
        0,  //index in planned mock coinbase tx
        make_secret_key(),
        enote_1,
        enote_ephemeral_pubkey_1,
        key_image);

    TxExtra tx_extra_1;
    ASSERT_TRUE(try_append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                enote_ephemeral_pubkey_1
            },
            tx_extra_1
        ));

    //add legacy enote in block 0
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_1,
            {},
            {
                enote_1
            }
        ));

    //intermediate refresh
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 0);
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == -1);
    ASSERT_TRUE(enote_store.legacy_intermediate_records().size() == 1);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 1);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 0);

    //spend enote in block 1
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            TxExtra{},
            {
                key_image
            },
            {}
        ));

    //intermediate refresh
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == -1);
    ASSERT_TRUE(enote_store.legacy_intermediate_records().size() == 1);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 1);

    //export intermediate onetime addresses that need key images
    //(not done for this mock-up)

    //save current index that was legacy partial-scanned
    const std::uint64_t intermediate_index_pre_import_cycle{
            enote_store.top_legacy_partialscanned_block_index()
        };

    //import key images for onetime addresses of intermediate records in the enote store
    ASSERT_TRUE(enote_store.try_import_legacy_key_image(key_image, enote_1.onetime_address, events));

    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == -1);
    ASSERT_TRUE(enote_store.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 1);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 1);  //intermediate record promoted to full

    //add empty block 2 (inject to test ledger index trackers)
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            TxExtra{},
            {},
            {}
        ));

    //collect legacy key images since last fullscan (block -1)
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::KEY_IMAGES_ONLY,  //only collect key images with spent contexts
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 1);
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == -1);
    ASSERT_TRUE(enote_store.top_sp_scanned_block_index() == -1);
    ASSERT_TRUE(enote_store.top_block_index() == 1);  //key image recovery scan should not update block index

    //update legacy fullscan index in enote store to partialscan index the store had when exporting onetime addresses
    ASSERT_NO_THROW(enote_store.update_legacy_fullscan_index_for_import_cycle(intermediate_index_pre_import_cycle));

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 1);
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == 1);
    ASSERT_TRUE(enote_store.top_block_index() == 1);

    //intermediate scan
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 2);
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == 1);
    ASSERT_TRUE(enote_store.top_sp_scanned_block_index() == -1);
    ASSERT_TRUE(enote_store.top_block_index() == 2);
    ASSERT_TRUE(enote_store.legacy_intermediate_records().size() == 0);

    //remove block 2
    ledger_context.pop_blocks(1);

    //collect legacy key images since last fullscan (block 1)
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        //key image recovery mode to demonstrate it doesn't affect seraphis block index tracker or block ids
        LegacyScanMode::KEY_IMAGES_ONLY,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 2);  //key images only mode does't detect reorgs
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == 1);
    ASSERT_TRUE(enote_store.top_sp_scanned_block_index() == -1);
    ASSERT_TRUE(enote_store.top_block_index() == 2);

    //mock seraphis refresh to fix enote store block index trackers after reorg
    refresh_user_enote_store(jamtis_mock_keys{},
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 2);  //sp refresh doesn't affect legacy indices
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == 1);
    ASSERT_TRUE(enote_store.top_sp_scanned_block_index() == 1);
    ASSERT_TRUE(enote_store.top_block_index() == 2);  //sp refresh doesn't affect legacy indices
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, legacy_pre_transition_3)
{
    /// setup

    // 1. config
    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 0
        };

    // 2. user keys
    legacy_mock_keys legacy_keys;
    make_legacy_mock_keys(legacy_keys);

    // 3. user normal address
    //const rct::key normal_addr_spendkey{legacy_keys.Ks};
    //const rct::key normal_addr_viewkey{rct::scalarmultBase(rct::sk2rct(legacy_keys.k_v))};

    // 4. user subaddress
    rct::key subaddr_spendkey;
    rct::key subaddr_viewkey;
    cryptonote::subaddress_index subaddr_index;

    gen_legacy_subaddress(legacy_keys.Ks, legacy_keys.k_v, subaddr_spendkey, subaddr_viewkey, subaddr_index);

    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;
    legacy_subaddress_map[subaddr_spendkey] = subaddr_index;

    // 5. random 'other' address
    const rct::key subaddr_spendkey_rand{rct::pkGen()};
    const rct::key subaddr_viewkey_rand{rct::pkGen()};

    // 6. events cache
    std::list<EnoteStoreEvent> events;


    /// test

    // 3. manual scanning with key image imports: test 2
    MockLedgerContext ledger_context{10000, 10000};
    SpEnoteStore enote_store{0, 10000, 0};

    //make enotes: 1 -> user, 1 -> rand
    LegacyEnoteV5 enote_1;
    rct::key enote_ephemeral_pubkey_1;
    crypto::key_image key_image_1;

    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        1,  //amount
        0,  //index in planned mock coinbase tx
        make_secret_key(),
        enote_1,
        enote_ephemeral_pubkey_1,
        key_image_1);

    LegacyEnoteV5 enote_rand;
    ASSERT_NO_THROW(make_legacy_enote_v5(subaddr_spendkey_rand,  //random enote
        subaddr_viewkey_rand,
        1,  //amount
        1,  //index in planned mock coinbase tx
        make_secret_key(),
        enote_rand));

    TxExtra tx_extra_1;
    ASSERT_TRUE(try_append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                enote_ephemeral_pubkey_1,
                rct::pkGen()  //random enote gets a random enote ephemeral pubkey
            },
            tx_extra_1
        ));

    //block 0: 1 -> user, 1 -> rand
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_1,
            {},
            {
                enote_1,
                enote_rand
            }
        ));

    //intermediate scan
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 0);
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == -1);
    ASSERT_TRUE(enote_store.legacy_intermediate_records().size() == 1);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 0);

    //make enote: 2 -> user
    LegacyEnoteV5 enote_2;
    rct::key enote_ephemeral_pubkey_2;
    crypto::key_image key_image_2;

    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        2,  //amount
        0,  //index in planned mock coinbase tx
        make_secret_key(),
        enote_2,
        enote_ephemeral_pubkey_2,
        key_image_2);

    TxExtra tx_extra_2;
    ASSERT_TRUE(try_append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                enote_ephemeral_pubkey_2
            },
            tx_extra_2
        ));

    //block 1: 2 -> user
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_2,
            {},
            {
                enote_2
            }
        ));

    //get intermediate scan index
    const std::uint64_t intermediate_index_pre_import_cycle_1{
            enote_store.top_legacy_partialscanned_block_index()
        };

    //import key images: enote 1 in block 0
    ASSERT_TRUE(enote_store.try_import_legacy_key_image(key_image_1, enote_1.onetime_address, events));

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 0);
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == -1);
    ASSERT_TRUE(enote_store.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 1);  //intermediate record promoted to full

    //legacy key image scan
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::KEY_IMAGES_ONLY,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 0);
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == -1);
    ASSERT_TRUE(enote_store.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 1);

    //set fullscan index to saved intermediate block index
    ASSERT_NO_THROW(enote_store.update_legacy_fullscan_index_for_import_cycle(intermediate_index_pre_import_cycle_1));

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 0);
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == 0);

    //intermediate scan (to read block 1)
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 1);
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == 0);
    ASSERT_TRUE(enote_store.legacy_intermediate_records().size() == 1);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 1);

    //get intermediate block index
    const std::uint64_t intermediate_index_pre_import_cycle_2{
            enote_store.top_legacy_partialscanned_block_index()
        };

    //import key image: enote 2 in block 1
    ASSERT_TRUE(enote_store.try_import_legacy_key_image(key_image_2, enote_2.onetime_address, events));

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 1);
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == 0);
    ASSERT_TRUE(enote_store.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 3);  //intermediate record promoted to full

    //legacy key image scan
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::KEY_IMAGES_ONLY,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 1);
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == 0);
    ASSERT_TRUE(enote_store.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 3);

    //set fullscan index to saved intermediate block index
    ASSERT_NO_THROW(enote_store.update_legacy_fullscan_index_for_import_cycle(intermediate_index_pre_import_cycle_2));

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 1);
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == 1);

    //block 2: spend enote 2
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            TxExtra{},
            {
                key_image_2
            },
            {}
        ));

    //intermediate scan (to read block 2)
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 2);
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == 1);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 1);

    //get intermediate block index
    const std::uint64_t intermediate_index_pre_import_cycle_3{
            enote_store.top_legacy_partialscanned_block_index()
        };

    //skip key image import + legacy key image scan (no intermediate records)
    ASSERT_TRUE(enote_store.legacy_intermediate_records().size() == 0);

    //set fullscan index to saved intermediate block index
    ASSERT_NO_THROW(enote_store.update_legacy_fullscan_index_for_import_cycle(intermediate_index_pre_import_cycle_3));

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 2);
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == 2);

    //pop block 2
    ledger_context.pop_blocks(1);

    //intermediate scan
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 1);
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == 1);
    ASSERT_TRUE(enote_store.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);  //enote 2 is now unspent
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 3);

    //get intermediate block index
    const std::uint64_t intermediate_index_pre_import_cycle_4{
            enote_store.top_legacy_partialscanned_block_index()
        };

    //skip key image import + legacy key image scan (no intermediate records)
    ASSERT_TRUE(enote_store.legacy_intermediate_records().size() == 0);

    //set fullscan index to saved intermediate block index (this is redundant since the reorg only popped blocks)
    ASSERT_NO_THROW(enote_store.update_legacy_fullscan_index_for_import_cycle(intermediate_index_pre_import_cycle_4));

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 1);
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == 1);

    //make enote: 4 -> user
    LegacyEnoteV5 enote_3;
    rct::key enote_ephemeral_pubkey_3;
    crypto::key_image key_image_3;

    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        4,  //amount
        0,  //index in planned mock coinbase tx
        make_secret_key(),
        enote_3,
        enote_ephemeral_pubkey_3,
        key_image_3);

    TxExtra tx_extra_3;
    ASSERT_TRUE(try_append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                enote_ephemeral_pubkey_3
            },
            tx_extra_3
        ));

    //block 2: 4 -> user, spend enote 1
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_3,
            {
                key_image_1
            },
            {
                enote_3
            }
        ));

    //full scan
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 2);
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == 2);
    ASSERT_TRUE(enote_store.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 6);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 6);

    //intermediate scan (this should have no effect right after a full scan)
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 2);
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == 2);
    ASSERT_TRUE(enote_store.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 6);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 6);

    //get intermediate block index
    const std::uint64_t intermediate_index_pre_import_cycle_5{
            enote_store.top_legacy_partialscanned_block_index()
        };

    //skip key image import + legacy key image scan (no intermediate records)
    ASSERT_TRUE(enote_store.legacy_intermediate_records().size() == 0);

    //set fullscan index to saved intermediate block index (should do nothing)
    ASSERT_NO_THROW(enote_store.update_legacy_fullscan_index_for_import_cycle(intermediate_index_pre_import_cycle_5));

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 2);
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == 2);

    //block 3: spend enote 3
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            TxExtra{},
            {
                key_image_3
            },
            {}
        ));

    //full scan
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 3);
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == 3);
    ASSERT_TRUE(enote_store.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 2);

    //pop block 3
    ledger_context.pop_blocks(1);

    //full scan
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 2);  //fullscan fixed our intermediate index
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == 2);
    ASSERT_TRUE(enote_store.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 6);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 6);

    //intermediate scan to show there is no effect on index trackers
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 2);
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == 2);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 6);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 6);

    //get intermediate block index
    const std::uint64_t intermediate_index_pre_import_cycle_6{
            enote_store.top_legacy_partialscanned_block_index()
        };

    //skip key image import + legacy key image scan (no intermediate records)
    ASSERT_TRUE(enote_store.legacy_intermediate_records().size() == 0);

    //set fullscan index to saved intermediate block index (should do nothing)
    ASSERT_NO_THROW(enote_store.update_legacy_fullscan_index_for_import_cycle(intermediate_index_pre_import_cycle_6));

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 2);
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == 2);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, legacy_pre_transition_4)
{
    /// setup

    // 1. config
    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 0
        };

    // 2. user keys
    legacy_mock_keys legacy_keys;
    make_legacy_mock_keys(legacy_keys);

    // 3. user normal address
    //const rct::key normal_addr_spendkey{legacy_keys.Ks};
    //const rct::key normal_addr_viewkey{rct::scalarmultBase(rct::sk2rct(legacy_keys.k_v))};

    // 4. user subaddress
    rct::key subaddr_spendkey;
    rct::key subaddr_viewkey;
    cryptonote::subaddress_index subaddr_index;

    gen_legacy_subaddress(legacy_keys.Ks, legacy_keys.k_v, subaddr_spendkey, subaddr_viewkey, subaddr_index);

    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;
    legacy_subaddress_map[subaddr_spendkey] = subaddr_index;

    // 5. events cache
    std::list<EnoteStoreEvent> events;


    /// test

    // 3. manual scanning with key image imports: test 3 (with reorg that drops a partialscanned block)
    MockLedgerContext ledger_context{10000, 10000};
    SpEnoteStore enote_store{0, 10000, 0};

    //make enotes: 1 -> user
    LegacyEnoteV5 enote_1;
    rct::key enote_ephemeral_pubkey_1;
    crypto::key_image key_image_1;

    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        1,  //amount
        0,  //index in planned mock coinbase tx
        make_secret_key(),
        enote_1,
        enote_ephemeral_pubkey_1,
        key_image_1);

    TxExtra tx_extra_1;
    ASSERT_TRUE(try_append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                enote_ephemeral_pubkey_1
            },
            tx_extra_1
        ));

    //block 0: 1 -> user
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_1,
            {},
            {
                enote_1
            }
        ));

    //make enote: 2 -> user
    LegacyEnoteV5 enote_2;
    rct::key enote_ephemeral_pubkey_2;
    crypto::key_image key_image_2;

    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        2,  //amount
        0,  //index in planned mock coinbase tx
        make_secret_key(),
        enote_2,
        enote_ephemeral_pubkey_2,
        key_image_2);

    TxExtra tx_extra_2;
    ASSERT_TRUE(try_append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                enote_ephemeral_pubkey_2
            },
            tx_extra_2
        ));

    //block 1: 2 -> user
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_2,
            {},
            {
                enote_2
            }
        ));

    //intermediate scan
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 1);
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == -1);
    ASSERT_TRUE(enote_store.legacy_intermediate_records().size() == 2);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 0);

    //get intermediate scan index
    const std::uint64_t intermediate_index_pre_import_cycle_1{
            enote_store.top_legacy_partialscanned_block_index()
        };

    //pop block 1 (in the middle of an intermediate scan cycle)
    ledger_context.pop_blocks(1);

        //intermediate scan again (emulating a user who, for whatever reason, refreshes again)
        refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
            legacy_subaddress_map,
            legacy_keys.k_v,
            LegacyScanMode::SCAN,
            refresh_config,
            ledger_context,
            enote_store);

        ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 0);
        ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == -1);
        ASSERT_TRUE(enote_store.legacy_intermediate_records().size() == 1);
        ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
            {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
        ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
            {SpEnoteSpentStatus::SPENT_ONCHAIN},
            {BalanceExclusions::LEGACY_INTERMEDIATE}) == 0);

    //import key images: enote 1 in block 0, enote 2 in block 1
    ASSERT_TRUE(enote_store.try_import_legacy_key_image(key_image_1, enote_1.onetime_address, events));
    ASSERT_FALSE(enote_store.try_import_legacy_key_image(key_image_2, enote_2.onetime_address, events));  //ignore failed import

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 0);
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == -1);
    ASSERT_TRUE(enote_store.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 1);  //intermediate record promoted to full

    //legacy key image scan (does nothing, no enotes were spent)
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::KEY_IMAGES_ONLY,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 0);
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == -1);
    ASSERT_TRUE(enote_store.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 1);

    //set fullscan index to saved intermediate block index
    ASSERT_NO_THROW(enote_store.update_legacy_fullscan_index_for_import_cycle(intermediate_index_pre_import_cycle_1));

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 0); //index not effected
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == 0);  //index set
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, legacy_pre_transition_5)
{
    /// setup

    // 1. config
    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 0
        };

    // 2. user keys
    legacy_mock_keys legacy_keys;
    make_legacy_mock_keys(legacy_keys);

    // 3. user normal address
    //const rct::key normal_addr_spendkey{legacy_keys.Ks};
    //const rct::key normal_addr_viewkey{rct::scalarmultBase(rct::sk2rct(legacy_keys.k_v))};

    // 4. user subaddress
    rct::key subaddr_spendkey;
    rct::key subaddr_viewkey;
    cryptonote::subaddress_index subaddr_index;

    gen_legacy_subaddress(legacy_keys.Ks, legacy_keys.k_v, subaddr_spendkey, subaddr_viewkey, subaddr_index);

    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;
    legacy_subaddress_map[subaddr_spendkey] = subaddr_index;

    // 5. events cache
    std::list<EnoteStoreEvent> events;


    /// test

    // 3. manual scanning with key image imports: test 4 (with reorg that replaces a partialscanned block)
    MockLedgerContext ledger_context{10000, 10000};
    SpEnoteStore enote_store{0, 10000, 0};

    //make enotes: 1 -> user
    LegacyEnoteV5 enote_1;
    rct::key enote_ephemeral_pubkey_1;
    crypto::key_image key_image_1;

    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        1,  //amount
        0,  //index in planned mock coinbase tx
        make_secret_key(),
        enote_1,
        enote_ephemeral_pubkey_1,
        key_image_1);

    TxExtra tx_extra_1;
    ASSERT_TRUE(try_append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                enote_ephemeral_pubkey_1
            },
            tx_extra_1
        ));

    //block 0: 1 -> user
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_1,
            {},
            {
                enote_1
            }
        ));

    //make enote: 2 -> user
    LegacyEnoteV5 enote_2;
    rct::key enote_ephemeral_pubkey_2;
    crypto::key_image key_image_2;

    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        2,  //amount
        0,  //index in planned mock coinbase tx
        make_secret_key(),
        enote_2,
        enote_ephemeral_pubkey_2,
        key_image_2);

    TxExtra tx_extra_2;
    ASSERT_TRUE(try_append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                enote_ephemeral_pubkey_2
            },
            tx_extra_2
        ));

    //block 1: 2 -> user
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_2,
            {},
            {
                enote_2
            }
        ));

    //intermediate scan
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 1);
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == -1);
    ASSERT_TRUE(enote_store.legacy_intermediate_records().size() == 2);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 0);

    //get intermediate scan index
    const std::uint64_t intermediate_index_pre_import_cycle_1{
            enote_store.top_legacy_partialscanned_block_index()
        };

    //pop block 1 (in the middle of an intermediate scan cycle)
    ledger_context.pop_blocks(1);

    //block 1: empty
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            TxExtra{},
            {},
            {}
        ));

        //intermediate scan again (emulating a user who, for whatever reason, refreshes again)
        refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
            legacy_subaddress_map,
            legacy_keys.k_v,
            LegacyScanMode::SCAN,
            refresh_config,
            ledger_context,
            enote_store);

        ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 1);
        ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == -1);
        ASSERT_TRUE(enote_store.legacy_intermediate_records().size() == 1);
        ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
            {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
        ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
            {SpEnoteSpentStatus::SPENT_ONCHAIN},
            {BalanceExclusions::LEGACY_INTERMEDIATE}) == 0);

    //import key images: enote 1 in block 0, enote 2 in block 1
    ASSERT_TRUE(enote_store.try_import_legacy_key_image(key_image_1, enote_1.onetime_address, events));
    ASSERT_FALSE(enote_store.try_import_legacy_key_image(key_image_2, enote_2.onetime_address, events));  //ignore failed import

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 1);
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == -1);
    ASSERT_TRUE(enote_store.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 1);  //intermediate record promoted to full

    //legacy key image scan (does nothing, no enotes were spent)
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::KEY_IMAGES_ONLY,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 1);
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == -1);
    ASSERT_TRUE(enote_store.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 1);

    //set fullscan index to saved intermediate block index
    ASSERT_NO_THROW(enote_store.update_legacy_fullscan_index_for_import_cycle(intermediate_index_pre_import_cycle_1));

    ASSERT_TRUE(enote_store.top_legacy_partialscanned_block_index() == 1); //index not effected
    ASSERT_TRUE(enote_store.top_legacy_fullscanned_block_index() == 1);  //index set
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, legacy_pre_transition_6)
{
    /// setup

    // 1. config
    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 0
        };

    // 2. user keys
    legacy_mock_keys legacy_keys;
    make_legacy_mock_keys(legacy_keys);

    // 3. user normal address
   // const rct::key normal_addr_spendkey{legacy_keys.Ks};
    //const rct::key normal_addr_viewkey{rct::scalarmultBase(rct::sk2rct(legacy_keys.k_v))};

    // 4. user subaddress
    rct::key subaddr_spendkey;
    rct::key subaddr_viewkey;
    cryptonote::subaddress_index subaddr_index;

    gen_legacy_subaddress(legacy_keys.Ks, legacy_keys.k_v, subaddr_spendkey, subaddr_viewkey, subaddr_index);

    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;
    legacy_subaddress_map[subaddr_spendkey] = subaddr_index;

    // 5. events cache
    std::list<EnoteStoreEvent> events;


    /// test

    // 4. duplicate onetime addresses: same amounts
    MockLedgerContext ledger_context{10000, 10000};
    SpEnoteStore enote_store_int{0, 10000, 0};  //for view-only scanning
    SpEnoteStore enote_store_full{0, 10000, 0};  //for full scanning

    //make enote: 1 -> user (this will be reused throughout the test)
    LegacyEnoteV5 enote_1;
    rct::key enote_ephemeral_pubkey_1;
    crypto::key_image key_image_1;

    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        1,  //amount
        0,  //index in planned mock coinbase tx
        make_secret_key(),
        enote_1,
        enote_ephemeral_pubkey_1,
        key_image_1);

    TxExtra tx_extra_1;
    ASSERT_TRUE(try_append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                enote_ephemeral_pubkey_1
            },
            tx_extra_1
        ));

    //block 0: enote 1-a
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_1,
            {},
            {
                enote_1
            }
        ));

    //intermediate scan (don't import key image yet)
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 1);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 0);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);

    //block 1: enote 1-b
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_1,
            {},
            {
                enote_1
            }
        ));

    //intermediate scan (don't import key image yet); should still be only 1 intermediate record, with origin index 0
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 1);
    ASSERT_TRUE(
            enote_store_int.legacy_intermediate_records().begin()->second.origin_context.block_index == 0
        );
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 0);

    //full scan (separate enote store); balance should still be 1
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);

    //pop block 1
    ledger_context.pop_blocks(1);

    //intermediate scan: still one intermediate record for enote 1-a
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 1);
    ASSERT_TRUE(
            enote_store_int.legacy_intermediate_records().begin()->second.origin_context.block_index == 0
        );
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 0);

    //get intermediate block index
    const std::uint64_t intermediate_index_pre_import_cycle_1{
            enote_store_int.top_legacy_partialscanned_block_index()
        };

    //import key image: enote 1
    ASSERT_TRUE(enote_store_int.try_import_legacy_key_image(key_image_1, enote_1.onetime_address, events));

    ASSERT_TRUE(enote_store_int.top_legacy_partialscanned_block_index() == 0);
    ASSERT_TRUE(enote_store_int.top_legacy_fullscanned_block_index() == -1);
    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 1);  //intermediate record promoted to full

    //legacy key image scan
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::KEY_IMAGES_ONLY,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.top_legacy_partialscanned_block_index() == 0);
    ASSERT_TRUE(enote_store_int.top_legacy_fullscanned_block_index() == -1);
    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 1);

    //set fullscan index to saved intermediate block index
    ASSERT_NO_THROW(enote_store_int.update_legacy_fullscan_index_for_import_cycle(
        intermediate_index_pre_import_cycle_1));

    ASSERT_TRUE(enote_store_int.top_legacy_partialscanned_block_index() == 0);
    ASSERT_TRUE(enote_store_int.top_legacy_fullscanned_block_index() == 0);

    //full scan
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);

    //block 1: enote 1-c
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_1,
            {},
            {
                enote_1
            }
        ));

    //intermediate scan: no intermediate records
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.top_legacy_partialscanned_block_index() == 1);
    ASSERT_TRUE(enote_store_int.top_legacy_fullscanned_block_index() == 0);
    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 1);

    //get intermediate block index
    const std::uint64_t intermediate_index_pre_import_cycle_2{
            enote_store_int.top_legacy_partialscanned_block_index()
        };

    //skip key image import + legacy key image scan (no intermediate records)
    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 0);

    //set fullscan index to saved intermediate block index
    ASSERT_NO_THROW(enote_store_int.update_legacy_fullscan_index_for_import_cycle(
        intermediate_index_pre_import_cycle_2));

    ASSERT_TRUE(enote_store_int.top_legacy_partialscanned_block_index() == 1);
    ASSERT_TRUE(enote_store_int.top_legacy_fullscanned_block_index() == 1);

    //full scan
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);

    //pop block 1
    ledger_context.pop_blocks(1);

    //intermediate scan: still no intermediate records, balance still has enote 1-a
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 1);

    //get intermediate block index
    const std::uint64_t intermediate_index_pre_import_cycle_3{
            enote_store_int.top_legacy_partialscanned_block_index()
        };

    //skip key image import + legacy key image scan (no intermediate records)
    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 0);

    //set fullscan index to saved intermediate block index
    ASSERT_NO_THROW(enote_store_int.update_legacy_fullscan_index_for_import_cycle(
        intermediate_index_pre_import_cycle_3));

    ASSERT_TRUE(enote_store_int.top_legacy_partialscanned_block_index() == 0);
    ASSERT_TRUE(enote_store_int.top_legacy_fullscanned_block_index() == 0);

    //full scan
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);

    //block 1: enote 1-d
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_1,
            {},
            {
                enote_1
            }
        ));

    //intermediate scan: still no intermediate records, balance still has enote 1-a
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 1);

    //get intermediate block index
    const std::uint64_t intermediate_index_pre_import_cycle_4{
            enote_store_int.top_legacy_partialscanned_block_index()
        };

    //skip key image import + legacy key image scan (no intermediate records)
    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 0);

    //set fullscan index to saved intermediate block index
    ASSERT_NO_THROW(enote_store_int.update_legacy_fullscan_index_for_import_cycle(
        intermediate_index_pre_import_cycle_4));

    ASSERT_TRUE(enote_store_int.top_legacy_partialscanned_block_index() == 1);
    ASSERT_TRUE(enote_store_int.top_legacy_fullscanned_block_index() == 1);

    //full scan
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);

    //block 2: spend enote 1
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            TxExtra{},
            {
                key_image_1
            },
            {}
        ));

    //intermediate scan: still no intermediate records, 0 balance now
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 0);

    //get intermediate block index
    const std::uint64_t intermediate_index_pre_import_cycle_5{
            enote_store_int.top_legacy_partialscanned_block_index()
        };

    //skip key image import + legacy key image scan (no intermediate records)
    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 0);

    //set fullscan index to saved intermediate block index
    ASSERT_NO_THROW(enote_store_int.update_legacy_fullscan_index_for_import_cycle(
        intermediate_index_pre_import_cycle_5));

    ASSERT_TRUE(enote_store_int.top_legacy_partialscanned_block_index() == 2);
    ASSERT_TRUE(enote_store_int.top_legacy_fullscanned_block_index() == 2);

    //full scan
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, legacy_pre_transition_7)
{
    /// setup

    // 1. config
    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 0
        };

    // 2. user keys
    legacy_mock_keys legacy_keys;
    make_legacy_mock_keys(legacy_keys);

    // 3. user normal address
    //const rct::key normal_addr_spendkey{legacy_keys.Ks};
    //const rct::key normal_addr_viewkey{rct::scalarmultBase(rct::sk2rct(legacy_keys.k_v))};

    // 4. user subaddress
    rct::key subaddr_spendkey;
    rct::key subaddr_viewkey;
    cryptonote::subaddress_index subaddr_index;

    gen_legacy_subaddress(legacy_keys.Ks, legacy_keys.k_v, subaddr_spendkey, subaddr_viewkey, subaddr_index);

    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;
    legacy_subaddress_map[subaddr_spendkey] = subaddr_index;

    // 5. events cache
    std::list<EnoteStoreEvent> events;


    /// test

    // 5. duplicate onetime addresses: different amounts
    MockLedgerContext ledger_context{10000, 10000};
    SpEnoteStore enote_store_int{0, 10000, 0};  //for view-only scanning
    SpEnoteStore enote_store_full{0, 10000, 0};  //for full scanning

    //make enotes: 1-a (amount 3), 1-b (amount 5), 1-c (amount 1), 1-d (amount 4)
    LegacyEnoteV5 enote_1a;
    LegacyEnoteV5 enote_1b;
    LegacyEnoteV5 enote_1c;
    LegacyEnoteV5 enote_1d;
    const crypto::secret_key enote_ephemeral_privkey{make_secret_key()};
    rct::key enote_ephemeral_pubkey;
    rct::key enote_ephemeral_pubkey_temp;
    crypto::key_image key_image;
    crypto::key_image key_image_temp;

    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        3,  //amount
        0,  //index in planned mock coinbase tx
        enote_ephemeral_privkey,
        enote_1a,
        enote_ephemeral_pubkey,
        key_image);

    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        5,  //amount
        0,  //index in planned mock coinbase tx
        enote_ephemeral_privkey,
        enote_1b,
        enote_ephemeral_pubkey_temp,
        key_image_temp);
    ASSERT_TRUE(enote_ephemeral_pubkey_temp == enote_ephemeral_pubkey);
    ASSERT_TRUE(key_image_temp == key_image);

    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        1,  //amount
        0,  //index in planned mock coinbase tx
        enote_ephemeral_privkey,
        enote_1c,
        enote_ephemeral_pubkey_temp,
        key_image_temp);
    ASSERT_TRUE(enote_ephemeral_pubkey_temp == enote_ephemeral_pubkey);
    ASSERT_TRUE(key_image_temp == key_image);

    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        4,  //amount
        0,  //index in planned mock coinbase tx
        enote_ephemeral_privkey,
        enote_1d,
        enote_ephemeral_pubkey_temp,
        key_image_temp);
    ASSERT_TRUE(enote_ephemeral_pubkey_temp == enote_ephemeral_pubkey);
    ASSERT_TRUE(key_image_temp == key_image);

    TxExtra tx_extra;
    ASSERT_TRUE(try_append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                enote_ephemeral_pubkey
            },
            tx_extra
        ));

    //block 0: enote 1-a (amount 3)
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra,
            {},
            {
                enote_1a
            }
        ));

    //intermediate scan (don't import key image yet)
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 1);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 0);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);

    //block 1: enote 1-b (amount 5)
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra,
            {},
            {
                enote_1b
            }
        ));

    //intermediate scan (with key image import)
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 2);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 5);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 0);

    //get intermediate block index
    const std::uint64_t intermediate_index_pre_import_cycle_1{
            enote_store_int.top_legacy_partialscanned_block_index()
        };

    //import key image: enote 1
    ASSERT_TRUE(enote_store_int.try_import_legacy_key_image(key_image, enote_1a.onetime_address, events));

    ASSERT_TRUE(enote_store_int.top_legacy_partialscanned_block_index() == 1);
    ASSERT_TRUE(enote_store_int.top_legacy_fullscanned_block_index() == -1);
    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 5);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 5);  //intermediate records promoted to full

    //legacy key image scan
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::KEY_IMAGES_ONLY,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.top_legacy_partialscanned_block_index() == 1);
    ASSERT_TRUE(enote_store_int.top_legacy_fullscanned_block_index() == -1);
    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 5);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 5);

    //set fullscan index to saved intermediate block index
    ASSERT_NO_THROW(enote_store_int.update_legacy_fullscan_index_for_import_cycle(
        intermediate_index_pre_import_cycle_1));

    ASSERT_TRUE(enote_store_int.top_legacy_partialscanned_block_index() == 1);
    ASSERT_TRUE(enote_store_int.top_legacy_fullscanned_block_index() == 1);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 5);

    //pop block 1
    ledger_context.pop_blocks(1);

    //intermediate scan
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 3);

    //get intermediate block index
    const std::uint64_t intermediate_index_pre_import_cycle_2{
            enote_store_int.top_legacy_partialscanned_block_index()
        };

    //skip key image import + legacy key image scan (no intermediate records)
    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 0);

    //set fullscan index to saved intermediate block index
    ASSERT_NO_THROW(enote_store_int.update_legacy_fullscan_index_for_import_cycle(
        intermediate_index_pre_import_cycle_2));

    ASSERT_TRUE(enote_store_int.top_legacy_partialscanned_block_index() == 0);
    ASSERT_TRUE(enote_store_int.top_legacy_fullscanned_block_index() == 0);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);

    //block 1: enote 1-c (amount 1)
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra,
            {},
            {
                enote_1c
            }
        ));

    //block 2: enote 1-d (amount 4)
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra,
            {},
            {
                enote_1d
            }
        ));

    //intermediate scan
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 4);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 4);

    //get intermediate block index
    const std::uint64_t intermediate_index_pre_import_cycle_3{
            enote_store_int.top_legacy_partialscanned_block_index()
        };

    //skip key image import + legacy key image scan (no intermediate records)
    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 0);

    //set fullscan index to saved intermediate block index
    ASSERT_NO_THROW(enote_store_int.update_legacy_fullscan_index_for_import_cycle(
        intermediate_index_pre_import_cycle_3));

    ASSERT_TRUE(enote_store_int.top_legacy_partialscanned_block_index() == 2);
    ASSERT_TRUE(enote_store_int.top_legacy_fullscanned_block_index() == 2);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 4);

    //block 3: spend enote 1
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            TxExtra{},
            {
                key_image
            },
            {}
        ));

    //intermediate scan
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN}, {}) == 4);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 0);

    //get intermediate block index
    const std::uint64_t intermediate_index_pre_import_cycle_4{
            enote_store_int.top_legacy_partialscanned_block_index()
        };

    //skip key image import + legacy key image scan (no intermediate records)
    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 0);

    //set fullscan index to saved intermediate block index
    ASSERT_NO_THROW(enote_store_int.update_legacy_fullscan_index_for_import_cycle(
        intermediate_index_pre_import_cycle_4));

    ASSERT_TRUE(enote_store_int.top_legacy_partialscanned_block_index() == 3);
    ASSERT_TRUE(enote_store_int.top_legacy_fullscanned_block_index() == 3);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN}, {}) == 4);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);

    //pop block 3
    ledger_context.pop_blocks(1);

    //intermediate scan
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN}, {}) == 4);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 4);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE}) == 4);

    //get intermediate block index
    const std::uint64_t intermediate_index_pre_import_cycle_5{
            enote_store_int.top_legacy_partialscanned_block_index()
        };

    //skip key image import + legacy key image scan (no intermediate records)
    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 0);

    //set fullscan index to saved intermediate block index
    ASSERT_NO_THROW(enote_store_int.update_legacy_fullscan_index_for_import_cycle(
        intermediate_index_pre_import_cycle_5));

    ASSERT_TRUE(enote_store_int.top_legacy_partialscanned_block_index() == 2);
    ASSERT_TRUE(enote_store_int.top_legacy_fullscanned_block_index() == 2);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN}, {}) == 4);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 4);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, legacy_pre_transition_8)
{
    /// setup

    // 1. config
    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 0
        };

    // 2. user keys
    legacy_mock_keys legacy_keys;
    make_legacy_mock_keys(legacy_keys);

    // 3. user normal address
    //const rct::key normal_addr_spendkey{legacy_keys.Ks};
    //const rct::key normal_addr_viewkey{rct::scalarmultBase(rct::sk2rct(legacy_keys.k_v))};

    // 4. user subaddress
    rct::key subaddr_spendkey;
    rct::key subaddr_viewkey;
    cryptonote::subaddress_index subaddr_index;

    gen_legacy_subaddress(legacy_keys.Ks, legacy_keys.k_v, subaddr_spendkey, subaddr_viewkey, subaddr_index);

    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;
    legacy_subaddress_map[subaddr_spendkey] = subaddr_index;

    // 5. events cache
    std::list<EnoteStoreEvent> events;


    /// test

    // 6. locktime test 1: basic
    MockLedgerContext ledger_context{10000, 10000};
    SpEnoteStore enote_store_int{0, 10000, 2};  //for view-only scanning
    SpEnoteStore enote_store_full{0, 10000, 2};  //for full scanning

    //make enotes: enote 1, 2, 3
    LegacyEnoteV5 enote_1;
    LegacyEnoteV5 enote_2;
    LegacyEnoteV5 enote_3;
    rct::key enote_ephemeral_pubkey_1;
    rct::key enote_ephemeral_pubkey_2;
    rct::key enote_ephemeral_pubkey_3;
    crypto::key_image key_image_1;
    crypto::key_image key_image_2;
    crypto::key_image key_image_3;

    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        1,  //amount
        0,  //index in planned mock coinbase tx
        make_secret_key(),
        enote_1,
        enote_ephemeral_pubkey_1,
        key_image_1);

    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        1,  //amount
        0,  //index in planned mock coinbase tx
        make_secret_key(),
        enote_2,
        enote_ephemeral_pubkey_2,
        key_image_2);

    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        1,  //amount
        0,  //index in planned mock coinbase tx
        make_secret_key(),
        enote_3,
        enote_ephemeral_pubkey_3,
        key_image_3);

    TxExtra tx_extra_1;
    ASSERT_TRUE(try_append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                enote_ephemeral_pubkey_1
            },
            tx_extra_1
        ));
    TxExtra tx_extra_2;
    ASSERT_TRUE(try_append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                enote_ephemeral_pubkey_2
            },
            tx_extra_2
        ));
    TxExtra tx_extra_3;
    ASSERT_TRUE(try_append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                enote_ephemeral_pubkey_3
            },
            tx_extra_3
        ));

    //block 0: enote 1 (unlock at block 0)
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_1,
            {},
            {
                enote_1
            }
        ));

    //intermediate scan (don't import key image yet)
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 1);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 0);  //enote 1 is locked
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE,
        BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 0);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 0);  //enote 1 is locked

    //block 1: enote 2 (unlock at block 3)
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            3,
            tx_extra_2,
            {},
            {
                enote_2
            }
        ));

    //intermediate scan (don't import key image yet)
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 2);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 1);  //enote 1 is unlocked, enote 2 is locked
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE,
        BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 0);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 1);  //enote 1 is unlocked, enote 2 is locked

    //block 2: enote 3 (unlock at block 5)
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            5,
            tx_extra_3,
            {},
            {
                enote_3
            }
        ));

    //intermediate scan (don't import key image yet)
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 3);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 2);  //enotes 1, 2 are unlocked, enote 3 is locked
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE,
        BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 0);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 2);  //enotes 1, 2 are unlocked, enote 3 is locked

    //block 3: empty
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            TxExtra{},
            {},
            {}
        ));

    //intermediate scan (don't import key image yet)
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 3);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 2);  //enotes 1, 2 are unlocked, enote 3 is locked
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE,
        BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 0);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 2);  //enotes 1, 2 are unlocked, enote 3 is locked

    //block 4: empty
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            TxExtra{},
            {},
            {}
        ));

    //intermediate scan
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 3);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 3);  //enotes 1, 2, 3 are unlocked
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE,
        BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 0);

    //get intermediate block index
    const std::uint64_t intermediate_index_pre_import_cycle_1{
            enote_store_int.top_legacy_partialscanned_block_index()
        };

    //import key images: enotes 1, 2, 3
    ASSERT_TRUE(enote_store_int.try_import_legacy_key_image(key_image_1, enote_1.onetime_address, events));
    ASSERT_TRUE(enote_store_int.try_import_legacy_key_image(key_image_2, enote_2.onetime_address, events));
    ASSERT_TRUE(enote_store_int.try_import_legacy_key_image(key_image_3, enote_3.onetime_address, events));

    ASSERT_TRUE(enote_store_int.top_legacy_partialscanned_block_index() == 4);
    ASSERT_TRUE(enote_store_int.top_legacy_fullscanned_block_index() == -1);
    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 3);  //enotes 1, 2, 3 are unlocked
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE,
        BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 3);  //intermediate records promoted to full

    //legacy key image scan
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::KEY_IMAGES_ONLY,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.top_legacy_partialscanned_block_index() == 4);
    ASSERT_TRUE(enote_store_int.top_legacy_fullscanned_block_index() == -1);
    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 3);  //enotes 1, 2, 3 are unlocked
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE,
        BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 3);

    //set fullscan index to saved intermediate block index
    ASSERT_NO_THROW(enote_store_int.update_legacy_fullscan_index_for_import_cycle(
        intermediate_index_pre_import_cycle_1));

    ASSERT_TRUE(enote_store_int.top_legacy_partialscanned_block_index() == 4);
    ASSERT_TRUE(enote_store_int.top_legacy_fullscanned_block_index() == 4);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 3);  //enotes 1, 2, 3 are unlocked
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, legacy_pre_transition_9)
{
    /// setup

    // 1. config
    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 0
        };

    // 2. user keys
    legacy_mock_keys legacy_keys;
    make_legacy_mock_keys(legacy_keys);

    // 3. user normal address
    //const rct::key normal_addr_spendkey{legacy_keys.Ks};
    //const rct::key normal_addr_viewkey{rct::scalarmultBase(rct::sk2rct(legacy_keys.k_v))};

    // 4. user subaddress
    rct::key subaddr_spendkey;
    rct::key subaddr_viewkey;
    cryptonote::subaddress_index subaddr_index;

    gen_legacy_subaddress(legacy_keys.Ks, legacy_keys.k_v, subaddr_spendkey, subaddr_viewkey, subaddr_index);

    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;
    legacy_subaddress_map[subaddr_spendkey] = subaddr_index;

    // 5. events cache
    std::list<EnoteStoreEvent> events;


    /// test

    // 7. locktime test 2: duplicate onetime addresses
    MockLedgerContext ledger_context{10000, 10000};
    SpEnoteStore enote_store_int{0, 10000, 2};  //for view-only scanning
    SpEnoteStore enote_store_full{0, 10000, 2};  //for full scanning

    //make enotes: 1-a (amount 1), 1-b (amount 2), 1-c (amount 3)
    LegacyEnoteV5 enote_1a;
    LegacyEnoteV5 enote_1b;
    LegacyEnoteV5 enote_1c;
    const crypto::secret_key enote_ephemeral_privkey{make_secret_key()};
    rct::key enote_ephemeral_pubkey;
    rct::key enote_ephemeral_pubkey_temp;
    crypto::key_image key_image;
    crypto::key_image key_image_temp;

    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        1,  //amount
        0,  //index in planned mock coinbase tx
        enote_ephemeral_privkey,
        enote_1a,
        enote_ephemeral_pubkey,
        key_image);

    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        2,  //amount
        0,  //index in planned mock coinbase tx
        enote_ephemeral_privkey,
        enote_1b,
        enote_ephemeral_pubkey_temp,
        key_image_temp);
    ASSERT_TRUE(enote_ephemeral_pubkey_temp == enote_ephemeral_pubkey);
    ASSERT_TRUE(key_image_temp == key_image);

    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        3,  //amount
        0,  //index in planned mock coinbase tx
        enote_ephemeral_privkey,
        enote_1c,
        enote_ephemeral_pubkey_temp,
        key_image_temp);
    ASSERT_TRUE(enote_ephemeral_pubkey_temp == enote_ephemeral_pubkey);
    ASSERT_TRUE(key_image_temp == key_image);

    TxExtra tx_extra;
    ASSERT_TRUE(try_append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                enote_ephemeral_pubkey
            },
            tx_extra
        ));

    //block 0: enote 1-a (amount 1; unlock 0)
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra,
            {},
            {
                enote_1a
            }
        ));

    //intermediate scan (don't import key image yet)
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 1);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 0);  //enote 1a is locked
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE,
        BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 0);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 0);  //enote 1a is locked

    //block 1: empty
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            TxExtra{},
            {},
            {}
        ));

    //intermediate scan (don't import key image yet)
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 1);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 1);  //enote 1a is unlocked
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE,
        BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 0);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 1);  //enote 1a is unlocked

    //block 2: enote 1-b (amount 2; unlock 0)
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra,
            {},
            {
                enote_1b
            }
        ));

    //intermediate scan (don't import key image yet)
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 2);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 0);  //enote 1a is unlocked, 1b is locked (hides 1a)
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE,
        BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 0);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 0);  //enote 1a is unlocked, 1b is locked (hides 1a)

    //block 3: empty
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            TxExtra{},
            {},
            {}
        ));

    //intermediate scan
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 2);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 2);  //enotes 1a, 1b are unlocked
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE,
        BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 0);

    //get intermediate block index
    const std::uint64_t intermediate_index_pre_import_cycle_1{
            enote_store_int.top_legacy_partialscanned_block_index()
        };

    //import key image: enote 1
    ASSERT_TRUE(enote_store_int.try_import_legacy_key_image(key_image, enote_1a.onetime_address, events));

    ASSERT_TRUE(enote_store_int.top_legacy_partialscanned_block_index() == 3);
    ASSERT_TRUE(enote_store_int.top_legacy_fullscanned_block_index() == -1);
    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 2);  //enotes 1a, 1b are unlocked
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE,
        BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 2);  //intermediate records promoted to full

    //legacy key image scan
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::KEY_IMAGES_ONLY,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.top_legacy_partialscanned_block_index() == 3);
    ASSERT_TRUE(enote_store_int.top_legacy_fullscanned_block_index() == -1);
    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 2);  //enotes 1a, 1b are unlocked
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE,
        BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 2);

    //set fullscan index to saved intermediate block index
    ASSERT_NO_THROW(enote_store_int.update_legacy_fullscan_index_for_import_cycle(
        intermediate_index_pre_import_cycle_1));

    ASSERT_TRUE(enote_store_int.top_legacy_partialscanned_block_index() == 3);
    ASSERT_TRUE(enote_store_int.top_legacy_fullscanned_block_index() == 3);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 2);  //enotes 1a, 1b are unlocked

    //block 4: enote 1-c (amount 3; unlock 0), spend enote 1   (check balance with a locked and spent enote [enote 1-c])
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra,
            {
                key_image
            },
            {
                enote_1c
            }
        ));

    //intermediate scan
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN}) == 3);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 0);  //enotes 1a, 1b, are unlocked, 1c is locked
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 0);
    ASSERT_TRUE(get_balance(enote_store_int, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::LEGACY_INTERMEDIATE,
        BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 0);

    //get intermediate block index
    const std::uint64_t intermediate_index_pre_import_cycle_2{
            enote_store_int.top_legacy_partialscanned_block_index()
        };

    //skip key image import + legacy key image scan (no intermediate records)
    ASSERT_TRUE(enote_store_int.legacy_intermediate_records().size() == 0);

    //set fullscan index to saved intermediate block index
    ASSERT_NO_THROW(enote_store_int.update_legacy_fullscan_index_for_import_cycle(
        intermediate_index_pre_import_cycle_2));

    ASSERT_TRUE(enote_store_int.top_legacy_partialscanned_block_index() == 4);
    ASSERT_TRUE(enote_store_int.top_legacy_fullscanned_block_index() == 4);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN}) == 3);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 0);  //enotes 1a, 1b are unlocked, 1c is locked
    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {BalanceExclusions::ORIGIN_LEDGER_LOCKED}) == 0);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
// functions for legacy-seraphis transition
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void legacy_view_scan_recovery_cycle(const legacy_mock_keys &legacy_keys,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const scanning::ScanMachineConfig &refresh_config,
    const MockLedgerContext &ledger_context,
    const std::vector<rct::key> &legacy_onetime_addresses_expected,
    const std::vector<crypto::key_image> &legacy_key_images_expected,
    const std::uint64_t expected_balance_after_intermediate_scan,
    const std::uint64_t expected_balance_after_importing,
    const std::uint64_t expected_balance_after_key_image_refresh,
    const std::uint64_t expected_final_legacy_fullscan_index,
    SpEnoteStore &enote_store_inout)
{
    ASSERT_TRUE(legacy_onetime_addresses_expected.size() == legacy_key_images_expected.size());

    // 1. legacy view-only scan
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store_inout);

    // 2. check results of view-only scan
    ASSERT_TRUE(get_balance(enote_store_inout, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == expected_balance_after_intermediate_scan);


    /// ATOMIC READ-LOCK
    // 3. get enote store current state
    LegacyKIImportCheckpoint import_cycle_checkpoint;
    ASSERT_NO_THROW(make_legacy_ki_import_checkpoint(enote_store_inout, import_cycle_checkpoint));

    // 4. check the intermediate onetime addresses that need key images are expected
    for (const auto &legacy_intermediate_record : import_cycle_checkpoint.legacy_intermediate_records)
    {
        ASSERT_TRUE(std::find(legacy_onetime_addresses_expected.begin(),
                legacy_onetime_addresses_expected.end(),
                onetime_address_ref(legacy_intermediate_record.second))
            != legacy_onetime_addresses_expected.end());
    }
    /// end ATOMIC READ-LOCK


    // 4. import expected key images (will fail if the onetime addresses and key images don't line up)
    std::list<EnoteStoreEvent> events;
    std::unordered_map<rct::key, crypto::key_image> recovered_key_images;  //[ Ko : KI ]

    for (std::size_t i{0}; i < legacy_onetime_addresses_expected.size(); ++i)
        recovered_key_images[legacy_onetime_addresses_expected[i]] = legacy_key_images_expected[i];

    ASSERT_NO_THROW(import_legacy_key_images(recovered_key_images, enote_store_inout, events));

    // 5. check results of importing key images
    ASSERT_TRUE(get_balance(enote_store_inout, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == expected_balance_after_importing);
    ASSERT_TRUE(enote_store_inout.legacy_intermediate_records().size() == 0);

    // 6. legacy key-image-refresh scan
    refresh_user_enote_store_legacy_intermediate(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_v,
        LegacyScanMode::KEY_IMAGES_ONLY,
        refresh_config,
        ledger_context,
        enote_store_inout);

    // 7. check results of key image refresh scan
    ASSERT_TRUE(get_balance(enote_store_inout, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == expected_balance_after_key_image_refresh);
    ASSERT_TRUE(enote_store_inout.legacy_intermediate_records().size() == 0);


    /// ATOMIC WRITE-LOCK
    // 8. update the legacy fullscan index to account for a complete view-only scan cycle with key image recovery
    // - only update up to the highest aligned checkpoint from when intermediate records were exported, so that
    //   any reorg that replaced blocks below the partial scan index recorded at the beginning of the cycle won't
    //   be ignored by the next partial scan
    ASSERT_NO_THROW(finish_legacy_ki_import_cycle(import_cycle_checkpoint, enote_store_inout));

    // 9. check the legacy fullscan index is at the expected value
    ASSERT_TRUE(enote_store_inout.top_legacy_fullscanned_block_index() == expected_final_legacy_fullscan_index);
    /// end ATOMIC WRITE-LOCK
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void legacy_sp_transition_test_recovery_assertions(const legacy_mock_keys &legacy_keys,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const jamtis_mock_keys &sp_keys,
    const scanning::ScanMachineConfig &refresh_config,
    const MockLedgerContext &ledger_context,

    const std::vector<rct::key> &view_scan_legacy_onetime_addresses_expected,
    const std::vector<crypto::key_image> &view_scan_legacy_key_images_expected,

    const std::vector<rct::key> &re_view_scan_legacy_onetime_addresses_expected,
    const std::vector<crypto::key_image> &re_view_scan_legacy_key_images_expected,

    const std::uint64_t first_sp_allowed_block,

    const std::uint64_t final_balance,
    const std::uint64_t final_legacy_fullscan_index,

    const std::uint64_t view_scan_expected_balance_after_intermediate_scan,
    const std::uint64_t view_scan_expected_balance_after_importing_key_images,
    const std::uint64_t view_scan_expected_balance_after_keyimage_refresh,

    const std::uint64_t re_view_scan_expected_balance_after_intermediate_scan,
    const std::uint64_t re_view_scan_expected_balance_after_importing_key_images,
    const std::uint64_t re_view_scan_expected_balance_after_keyimage_refresh,

    SpEnoteStore &enote_store_full_inout,
    SpEnoteStore &enote_store_view_inout)
{
    // 1. test full-scan recovery
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store_full_inout);
    refresh_user_enote_store(sp_keys, refresh_config, ledger_context, enote_store_full_inout);

    ASSERT_TRUE(get_balance(enote_store_full_inout, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == final_balance);
    ASSERT_TRUE(enote_store_full_inout.top_legacy_fullscanned_block_index() == final_legacy_fullscan_index);

    // 2. test view-scan recovery
    legacy_view_scan_recovery_cycle(legacy_keys,
        legacy_subaddress_map,
        refresh_config,
        ledger_context,
        view_scan_legacy_onetime_addresses_expected,
        view_scan_legacy_key_images_expected,
        view_scan_expected_balance_after_intermediate_scan,  //expected balance after intermediate scan
        view_scan_expected_balance_after_importing_key_images,  //expected balance after importing key images
        view_scan_expected_balance_after_keyimage_refresh,  //expected balance after key-image refresh
        final_legacy_fullscan_index,  //expected final legacy fullscan index
        enote_store_view_inout);
    refresh_user_enote_store(sp_keys, refresh_config, ledger_context, enote_store_view_inout);

    ASSERT_TRUE(get_balance(enote_store_view_inout, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == final_balance);

    // 3. test re-scan from empty enote stores
    {
        SpEnoteStore enote_store_full_temp{0, first_sp_allowed_block, 0};
        SpEnoteStore enote_store_view_temp{0, first_sp_allowed_block, 0};

        //test full-scan recovery
        refresh_user_enote_store_legacy_full(legacy_keys.Ks,
            legacy_subaddress_map,
            legacy_keys.k_s,
            legacy_keys.k_v,
            refresh_config,
            ledger_context,
            enote_store_full_temp);
        refresh_user_enote_store(sp_keys, refresh_config, ledger_context, enote_store_full_temp);

        ASSERT_TRUE(get_balance(enote_store_full_temp, {SpEnoteOriginStatus::ONCHAIN},
            {SpEnoteSpentStatus::SPENT_ONCHAIN}) == final_balance);
        ASSERT_TRUE(enote_store_full_temp.top_legacy_fullscanned_block_index() == final_legacy_fullscan_index);

        //test view-scan recovery
        legacy_view_scan_recovery_cycle(legacy_keys,
            legacy_subaddress_map,
            refresh_config,
            ledger_context,
            re_view_scan_legacy_onetime_addresses_expected,
            re_view_scan_legacy_key_images_expected,
            re_view_scan_expected_balance_after_intermediate_scan,  //expected balance after intermediate scan
            re_view_scan_expected_balance_after_importing_key_images,  //expected balance after importing key images
            re_view_scan_expected_balance_after_keyimage_refresh,  //expected balance after key-image refresh
            final_legacy_fullscan_index,  //expected final legacy fullscan index
            enote_store_view_temp);
        refresh_user_enote_store(sp_keys, refresh_config, ledger_context, enote_store_view_temp);

        ASSERT_TRUE(get_balance(enote_store_view_temp, {SpEnoteOriginStatus::ONCHAIN},
            {SpEnoteSpentStatus::SPENT_ONCHAIN}) == final_balance);
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
// legacy-seraphis transition
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, legacy_sp_transition_1)
{
/*
    - test 1:
        - [first sp allowed: 0, first sp only: 2, chunk size: 2]
        - 0: legacy x2
        - 1: legacy + 1 legacy spend
        - 2: sp
        - 3: sp
        - 4: send all to B
        - pop 5
        - 0: sp
        - 1: legacy x2 (need 2 for ring signatures)
        - 2: sp
        - 3: sp
        - 4: send all to B
        - pop 5
        - 0: sp
        - 1: sp
        - pop 1 between legacy and seraphis scan
        - 1: legacy x2
        - 2: sp
        - 3: sp
        - 4: send all to B
        - pop 3
        - 2: sp
        - 3: sp
        - 4: send all to B
*/

    /// setup

    // 1. config
    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 2,
            .max_partialscan_attempts = 0
        };

    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{0};  // 0 fee here
    const std::size_t legacy_ring_size{2};
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator here (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .bin_radius = 1,
            .num_bin_members = 2
        };

    const std::uint64_t first_sp_allowed_block{0};
    const std::uint64_t first_sp_only_block{2};

    // 2. legacy user keys
    legacy_mock_keys legacy_keys;
    make_legacy_mock_keys(legacy_keys);

    // 3. user legacy subaddress
    rct::key subaddr_spendkey;
    rct::key subaddr_viewkey;
    cryptonote::subaddress_index subaddr_index;

    gen_legacy_subaddress(legacy_keys.Ks, legacy_keys.k_v, subaddr_spendkey, subaddr_viewkey, subaddr_index);

    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;
    legacy_subaddress_map[subaddr_spendkey] = subaddr_index;

    // 4. seraphis user keys
    jamtis_mock_keys sp_keys;
    make_jamtis_mock_keys(sp_keys);

    // 5. user seraphis address
    JamtisDestinationV1 sp_destination;
    make_random_address_for_user(sp_keys, sp_destination);

    // 6. random user address
    JamtisDestinationV1 sp_destination_random;
    sp_destination_random = gen_jamtis_destination_v1();


    /// test

    // 1. mixed seraphis/legacy enotes in transition zone
    MockLedgerContext ledger_context{first_sp_allowed_block, first_sp_only_block};
    SpEnoteStore enote_store_full{0, first_sp_allowed_block, 0};
    SpEnoteStore enote_store_view{0, first_sp_allowed_block, 0};
    InputSelectorMockV1 input_selector{enote_store_full};

    //make two legacy enotes
    LegacyEnoteV5 legacy_enote_1;
    rct::key legacy_enote_ephemeral_pubkey_1;
    crypto::key_image legacy_key_image_1;
    LegacyEnoteV5 legacy_enote_2;
    rct::key legacy_enote_ephemeral_pubkey_2;
    crypto::key_image legacy_key_image_2;

    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        1,  //amount
        0,  //index in planned mock coinbase tx
        make_secret_key(),
        legacy_enote_1,
        legacy_enote_ephemeral_pubkey_1,
        legacy_key_image_1);
    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        1,  //amount
        1,  //index in planned mock coinbase tx
        make_secret_key(),
        legacy_enote_2,
        legacy_enote_ephemeral_pubkey_2,
        legacy_key_image_2);

    TxExtra tx_extra_1;
    ASSERT_TRUE(try_append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                legacy_enote_ephemeral_pubkey_1,
                legacy_enote_ephemeral_pubkey_2
            },
            tx_extra_1
        ));

    //block 0: legacy enote 1, legacy enote 2
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_1,
            {},
            {
                legacy_enote_1,
                legacy_enote_2
            }
        ));

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        2, //final_balance
        0, //final_legacy_fullscan_index

        2, //view_scan_expected_balance_after_intermediate_scan
        2, //view_scan_expected_balance_after_importing_key_images
        2, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //make legacy enote 3
    LegacyEnoteV5 legacy_enote_3;
    rct::key legacy_enote_ephemeral_pubkey_3;
    crypto::key_image legacy_key_image_3;

    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        2,  //amount
        0,  //index in planned mock coinbase tx
        make_secret_key(),
        legacy_enote_3,
        legacy_enote_ephemeral_pubkey_3,
        legacy_key_image_3);

    TxExtra tx_extra_3;
    ASSERT_TRUE(try_append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                legacy_enote_ephemeral_pubkey_3
            },
            tx_extra_3
        ));

    //block 1: legacy enote 3, spend legacy enote 2
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_3,
            {
                legacy_key_image_2
            },
            {
                legacy_enote_3
            }
        ));

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {
            legacy_enote_3.onetime_address
        }, //view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_3
        }, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address,
            legacy_enote_3.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2,
            legacy_key_image_3
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        3, //final_balance
        1, //final_legacy_fullscan_index

        3, //view_scan_expected_balance_after_intermediate_scan
        3, //view_scan_expected_balance_after_importing_key_images
        3, //view_scan_expected_balance_after_keyimage_refresh

        4, //re_view_scan_expected_balance_after_intermediate_scan
        4, //re_view_scan_expected_balance_after_importing_key_images
        3, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 2: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}, {0, 0, 0}}, {sp_destination, sp_destination_random}, ledger_context);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address,
            legacy_enote_3.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2,
            legacy_key_image_3
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        13, //final_balance
        1, //final_legacy_fullscan_index

        3, //view_scan_expected_balance_after_intermediate_scan
        3, //view_scan_expected_balance_after_importing_key_images
        3, //view_scan_expected_balance_after_keyimage_refresh

        4, //re_view_scan_expected_balance_after_intermediate_scan
        4, //re_view_scan_expected_balance_after_importing_key_images
        3, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 3: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}, {0, 0, 0}}, {sp_destination, sp_destination_random}, ledger_context);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address,
            legacy_enote_3.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2,
            legacy_key_image_3
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        23, //final_balance
        1, //final_legacy_fullscan_index

        13, //view_scan_expected_balance_after_intermediate_scan
        13, //view_scan_expected_balance_after_importing_key_images
        13, //view_scan_expected_balance_after_keyimage_refresh

        4, //re_view_scan_expected_balance_after_intermediate_scan
        4, //re_view_scan_expected_balance_after_importing_key_images
        3, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 4: send all to random
    transfer_funds_single_mock_v1_unconfirmed(legacy_keys,
        sp_keys,
        input_selector,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{23, sp_destination_random, TxExtra{}}},
        legacy_ring_size,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);
    ledger_context.commit_unconfirmed_txs_v1(rct::pkGen(), rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteVariant>{});

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address,
            legacy_enote_3.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2,
            legacy_key_image_3
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        0, //final_balance
        1, //final_legacy_fullscan_index

        23, //view_scan_expected_balance_after_intermediate_scan
        23, //view_scan_expected_balance_after_importing_key_images
        23, //view_scan_expected_balance_after_keyimage_refresh

        4, //re_view_scan_expected_balance_after_intermediate_scan
        4, //re_view_scan_expected_balance_after_importing_key_images
        3, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);


    //remove blocks 0, 1, 2, 3, 4
    ledger_context.pop_blocks(5);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {}, //re_view_scan_legacy_onetime_addresses_expected
        {}, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        0, //final_balance
        -1, //final_legacy_fullscan_index

        0, //view_scan_expected_balance_after_intermediate_scan
        0, //view_scan_expected_balance_after_importing_key_images
        0, //view_scan_expected_balance_after_keyimage_refresh

        0, //re_view_scan_expected_balance_after_intermediate_scan
        0, //re_view_scan_expected_balance_after_importing_key_images
        0, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 0: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}, {0, 0, 0}}, {sp_destination, sp_destination_random}, ledger_context);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {}, //re_view_scan_legacy_onetime_addresses_expected
        {}, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        10, //final_balance
        0, //final_legacy_fullscan_index

        0, //view_scan_expected_balance_after_intermediate_scan
        0, //view_scan_expected_balance_after_importing_key_images
        0, //view_scan_expected_balance_after_keyimage_refresh

        0, //re_view_scan_expected_balance_after_intermediate_scan
        0, //re_view_scan_expected_balance_after_importing_key_images
        0, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //make legacy enotes 4, 5
    LegacyEnoteV5 legacy_enote_4;
    rct::key legacy_enote_ephemeral_pubkey_4;
    crypto::key_image legacy_key_image_4;
    LegacyEnoteV5 legacy_enote_5;
    rct::key legacy_enote_ephemeral_pubkey_5;
    crypto::key_image legacy_key_image_5;

    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        1,  //amount
        0,  //index in planned mock coinbase tx
        make_secret_key(),
        legacy_enote_4,
        legacy_enote_ephemeral_pubkey_4,
        legacy_key_image_4);
    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        1,  //amount
        1,  //index in planned mock coinbase tx
        make_secret_key(),
        legacy_enote_5,
        legacy_enote_ephemeral_pubkey_5,
        legacy_key_image_5);

    TxExtra tx_extra_4;
    ASSERT_TRUE(try_append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                legacy_enote_ephemeral_pubkey_4,
                legacy_enote_ephemeral_pubkey_5
            },
            tx_extra_4
        ));

    //block 1: legacy enote 4, legacy enote 5
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_4,
            {},
            {
                legacy_enote_4,
                legacy_enote_5
            }
        ));

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {
            legacy_enote_4.onetime_address,
            legacy_enote_5.onetime_address
        }, //view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_4,
            legacy_key_image_5
        }, //view_scan_legacy_key_images_expected

        {
            legacy_enote_4.onetime_address,
            legacy_enote_5.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_4,
            legacy_key_image_5
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        12, //final_balance
        1, //final_legacy_fullscan_index

        12, //view_scan_expected_balance_after_intermediate_scan
        12, //view_scan_expected_balance_after_importing_key_images
        12, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 2: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}}, {sp_destination}, ledger_context);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_4.onetime_address,
            legacy_enote_5.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_4,
            legacy_key_image_5
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        22, //final_balance
        1, //final_legacy_fullscan_index

        12, //view_scan_expected_balance_after_intermediate_scan
        12, //view_scan_expected_balance_after_importing_key_images
        12, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 3: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}}, {sp_destination}, ledger_context);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_4.onetime_address,
            legacy_enote_5.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_4,
            legacy_key_image_5
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        32, //final_balance
        1, //final_legacy_fullscan_index

        22, //view_scan_expected_balance_after_intermediate_scan
        22, //view_scan_expected_balance_after_importing_key_images
        22, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 4: send all to random
    transfer_funds_single_mock_v1_unconfirmed(legacy_keys,
        sp_keys,
        input_selector,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{32, sp_destination_random, TxExtra{}}},
        legacy_ring_size,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);
    ledger_context.commit_unconfirmed_txs_v1(rct::pkGen(), rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteVariant>{});

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_4.onetime_address,
            legacy_enote_5.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_4,
            legacy_key_image_5
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        0, //final_balance
        1, //final_legacy_fullscan_index

        32, //view_scan_expected_balance_after_intermediate_scan
        32, //view_scan_expected_balance_after_importing_key_images
        32, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);


    //remove blocks 0, 1, 2, 3, 4
    ledger_context.pop_blocks(5);

    //no recovery: pop then add a block to see what happens

    //block 0: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}}, {sp_destination}, ledger_context);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {}, //re_view_scan_legacy_onetime_addresses_expected
        {}, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        10, //final_balance
        0, //final_legacy_fullscan_index

        0, //view_scan_expected_balance_after_intermediate_scan
        0, //view_scan_expected_balance_after_importing_key_images
        0, //view_scan_expected_balance_after_keyimage_refresh

        0, //re_view_scan_expected_balance_after_intermediate_scan
        0, //re_view_scan_expected_balance_after_importing_key_images
        0, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 1: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}}, {sp_destination}, ledger_context);

    //legacy scan
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 10);

    //pop block 1
    ledger_context.pop_blocks(1);

    //seraphis scan
    refresh_user_enote_store(sp_keys, refresh_config, ledger_context, enote_store_full);

    ASSERT_TRUE(get_balance(enote_store_full, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 10);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {}, //re_view_scan_legacy_onetime_addresses_expected
        {}, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        10, //final_balance
        0, //final_legacy_fullscan_index

        10, //view_scan_expected_balance_after_intermediate_scan
        10, //view_scan_expected_balance_after_importing_key_images
        10, //view_scan_expected_balance_after_keyimage_refresh

        0, //re_view_scan_expected_balance_after_intermediate_scan
        0, //re_view_scan_expected_balance_after_importing_key_images
        0, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 1: legacy enote 4, legacy enote 5 (reuse these)
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_4,
            {},
            {
                legacy_enote_4,
                legacy_enote_5
            }
        ));

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {
            legacy_enote_4.onetime_address,
            legacy_enote_5.onetime_address
        }, //view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_4,
            legacy_key_image_5
        }, //view_scan_legacy_key_images_expected

        {
            legacy_enote_4.onetime_address,
            legacy_enote_5.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_4,
            legacy_key_image_5
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        12, //final_balance
        1, //final_legacy_fullscan_index

        12, //view_scan_expected_balance_after_intermediate_scan
        12, //view_scan_expected_balance_after_importing_key_images
        12, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 2: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}}, {sp_destination}, ledger_context);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_4.onetime_address,
            legacy_enote_5.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_4,
            legacy_key_image_5
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        22, //final_balance
        1, //final_legacy_fullscan_index

        12, //view_scan_expected_balance_after_intermediate_scan
        12, //view_scan_expected_balance_after_importing_key_images
        12, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 3: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}}, {sp_destination}, ledger_context);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_4.onetime_address,
            legacy_enote_5.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_4,
            legacy_key_image_5
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        32, //final_balance
        1, //final_legacy_fullscan_index

        22, //view_scan_expected_balance_after_intermediate_scan
        22, //view_scan_expected_balance_after_importing_key_images
        22, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 4: send all to random
    transfer_funds_single_mock_v1_unconfirmed(legacy_keys,
        sp_keys,
        input_selector,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{32, sp_destination_random, TxExtra{}}},
        legacy_ring_size,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);
    ledger_context.commit_unconfirmed_txs_v1(rct::pkGen(), rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteVariant>{});

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_4.onetime_address,
            legacy_enote_5.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_4,
            legacy_key_image_5
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        0, //final_balance
        1, //final_legacy_fullscan_index

        32, //view_scan_expected_balance_after_intermediate_scan
        32, //view_scan_expected_balance_after_importing_key_images
        32, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);


    //remove blocks 2, 3, 4
    ledger_context.pop_blocks(3);

    //no recovery: pop then add a block to see what happens

    //block 2: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}}, {sp_destination}, ledger_context);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_4.onetime_address,
            legacy_enote_5.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_4,
            legacy_key_image_5
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        22, //final_balance
        1, //final_legacy_fullscan_index

        0, //view_scan_expected_balance_after_intermediate_scan
        0, //view_scan_expected_balance_after_importing_key_images
        0, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 3: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}}, {sp_destination}, ledger_context);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_4.onetime_address,
            legacy_enote_5.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_4,
            legacy_key_image_5
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        32, //final_balance
        1, //final_legacy_fullscan_index

        22, //view_scan_expected_balance_after_intermediate_scan
        22, //view_scan_expected_balance_after_importing_key_images
        22, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 4: send all to random
    transfer_funds_single_mock_v1_unconfirmed(legacy_keys,
        sp_keys,
        input_selector,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{32, sp_destination_random, TxExtra{}}},
        legacy_ring_size,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);
    ledger_context.commit_unconfirmed_txs_v1(rct::pkGen(), rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteVariant>{});

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_4.onetime_address,
            legacy_enote_5.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_4,
            legacy_key_image_5
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        0, //final_balance
        1, //final_legacy_fullscan_index

        32, //view_scan_expected_balance_after_intermediate_scan
        32, //view_scan_expected_balance_after_importing_key_images
        32, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, legacy_sp_transition_2)
{
/*
    - test 2:
        - [first sp allowed: 1, first sp only: 3, chunk size: 2]
        - 0: legacy
        - 1: legacy
        - 2: sp
            - fresh enote store: seraphis scan should throw if this line in mock ledger context is changed to > 0
                if (chunk_start_adjusted > m_first_seraphis_allowed_block)
        - 3: sp
        - 4: sp
        - 5: send all to B
        - pop 4
        //don't scan
        - 1: sp
        //scan
        - 2: legacy
        - 3: sp
        - 4: sp
        - 5: send all to B
        - pop 5
        - 1: sp
        - 2: sp
        - 3: sp
        - 4: sp
        - 5: send all to B
        - pop 3
        - 3: sp
        - 4: sp
*/

    /// setup

    // 1. config
    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 2,
            .max_partialscan_attempts = 0
        };

    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{0};  // 0 fee here
    const std::size_t legacy_ring_size{2};
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator here (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .bin_radius = 1,
            .num_bin_members = 2
        };

    const std::uint64_t first_sp_allowed_block{1};
    const std::uint64_t first_sp_only_block{3};

    // 2. legacy user keys
    legacy_mock_keys legacy_keys;
    make_legacy_mock_keys(legacy_keys);

    // 3. user legacy subaddress
    rct::key subaddr_spendkey;
    rct::key subaddr_viewkey;
    cryptonote::subaddress_index subaddr_index;

    gen_legacy_subaddress(legacy_keys.Ks, legacy_keys.k_v, subaddr_spendkey, subaddr_viewkey, subaddr_index);

    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;
    legacy_subaddress_map[subaddr_spendkey] = subaddr_index;

    // 4. seraphis user keys
    jamtis_mock_keys sp_keys;
    make_jamtis_mock_keys(sp_keys);

    // 5. user seraphis address
    JamtisDestinationV1 sp_destination;
    make_random_address_for_user(sp_keys, sp_destination);

    // 6. random user address
    JamtisDestinationV1 sp_destination_random;
    sp_destination_random = gen_jamtis_destination_v1();


    /// test

    // 2. legacy in pre-transition zone into mixed seraphis/legacy enotes in transition zone
    MockLedgerContext ledger_context{first_sp_allowed_block, first_sp_only_block};
    SpEnoteStore enote_store_full{0, first_sp_allowed_block, 0};
    SpEnoteStore enote_store_view{0, first_sp_allowed_block, 0};
    InputSelectorMockV1 input_selector{enote_store_full};

    //make two legacy enotes
    LegacyEnoteV5 legacy_enote_1;
    rct::key legacy_enote_ephemeral_pubkey_1;
    crypto::key_image legacy_key_image_1;
    LegacyEnoteV5 legacy_enote_2;
    rct::key legacy_enote_ephemeral_pubkey_2;
    crypto::key_image legacy_key_image_2;

    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        1,  //amount
        0,  //index in planned mock coinbase tx (block 0)
        make_secret_key(),
        legacy_enote_1,
        legacy_enote_ephemeral_pubkey_1,
        legacy_key_image_1);
    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        1,  //amount
        1,  //index in planned mock coinbase tx (block 0)
        make_secret_key(),
        legacy_enote_2,
        legacy_enote_ephemeral_pubkey_2,
        legacy_key_image_2);

    TxExtra tx_extra_1;
    ASSERT_TRUE(try_append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                legacy_enote_ephemeral_pubkey_1,
                legacy_enote_ephemeral_pubkey_2
            },
            tx_extra_1
        ));

    //block 0: legacy enote 1, legacy enote 2
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_1,
            {},
            {
                legacy_enote_1,
                legacy_enote_2
            }
        ));

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        2, //final_balance
        0, //final_legacy_fullscan_index

        2, //view_scan_expected_balance_after_intermediate_scan
        2, //view_scan_expected_balance_after_importing_key_images
        2, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //make legacy enote 3
    LegacyEnoteV5 legacy_enote_3;
    rct::key legacy_enote_ephemeral_pubkey_3;
    crypto::key_image legacy_key_image_3;

    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        2,  //amount
        0,  //index in planned mock coinbase tx
        make_secret_key(),
        legacy_enote_3,
        legacy_enote_ephemeral_pubkey_3,
        legacy_key_image_3);

    TxExtra tx_extra_2;
    ASSERT_TRUE(try_append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                legacy_enote_ephemeral_pubkey_3
            },
            tx_extra_2
        ));

    //block 1: legacy enote 3, spend legacy enote 2
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_2,
            {
                legacy_key_image_2
            },
            {
                legacy_enote_3
            }
        ));

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {
            legacy_enote_3.onetime_address
        }, //view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_3
        }, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address,
            legacy_enote_3.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2,
            legacy_key_image_3
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        3, //final_balance
        1, //final_legacy_fullscan_index

        3, //view_scan_expected_balance_after_intermediate_scan
        3, //view_scan_expected_balance_after_importing_key_images
        3, //view_scan_expected_balance_after_keyimage_refresh

        4, //re_view_scan_expected_balance_after_intermediate_scan
        4, //re_view_scan_expected_balance_after_importing_key_images
        3, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 2: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}, {0, 0, 0}}, {sp_destination, sp_destination_random}, ledger_context);

    //test recovery
    //seraphis scan should throw if this line in mock ledger context is changed to '> 0'
    //            if (chunk_start_adjusted > m_first_seraphis_allowed_block)
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address,
            legacy_enote_3.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2,
            legacy_key_image_3
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        13, //final_balance
        2, //final_legacy_fullscan_index

        3, //view_scan_expected_balance_after_intermediate_scan
        3, //view_scan_expected_balance_after_importing_key_images
        3, //view_scan_expected_balance_after_keyimage_refresh

        4, //re_view_scan_expected_balance_after_intermediate_scan
        4, //re_view_scan_expected_balance_after_importing_key_images
        3, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 3: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}}, {sp_destination}, ledger_context);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address,
            legacy_enote_3.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2,
            legacy_key_image_3
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        23, //final_balance
        2, //final_legacy_fullscan_index

        13, //view_scan_expected_balance_after_intermediate_scan
        13, //view_scan_expected_balance_after_importing_key_images
        13, //view_scan_expected_balance_after_keyimage_refresh

        4, //re_view_scan_expected_balance_after_intermediate_scan
        4, //re_view_scan_expected_balance_after_importing_key_images
        3, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 4: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}}, {sp_destination}, ledger_context);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address,
            legacy_enote_3.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2,
            legacy_key_image_3
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        33, //final_balance
        2, //final_legacy_fullscan_index

        23, //view_scan_expected_balance_after_intermediate_scan
        23, //view_scan_expected_balance_after_importing_key_images
        23, //view_scan_expected_balance_after_keyimage_refresh

        4, //re_view_scan_expected_balance_after_intermediate_scan
        4, //re_view_scan_expected_balance_after_importing_key_images
        3, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 5: send all to random
    transfer_funds_single_mock_v1_unconfirmed(legacy_keys,
        sp_keys,
        input_selector,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{33, sp_destination_random, TxExtra{}}},
        legacy_ring_size,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);
    ledger_context.commit_unconfirmed_txs_v1(rct::pkGen(), rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteVariant>{});

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address,
            legacy_enote_3.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2,
            legacy_key_image_3
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        0, //final_balance
        2, //final_legacy_fullscan_index

        33, //view_scan_expected_balance_after_intermediate_scan
        33, //view_scan_expected_balance_after_importing_key_images
        33, //view_scan_expected_balance_after_keyimage_refresh

        4, //re_view_scan_expected_balance_after_intermediate_scan
        4, //re_view_scan_expected_balance_after_importing_key_images
        3, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);


    //remove blocks 1, 2, 3, 4, 5
    ledger_context.pop_blocks(5);

    //no recovery: pop then add a block to see what happens

    //block 1: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}, {0, 0, 0}}, {sp_destination, sp_destination_random}, ledger_context);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        12, //final_balance
        1, //final_legacy_fullscan_index

        //note: legacy key images in seraphis txs removed by reorgs are only cleaned in seraphis scans, so if legacy
        //      scanning after a reorg then it will look like legacy enotes older than the reorg are still spent
        1, //view_scan_expected_balance_after_intermediate_scan
        1, //view_scan_expected_balance_after_importing_key_images
        1, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 2: legacy enote 3, spend legacy enote 1
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_2,
            {
                legacy_key_image_1
            },
            {
                legacy_enote_3
            }
        ));

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {
            legacy_enote_3.onetime_address
        }, //view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_3
        }, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address,
            legacy_enote_3.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2,
            legacy_key_image_3
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        13, //final_balance
        2, //final_legacy_fullscan_index

        13, //view_scan_expected_balance_after_intermediate_scan
        13, //view_scan_expected_balance_after_importing_key_images
        13, //view_scan_expected_balance_after_keyimage_refresh

        4, //re_view_scan_expected_balance_after_intermediate_scan
        4, //re_view_scan_expected_balance_after_importing_key_images
        3, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 3: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}}, {sp_destination}, ledger_context);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address,
            legacy_enote_3.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2,
            legacy_key_image_3
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        23, //final_balance
        2, //final_legacy_fullscan_index

        13, //view_scan_expected_balance_after_intermediate_scan
        13, //view_scan_expected_balance_after_importing_key_images
        13, //view_scan_expected_balance_after_keyimage_refresh

        4, //re_view_scan_expected_balance_after_intermediate_scan
        4, //re_view_scan_expected_balance_after_importing_key_images
        3, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 4: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}}, {sp_destination}, ledger_context);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address,
            legacy_enote_3.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2,
            legacy_key_image_3
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        33, //final_balance
        2, //final_legacy_fullscan_index

        23, //view_scan_expected_balance_after_intermediate_scan
        23, //view_scan_expected_balance_after_importing_key_images
        23, //view_scan_expected_balance_after_keyimage_refresh

        4, //re_view_scan_expected_balance_after_intermediate_scan
        4, //re_view_scan_expected_balance_after_importing_key_images
        3, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 5: send all to random
    transfer_funds_single_mock_v1_unconfirmed(legacy_keys,
        sp_keys,
        input_selector,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{33, sp_destination_random, TxExtra{}}},
        legacy_ring_size,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);
    ledger_context.commit_unconfirmed_txs_v1(rct::pkGen(), rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteVariant>{});

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address,
            legacy_enote_3.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2,
            legacy_key_image_3
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        0, //final_balance
        2, //final_legacy_fullscan_index

        33, //view_scan_expected_balance_after_intermediate_scan
        33, //view_scan_expected_balance_after_importing_key_images
        33, //view_scan_expected_balance_after_keyimage_refresh

        4, //re_view_scan_expected_balance_after_intermediate_scan
        4, //re_view_scan_expected_balance_after_importing_key_images
        3, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);


    //remove blocks 1, 2, 3, 4, 5
    ledger_context.pop_blocks(5);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        2, //final_balance
        0, //final_legacy_fullscan_index

        1, //view_scan_expected_balance_after_intermediate_scan
        1, //view_scan_expected_balance_after_importing_key_images
        1, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 1: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}}, {sp_destination}, ledger_context);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        12, //final_balance
        1, //final_legacy_fullscan_index

        2, //view_scan_expected_balance_after_intermediate_scan
        2, //view_scan_expected_balance_after_importing_key_images
        2, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 2: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}}, {sp_destination}, ledger_context);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        22, //final_balance
        2, //final_legacy_fullscan_index

        12, //view_scan_expected_balance_after_intermediate_scan
        12, //view_scan_expected_balance_after_importing_key_images
        12, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 3: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}}, {sp_destination}, ledger_context);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        32, //final_balance
        2, //final_legacy_fullscan_index

        22, //view_scan_expected_balance_after_intermediate_scan
        22, //view_scan_expected_balance_after_importing_key_images
        22, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 4: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}}, {sp_destination}, ledger_context);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        42, //final_balance
        2, //final_legacy_fullscan_index

        32, //view_scan_expected_balance_after_intermediate_scan
        32, //view_scan_expected_balance_after_importing_key_images
        32, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 5: send all to random
    transfer_funds_single_mock_v1_unconfirmed(legacy_keys,
        sp_keys,
        input_selector,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{42, sp_destination_random, TxExtra{}}},
        legacy_ring_size,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);
    ledger_context.commit_unconfirmed_txs_v1(rct::pkGen(), rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteVariant>{});

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        0, //final_balance
        2, //final_legacy_fullscan_index

        42, //view_scan_expected_balance_after_intermediate_scan
        42, //view_scan_expected_balance_after_importing_key_images
        42, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);


    //remove blocks 3, 4, 5
    ledger_context.pop_blocks(3);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        22, //final_balance
        2, //final_legacy_fullscan_index

        0, //view_scan_expected_balance_after_intermediate_scan
        0, //view_scan_expected_balance_after_importing_key_images
        0, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 3: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}}, {sp_destination}, ledger_context);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        32, //final_balance
        2, //final_legacy_fullscan_index

        22, //view_scan_expected_balance_after_intermediate_scan
        22, //view_scan_expected_balance_after_importing_key_images
        22, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 4: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}}, {sp_destination}, ledger_context);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        42, //final_balance
        2, //final_legacy_fullscan_index

        32, //view_scan_expected_balance_after_intermediate_scan
        32, //view_scan_expected_balance_after_importing_key_images
        32, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, legacy_sp_transition_3)
{
/*
    - test 3:
        - [first sp allowed: 1, first sp only: 1, chunk size: 1]
        - 0: legacy
        - 1: sp
        - 2: sp
        - pop 3
        //don't scan
        - 0: legacy
        //scan
        - 1: sp
        - 2: sp
        - pop 2
        //don't scan
        - 1: sp
        //scan
        - 2: sp
        - pop 2
        //scan
        - 1: sp
        //scan
        - 2: sp
*/

    /// setup

    // 1. config
    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 1,
            .max_partialscan_attempts = 0
        };

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator here (fee = fee/weight * 1 weight)

    const std::uint64_t first_sp_allowed_block{1};
    const std::uint64_t first_sp_only_block{1};

    // 2. legacy user keys
    legacy_mock_keys legacy_keys;
    make_legacy_mock_keys(legacy_keys);

    // 3. user legacy subaddress
    rct::key subaddr_spendkey;
    rct::key subaddr_viewkey;
    cryptonote::subaddress_index subaddr_index;

    gen_legacy_subaddress(legacy_keys.Ks, legacy_keys.k_v, subaddr_spendkey, subaddr_viewkey, subaddr_index);

    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;
    legacy_subaddress_map[subaddr_spendkey] = subaddr_index;

    // 4. seraphis user keys
    jamtis_mock_keys sp_keys;
    make_jamtis_mock_keys(sp_keys);

    // 5. user seraphis address
    JamtisDestinationV1 sp_destination;
    make_random_address_for_user(sp_keys, sp_destination);

    // 6. random user address
    JamtisDestinationV1 sp_destination_random;
    sp_destination_random = gen_jamtis_destination_v1();


    /// test

    // 3. pop into the pre-transition zone
    MockLedgerContext ledger_context{first_sp_allowed_block, first_sp_only_block};
    SpEnoteStore enote_store_full{0, first_sp_allowed_block, 0};
    SpEnoteStore enote_store_view{0, first_sp_allowed_block, 0};
    InputSelectorMockV1 input_selector{enote_store_full};

    //make one legacy enote
    LegacyEnoteV5 legacy_enote_1;
    rct::key legacy_enote_ephemeral_pubkey_1;
    crypto::key_image legacy_key_image_1;

    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        1,  //amount
        0,  //index in planned mock coinbase tx (block 0)
        make_secret_key(),
        legacy_enote_1,
        legacy_enote_ephemeral_pubkey_1,
        legacy_key_image_1);

    TxExtra tx_extra_1;
    ASSERT_TRUE(try_append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                legacy_enote_ephemeral_pubkey_1
            },
            tx_extra_1
        ));

    //block 0: legacy enote 1
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_1,
            {},
            {
                legacy_enote_1
            }
        ));

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {
            legacy_enote_1.onetime_address
        }, //view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1
        }, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        1, //final_balance
        0, //final_legacy_fullscan_index

        1, //view_scan_expected_balance_after_intermediate_scan
        1, //view_scan_expected_balance_after_importing_key_images
        1, //view_scan_expected_balance_after_keyimage_refresh

        1, //re_view_scan_expected_balance_after_intermediate_scan
        1, //re_view_scan_expected_balance_after_importing_key_images
        1, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 1: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}, {0, 0, 0}}, {sp_destination, sp_destination_random}, ledger_context);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        11, //final_balance
        0, //final_legacy_fullscan_index

        1, //view_scan_expected_balance_after_intermediate_scan
        1, //view_scan_expected_balance_after_importing_key_images
        1, //view_scan_expected_balance_after_keyimage_refresh

        1, //re_view_scan_expected_balance_after_intermediate_scan
        1, //re_view_scan_expected_balance_after_importing_key_images
        1, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 2: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}, {0, 0, 0}}, {sp_destination, sp_destination_random}, ledger_context);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        21, //final_balance
        0, //final_legacy_fullscan_index

        11, //view_scan_expected_balance_after_intermediate_scan
        11, //view_scan_expected_balance_after_importing_key_images
        11, //view_scan_expected_balance_after_keyimage_refresh

        1, //re_view_scan_expected_balance_after_intermediate_scan
        1, //re_view_scan_expected_balance_after_importing_key_images
        1, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);


    //remove blocks 0, 1, 2
    ledger_context.pop_blocks(3);

    //don't scan

    //block 0: legacy enote 1
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_1,
            {},
            {
                legacy_enote_1
            }
        ));

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {
            legacy_enote_1.onetime_address
        }, //view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1
        }, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        1, //final_balance
        0, //final_legacy_fullscan_index

        21, //view_scan_expected_balance_after_intermediate_scan
        21, //view_scan_expected_balance_after_importing_key_images
        21, //view_scan_expected_balance_after_keyimage_refresh

        1, //re_view_scan_expected_balance_after_intermediate_scan
        1, //re_view_scan_expected_balance_after_importing_key_images
        1, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 1: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}, {0, 0, 0}}, {sp_destination, sp_destination_random}, ledger_context);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        11, //final_balance
        0, //final_legacy_fullscan_index

        1, //view_scan_expected_balance_after_intermediate_scan
        1, //view_scan_expected_balance_after_importing_key_images
        1, //view_scan_expected_balance_after_keyimage_refresh

        1, //re_view_scan_expected_balance_after_intermediate_scan
        1, //re_view_scan_expected_balance_after_importing_key_images
        1, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 2: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}, {0, 0, 0}}, {sp_destination, sp_destination_random}, ledger_context);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        21, //final_balance
        0, //final_legacy_fullscan_index

        11, //view_scan_expected_balance_after_intermediate_scan
        11, //view_scan_expected_balance_after_importing_key_images
        11, //view_scan_expected_balance_after_keyimage_refresh

        1, //re_view_scan_expected_balance_after_intermediate_scan
        1, //re_view_scan_expected_balance_after_importing_key_images
        1, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);


    //remove blocks 1, 2
    ledger_context.pop_blocks(2);

    //don't scan

    //block 1: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}, {0, 0, 0}}, {sp_destination, sp_destination_random}, ledger_context);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        11, //final_balance
        0, //final_legacy_fullscan_index

        21, //view_scan_expected_balance_after_intermediate_scan
        21, //view_scan_expected_balance_after_importing_key_images
        21, //view_scan_expected_balance_after_keyimage_refresh

        1, //re_view_scan_expected_balance_after_intermediate_scan
        1, //re_view_scan_expected_balance_after_importing_key_images
        1, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 2: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}, {0, 0, 0}}, {sp_destination, sp_destination_random}, ledger_context);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        21, //final_balance
        0, //final_legacy_fullscan_index

        11, //view_scan_expected_balance_after_intermediate_scan
        11, //view_scan_expected_balance_after_importing_key_images
        11, //view_scan_expected_balance_after_keyimage_refresh

        1, //re_view_scan_expected_balance_after_intermediate_scan
        1, //re_view_scan_expected_balance_after_importing_key_images
        1, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);


    //remove blocks 1, 2
    ledger_context.pop_blocks(2);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        1, //final_balance
        0, //final_legacy_fullscan_index

        21, //view_scan_expected_balance_after_intermediate_scan
        21, //view_scan_expected_balance_after_importing_key_images
        21, //view_scan_expected_balance_after_keyimage_refresh

        1, //re_view_scan_expected_balance_after_intermediate_scan
        1, //re_view_scan_expected_balance_after_importing_key_images
        1, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 1: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}, {0, 0, 0}}, {sp_destination, sp_destination_random}, ledger_context);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        11, //final_balance
        0, //final_legacy_fullscan_index

        1, //view_scan_expected_balance_after_intermediate_scan
        1, //view_scan_expected_balance_after_importing_key_images
        1, //view_scan_expected_balance_after_keyimage_refresh

        1, //re_view_scan_expected_balance_after_intermediate_scan
        1, //re_view_scan_expected_balance_after_importing_key_images
        1, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 2: seraphis amount 10
    send_sp_coinbase_amounts_to_users({{10}, {0, 0, 0}}, {sp_destination, sp_destination_random}, ledger_context);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        21, //final_balance
        0, //final_legacy_fullscan_index

        11, //view_scan_expected_balance_after_intermediate_scan
        11, //view_scan_expected_balance_after_importing_key_images
        11, //view_scan_expected_balance_after_keyimage_refresh

        1, //re_view_scan_expected_balance_after_intermediate_scan
        1, //re_view_scan_expected_balance_after_importing_key_images
        1, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, legacy_sp_transition_4)
{
/*
    - test 4:
        - [first sp allowed: 0, first sp only: 2, chunk size: 2]
        - 0: legacy x2
        - 1: spend legacy
        - pop 1
        //don't scan
        - 1: send all to random with seraphis tx
        //scan
        //scan
        - pop 1
        //scan
        //scan
        - 1: send all to self with seraphis tx
        //scan
        - pop 1
        //don't scan
        - 1: spend legacy
        //scan
        //scan
*/

    /// setup

    // 1. config
    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 2,
            .max_partialscan_attempts = 0
        };

    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{0};  // 0 fee here
    const std::size_t legacy_ring_size{2};
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator here (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .bin_radius = 1,
            .num_bin_members = 2
        };

    const std::uint64_t first_sp_allowed_block{0};
    const std::uint64_t first_sp_only_block{2};

    // 2. legacy user keys
    legacy_mock_keys legacy_keys;
    make_legacy_mock_keys(legacy_keys);

    // 3. user legacy subaddress
    rct::key subaddr_spendkey;
    rct::key subaddr_viewkey;
    cryptonote::subaddress_index subaddr_index;

    gen_legacy_subaddress(legacy_keys.Ks, legacy_keys.k_v, subaddr_spendkey, subaddr_viewkey, subaddr_index);

    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;
    legacy_subaddress_map[subaddr_spendkey] = subaddr_index;

    // 4. seraphis user keys
    jamtis_mock_keys sp_keys;
    make_jamtis_mock_keys(sp_keys);

    // 5. user seraphis address
    JamtisDestinationV1 sp_destination;
    make_random_address_for_user(sp_keys, sp_destination);

    // 6. random user address
    JamtisDestinationV1 sp_destination_random;
    sp_destination_random = gen_jamtis_destination_v1();


    /// test

    // 4. legacy spends legacy X, then pop the spender and spend legacy X again in a seraphis tx
    MockLedgerContext ledger_context{first_sp_allowed_block, first_sp_only_block};
    SpEnoteStore enote_store_full{0, first_sp_allowed_block, 0};
    SpEnoteStore enote_store_view{0, first_sp_allowed_block, 0};
    InputSelectorMockV1 input_selector{enote_store_full};

    SpEnoteStore enote_store_temp{0, first_sp_allowed_block, 0};
    InputSelectorMockV1 input_selector_temp{enote_store_temp};

    //make two legacy enotes
    LegacyEnoteV5 legacy_enote_1;
    rct::key legacy_enote_ephemeral_pubkey_1;
    crypto::key_image legacy_key_image_1;
    LegacyEnoteV5 legacy_enote_2;
    rct::key legacy_enote_ephemeral_pubkey_2;
    crypto::key_image legacy_key_image_2;

    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        1,  //amount
        0,  //index in planned mock coinbase tx
        make_secret_key(),
        legacy_enote_1,
        legacy_enote_ephemeral_pubkey_1,
        legacy_key_image_1);
    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        1,  //amount
        1,  //index in planned mock coinbase tx
        make_secret_key(),
        legacy_enote_2,
        legacy_enote_ephemeral_pubkey_2,
        legacy_key_image_2);

    TxExtra tx_extra_1;
    ASSERT_TRUE(try_append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                legacy_enote_ephemeral_pubkey_1,
                legacy_enote_ephemeral_pubkey_2
            },
            tx_extra_1
        ));

    //block 0: legacy enote 1, legacy enote 2
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_1,
            {},
            {
                legacy_enote_1,
                legacy_enote_2
            }
        ));

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        2, //final_balance
        0, //final_legacy_fullscan_index

        2, //view_scan_expected_balance_after_intermediate_scan
        2, //view_scan_expected_balance_after_importing_key_images
        2, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //make legacy enote 3
    LegacyEnoteV5 legacy_enote_3;
    rct::key legacy_enote_ephemeral_pubkey_3;
    crypto::key_image legacy_key_image_3;

    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        2,  //amount
        0,  //index in planned mock coinbase tx
        make_secret_key(),
        legacy_enote_3,
        legacy_enote_ephemeral_pubkey_3,
        legacy_key_image_3);

    TxExtra tx_extra_2;
    ASSERT_TRUE(try_append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                legacy_enote_ephemeral_pubkey_3
            },
            tx_extra_2
        ));

    //block 1: legacy enote 3, spend legacy enote 2
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_2,
            {
                legacy_key_image_2
            },
            {
                legacy_enote_3
            }
        ));

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {
            legacy_enote_3.onetime_address
        }, //view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_3
        }, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address,
            legacy_enote_3.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2,
            legacy_key_image_3
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        3, //final_balance
        1, //final_legacy_fullscan_index

        3, //view_scan_expected_balance_after_intermediate_scan
        3, //view_scan_expected_balance_after_importing_key_images
        3, //view_scan_expected_balance_after_keyimage_refresh

        4, //re_view_scan_expected_balance_after_intermediate_scan
        4, //re_view_scan_expected_balance_after_importing_key_images
        3, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);


    //remove block 1
    ledger_context.pop_blocks(1);

    //don't scan

    //block 1: send all to random (use temporary enote store)
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store_temp);

    transfer_funds_single_mock_v1_unconfirmed(legacy_keys,
        sp_keys,
        input_selector_temp,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{2, sp_destination_random, TxExtra{}}},
        legacy_ring_size,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);
    ledger_context.commit_unconfirmed_txs_v1(rct::pkGen(), rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteVariant>{});

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        0, //final_balance
        1, //final_legacy_fullscan_index

        2, //view_scan_expected_balance_after_intermediate_scan
        2, //view_scan_expected_balance_after_importing_key_images
        2, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        0, //final_balance
        1, //final_legacy_fullscan_index

        0, //view_scan_expected_balance_after_intermediate_scan
        0, //view_scan_expected_balance_after_importing_key_images
        0, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);


    //remove block 1
    ledger_context.pop_blocks(1);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        2, //final_balance
        0, //final_legacy_fullscan_index

        0, //view_scan_expected_balance_after_intermediate_scan
        0, //view_scan_expected_balance_after_importing_key_images
        0, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        2, //final_balance
        0, //final_legacy_fullscan_index

        2, //view_scan_expected_balance_after_intermediate_scan
        2, //view_scan_expected_balance_after_importing_key_images
        2, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 1: churn all to self
    transfer_funds_single_mock_v1_unconfirmed(legacy_keys,
        sp_keys,
        input_selector,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{2, sp_destination, TxExtra{}}},
        legacy_ring_size,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);
    ledger_context.commit_unconfirmed_txs_v1(rct::pkGen(), rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteVariant>{});

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        2, //final_balance
        1, //final_legacy_fullscan_index

        2, //view_scan_expected_balance_after_intermediate_scan
        2, //view_scan_expected_balance_after_importing_key_images
        2, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        2, //final_balance
        1, //final_legacy_fullscan_index

        2, //view_scan_expected_balance_after_intermediate_scan
        2, //view_scan_expected_balance_after_importing_key_images
        2, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);


    //remove block 1
    ledger_context.pop_blocks(1);

    //don't scan

    //block 1: legacy enote 1
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            TxExtra{},
            {
                legacy_key_image_1
            },
            {}
        ));

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        1, //final_balance
        1, //final_legacy_fullscan_index

        2, //view_scan_expected_balance_after_intermediate_scan
        2, //view_scan_expected_balance_after_importing_key_images
        2, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        1, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        1, //final_balance
        1, //final_legacy_fullscan_index

        1, //view_scan_expected_balance_after_intermediate_scan
        1, //view_scan_expected_balance_after_importing_key_images
        1, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        1, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, legacy_sp_transition_5)
{
/*
    - test 5:
        - [first sp allowed: 0, first sp only: 3, chunk size: 2]
        - 0: legacy x2
        - 1: legacy spend
        //scan
        - pop 1
        //don't scan
        - 1: sp
        //don't scan
        - 2: sp spend
        //scan
        //scan

        - pop 2
        - 1: sp spend legacy x2
            - scan fresh store: seraphis only
        //scan
        - pop 1
        //don't scan
        - 1: sp
        //don't scan
        - 2: legacy spend
            - scan fresh store: legacy intermediate; after importing key images the balance should be 0,
              then after key image refresh it is still 0 but one of the key images is marked spent by the legacy tx
        //scan
        //scan
        - pop 1
            - scan fresh store: legacy intermediate; reorg should remove spent context on key image spent by legacy tx,
              but not the remaining one spent by the seraphis tx from a while ago
            - scan fresh store: seraphis only; scan should remove spent context from the remaining legacy key image
*/

    /// setup

    // 1. config
    const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1,
            .max_chunk_size_hint = 2,
            .max_partialscan_attempts = 0
        };

    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{0};  // 0 fee here
    const std::size_t legacy_ring_size{2};
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator here (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .bin_radius = 1,
            .num_bin_members = 2
        };

    const std::uint64_t first_sp_allowed_block{0};
    const std::uint64_t first_sp_only_block{3};

    // 2. legacy user keys
    legacy_mock_keys legacy_keys;
    make_legacy_mock_keys(legacy_keys);

    // 3. user legacy subaddress
    rct::key subaddr_spendkey;
    rct::key subaddr_viewkey;
    cryptonote::subaddress_index subaddr_index;

    gen_legacy_subaddress(legacy_keys.Ks, legacy_keys.k_v, subaddr_spendkey, subaddr_viewkey, subaddr_index);

    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;
    legacy_subaddress_map[subaddr_spendkey] = subaddr_index;

    // 4. seraphis user keys
    jamtis_mock_keys sp_keys;
    make_jamtis_mock_keys(sp_keys);

    // 5. user seraphis address
    JamtisDestinationV1 sp_destination;
    make_random_address_for_user(sp_keys, sp_destination);

    // 6. random user address
    JamtisDestinationV1 sp_destination_random;
    sp_destination_random = gen_jamtis_destination_v1();


    /// test

    // 5. spend legacy X, then pop, add 1 block, spend legacy X in other tx type (between legacy, seraphis tx types)
    MockLedgerContext ledger_context{first_sp_allowed_block, first_sp_only_block};
    SpEnoteStore enote_store_full{0, first_sp_allowed_block, 0};
    SpEnoteStore enote_store_view{0, first_sp_allowed_block, 0};
    InputSelectorMockV1 input_selector{enote_store_full};

    SpEnoteStore enote_store_temp{0, first_sp_allowed_block, 0};
    InputSelectorMockV1 input_selector_temp{enote_store_temp};

    //make two legacy enotes
    LegacyEnoteV5 legacy_enote_1;
    rct::key legacy_enote_ephemeral_pubkey_1;
    crypto::key_image legacy_key_image_1;
    LegacyEnoteV5 legacy_enote_2;
    rct::key legacy_enote_ephemeral_pubkey_2;
    crypto::key_image legacy_key_image_2;

    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        1,  //amount
        0,  //index in planned mock coinbase tx
        make_secret_key(),
        legacy_enote_1,
        legacy_enote_ephemeral_pubkey_1,
        legacy_key_image_1);
    prepare_mock_v5_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        1,  //amount
        1,  //index in planned mock coinbase tx
        make_secret_key(),
        legacy_enote_2,
        legacy_enote_ephemeral_pubkey_2,
        legacy_key_image_2);

    TxExtra tx_extra_1;
    ASSERT_TRUE(try_append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                legacy_enote_ephemeral_pubkey_1,
                legacy_enote_ephemeral_pubkey_2
            },
            tx_extra_1
        ));

    //block 0: legacy enote 1, legacy enote 2
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_1,
            {},
            {
                legacy_enote_1,
                legacy_enote_2
            }
        ));

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        2, //final_balance
        0, //final_legacy_fullscan_index

        2, //view_scan_expected_balance_after_intermediate_scan
        2, //view_scan_expected_balance_after_importing_key_images
        2, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //block 1: legacy enote 1
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            TxExtra{},
            {
                legacy_key_image_1
            },
            {}
        ));

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        1, //final_balance
        1, //final_legacy_fullscan_index

        1, //view_scan_expected_balance_after_intermediate_scan
        1, //view_scan_expected_balance_after_importing_key_images
        1, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        1, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);


    //remove block 1
    ledger_context.pop_blocks(1);

    //don't scan

    //block 1: seraphis block
    send_sp_coinbase_amounts_to_users({{0}}, {sp_destination_random}, ledger_context);

    //don't scan

    //block 2: send all to random (use temporary enote store)
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store_temp);

    transfer_funds_single_mock_v1_unconfirmed(legacy_keys,
        sp_keys,
        input_selector_temp,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{2, sp_destination_random, TxExtra{}}},
        legacy_ring_size,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);
    ledger_context.commit_unconfirmed_txs_v1(rct::pkGen(), rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteVariant>{});

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        0, //final_balance
        2, //final_legacy_fullscan_index

        2, //view_scan_expected_balance_after_intermediate_scan
        2, //view_scan_expected_balance_after_importing_key_images
        2, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        0, //final_balance
        2, //final_legacy_fullscan_index

        0, //view_scan_expected_balance_after_intermediate_scan
        0, //view_scan_expected_balance_after_importing_key_images
        0, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);


    //remove blocks 1, 2
    ledger_context.pop_blocks(2);

    //don't scan

    //block 1: send all to random (use temporary enote store)
    refresh_user_enote_store_legacy_full(legacy_keys.Ks,
        legacy_subaddress_map,
        legacy_keys.k_s,
        legacy_keys.k_v,
        refresh_config,
        ledger_context,
        enote_store_temp);
    refresh_user_enote_store(sp_keys, refresh_config, ledger_context, enote_store_temp);

    transfer_funds_single_mock_v1_unconfirmed(legacy_keys,
        sp_keys,
        input_selector_temp,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{2, sp_destination_random, TxExtra{}}},
        legacy_ring_size,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);
    ledger_context.commit_unconfirmed_txs_v1(rct::pkGen(), rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteVariant>{});

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        0, //final_balance
        1, //final_legacy_fullscan_index

        0, //view_scan_expected_balance_after_intermediate_scan
        0, //view_scan_expected_balance_after_importing_key_images
        0, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        2, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //recover fresh enote store with seraphis-only scan
    SpEnoteStore enote_store_fresh{0, first_sp_allowed_block, 0};
    refresh_user_enote_store(sp_keys, refresh_config, ledger_context, enote_store_fresh);

    ASSERT_TRUE(get_balance(enote_store_fresh, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);

    //remove block 1
    ledger_context.pop_blocks(1);

    //don't scan

    //block 1: seraphis block
    send_sp_coinbase_amounts_to_users({{0}}, {sp_destination_random}, ledger_context);

    //don't scan

    //block 2: legacy enote 2
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            TxExtra{},
            {
                legacy_key_image_2
            },
            {}
        ));

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        1, //final_balance
        2, //final_legacy_fullscan_index

        0, //view_scan_expected_balance_after_intermediate_scan
        0, //view_scan_expected_balance_after_importing_key_images
        0, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        1, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //test recovery
    legacy_sp_transition_test_recovery_assertions(legacy_keys,
        legacy_subaddress_map,
        sp_keys,
        refresh_config,
        ledger_context,

        {}, //view_scan_legacy_onetime_addresses_expected
        {}, //view_scan_legacy_key_images_expected

        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //re_view_scan_legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //re_view_scan_legacy_key_images_expected

        first_sp_allowed_block, //first_sp_allowed_block

        1, //final_balance
        2, //final_legacy_fullscan_index

        1, //view_scan_expected_balance_after_intermediate_scan
        1, //view_scan_expected_balance_after_importing_key_images
        1, //view_scan_expected_balance_after_keyimage_refresh

        2, //re_view_scan_expected_balance_after_intermediate_scan
        2, //re_view_scan_expected_balance_after_importing_key_images
        1, //re_view_scan_expected_balance_after_keyimage_refresh

        enote_store_full,
        enote_store_view);

    //legacy intermediate balance recovery (fresh enote store): intermediate scan (find 2 legacy enotes)
    //legacy intermediate balance recovery (fresh enote store): import key images
    // - should expect key images found by seraphis scan to be used to set the spent context of intermediate records
    //   promoted to full
    //legacy intermediate balance recovery (fresh enote store): refresh key images
    // - should expect key image found in block 2 to be used to update the spent context of legacy enote 2, however
    //   legacy enote 1 should still have the spent context from the seraphis scan (can use debugger to verify this,
    //   but view-scan recovery after popping 1 block should also confirm it)
    legacy_view_scan_recovery_cycle(legacy_keys,
        legacy_subaddress_map,
        refresh_config,
        ledger_context,
        {
            legacy_enote_1.onetime_address,
            legacy_enote_2.onetime_address
        }, //legacy_onetime_addresses_expected
        {
            legacy_key_image_1,
            legacy_key_image_2
        }, //legacy_key_images_expected
        2, //expected_balance_after_intermediate_scan
        0, //expected_balance_after_importing
        0, //expected_balance_after_key_image_refresh
        2, //expected_final_legacy_fullscan_index
        enote_store_fresh);

    //remove block 2
    ledger_context.pop_blocks(1);

    //legacy intermediate balance recovery (fresh enote store): intermediate scan
    // - should expect reorg to remove spent context on legacy enote 2, but not on legacy enote 1 which still has the spent
    //   context from the seraphis scan
    //legacy intermediate balance recovery (fresh enote store): import key images (not needed, they are known)
    //legacy intermediate balance recovery (fresh enote store): refresh key images (not needed, no key images to import)
    legacy_view_scan_recovery_cycle(legacy_keys,
        legacy_subaddress_map,
        refresh_config,
        ledger_context,
        {}, //legacy_onetime_addresses_expected
        {}, //legacy_key_images_expected
        1, //expected_balance_after_intermediate_scan
        1, //expected_balance_after_importing
        1, //expected_balance_after_key_image_refresh
        1, //expected_final_legacy_fullscan_index
        enote_store_fresh);

    //seraphis scan (fresh enote store)
    // - now the spent context on legacy enote 1 should be cleared
    refresh_user_enote_store(sp_keys, refresh_config, ledger_context, enote_store_fresh);

    ASSERT_TRUE(get_balance(enote_store_fresh, {SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);
}
