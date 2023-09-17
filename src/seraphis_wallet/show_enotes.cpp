// Copyright (c) 2023, The Monero Project
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

// paired header
#include "seraphis_wallet/show_enotes.h"

// local headers
#include "common/util.h"
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_enote_utils.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_impl/enote_store.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/tx_builders_outputs.h"
#include "seraphis_main/tx_component_types.h"
#include "seraphis_wallet/transaction_history.h"
#include "seraphis_wallet/transaction_utils.h"
#include "string_tools.h"

// third party headers
#include <boost/optional/optional_io.hpp>

// standard headers


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_wallet"

using namespace std;
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static string sp_origin_status_to_string(SpEnoteOriginStatus status)
{
    switch (status)
    {
        case sp::SpEnoteOriginStatus::OFFCHAIN:
            return string("Off-chain");
        case sp::SpEnoteOriginStatus::ONCHAIN:
            return string("On-chain");
        case sp::SpEnoteOriginStatus::UNCONFIRMED:
            return string("Unconfirmed");
        default:
            return "";
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static string sp_spent_status_to_string(SpEnoteSpentStatus status)
{
    switch (status)
    {
        case sp::SpEnoteSpentStatus::UNSPENT:
            return string("Unspent");
        case sp::SpEnoteSpentStatus::SPENT_OFFCHAIN:
            return string("Spent off-chain");
        case sp::SpEnoteSpentStatus::SPENT_UNCONFIRMED:
            return string("Spent - pending");
        case sp::SpEnoteSpentStatus::SPENT_ONCHAIN:
            return string("Spent - confirmed");
        default:
            return "";
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static string sp_jamtis_enote_type_to_string(JamtisEnoteType type)
{
    switch (type)
    {
        case JamtisEnoteType::CHANGE:
            return string("Change");
        case JamtisEnoteType::DUMMY:
            return string("Dummy");
        case JamtisEnoteType::PLAIN:
            return string("Plain");
        case JamtisEnoteType::SELF_SPEND:
            return string("Self-spend");
        default:
            return "";
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static string sp_jamtis_enote_selfsend_type_to_string(JamtisSelfSendType type)
{
    switch (type)
    {
        case JamtisSelfSendType::CHANGE:
            return string("Change");
        case JamtisSelfSendType::SELF_SPEND:
            return string("Self-Spend");
        case JamtisSelfSendType::DUMMY:
            return string("Dummy");
        default:
            return "";
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool compare_block_timestamp(const ContextualRecordVariant &a, const ContextualRecordVariant &b)
{
    if (spent_context_ref(a).spent_status != spent_context_ref(b).spent_status)
    {
        if (spent_context_ref(a).spent_status == sp::SpEnoteSpentStatus::UNSPENT)
            return true;
        else
            return false;
    }
    else
        return spent_context_ref(a).block_timestamp > spent_context_ref(b).block_timestamp;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool compare_block_timestamp_in(const ContextualRecordVariant &a, const ContextualRecordVariant &b)
{
    return origin_context_ref(a).block_timestamp > origin_context_ref(b).block_timestamp;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool compare_block_timestamp_out(const ContextualRecordVariant &a, const ContextualRecordVariant &b)
{
    return spent_context_ref(a).block_timestamp > spent_context_ref(b).block_timestamp;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void filter_all(const ContextualRecordVariant &enote,
    const pair<uint64_t, uint64_t> range_height,
    vector<ContextualRecordVariant> &vec_out)
{
    if (origin_context_ref(enote).block_index >= range_height.first &&
        (spent_context_ref(enote).block_index <= range_height.second ||
            spent_context_ref(enote).spent_status == sp::SpEnoteSpentStatus::UNSPENT))
        vec_out.push_back(enote);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void filter_in(const ContextualRecordVariant &enote,
    const pair<uint64_t, uint64_t> range_height,
    vector<ContextualRecordVariant> &vec_out)
{
    if (spent_context_ref(enote).spent_status == sp::SpEnoteSpentStatus::UNSPENT &&
        origin_context_ref(enote).origin_status == sp::SpEnoteOriginStatus::ONCHAIN &&
        origin_context_ref(enote).block_index >= range_height.first &&
        origin_context_ref(enote).block_index <= range_height.second)
        vec_out.push_back(enote);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void filter_in_pool(const ContextualRecordVariant &enote,
    const pair<uint64_t, uint64_t> range_height,
    vector<ContextualRecordVariant> &vec_out)
{
    if (spent_context_ref(enote).spent_status == sp::SpEnoteSpentStatus::UNSPENT &&
        origin_context_ref(enote).origin_status == sp::SpEnoteOriginStatus::UNCONFIRMED)
        vec_out.push_back(enote);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void filter_in_offchain(const ContextualRecordVariant &enote,
    const pair<uint64_t, uint64_t> range_height,
    vector<ContextualRecordVariant> &vec_out)
{
    if (spent_context_ref(enote).spent_status == sp::SpEnoteSpentStatus::UNSPENT &&
        origin_context_ref(enote).origin_status == sp::SpEnoteOriginStatus::OFFCHAIN)
        vec_out.push_back(enote);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void filter_out(const ContextualRecordVariant &enote,
    const pair<uint64_t, uint64_t> range_height,
    vector<ContextualRecordVariant> &vec_out)
{
    if (spent_context_ref(enote).spent_status == sp::SpEnoteSpentStatus::SPENT_ONCHAIN &&
        origin_context_ref(enote).origin_status == sp::SpEnoteOriginStatus::ONCHAIN &&
        origin_context_ref(enote).block_index >= range_height.first &&
        spent_context_ref(enote).block_index <= range_height.second)
        vec_out.push_back(enote);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void filter_out_pool(const ContextualRecordVariant &enote,
    const pair<uint64_t, uint64_t> range_height,
    vector<ContextualRecordVariant> &vec_out)
{
    if (spent_context_ref(enote).spent_status == sp::SpEnoteSpentStatus::SPENT_UNCONFIRMED &&
        origin_context_ref(enote).origin_status == sp::SpEnoteOriginStatus::ONCHAIN &&
        origin_context_ref(enote).block_index >= range_height.first)
        vec_out.push_back(enote);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void filter_out_offchain(const ContextualRecordVariant &enote,
    const pair<uint64_t, uint64_t> range_height,
    vector<ContextualRecordVariant> &vec_out)
{
    if (spent_context_ref(enote).spent_status == sp::SpEnoteSpentStatus::SPENT_OFFCHAIN &&
        origin_context_ref(enote).block_index >= range_height.first)
        vec_out.push_back(enote);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void select_filter_comparator(const SpTxDirectionStatus tx_status,
    const pair<uint64_t, uint64_t> range_height,
    FilterEnotes &filter_in_out,
    ComparatorEnotes &comparator_enotes)
{
    switch (tx_status)
    {
        case SpTxDirectionStatus::ALL:
        {
            filter_in_out     = filter_all;
            comparator_enotes = compare_block_timestamp;
            return;
        }
        case SpTxDirectionStatus::IN_ONCHAIN:
        {
            filter_in_out     = filter_in;
            comparator_enotes = compare_block_timestamp_in;
            return;
        }
        case SpTxDirectionStatus::IN_POOL:
        {
            filter_in_out     = filter_in_pool;
            comparator_enotes = compare_block_timestamp_in;
            return;
        }
        case SpTxDirectionStatus::IN_OFFCHAIN:
        {
            filter_in_out     = filter_in_offchain;
            comparator_enotes = compare_block_timestamp_in;
            return;
        }
        case SpTxDirectionStatus::OUT_ONCHAIN:
        {
            filter_in_out     = filter_out;
            comparator_enotes = compare_block_timestamp_out;
            return;
        }
        case SpTxDirectionStatus::OUT_POOL:
        {
            filter_in_out     = filter_out_pool;
            comparator_enotes = compare_block_timestamp_out;
            return;
        }
        case SpTxDirectionStatus::OUT_OFFCHAIN:
        {
            filter_in_out     = filter_out_offchain;
            comparator_enotes = compare_block_timestamp_out;
            return;
        }
        case SpTxDirectionStatus::FAILED:
        {
            return;
        }
        default:
            return;
    }
}

//-------------------------------------------------------------------------------------------------------------------
// SHOW ENOTES
//-------------------------------------------------------------------------------------------------------------------

void get_enotes(const SpEnoteStore &sp_enote_store,
    const SpTxDirectionStatus tx_status,
    const pair<uint64_t, uint64_t> range_height,
    vector<ContextualRecordVariant> &vec_enote_records_out)
{

    vec_enote_records_out.clear();

    FilterEnotes filter;
    ComparatorEnotes comparator;

    select_filter_comparator(tx_status, range_height, filter, comparator);

    for_each(sp_enote_store.sp_records().begin(),
        sp_enote_store.sp_records().end(),
        [&](const pair<crypto::key_image, SpContextualEnoteRecordV1> &enote)
        { filter(enote.second, range_height, vec_enote_records_out); });

    for_each(sp_enote_store.legacy_records().begin(),
        sp_enote_store.legacy_records().end(),
        [&](const pair<rct::key, LegacyContextualEnoteRecordV1> &enote)
        { filter(enote.second, range_height, vec_enote_records_out); });

    stable_sort(vec_enote_records_out.begin(), vec_enote_records_out.end(), comparator);
}
//-------------------------------------------------------------------------------------------------------------------
// Temporary function to show enotes
void show_enotes(const vector<ContextualRecordVariant> &vec_enote_records)
{
    rct::xmr_amount unspent_total{};
    for (int i = vec_enote_records.size() - 1; i >= 0; i--)
    {
        // Status
        cout << "Status: " << sp_spent_status_to_string(spent_context_ref(vec_enote_records[i]).spent_status);

        // Amount
        cout << "  |   Amount: " << amount_ref(vec_enote_records[i]);

        // Type
        if (vec_enote_records[i].is_type<SpContextualEnoteRecordV1>())
        {
            cout << "  |   Type: "
                 << "Sp";
            cout << "  |   Key-image: " << vec_enote_records[i].unwrap<SpContextualEnoteRecordV1>().record.key_image;
        }
        else
        {
            cout << "  |   Type: "
                 << "Legacy";
            cout << "  |   Key-image: "
                 << vec_enote_records[i].unwrap<LegacyContextualEnoteRecordV1>().record.key_image;
        }

        // Info from origin_context or spent_context
        if (spent_context_ref(vec_enote_records[i]).spent_status == sp::SpEnoteSpentStatus::UNSPENT)
        {
            cout << "  |   Timestamp origin: "
                 << tools::get_human_readable_timestamp(origin_context_ref(vec_enote_records[i]).block_timestamp);
            cout << "  |   Block height origin: " << origin_context_ref(vec_enote_records[i]).block_index;
            cout << "  |   Tx id origin: " << origin_context_ref(vec_enote_records[i]).transaction_id << endl;
            unspent_total += amount_ref(vec_enote_records[i]);
        }
        else
        {
            cout << "  |   Timestamp spent: "
                 << tools::get_human_readable_timestamp(spent_context_ref(vec_enote_records[i]).block_timestamp);
            cout << "  |   Block height spent: " << spent_context_ref(vec_enote_records[i]).block_index;
            cout << "  |   Tx id spent: " << spent_context_ref(vec_enote_records[i]).transaction_id << endl;
        }
    }
    cout << "Total unspent: " << unspent_total << endl;
}
//-------------------------------------------------------------------------------------------------------------------
// k_vb is only necessary to show selfsend enotes
// this could be done in a separate function
// TEMPORARY
void show_specific_enote(const SpEnoteStore &enote_store,
    const SpTransactionHistory &transaction_history,
    const crypto::key_image &key_image)
{
    // Legacy enote
    LegacyContextualEnoteRecordV1 legacy_enote_record;
    if (enote_store.try_get_legacy_enote_record(key_image, legacy_enote_record))
    {
        // Info from enote
        {
            cout << "--------------- INFO FROM ENOTE ---------------" << endl;

            cout << "  |   Type: "
                 << "Legacy" << endl;
            cout << "  |   Key image: " << legacy_enote_record.record.key_image << endl;

            // Amount
            cout << "  |   Amount commitment: " << amount_commitment_ref(legacy_enote_record.record.enote) << endl;
            cout << "  |   Amount: " << legacy_enote_record.record.amount << endl;
            cout << "  |   Amount blinding factor: " << legacy_enote_record.record.amount_blinding_factor << endl;
            // Onetime-Address
            cout << "  |   Onetime-Address: " << onetime_address_ref(legacy_enote_record.record.enote) << endl;
            cout << "  |   Address index: " << legacy_enote_record.record.address_index << endl;
            cout << "  |   Enote ephemeral public key: " << legacy_enote_record.record.enote_ephemeral_pubkey << endl;
            cout << "  |   Enote view extension (private key): " << legacy_enote_record.record.enote_view_extension
                 << endl;
            cout << "  |   Transaction output index: " << legacy_enote_record.record.tx_output_index << endl;
            cout << "  |   Unlock time: " << legacy_enote_record.record.unlock_time << endl;
        }

        // Info from origin_context
        cout << "--------------- ORIGIN CONTEXT ---------------" << endl;
        {
            cout << "  |   Timestamp origin: "
                 << tools::get_human_readable_timestamp(legacy_enote_record.origin_context.block_timestamp) << endl;
            cout << "  |   Block height origin: " << legacy_enote_record.origin_context.block_index << endl;
            cout << "  |   Tx id origin: " << legacy_enote_record.origin_context.transaction_id << endl;
            cout << "  |   Origin Status: "
                 << sp_origin_status_to_string(legacy_enote_record.origin_context.origin_status) << endl;
            cout << "  |   Enote Ledge Index: " << legacy_enote_record.origin_context.enote_ledger_index << endl;
            cout << "  |   Enote Transaction Index: " << legacy_enote_record.origin_context.enote_tx_index << endl;
            // TODO
            // cout << "  |   Memo: " << legacy_enote_record.origin_context.memo << endl;
        }
        // Info from spent_context if spent
        if (legacy_enote_record.spent_context.spent_status != sp::SpEnoteSpentStatus::UNSPENT)
        {
            cout << "--------------- SPENT CONTEXT ---------------" << endl;
            cout << "  |   Spent status: " << sp_spent_status_to_string(legacy_enote_record.spent_context.spent_status)
                 << endl;
            cout << "  |   Timestamp spent: "
                 << tools::get_human_readable_timestamp(legacy_enote_record.spent_context.block_timestamp) << endl;
            cout << "  |   Block height spent: " << legacy_enote_record.spent_context.block_index << endl;
            cout << "  |   Tx id spent: " << legacy_enote_record.spent_context.transaction_id << endl;

            // Get transaction record
            TransactionRecordV1 tx_record;
            if (transaction_history.try_get_tx_record_from_txid(
                    legacy_enote_record.spent_context.transaction_id, tx_record))
            {
                cout << "--------------- SPENT CONTEXT - DETAILED ---------------" << endl;
                cout << "This enote was consumed to send funds to the following addresses: " << endl;
                string str_addr_out;
                for (auto p : tx_record.normal_payments)
                {
                    // Prover does not need to know onetime-address to create knowledge proofs.
                    // But it is nice to show and include on the proofs to avoid mistakes on both sides.
                    rct::key input_context;
                    make_jamtis_input_context_standard(
                        tx_record.legacy_spent_enotes, tx_record.sp_spent_enotes, input_context);

                    SpOutputProposalV1 output_proposal;
                    make_v1_output_proposal_v1(p, input_context, output_proposal);
                    SpEnoteV1 enote;
                    get_enote_v1(output_proposal, enote);

                    get_str_from_destination(p.destination, str_addr_out);
                    cout << "  |   Destination: " << str_addr_out << endl;
                    cout << "  |   Onetime-address: " << enote.core.onetime_address << endl;
                    cout << "  |   Amount commitment: " << enote.core.amount_commitment << endl;

                    cout << "  |   Amount: " << p.amount << endl;
                    cout << "  |   Enote ephemeral private key: "
                         << epee::string_tools::pod_to_hex(p.enote_ephemeral_privkey) << endl;
                    // cout << "  |   Partial Memo: " << (p.partial_memo) << endl;
                    cout << "  |   --- " << endl;
                }
                for (auto p : tx_record.selfsend_payments)
                {
                    cout << "  |   Type: " << sp_jamtis_enote_selfsend_type_to_string(p.type) << endl;

                    // Prover does not need to know onetime-address to create knowledge proofs.
                    // But it is nice to show and include on the proofs to avoid mistakes on both sides.
                    // k_vb is only necessary for selfsend enotes.
                    // Selfsend OTA enotes can be obtained by different show functions.

                    get_str_from_destination(p.destination, str_addr_out);
                    cout << "  |   Destination: " << str_addr_out << endl;
                    cout << "  |   Amount: " << p.amount << endl;
                    cout << "  |   Enote ephemeral private key: "
                         << epee::string_tools::pod_to_hex(p.enote_ephemeral_privkey) << endl;
                    // cout << "  |   Partial Memo: " << (np.partial_memo) << endl;
                    cout << "  |   --- " << endl;
                }
            }
        }
        else
            cout << "This enote has not been spent yet." << endl;
    }

    // Seraphis enote
    SpContextualEnoteRecordV1 sp_enote_record;
    if (enote_store.try_get_sp_enote_record(key_image, sp_enote_record))
    {
        // Info from enote
        {
            cout << "--------------- INFO FROM ENOTE ---------------" << endl;
            cout << "  |   Type: "
                 << "Seraphis" << endl;
            cout << "  |   Jamtis Type: " << sp_jamtis_enote_type_to_string(sp_enote_record.record.type) << endl;
            cout << "  |   Key image: " << sp_enote_record.record.key_image << endl;

            // Amount
            cout << "  |   Amount commitment: " << amount_commitment_ref(sp_enote_record.record.enote) << endl;
            cout << "  |   Amount: " << sp_enote_record.record.amount << endl;
            cout << "  |   Amount blinding factor: " << sp_enote_record.record.amount_blinding_factor << endl;
            // Onetime-Address
            cout << "  |   Onetime-Address: " << onetime_address_ref(sp_enote_record.record.enote) << endl;
            cout << "  |   Address index: " << epee::string_tools::pod_to_hex(sp_enote_record.record.address_index)
                 << endl;
            cout << "  |   Enote ephemeral public key: "
                 << epee::string_tools::pod_to_hex(sp_enote_record.record.enote_ephemeral_pubkey) << endl;
            cout << "  |   Enote view extension g (private key): " << sp_enote_record.record.enote_view_extension_g
                 << endl;
            cout << "  |   Enote view extension u (private key): " << sp_enote_record.record.enote_view_extension_u
                 << endl;
            cout << "  |   Enote view extension x (private key): " << sp_enote_record.record.enote_view_extension_x
                 << endl;
            cout << "  |   Input context: " << sp_enote_record.record.input_context << endl;
        }

        // Info from origin_context
        {
            cout << "--------------- ORIGIN CONTEXT ---------------" << endl;
            cout << "  |   Timestamp origin: "
                 << tools::get_human_readable_timestamp(sp_enote_record.origin_context.block_timestamp);
            cout << "  |   Block height origin: " << sp_enote_record.origin_context.block_index;
            cout << "  |   Tx id origin: " << sp_enote_record.origin_context.transaction_id << endl;
            cout << "  |   Origin Status: " << sp_origin_status_to_string(sp_enote_record.origin_context.origin_status)
                 << endl;
            cout << "  |   Enote Ledge Index: " << sp_enote_record.origin_context.enote_ledger_index << endl;
            cout << "  |   Enote Transaction Index: " << sp_enote_record.origin_context.enote_tx_index << endl;
            // TODO
            // cout << "  |   Memo: " << sp_enote_record.origin_context.memo << endl;
        }
        // Info from spent_context if spent
        if (sp_enote_record.spent_context.spent_status != sp::SpEnoteSpentStatus::UNSPENT)
        {
            cout << "--------------- SPENT CONTEXT ---------------" << endl;
            cout << "  |   Spent status: " << sp_spent_status_to_string(sp_enote_record.spent_context.spent_status)
                 << endl;
            cout << "  |   Timestamp spent: "
                 << tools::get_human_readable_timestamp(sp_enote_record.spent_context.block_timestamp) << endl;
            cout << "  |   Block height spent: " << sp_enote_record.spent_context.block_index << endl;
            cout << "  |   Tx id spent: " << sp_enote_record.spent_context.transaction_id << endl;

            // Get transaction record
            TransactionRecordV1 tx_record;
            if (transaction_history.try_get_tx_record_from_txid(
                    sp_enote_record.spent_context.transaction_id, tx_record))
            {
                cout << "--------------- SPENT CONTEXT - DETAILED ---------------" << endl;
                cout << "This enote was consumed to send funds to the following addresses: " << endl;
                string str_addr_out;
                for (auto p : tx_record.normal_payments)
                {
                    // Prover does not need to know onetime-address to create knowledge proofs.
                    // But it is nice to show and include on the proofs to avoid mistakes on both sides.
                    rct::key input_context;
                    make_jamtis_input_context_standard(
                        tx_record.legacy_spent_enotes, tx_record.sp_spent_enotes, input_context);

                    SpOutputProposalV1 output_proposal;
                    make_v1_output_proposal_v1(p, input_context, output_proposal);
                    SpEnoteV1 enote;
                    get_enote_v1(output_proposal, enote);

                    get_str_from_destination(p.destination, str_addr_out);
                    cout << "  |   Destination: " << str_addr_out << endl;
                    cout << "  |   Onetime-address: " << enote.core.onetime_address << endl;
                    cout << "  |   Amount commitment: " << enote.core.amount_commitment << endl;
                    cout << "  |   Amount: " << p.amount << endl;
                    cout << "  |   Enote ephemeral private key: "
                         << epee::string_tools::pod_to_hex(p.enote_ephemeral_privkey) << endl;
                    cout << "  |   --- " << endl;
                    // cout << "  |   Partial Memo: " << (p.partial_memo) << endl;
                }
                for (auto p : tx_record.selfsend_payments)
                {
                    cout << "  |   Type: " << sp_jamtis_enote_selfsend_type_to_string(p.type) << endl;
                    // Prover does not need to know onetime-address to create knowledge proofs.
                    // But it is nice to show and include on the proofs to avoid mistakes on both sides.
                    // k_vb is only necessary for selfsend enotes.
                    // Selfsend OTA enotes can be obtained by different show functions.
                    get_str_from_destination(p.destination, str_addr_out);
                    cout << "  |   Destination: " << str_addr_out << endl;
                    cout << "  |   Amount: " << p.amount << endl;
                    cout << "  |   Enote ephemeral private key: "
                         << epee::string_tools::pod_to_hex(p.enote_ephemeral_privkey) << endl;
                    cout << "  |   --- " << endl;
                    // cout << "  |   Partial Memo: " << (np.partial_memo) << endl;
                }
            }
        }
        else
            cout << "This enote has not been spent yet." << endl;
    }
}
