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
#include "transaction_history.h"

// local headers
#include "common/container_helpers.h"
#include "seraphis_wallet/serialization_types.h"
#include "serialization/binary_utils.h"
#include "serialization/containers.h"
#include "serialization/pair.h"
#include "serialization_types.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_wallet"

bool operator==(const SpTransactionStore &a, const SpTransactionStore &b)
{
    return a.tx_records == b.tx_records && a.txs_by_timestamp == b.txs_by_timestamp;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const TransactionRecord &a, const TransactionRecord &b)
{
    return a.legacy_spent_enotes == b.legacy_spent_enotes && a.sp_spent_enotes == b.sp_spent_enotes &&
           a.normal_payments == b.normal_payments && a.selfsend_payments == b.selfsend_payments &&
           a.amount_sent == b.amount_sent && a.fee_sent == b.fee_sent;
}

//-----------------------------------------------------------------
/// Add entries to SpTransactionStore
//-----------------------------------------------------------------

void SpTransactionHistory::add_entry_to_tx_records(const rct::key &txid, const TransactionRecord &record)
{
    m_sp_tx_store.tx_records[txid] = record;
}
//-------------------------------------------------------------------------------------------------------------------
void SpTransactionHistory::add_entry_to_txs_by_timestamp(const uint64_t timestamp, const rct::key &txid)
{
    m_sp_tx_store.txs_by_timestamp.push_back(std::make_pair(timestamp,txid));
}
//-------------------------------------------------------------------------------------------------------------------
void SpTransactionHistory::add_single_tx(const SpTxSquashedV1 &single_tx,
    const std::vector<JamtisPaymentProposalSelfSendV1> &selfsend_payments,
    const std::vector<JamtisPaymentProposalV1> &normal_payments)
{
    /// 1. prepare variables of tx_store
    rct::key tx_id;
    std::vector<crypto::key_image> legacy_spent_ki;
    std::vector<crypto::key_image> sp_spent_ki;

    // a. tx_id
    get_sp_tx_squashed_v1_txid(single_tx, tx_id);

    // b. legacy_spent_key_images
    legacy_spent_ki.clear();
    for (auto legacy_images : single_tx.legacy_input_images)
    {
        legacy_spent_ki.push_back(legacy_images.key_image);
    }

    // c. sp_spent_key_images
    sp_spent_ki.clear();
    for (auto sp_images : single_tx.sp_input_images)
    {
        sp_spent_ki.push_back(sp_images.core.key_image);
    }

    // d. total amount sent
    rct::xmr_amount total_amount_sent{};
    for (auto outs : normal_payments)
    {
        total_amount_sent += outs.amount;
    }

    // e. fee
    rct::xmr_amount tx_fee;
    try_get_fee_value(single_tx.tx_fee, tx_fee);

    // f. get TransactionRecord
    TransactionRecord record{legacy_spent_ki, sp_spent_ki, selfsend_payments, normal_payments, total_amount_sent, tx_fee};

    // 2. add record to tx_record by tx_id
    add_entry_to_tx_records(tx_id, record);

    // 3. add record to txs_by_timestamp
    std::time_t timestamp = std::time(nullptr);
    std::asctime(std::localtime(&timestamp));
    add_entry_to_txs_by_timestamp(timestamp, tx_id);
}

//-----------------------------------------------------------------
/// Get/Set SpTransactionStore
//-----------------------------------------------------------------

const SpTransactionStore SpTransactionHistory::get_tx_store() const { return m_sp_tx_store; }
//-------------------------------------------------------------------------------------------------------------------
bool SpTransactionHistory::set_tx_store(const SpTransactionStore &tx_store)
{
    m_sp_tx_store = tx_store;
    return true;
}

//-----------------------------------------------------------------
/// Get info from enotes and txs
//-----------------------------------------------------------------

const std::vector<std::pair<uint64_t,rct::key>> SpTransactionHistory::get_last_N_txs(const uint64_t N)
{
    // 1. define vector and iterators
    std::vector<std::pair<uint64_t,rct::key>> last_txs{};
    auto it_begin = m_sp_tx_store.txs_by_timestamp.end();
    auto it_end   = m_sp_tx_store.txs_by_timestamp.end();

    // 2. get size
    uint64_t counts{m_sp_tx_store.txs_by_timestamp.size()};

    // 3. decrement the end iterator to the beginning or to the position N
    if (N < counts)
        std::advance(it_begin, -N);
    else
        std::advance(it_begin,-counts);

    // 4. add pair<timestamp,txid> to output vector
    for (auto it = it_begin; it!=it_end; it++)
    {
        last_txs.push_back(*it);
    }

    // 5. return last_txs where index 0 is the last tx
    std::reverse(last_txs.begin(),last_txs.end());
    return last_txs;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpTransactionHistory::get_enotes_from_tx(const rct::key &txid,
    const SpEnoteStore &enote_store,
    std::pair<std::vector<LegacyContextualEnoteRecordV1>, std::vector<SpContextualEnoteRecordV1>> &enotes_out) const
{
    // 1. get TransactionRecord if txid exists
    TransactionRecord tx_rec{};

    if (m_sp_tx_store.tx_records.find(txid) == m_sp_tx_store.tx_records.end())
        return false;
    else
        tx_rec = m_sp_tx_store.tx_records.at(txid);

    // 2. get Sp enotes context
    std::vector<SpContextualEnoteRecordV1> sp_spent;
    for (auto sp_ki : tx_rec.sp_spent_enotes)
    {
        enote_store.try_get_sp_enote_record(sp_ki, tools::add_element(sp_spent));
    }

    // 3. get Legacy enotes context
    std::vector<LegacyContextualEnoteRecordV1> legacy_spent;
    for (auto legacy_ki : tx_rec.legacy_spent_enotes)
    {
        enote_store.try_get_legacy_enote_record(legacy_ki, tools::add_element(legacy_spent));
    }

    // 4. return enotes in a pair
    enotes_out = std::make_pair(legacy_spent, sp_spent);
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpTransactionHistory::get_representing_enote_from_tx(
    const std::pair<std::vector<LegacyContextualEnoteRecordV1>, std::vector<SpContextualEnoteRecordV1>> &enotes_in_tx,
    ContextualRecordVariant &contextual_enote_out) const
{
    // 1. try to get the first sp enote representing the tx
    if (!enotes_in_tx.second.empty())
    {
        contextual_enote_out = enotes_in_tx.second[0];
        return true;
    }
    else
    // 2. try to get the first legacy enote representing the tx
    {
        if (!enotes_in_tx.first.empty())
        {
            contextual_enote_out = enotes_in_tx.first[0];
            return true;
        }
    }
    return false;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpTransactionHistory::try_get_tx_record_from_txid(const rct::key &txid, TransactionRecord &tx_record_out) const
{
    if (m_sp_tx_store.tx_records.find(txid) != m_sp_tx_store.tx_records.end())
        tx_record_out = m_sp_tx_store.tx_records.at(txid);
    else
        return false;
    return true;
}

//-----------------------------------------------------------------
/// Save/read data to/from file
//-----------------------------------------------------------------

// bool SpTransactionHistory::write_sp_tx_history(std::string path, const epee::wipeable_string &password)
// {
//     // 1. Get serializable of structure
//     ser_SpTransactionStoreV1 ser_tx_store;
//     make_serializable_sp_transaction_store_v1(m_sp_tx_store, ser_tx_store);

//     // 2. Save serializable struct to file
//     return write_file(path, ser_tx_store);
// }
// //-------------------------------------------------------------------------------------------------------------------
// bool SpTransactionHistory::read_sp_tx_history(std::string path,
//     const epee::wipeable_string &password,
//     SpTransactionStoreV1 &sp_tx_store)
// {
//     // 1. Read file into serializable
//     ser_SpTransactionStoreV1 ser_tx_store;
//     read_file(path, ser_tx_store);

//     // 2. Recover struct from serializable
//     recover_sp_transaction_store_v1(ser_tx_store, sp_tx_store);

//     return true;
// }
