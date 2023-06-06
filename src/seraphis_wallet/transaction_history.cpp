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
#include "common/util.h"
#include "crypto/crypto.h"
#include "file_io_utils.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_impl/enote_store.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/sp_knowledge_proof_types.h"
#include "seraphis_main/sp_knowledge_proof_utils.h"
#include "seraphis_wallet/encrypt_file.h"
#include "seraphis_wallet/serialization_types.h"
#include "serialization/binary_utils.h"
#include "serialization/containers.h"
#include "transaction_utils.h"
#include "serialization_types.h"
#include "string_tools.h"
#include "cryptonote_basic/account_boost_serialization.h"
#include "common/unordered_containers_boost_serialization.h"
#include "common/util.h"
#include "crypto/chacha.h"
#include "crypto/hash.h"
#include "ringct/rctTypes.h"
#include "ringct/rctOps.h"
#include "checkpoints/checkpoints.h"
#include "serialization/crypto.h"
#include "serialization/string.h"
#include "serialization/pair.h"
#include "serialization/tuple.h"
#include "serialization/containers.h"

// third party headers
#include <boost/range.hpp>
#include <boost/range/iterator_range_core.hpp>
#include "boost/range/iterator_range.hpp"

// standard headers
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/serialization/list.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/deque.hpp>
#include <boost/thread/lock_guard.hpp>

// #include <boost/program_options/variables_map.hpp>
#if BOOST_VERSION >= 107400
#include <boost/serialization/library_version_type.hpp>
#endif



bool operator==(const SpTransactionStoreV1 &a, const SpTransactionStoreV1 &b)
{
    
    return a.tx_records == b.tx_records &&
        a.confirmed_txids == b.confirmed_txids &&
        a.unconfirmed_txids == b.unconfirmed_txids &&
        a.offchain_txids == b.offchain_txids;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const TransactionRecordV1 &a, const TransactionRecordV1 &b)
{
    return a.legacy_spent_enotes == b.legacy_spent_enotes &&
        a.sp_spent_enotes == b.sp_spent_enotes &&
        a.outlays == b.outlays &&
        a.amount_sent == b.amount_sent &&
        a.fee_sent == b.fee_sent;
}
//-------------------------------------------------------------------------------------------------------------------
void SpTransactionHistory::add_entry_to_tx_records(const rct::key &txid, const TransactionRecordV1 &record)
{
    m_sp_tx_store.tx_records[txid] = record;
}
//-------------------------------------------------------------------------------------------------------------------
// std::multimap<std::uint64_t, rct::key, std::greater<std::uint64_t>> *SpTransactionStore::get_pointer_to_tx_status(
serializable_multimap<std::uint64_t, rct::key, std::greater<std::uint64_t>> *SpTransactionHistory::get_pointer_to_tx_status(
    const SpTxStatus tx_status)
{
    // get pointer to corresponding multimap
    // std::multimap<std::uint64_t, rct::key, std::greater<std::uint64_t>> *ptr = nullptr;
    serializable_multimap<std::uint64_t, rct::key, std::greater<std::uint64_t>> *ptr = nullptr;
    switch (tx_status)
    {
        case SpTxStatus::CONFIRMED:
        {
            ptr = &m_sp_tx_store.confirmed_txids;
            break;
        }
        case SpTxStatus::UNCONFIRMED:
        {
            ptr = &m_sp_tx_store.unconfirmed_txids;
            break;
        }
        case SpTxStatus::OFFCHAIN:
        {
            ptr = &m_sp_tx_store.offchain_txids;
            break;
        }
        default:
            break;
    }
    return ptr;
}
//-------------------------------------------------------------------------------------------------------------------
void SpTransactionHistory::add_entry_txs(const SpTxStatus tx_status, const uint64_t block_or_timestamp,
                                         const rct::key &txid)
{
    // add entry to corresponding variable
    auto ptr_status = get_pointer_to_tx_status(tx_status);
    ptr_status->emplace(block_or_timestamp, txid);
}
//-------------------------------------------------------------------------------------------------------------------
const SpTransactionStoreV1 SpTransactionHistory::get_tx_store()
{
    return m_sp_tx_store;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpTransactionHistory::set_tx_store(const SpTransactionStoreV1 &tx_store)
{
    m_sp_tx_store = tx_store;
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
const range_txids_by_block_or_time SpTransactionHistory::get_last_N_txs(const SpTxStatus tx_status, const uint64_t N)
{
    // 1. get pointer
    auto ptr_status = get_pointer_to_tx_status(tx_status);

    // 2. set begin and end iterators to beggining of multimap
    std::multimap<unsigned long, rct::key>::iterator it_begin = ptr_status->begin();
    std::multimap<unsigned long, rct::key>::iterator it_end = ptr_status->begin();

    // 3. get size of multimap
    uint64_t counts{ptr_status->size()};

    // 4. advance the end iterator to the end or to the position N
    if (N < counts)
        std::advance(it_end, N);
    else
        std::advance(it_end, counts);

    // 5. return range
    return boost::make_iterator_range(it_begin, it_end);
}
//-------------------------------------------------------------------------------------------------------------------
bool SpTransactionHistory::get_enotes_from_tx(
    const rct::key &txid, const SpEnoteStore &enote_store,
    std::pair<std::vector<LegacyContextualEnoteRecordV1>, std::vector<SpContextualEnoteRecordV1>> &enotes_out)
{
    // 1. get TransactionRecord if txid exists
    TransactionRecordV1 tx_rec{};
    if (m_sp_tx_store.tx_records.find(txid) == m_sp_tx_store.tx_records.end())
    {
        // TODO: which library to use to show wallet msgs?
        // std::cout << txid << " not found" << std::endl;
        return false;
    }
    else
        tx_rec = m_sp_tx_store.tx_records[txid];

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
    ContextualRecordVariant &contextual_enote_out)
{
    // try to get a sp enote representing the tx
    if (!enotes_in_tx.second.empty())
    {
        contextual_enote_out = enotes_in_tx.second[0];
        return true;
    }
    else
    // try to get a legacy enote representing the tx
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
bool SpTransactionHistory::get_tx_view(const ContextualRecordVariant &contextual_enote, TxViewV1 &tx_view_out)
{
    // Only a draft. Very simple version.

    // 1. get SpEnoteSpentContext and TransactionRecord from contextual_enote
    SpEnoteSpentContextV1 spent_context{spent_context_ref(contextual_enote)};
    rct::key tx_id{spent_context.transaction_id};
    TransactionRecordV1 tx_record{m_sp_tx_store.tx_records[tx_id]};

    // 2. fill TxView with info available
    tx_view_out.block = spent_context.block_index == static_cast<std::uint64_t>(-1)
                            ? std::string{"<unknown>"}
                            : std::to_string(spent_context.block_index);
    tx_view_out.direction = "out";
    tx_view_out.timestamp = tools::get_human_readable_timestamp(spent_context.block_timestamp);
    tx_view_out.amount = std::to_string(tx_record.amount_sent);
    tx_view_out.hash = epee::string_tools::pod_to_hex(spent_context.transaction_id);
    tx_view_out.fee = std::to_string(tx_record.fee_sent);
    std::string str_dest{};
    for (auto dest : tx_record.outlays)
    {
        get_str_from_destination(dest.first, str_dest);
        tx_view_out.destinations += str_dest + std::string(" , ");
    }
    tx_view_out.destinations.erase(tx_view_out.destinations.size() - 3, 3);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void SpTransactionHistory::print_tx_view(const TxViewV1 tx_view)
{
    // Only a draft. Very simple version.

    std::cout << tx_view.block << " | "
    << tx_view.direction << " | " 
    << tx_view.timestamp << " | " 
    << tx_view.amount << " | " 
    << tx_view.hash << " | " 
    << tx_view.fee << " | " 
    << tx_view.destinations << std::endl;
}
//-------------------------------------------------------------------------------------------------------------------
void SpTransactionHistory::show_txs(SpEnoteStore &enote_store, uint64_t N)
{
    std::cout << "Block | Direction | Timestamp | Amount | Tx id | Fee | Destination " << std::endl;
    std::cout << " ----------- Confirmed ----------- " << std::endl;

    // a. print last 3 confirmed txs
    const auto range_confirmed{get_last_N_txs(SpTxStatus::CONFIRMED,N)};
    if (!range_confirmed.empty())
    {
        std::pair<std::vector<LegacyContextualEnoteRecordV1>, std::vector<SpContextualEnoteRecordV1>> enotes_selected;
        ContextualRecordVariant contextual_record;
        TxViewV1 tx_view;
        for (auto it_range : range_confirmed)
        {
            get_enotes_from_tx(it_range.second, enote_store, enotes_selected);
            if (get_representing_enote_from_tx(enotes_selected, contextual_record))
            {
                get_tx_view(contextual_record, tx_view);
                print_tx_view(tx_view);
            }
        }
    }

    // b. print last 3 unconfirmed txs
    std::cout << " ----------- Unconfirmed ----------- " << std::endl;
    const auto range_unconfirmed{get_last_N_txs(SpTxStatus::UNCONFIRMED, N)};
    if (!range_unconfirmed.empty())
    {
        std::pair<std::vector<LegacyContextualEnoteRecordV1>, std::vector<SpContextualEnoteRecordV1>> enotes_selected;
        ContextualRecordVariant contextual_record;
        TxViewV1 tx_view;
        for (auto it_range : range_unconfirmed)
        {
            get_enotes_from_tx(it_range.second, enote_store, enotes_selected);
            if (get_representing_enote_from_tx(enotes_selected, contextual_record))
            {
                get_tx_view(contextual_record, tx_view);
                print_tx_view(tx_view);
            }
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
void SpTransactionHistory::show_tx_hashes(uint64_t N)
{
    // a. print last N confirmed txs
    const auto range_confirmed{get_last_N_txs(SpTxStatus::CONFIRMED,N)};
    if (!range_confirmed.empty())
    {
        for (auto it_range : range_confirmed)
        {
        std::cout << "Height: " << it_range.first << " Hash: " << it_range.second << std::endl;
        }

    }
}
//-------------------------------------------------------------------------------------------------------------------
bool SpTransactionHistory::write_tx_funded_proof(const rct::key &txid, const SpEnoteStore &enote_store,
                                               const crypto::secret_key &sp_spend_privkey,
                                               const crypto::secret_key &k_view_balance)
{
    std::pair<std::vector<LegacyContextualEnoteRecordV1>, std::vector<SpContextualEnoteRecordV1>> enotes_from_tx{};
    ContextualRecordVariant representing_enote{};

    // 1. get enotes and check if txid exists in storage
    if (!get_enotes_from_tx(txid, enote_store, enotes_from_tx)) return false;
    
    // 2. get representing enote from tx
    get_representing_enote_from_tx(enotes_from_tx,representing_enote);

    // 2. get random message
    const rct::key message{rct::skGen()};

    // 3. initialize proof struct
    sp::knowledge_proofs::TxFundedProofV1 tx_funded_proof{};

    // 4. make proof
    // TODO: verify legacy enotes too and make proof on whatever is available
    if (representing_enote.is_type<SpContextualEnoteRecordV1>())
        make_tx_funded_proof_v1(message,representing_enote.unwrap<SpContextualEnoteRecordV1>().record ,sp_spend_privkey, k_view_balance,
                            tx_funded_proof);
    // else
    // make legacy tx_funded_proof

    // 5. serialize struct
    ser_TxFundedProofV1 ser_tx_funded_proof{};
    make_serializable_tx_funded_proof_v1(tx_funded_proof,ser_tx_funded_proof);

    // 6. prepare to save to file by proof name and date
    write_encrypted_file("tx_funded_proof", "", ser_tx_funded_proof);
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpTransactionHistory::check_tx_funded_proof(const TxFundedProofV1 &proof, const rct::key &tx_id) 
{
    // 1. From tx_id get all key images of tx by querying node.

    // 2. Loop over key images to check if one corresponds to proof.
    //*(A better way would be to store the index of the key image in the proof structure)


    // 3. Verify tx_funded_proof
// verify_tx_funded_proof_v1(const TxFundedProofV1 &proof,
//     const rct::key &expected_message,
//     const crypto::key_image &expected_KI)
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpTransactionHistory::write_sp_tx_history(std::string path, const epee::wipeable_string &password)
{
    // 1. Get serializable of structure
    ser_SpTransactionStoreV1 ser_tx_store;
    make_serializable_sp_transaction_store_v1(m_sp_tx_store, ser_tx_store);

    // 3. Save serializable struct to file
    return write_encrypted_file(path, password, ser_tx_store);
}
// //-------------------------------------------------------------------------------------------------------------------
bool SpTransactionHistory::read_sp_tx_history(std::string path, const epee::wipeable_string &password, SpTransactionStoreV1 &sp_tx_store)
{
    // 1. Read file into serializable
    ser_SpTransactionStoreV1 ser_tx_store;
    read_encrypted_file(path, password, ser_tx_store);
    
    // 2. Recover struct from serializable
    recover_sp_transaction_store_v1(ser_tx_store,sp_tx_store);
    
    return true;
}