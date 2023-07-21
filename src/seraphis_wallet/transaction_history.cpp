// Copyright (c) 2023, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list
//    of conditions and the following disclaimer in the documentation and/or
//    other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors
// may be
//    used to endorse or promote products derived from this software without
//    specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

// paired header
#include "transaction_history.h"

// local headers
#include "checkpoints/checkpoints.h"
#include "common/container_helpers.h"
#include "common/unordered_containers_boost_serialization.h"
#include "common/util.h"
#include "crypto/chacha.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "cryptonote_basic/account_boost_serialization.h"
#include "file_io_utils.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_crypto/sp_hash_functions.h"
#include "seraphis_crypto/sp_transcript.h"
#include "seraphis_impl/enote_store.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/sp_knowledge_proof_types.h"
#include "seraphis_main/sp_knowledge_proof_utils.h"
#include "seraphis_mocks/mock_ledger_context.h"
#include "seraphis_mocks/seraphis_mocks.h"
#include "seraphis_wallet/encrypt_file.h"
#include "seraphis_wallet/serialization_types.h"
#include "serialization/binary_utils.h"
#include "serialization/containers.h"
#include "serialization/crypto.h"
#include "serialization/pair.h"
#include "serialization/string.h"
#include "serialization/tuple.h"
#include "serialization_types.h"
#include "string_tools.h"
#include "transaction_utils.h"

// third party headers
#include <boost/range.hpp>
#include <boost/range/iterator_range_core.hpp>

#include "boost/range/iterator_range.hpp"

// standard headers
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/serialization/deque.hpp>
#include <boost/serialization/list.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/thread/lock_guard.hpp>
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

// #include <boost/program_options/variables_map.hpp>
#if BOOST_VERSION >= 107400
#include <boost/serialization/library_version_type.hpp>
#endif

using namespace sp::knowledge_proofs;

//-------------------------------------------------------------------------------------------------------------------
static void make_message_v1(const rct::key &tx_id, const std::string &message_in, rct::key &message_out)
{
    rct::key message;
    if (message_in.empty())
        message = rct::zero();
    else
        sp_hash_to_32(message_in.data(), message_in.size(), message.bytes);

    // H_32(tx_id, message)
    SpFSTranscript transcript{
        config::HASH_KEY_SP_WALLET_TX_HISTORY_MESSAGE_V1,
        2 * sizeof(rct::key),
    };
    transcript.append("tx_id", tx_id);
    transcript.append("message", message);

    sp_hash_to_32(transcript.data(), transcript.size(), message_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
static void make_message_v2(const std::string &message_in, rct::key &message_out)
{
    rct::key message;
    if (message_in.empty())
        message = rct::zero();
    else
        sp_hash_to_32(message_in.data(), message_in.size(), message.bytes);

    // H_32(message)
    SpFSTranscript transcript{
        config::HASH_KEY_SP_WALLET_TX_HISTORY_MESSAGE_V2,
        sizeof(rct::key),
    };
    transcript.append("message", message);

    sp_hash_to_32(transcript.data(), transcript.size(), message_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const SpTransactionStoreV1 &a, const SpTransactionStoreV1 &b)
{

    return a.tx_records == b.tx_records && a.confirmed_txids == b.confirmed_txids &&
           a.unconfirmed_txids == b.unconfirmed_txids && a.offchain_txids == b.offchain_txids;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const TransactionRecordV1 &a, const TransactionRecordV1 &b)
{
    return a.legacy_spent_enotes == b.legacy_spent_enotes && a.sp_spent_enotes == b.sp_spent_enotes &&
           a.outlays == b.outlays && a.amount_sent == b.amount_sent && a.fee_sent == b.fee_sent;
}
//-------------------------------------------------------------------------------------------------------------------
void SpTransactionHistory::add_entry_to_tx_records(const rct::key &txid, const TransactionRecordV1 &record)
{
    m_sp_tx_store.tx_records[txid] = record;
}
//-------------------------------------------------------------------------------------------------------------------
serializable_multimap<std::uint64_t, rct::key, std::greater<std::uint64_t>> *
SpTransactionHistory::get_pointer_to_tx_status(const SpTxStatus tx_status)
{
    // get pointer to corresponding multimap
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
const SpTransactionStoreV1 SpTransactionHistory::get_tx_store() { return m_sp_tx_store; }
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

    std::cout << tx_view.block << " | " << tx_view.direction << " | " << tx_view.timestamp << " | " << tx_view.amount
              << " | " << tx_view.hash << " | " << tx_view.fee << " | " << tx_view.destinations << std::endl;
}
//-------------------------------------------------------------------------------------------------------------------
void SpTransactionHistory::show_txs(SpEnoteStore &enote_store, uint64_t N)
{
    std::cout << "Block | Direction | Timestamp | Amount | Tx id | Fee | Destination " << std::endl;
    std::cout << " ----------- Confirmed ----------- " << std::endl;

    // a. print last 3 confirmed txs
    const auto range_confirmed{get_last_N_txs(SpTxStatus::CONFIRMED, N)};
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

    // b. print last N unconfirmed txs
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
    const auto range_confirmed{get_last_N_txs(SpTxStatus::CONFIRMED, N)};
    if (!range_confirmed.empty())
    {
        for (auto it_range : range_confirmed)
        {
            std::cout << "Height: " << it_range.first << " Hash: " << it_range.second << std::endl;
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
// UPDATE TRANSACTION HISTORY
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
bool SpTransactionHistory::read_sp_tx_history(std::string path, const epee::wipeable_string &password,
                                              SpTransactionStoreV1 &sp_tx_store)
{
    // 1. Read file into serializable
    ser_SpTransactionStoreV1 ser_tx_store;
    read_encrypted_file(path, password, ser_tx_store);

    // 2. Recover struct from serializable
    recover_sp_transaction_store_v1(ser_tx_store, sp_tx_store);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
// KNOWLEDGE PROOFS
//-------------------------------------------------------------------------------------------------------------------
bool SpTransactionHistory::write_tx_funded_proof(const rct::key &txid, const SpEnoteStore &enote_store,
                                                 const crypto::secret_key &sp_spend_privkey,
                                                 const crypto::secret_key &k_view_balance,
                                                 const std::string &message_in)
{
    std::pair<std::vector<LegacyContextualEnoteRecordV1>, std::vector<SpContextualEnoteRecordV1>> enotes_from_tx{};
    ContextualRecordVariant representing_enote{};

    // 1. get enotes and check if txid exists in storage
    if (!get_enotes_from_tx(txid, enote_store, enotes_from_tx)) return false;

    // 2. get representing enote from tx
    get_representing_enote_from_tx(enotes_from_tx, representing_enote);

    // 3. this proof is interactive so a custom message should be sent from the
    // verifier or an agreed message should be used. In the case that no message
    // is given the agreed message is the hash of the txid
    rct::key message;
    make_message_v1(txid, message_in, message);

    // 4. initialize proof struct
    TxFundedProofV1 tx_funded_proof{};

    // 5. make proof
    if (representing_enote.is_type<SpContextualEnoteRecordV1>())
        make_tx_funded_proof_v1(message, representing_enote.unwrap<SpContextualEnoteRecordV1>().record,
                                sp_spend_privkey, k_view_balance, tx_funded_proof);
    // else
    // make legacy tx_funded_proof

    // 6. serialize struct
    ser_TxFundedProofV1 ser_tx_funded_proof{};
    make_serializable_tx_funded_proof_v1(tx_funded_proof, ser_tx_funded_proof);

    // 7. prepare to save to file by proof name and date
    // TODO: Add date into proof name
    write_encrypted_file("tx_funded_proof", "", ser_tx_funded_proof);
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool read_tx_funded_proof(std::string &path, const epee::wipeable_string &password, const rct::key &tx_id,
                          const std::string &message_in, const sp::mocks::MockLedgerContext &ledger_context)
{
    // 1. Read proof from file
    ser_TxFundedProofV1 ser_tx_funded_proof{};
    TxFundedProofV1 tx_funded_proof{};
    read_encrypted_file(path, password, ser_tx_funded_proof);
    recover_tx_funded_proof_v1(ser_tx_funded_proof, tx_funded_proof);

    // 2. Get msg
    rct::key message;
    make_message_v1(tx_id, message_in, message);

    // 3. From tx_id get all key images of tx by querying node.
    std::vector<crypto::key_image> key_images = ledger_context.get_sp_key_images_at_tx(tx_id);

    // 4. Loop over key images to check if one corresponds to proof.
    for (auto ki : key_images)
    {
        if (ki == tx_funded_proof.KI)
        {
            // 5. Verify tx_funded_proof
            return verify_tx_funded_proof_v1(tx_funded_proof, message, ki);
        }
    }
    return false;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpTransactionHistory::write_address_ownership_proof(const jamtis::address_index_t &j,
                                                         const crypto::secret_key &sp_spend_privkey,
                                                         const crypto::secret_key &k_view_balance,
                                                         const bool bool_Ks_K1, const std::string &message_in)
{
    // There are two scenarios for the message:
    // 1. message_in is an empty string -> in this case the prover can make a
    // proof on an empty string but anyone having this proof would be able to give
    // an address and the acquired proof showing that he owns this address though
    // not true. If the verifier does not provide a custom message he would be
    // succeptible of this type of deceivement anyway.
    // 2. the verifier provides a custom message -> the level of deceivement is
    // small.

    rct::key message;
    make_message_v2(message_in, message);

    // 2. initialize proof struct
    AddressOwnershipProofV1 address_ownership_proof{};

    // 3. make proof
    if (bool_Ks_K1)
        // proof is on K_s
        make_address_ownership_proof_v1(message, sp_spend_privkey, k_view_balance, address_ownership_proof);
    else
        // proof is on K_1
        make_address_ownership_proof_v1(message, sp_spend_privkey, k_view_balance, j, address_ownership_proof);

    // 4. serialize struct
    ser_AddressOwnershipProofV1 ser_address_ownership_proof{};
    make_serializable_address_ownership_proof_v1(address_ownership_proof, ser_address_ownership_proof);

    // 5. prepare to save to file by proof name and date
    // TODO: Add date into proof name
    write_encrypted_file("tx_address_ownership_proof", "", ser_address_ownership_proof);
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool read_address_ownership_proof(std::string &path, const epee::wipeable_string &password,
                                  const std::string &message_in, const rct::key &K)
{
    // 1. read from file
    ser_AddressOwnershipProofV1 ser_address_ownership_proof{};
    AddressOwnershipProofV1 address_ownership_proof{};
    read_encrypted_file(path, password, ser_address_ownership_proof);

    recover_address_ownership_proof_v1(ser_address_ownership_proof, address_ownership_proof);

    // 2. remake message from string provided
    rct::key message;
    make_message_v2(message_in, message);

    // 3. Verify address_ownership_proof
    return verify_address_ownership_proof_v1(address_ownership_proof, message, K);
}
//-------------------------------------------------------------------------------------------------------------------
bool SpTransactionHistory::write_address_index_proof(const rct::key &jamtis_spend_pubkey,
                                                     const jamtis::address_index_t &j, const crypto::secret_key &s_ga)
{

    // 2. initialize proof struct
    AddressIndexProofV1 proof{};

    // 3. make proof
    make_address_index_proof_v1(jamtis_spend_pubkey, j, s_ga, proof);

    // 4. serialize struct
    ser_AddressIndexProofV1 ser_address_index_proof{};
    make_serializable_address_index_proof_v1(proof, ser_address_index_proof);

    // 5. prepare to save to file by proof name and date
    // TODO: Add date into proof name
    write_encrypted_file("tx_address_index_proof", "", ser_address_index_proof);
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool read_address_index_proof(std::string &path, const epee::wipeable_string &password, const rct::key &K_1)
{
    // 1. read from file
    ser_AddressIndexProofV1 ser_address_index_proof{};
    AddressIndexProofV1 address_index_proof{};
    read_encrypted_file(path, password, ser_address_index_proof);

    recover_address_index_proof_v1(ser_address_index_proof, address_index_proof);

    // 2. Verify address_ownership_proof
    return verify_address_index_proof_v1(address_index_proof, K_1);
}
//-------------------------------------------------------------------------------------------------------------------
