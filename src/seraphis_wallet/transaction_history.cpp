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
#include "checkpoints/checkpoints.h"
#include "common/base58.h"
#include "common/container_helpers.h"
#include "common/unordered_containers_boost_serialization.h"
#include "common/util.h"
#include "crypto/chacha.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "cryptonote_basic/account_boost_serialization.h"
#include "file_io_utils.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_core/jamtis_enote_utils.h"
#include "seraphis_core/jamtis_payment_proposal.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_core/sp_core_types.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_crypto/sp_hash_functions.h"
#include "seraphis_crypto/sp_transcript.h"
#include "seraphis_impl/enote_store.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/enote_record_types.h"
#include "seraphis_main/sp_knowledge_proof_types.h"
#include "seraphis_main/sp_knowledge_proof_utils.h"
#include "seraphis_main/tx_builders_outputs.h"
#include "seraphis_main/tx_component_types.h"
#include "seraphis_main/tx_validation_context.h"
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
#include <iostream>
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

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_wallet"

using namespace sp::knowledge_proofs;

//-------------------------------------------------------------------------------------------------------------------
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
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const SpTransactionStoreV1 &a, const SpTransactionStoreV1 &b)
{

    return a.tx_records == b.tx_records && a.txs_by_timestamp == b.txs_by_timestamp;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const TransactionRecordV1 &a, const TransactionRecordV1 &b)
{
    return a.legacy_spent_enotes == b.legacy_spent_enotes && a.sp_spent_enotes == b.sp_spent_enotes &&
           a.normal_payments == b.normal_payments && a.selfsend_payments == b.selfsend_payments &&
           a.amount_sent == b.amount_sent && a.fee_sent == b.fee_sent;
}

//-----------------------------------------------------------------
/// Add entries to SpTransactionStore
//-----------------------------------------------------------------

void SpTransactionHistory::add_entry_to_tx_records(const rct::key &txid, const TransactionRecordV1 &record)
{
    m_sp_tx_store.tx_records[txid] = record;
}
//-------------------------------------------------------------------------------------------------------------------
void SpTransactionHistory::add_entry_to_txs_by_timestamp(const uint64_t timestamp, const rct::key &txid)
{
    m_sp_tx_store.txs_by_timestamp.emplace(timestamp,txid);
}
//-------------------------------------------------------------------------------------------------------------------
void SpTransactionHistory::add_single_tx_to_tx_history(const SpTxSquashedV1 &single_tx,
    const std::vector<JamtisPaymentProposalSelfSendV1> &selfsend_payments,
    const std::vector<JamtisPaymentProposalV1> &normal_payments)
{
    /// 1. prepare variables of tx_store
    rct::key tx_id;
    std::vector<crypto::key_image> legacy_spent_ki;
    std::vector<crypto::key_image> sp_spent_ki;
    TransactionRecordV1 record;

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
    record = TransactionRecordV1{
        legacy_spent_ki, sp_spent_ki, selfsend_payments, normal_payments, total_amount_sent, tx_fee};

    // 2. add record to tx_record by tx_id
    add_entry_to_tx_records(tx_id, std::move(record));

    // 3. add record to txs_by_timestamp
    std::time_t timestamp = std::time(nullptr);
    std::asctime(std::localtime(&timestamp));
    add_entry_to_txs_by_timestamp(timestamp, tx_id);
}

//-----------------------------------------------------------------
/// Get/Set SpTransactionStore
//-----------------------------------------------------------------

const SpTransactionStoreV1 SpTransactionHistory::get_tx_store() { return m_sp_tx_store; }
//-------------------------------------------------------------------------------------------------------------------
bool SpTransactionHistory::set_tx_store(const SpTransactionStoreV1 &tx_store)
{
    m_sp_tx_store = tx_store;
    return true;
}

//-----------------------------------------------------------------
/// Get info from enotes and txs
//-----------------------------------------------------------------

const range_txids_by_block_or_time SpTransactionHistory::get_last_N_txs(const uint64_t N) 
{
    // 1. set begin and end iterators to beggining of multimap
    auto it_begin = m_sp_tx_store.txs_by_timestamp.begin();
    auto it_end   = m_sp_tx_store.txs_by_timestamp.begin();


    // 2. get size of multimap
    uint64_t counts{m_sp_tx_store.txs_by_timestamp.size()};

    // 3. advance the end iterator to the end or to the position N
    if (N < counts)
        std::advance(it_end, N);
    else
        std::advance(it_end, counts);

    // 4. return range
    return boost::make_iterator_range(it_begin, it_end);
}
//-------------------------------------------------------------------------------------------------------------------
bool SpTransactionHistory::get_enotes_from_tx(const rct::key &txid,
    const SpEnoteStore &enote_store,
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
    // try to get the first sp enote representing the tx
    if (!enotes_in_tx.second.empty())
    {
        contextual_enote_out = enotes_in_tx.second[0];
        return true;
    }
    else
    // try to get the first legacy enote representing the tx
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
bool SpTransactionHistory::try_get_tx_record_from_txid(const rct::key &txid, TransactionRecordV1 &tx_record_out) const
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

bool SpTransactionHistory::write_sp_tx_history(std::string path, const epee::wipeable_string &password)
{
    // 1. Get serializable of structure
    ser_SpTransactionStoreV1 ser_tx_store;
    make_serializable_sp_transaction_store_v1(m_sp_tx_store, ser_tx_store);

    // 3. Save serializable struct to file
    return write_encrypted_file(path, password, ser_tx_store);
}
//-------------------------------------------------------------------------------------------------------------------
bool SpTransactionHistory::read_sp_tx_history(std::string path,
    const epee::wipeable_string &password,
    SpTransactionStoreV1 &sp_tx_store)
{
    // 1. Read file into serializable
    ser_SpTransactionStoreV1 ser_tx_store;
    read_encrypted_file(path, password, ser_tx_store);

    // 2. Recover struct from serializable
    recover_sp_transaction_store_v1(ser_tx_store, sp_tx_store);

    return true;
}

//-----------------------------------------------------------------
/// Get Knowledge proofs
//-----------------------------------------------------------------

std::string SpTransactionHistory::get_address_ownership_proof(const jamtis::address_index_t &j,
    const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_view_balance,
    const bool bool_Ks_K1,
    const std::string message_in,
    const boost::optional<std::string> filename)
{
    // There are two scenarios for the message:
    // 1. message_in is an empty string -> in this case the prover can make a
    // proof on an empty string but anyone having this proof would be able to give
    // an address and the acquired proof showing that he owns this address though
    // not true. If the verifier does not provide a custom message he would be
    // succeptible of this type of deceivement anyway.
    // 2. the verifier provides a custom message -> the level of deceivement is
    // small.

    // 1. prepare message
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

    // 5. prepare to save to file and return string of proof
    std::string proof_str = proof_to_str(ser_address_ownership_proof, "SpAddressOwnershipProofV1");

    if (filename && !proof_str.empty())
    {
        CHECK_AND_ASSERT_THROW_MES(epee::file_io_utils::save_string_to_file(filename.get(), proof_str),
            "get_address_ownership_proof: failed to save string to file");
    }

    return proof_str;
}
//-------------------------------------------------------------------------------------------------------------------
std::string SpTransactionHistory::get_address_index_proof(const rct::key &jamtis_spend_pubkey,
    const jamtis::address_index_t &j,
    const crypto::secret_key &s_ga,
    const boost::optional<std::string> filename)
{

    // 1. initialize proof struct
    AddressIndexProofV1 proof{};

    // 2. make proof
    make_address_index_proof_v1(jamtis_spend_pubkey, j, s_ga, proof);

    // 3. serialize struct
    ser_AddressIndexProofV1 ser_address_index_proof{};
    make_serializable_address_index_proof_v1(proof, ser_address_index_proof);

    // 4. prepare to save to file and return string of proof
    std::string proof_str = proof_to_str(ser_address_index_proof, "SpAddressIndexProofV1");
    if (filename && !proof_str.empty())
    {
        CHECK_AND_ASSERT_THROW_MES(epee::file_io_utils::save_string_to_file(filename.get(), proof_str),
            "get_address_index_proof: failed to save string to file");
    }

    return proof_str;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpTransactionHistory::try_make_enote_ownership_proof_sender(const rct::key txid,
    const rct::key &onetime_address,
    const JamtisDestinationV1 &dest,
    const crypto::secret_key &k_vb,
    const bool selfsend,
    EnoteOwnershipProofV1 &proof)
{
    // get tx info from this enote
    auto tx_record = m_sp_tx_store.tx_records.find(txid);
    if (tx_record != m_sp_tx_store.tx_records.end())
    {
        if (selfsend)
        {
            JamtisPaymentProposalSelfSendV1 payment_proposal;
            for (auto rec : tx_record->second.selfsend_payments)
            {
                if (rec.destination == dest)
                    payment_proposal = rec;
            }

            // check if payment proposal is not empty
            if (!(payment_proposal.destination == dest))
                return false;

            rct::key input_context;
            make_jamtis_input_context_standard(
                tx_record->second.legacy_spent_enotes, tx_record->second.sp_spent_enotes, input_context);

            SpOutputProposalV1 output_proposal;
            make_v1_output_proposal_v1(payment_proposal, k_vb, input_context, output_proposal);
            SpEnoteV1 enote;
            get_enote_v1(output_proposal, enote);

            // check if onetime_address corresponds to enote onetime_address
            if (!(enote.core.onetime_address == onetime_address))
                return false;

            make_enote_ownership_proof_v1_sender_selfsend(output_proposal.enote_ephemeral_pubkey,
                dest.addr_K1,
                input_context,
                k_vb,
                payment_proposal.type,
                enote.core.amount_commitment,
                enote.core.onetime_address,
                proof);
        }
        else
        {
            JamtisPaymentProposalV1 payment_proposal;
            for (auto rec : tx_record->second.normal_payments)
            {
                if (rec.destination == dest)
                    payment_proposal = rec;
            }

            // check if payment proposal is not empty
            if (!(payment_proposal.destination == dest))
                return false;

            rct::key input_context;
            make_jamtis_input_context_standard(
                tx_record->second.legacy_spent_enotes, tx_record->second.sp_spent_enotes, input_context);

            SpOutputProposalV1 output_proposal;
            make_v1_output_proposal_v1(payment_proposal, input_context, output_proposal);
            SpEnoteV1 enote;
            get_enote_v1(output_proposal, enote);

            // check if onetime_address corresponds to enote onetime_address
            if (!(enote.core.onetime_address == onetime_address))
                return false;

            make_enote_ownership_proof_v1_sender_plain(payment_proposal.enote_ephemeral_privkey,
                dest,
                input_context,
                enote.core.amount_commitment,
                enote.core.onetime_address,
                proof);
        }
    }

    // Check if proof is not empty
    if (!(proof.Ko == onetime_address))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
std::string SpTransactionHistory::get_enote_ownership_proof_sender(const rct::key txid,
    const rct::key &onetime_address,
    const JamtisDestinationV1 &dest,
    const crypto::secret_key &k_vb,
    const bool selfsend,
    const boost::optional<std::string> filename)
{
    // 1. make proof
    EnoteOwnershipProofV1 proof;
    CHECK_AND_ASSERT_THROW_MES(
        try_make_enote_ownership_proof_sender(txid, onetime_address, dest, k_vb, selfsend, proof),
        "get_enote_ownership_proof_sender: failed to make enote ownership proof "
        "sender.");

    // 2. serialize struct
    ser_EnoteOwnershipProofV1 ser_enote_ownership_proof{};
    make_serializable_enote_ownership_proof_v1(proof, ser_enote_ownership_proof);

    // 3. prepare to save to file and return string of proof
    std::string proof_str = proof_to_str(ser_enote_ownership_proof, "SpEnoteOwnershipProofV1");
    if (filename && !proof_str.empty())
        CHECK_AND_ASSERT_THROW_MES(epee::file_io_utils::save_string_to_file(filename.get(), proof_str),
            "get_enote_ownership_proof_sender: failed to save string to file");

    return proof_str;
}
//-------------------------------------------------------------------------------------------------------------------
std::string SpTransactionHistory::get_enote_ownership_proof_receiver(const SpEnoteRecordV1 &enote_record,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_vb,
    const boost::optional<std::string> filename)
{
    // 1. make proof
    EnoteOwnershipProofV1 proof;
    make_enote_ownership_proof_v1_receiver(enote_record, jamtis_spend_pubkey, k_vb, proof);

    // 2. serialize struct
    ser_EnoteOwnershipProofV1 ser_enote_ownership_proof{};
    make_serializable_enote_ownership_proof_v1(proof, ser_enote_ownership_proof);

    // 3. prepare to save to file and return string of proof
    std::string proof_str = proof_to_str(ser_enote_ownership_proof, "SpEnoteOwnershipProofV1");
    if (filename && !proof_str.empty())
        CHECK_AND_ASSERT_THROW_MES(epee::file_io_utils::save_string_to_file(filename.get(), proof_str),
            "get_enote_ownership_proof_receiver: failed to save string to file");

    return proof_str;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpTransactionHistory::try_make_amount_proof(const rct::xmr_amount &amount,
    const crypto::secret_key &mask,
    const rct::key &commitment,
    EnoteAmountProofV1 &amount_proof)
{
    make_enote_amount_proof_v1(amount, mask, commitment, amount_proof);

    if (!(amount_proof.C == rct::commit(amount_proof.a, amount_proof.x)))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
std::string SpTransactionHistory::get_amount_proof(const rct::xmr_amount &amount,
    const crypto::secret_key &mask,
    const rct::key &commitment,
    const boost::optional<std::string> filename)
{
    // 1. initialize proof struct
    EnoteAmountProofV1 amount_proof{};

    // 2. make proof
    CHECK_AND_ASSERT_THROW_MES(try_make_amount_proof(amount, mask, commitment, amount_proof),
        "get_enote_amount_proof: failed to make amount proof.");

    // 3. serialize struct
    ser_EnoteAmountProofV1 ser_amount_proof{};
    make_serializable_enote_amount_proof_v1(amount_proof, ser_amount_proof);

    // 4. prepare to save to file and return string of proof
    std::string proof_str = proof_to_str(ser_amount_proof, "SpEnoteAmountProofV1");
    if (filename && !proof_str.empty())
        CHECK_AND_ASSERT_THROW_MES(epee::file_io_utils::save_string_to_file(filename.get(), proof_str),
            "get_enote_amount_proof: failed to save string to file");

    return proof_str;
}
//-------------------------------------------------------------------------------------------------------------------
std::string SpTransactionHistory::get_enote_key_image_proof(const SpEnoteStore &enote_store,
    const crypto::key_image &key_image,
    const crypto::secret_key &k_m,
    const crypto::secret_key &k_vb,
    const boost::optional<std::string> filename)
{
    // 1. initialize proof struct
    EnoteKeyImageProofV1 key_image_proof{};
    SpContextualEnoteRecordV1 contextual_record{};

    enote_store.try_get_sp_enote_record(key_image, contextual_record);

    // 2. make proof
    make_enote_key_image_proof_v1(contextual_record.record, k_m, k_vb, key_image_proof);

    // 3. serialize struct
    ser_EnoteKeyImageProofV1 ser_key_image_proof{};
    make_serializable_enote_key_image_proof_v1(key_image_proof, ser_key_image_proof);

    // 4. prepare to save to file and return string of proof
    std::string proof_str = proof_to_str(ser_key_image_proof, "SpEnoteKeyImageProofV1");
    if (filename && !proof_str.empty())
        CHECK_AND_ASSERT_THROW_MES(epee::file_io_utils::save_string_to_file(filename.get(), proof_str),
            "get_enote_key_image_proof: failed to save string to file");

    return proof_str;
}
//-------------------------------------------------------------------------------------------------------------------
std::string SpTransactionHistory::get_enote_sent_proof(const rct::key txid,
    const rct::key &onetime_address,
    const JamtisDestinationV1 &dest,
    const crypto::secret_key &k_vb,
    const bool selfsend,
    const rct::xmr_amount &amount,
    const crypto::secret_key &mask,
    const rct::key &commitment,
    const boost::optional<std::string> filename)
{
    // 1. initialize proof struct
    EnoteOwnershipProofV1 enote_onwnership_proof{};
    EnoteAmountProofV1 enote_amount_proof{};
    EnoteSentProofV1 enote_sent_proof{};

    // 2. make proofs
    CHECK_AND_ASSERT_THROW_MES(try_make_amount_proof(amount, mask, commitment, enote_amount_proof),
        "get_enote_sent_proof: failed to make amount proof.");
    CHECK_AND_ASSERT_THROW_MES(
        try_make_enote_ownership_proof_sender(txid, onetime_address, dest, k_vb, selfsend, enote_onwnership_proof),
        "get_enote_sent_proof: failed to make ownership proof.");

    make_enote_sent_proof_v1(enote_onwnership_proof, enote_amount_proof, enote_sent_proof);

    // 3. serialize struct
    ser_EnoteSentProofV1 ser_enote_sent_proof{};
    make_serializable_enote_sent_proof_v1(enote_sent_proof, ser_enote_sent_proof);

    // 4. prepare to save to file and return string of proof
    std::string proof_str = proof_to_str(ser_enote_sent_proof, "SpEnoteSentProofV1");
    if (filename && !proof_str.empty())
        CHECK_AND_ASSERT_THROW_MES(epee::file_io_utils::save_string_to_file(filename.get(), proof_str),
            "get_enote_sent_proof: failed to save string to file");

    return proof_str;
}
//-------------------------------------------------------------------------------------------------------------------
std::string SpTransactionHistory::get_tx_funded_proof(const rct::key &txid,
    const SpEnoteStore &enote_store,
    const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_view_balance,
    const std::string &message_in,
    const boost::optional<std::string> filename)
{
    // 1. get enotes and check if txid exists in storage
    std::pair<std::vector<LegacyContextualEnoteRecordV1>, std::vector<SpContextualEnoteRecordV1>> enotes_from_tx{};
    ContextualRecordVariant representing_enote{};
    CHECK_AND_ASSERT_THROW_MES(
        get_enotes_from_tx(txid, enote_store, enotes_from_tx), "get_tx_funded_proof: failed to get enotes from tx.");

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
    // (the corresponding legacy proof is the SpentProof)
    if (representing_enote.is_type<SpContextualEnoteRecordV1>())
        make_tx_funded_proof_v1(message,
            representing_enote.unwrap<SpContextualEnoteRecordV1>().record,
            sp_spend_privkey,
            k_view_balance,
            tx_funded_proof);

    // 6. serialize struct
    ser_TxFundedProofV1 ser_tx_funded_proof{};
    make_serializable_tx_funded_proof_v1(tx_funded_proof, ser_tx_funded_proof);

    // 7. prepare to save to file and return string of proof
    std::string proof_str = proof_to_str(ser_tx_funded_proof, "SpTxFundedProofV1");
    if (filename && !proof_str.empty())
    {
        CHECK_AND_ASSERT_THROW_MES(epee::file_io_utils::save_string_to_file(filename.get(), proof_str),
            "get_tx_funded_proof: failed to save string to file");
    }

    return proof_str;
}
//-------------------------------------------------------------------------------------------------------------------
std::string SpTransactionHistory::get_enote_reserve_proof(const std::string &message_in,
    const std::vector<SpContextualEnoteRecordV1> &reserved_enote_records,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_view_balance,
    const rct::xmr_amount proof_amount,
    const boost::optional<std::string> filename)
{
    // 1. initialize proof struct and get message
    ReserveProofV1 proof;
    rct::key message;
    make_message_v2(message_in, message);

    // 2. select unspent enotes
    std::vector<SpContextualEnoteRecordV1> selected_enotes;
    for (const auto &enote : reserved_enote_records)
    {
        if (enote.spent_context.spent_status == SpEnoteSpentStatus::UNSPENT)
        {
            selected_enotes.push_back(enote);
        }
    }

    // 3. select unspent enotes up to amount
    std::sort(selected_enotes.begin(),
        selected_enotes.end(),
        [&](const SpContextualEnoteRecordV1 a, const SpContextualEnoteRecordV1 b)
        { return a.record.amount > b.record.amount; });

    rct::xmr_amount total{0};
    size_t i = 0;
    while (total < proof_amount)
    {
        total += selected_enotes[i].record.amount;
        ++i;
    }
    selected_enotes.resize(i);

    // 4. make proof
    CHECK_AND_ASSERT_THROW_MES(!selected_enotes.empty(), "get_enote_reserve_proof: selected_enotes is empty.");
    make_reserve_proof_v1(message, selected_enotes, jamtis_spend_pubkey, sp_spend_privkey, k_view_balance, proof);

    // 5. serialize struct
    ser_ReserveProofV1 ser_reserve_proof{};
    make_serializable_reserve_proof_v1(proof, ser_reserve_proof);

    // 6. prepare to save to file and return string of proof
    std::string proof_str = proof_to_str(ser_reserve_proof, "SpEnoteReserveProofV1");
    if (filename && !proof_str.empty())
    {
        CHECK_AND_ASSERT_THROW_MES(epee::file_io_utils::save_string_to_file(filename.get(), proof_str),
            "get_enote_reserve_proof: failed to save string to file");
    }

    return proof_str;
}

//-----------------------------------------------------------------
/// Read/Verify Knowledge proofs
//-------------------------------------------------------------------------------------------------------------------

bool read_address_ownership_proof(const boost::optional<std::string> filename,
    const boost::optional<std::string> proof_str,
    const std::string &message_in,
    const rct::key &K)
{
    // 1. read from file or string
    ser_AddressOwnershipProofV1 ser_address_ownership_proof{
        str_to_proof<ser_AddressOwnershipProofV1>("SpAddressOwnershipProofV1", filename, proof_str)};
    AddressOwnershipProofV1 address_ownership_proof{};
    recover_address_ownership_proof_v1(ser_address_ownership_proof, address_ownership_proof);

    // 2. remake message from string provided
    rct::key message;
    make_message_v2(message_in, message);

    // 3. Verify proof
    return verify_address_ownership_proof_v1(address_ownership_proof, message, K);
}
//-------------------------------------------------------------------------------------------------------------------
bool read_address_index_proof(const boost::optional<std::string> filename,
    const boost::optional<std::string> proof_str,
    const rct::key &K_1)
{
    // 1. read from file or string
    ser_AddressIndexProofV1 ser_address_index_proof{
        str_to_proof<ser_AddressIndexProofV1>("SpAddressIndexProofV1", filename, proof_str)};
    AddressIndexProofV1 address_index_proof{};
    recover_address_index_proof_v1(ser_address_index_proof, address_index_proof);

    // 2. Verify proof
    return verify_address_index_proof_v1(address_index_proof, K_1);
}
//-------------------------------------------------------------------------------------------------------------------
bool read_enote_ownership_proof(const boost::optional<std::string> filename,
    const boost::optional<std::string> proof_str,
    const rct::key &expected_amount_commitment,
    const rct::key &expected_onetime_address)
{
    // 1. Read proof from file or string
    ser_EnoteOwnershipProofV1 ser_enote_ownership_proof{
        str_to_proof<ser_EnoteOwnershipProofV1>("SpEnoteOwnershipProofV1", filename, proof_str)};
    EnoteOwnershipProofV1 enote_ownership_proof{};
    recover_enote_ownership_proof_v1(ser_enote_ownership_proof, enote_ownership_proof);

    // 2. verify proof
    return verify_enote_ownership_proof_v1(enote_ownership_proof, expected_amount_commitment, expected_onetime_address);
}
//-------------------------------------------------------------------------------------------------------------------
bool read_amount_proof(const boost::optional<std::string> filename,
    const boost::optional<std::string> proof_str,
    const rct::key &expected_amount_commitment)
{

    // 1. read from file or string
    ser_EnoteAmountProofV1 ser_enote_amount_proof{
        str_to_proof<ser_EnoteAmountProofV1>("SpEnoteAmountProofV1", filename, proof_str)};
    EnoteAmountProofV1 enote_amount_proof{};
    recover_enote_amount_proof_v1(ser_enote_amount_proof, enote_amount_proof);

    // 2. Verify proof
    return verify_enote_amount_proof_v1(enote_amount_proof, expected_amount_commitment);
}
//-------------------------------------------------------------------------------------------------------------------
bool read_enote_key_image_proof(const boost::optional<std::string> filename,
    const boost::optional<std::string> proof_str,
    const rct::key &expected_onetime_address,
    const crypto::key_image &expected_KI)
{
    // 1. read from file or string
    ser_EnoteKeyImageProofV1 ser_key_image_proof{
        str_to_proof<ser_EnoteKeyImageProofV1>("SpEnoteKeyImageProofV1", filename, proof_str)};
    EnoteKeyImageProofV1 enote_key_image_proof{};
    recover_enote_key_image_proof_v1(ser_key_image_proof, enote_key_image_proof);

    // 2. Verify proof
    return verify_enote_key_image_proof_v1(enote_key_image_proof, expected_onetime_address, expected_KI);
}
//-------------------------------------------------------------------------------------------------------------------
bool read_enote_sent_proof(const boost::optional<std::string> filename,
    const boost::optional<std::string> proof_str,
    const rct::key &expected_amount_commitment,
    const rct::key &expected_onetime_address)
{
    // 1. read from file or string
    ser_EnoteSentProofV1 ser_enote_sent_proof{
        str_to_proof<ser_EnoteSentProofV1>("SpEnoteSentProofV1", filename, proof_str)};
    EnoteSentProofV1 enote_sent_proof{};
    recover_enote_sent_proof_v1(ser_enote_sent_proof, enote_sent_proof);

    // 2. Verify proof
    return verify_enote_sent_proof_v1(enote_sent_proof, expected_amount_commitment, expected_onetime_address);
}
//-------------------------------------------------------------------------------------------------------------------
bool read_tx_funded_proof(const boost::optional<std::string> filename,
    const boost::optional<std::string> proof_str,
    const rct::key &tx_id,
    const std::string &message_in,
    const std::vector<crypto::key_image> &key_images)
{
    // 1. read proof from file or string
    ser_TxFundedProofV1 ser_tx_funded_proof{
        str_to_proof<ser_TxFundedProofV1>("SpTxFundedProofV1", filename, proof_str)};
    TxFundedProofV1 tx_funded_proof{};
    recover_tx_funded_proof_v1(ser_tx_funded_proof, tx_funded_proof);

    // 2. get msg
    rct::key message;
    make_message_v1(tx_id, message_in, message);

    // 3. loop over key images to check if one corresponds to proof
    for (auto ki : key_images)
    {
        if (ki == tx_funded_proof.KI)
        {
            // 4. verify tx_funded_proof
            return verify_tx_funded_proof_v1(tx_funded_proof, message, ki);
        }
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
bool read_enote_reserve_proof(const boost::optional<std::string> filename,
    const boost::optional<std::string> proof_str,
    const std::string &expected_message,
    const TxValidationContext &validation_context)
{
    // 1. read proof from file or string
    ser_ReserveProofV1 ser_reserve_proof{
        str_to_proof<ser_ReserveProofV1>("SpEnoteReserveProofV1", filename, proof_str)};
    ReserveProofV1 reserve_proof{};
    recover_reserve_proof_v1(ser_reserve_proof, reserve_proof);

    // 2. get msg
    rct::key message;
    make_message_v2(expected_message, message);

    // 3. verify proof and get amount
    if (verify_reserve_proof_v1(reserve_proof, message, validation_context))
        std::cout << "Reserve proof is valid. Value of reserves: " << total_reserve_amount(reserve_proof) << std::endl;
    else
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool get_enote_out_info(std::vector<SpEnoteVariant> &enotes_out,
    const std::vector<JamtisPaymentProposalV1> &normal_payments,
    const std::vector<JamtisPaymentProposalSelfSendV1> &selfsend_payments,
    const rct::key &input_context,
    const crypto::secret_key &k_vb,
    std::vector<EnoteOutInfo> &enote_info)
{
    // find correspondence between enote and destination

    // 1. check if size(normal) + size(selfsend) == size(enotes_out)
    size_t s = enotes_out.size();
    if (normal_payments.size() + selfsend_payments.size() != s)
        return false;

    enote_info.clear();
    crypto::x25519_pubkey xK_e;
    rct::key q;
    rct::key baked_key;
    crypto::secret_key mask;
    // 2. loop over normal
    for (auto payment : normal_payments)
    {
        // 2.1. calculate sender-receiver secret
        // enote ephemeral pubkey: xK_e = xr xK_3
        make_jamtis_enote_ephemeral_pubkey(payment.enote_ephemeral_privkey, payment.destination.addr_K3, xK_e);
        make_jamtis_sender_receiver_secret_plain(
            payment.enote_ephemeral_privkey, payment.destination.addr_K2, xK_e, input_context, q);
        // loop over enotes
        for (size_t i = 0; i < enotes_out.size(); i++)
        {
            if (test_jamtis_onetime_address(payment.destination.addr_K1,
                    q,
                    amount_commitment_ref(enotes_out[i]),
                    onetime_address_ref(enotes_out[i])))
            {
                make_jamtis_amount_baked_key_plain_sender(payment.enote_ephemeral_privkey, baked_key);
                make_jamtis_amount_blinding_factor(q, baked_key, mask);

                // add to vector
                enote_info.push_back(EnoteOutInfo{enotes_out[i],
                    payment.destination,
                    payment.amount,
                    payment.enote_ephemeral_privkey,
                    q,
                    mask,
                    false});
                enotes_out.erase(enotes_out.begin() + i);
                break;
            }
        }
    }

    // 3. loop over selfsend
    for (auto payment : selfsend_payments)
    {
        // 3.1. calculate sender-receiver secret
        // enote ephemeral pubkey: xK_e = xr xK_3
        make_jamtis_enote_ephemeral_pubkey(payment.enote_ephemeral_privkey, payment.destination.addr_K3, xK_e);

        make_jamtis_sender_receiver_secret_selfsend(k_vb, xK_e, input_context, payment.type, q);

        // loop over enotes
        for (size_t i = 0; i < enotes_out.size(); i++)
        {
            if (test_jamtis_onetime_address(payment.destination.addr_K1,
                    q,
                    amount_commitment_ref(enotes_out[i]),
                    onetime_address_ref(enotes_out[i])))
            {
                make_jamtis_amount_baked_key_selfsend(k_vb, q, baked_key);
                make_jamtis_amount_blinding_factor(q, baked_key, mask);

                // add to vector
                enote_info.push_back(EnoteOutInfo{enotes_out[i],
                    payment.destination,
                    payment.amount,
                    payment.enote_ephemeral_privkey,
                    q,
                    mask,
                    true});
                enotes_out.erase(enotes_out.begin() + i);
                break;
            }
        }
    }

    // 4. check if all onetime addresses were properly built
    // and match all jamtis payments
    if (enote_info.size() != s)
        return false;

    return true;
}

template <typename T>
std::string proof_to_str(T &serializable_proof, std::string prefix)
{
    std::stringstream data_oss;
    binary_archive<true> data_ar(data_oss);
    if (!::serialization::serialize(data_ar, serializable_proof))
        return std::string("");
    std::string buf = data_oss.str();
    return (prefix + tools::base58::encode(buf));
}

template <typename T>
T str_to_proof(const std::string prefix,
    const boost::optional<std::string> filename,
    const boost::optional<std::string> proof_str)
{
    // 1. check if both (filename and string with proof) are not empty
    if (!filename && !proof_str)
        ASSERT_MES_AND_THROW("str_to_proof failed. Both filename and proof_str are empty.")

    // 2. try to read proof from file
    std::string proof_str_from_file;
    if (filename)
        CHECK_AND_ASSERT_THROW_MES(epee::file_io_utils::load_file_to_string(filename.get(), proof_str_from_file),
            "str_to_proof failed. Error loading file to string.");

    // 3. try to use proof from file otherwise use proof from string
    std::string proof_str_used;
    if (!proof_str_from_file.empty())
        proof_str_used = proof_str_from_file;
    else
        proof_str_used = proof_str.get();

    // 4. decode proof from base58
    std::string proof_decoded;
    CHECK_AND_ASSERT_THROW_MES(tools::base58::decode(proof_str_used.substr(prefix.length()), proof_decoded),
        "str_to_proof failed. Error decoding string.");

    // 5. deserialize into the structure
    T serializable_proof;
    binary_archive<false> ar{epee::strspan<std::uint8_t>(proof_decoded)};
    CHECK_AND_ASSERT_THROW_MES(
        ::serialization::serialize(ar, serializable_proof), "str_to_proof failed. Error to get serializable.");

    // 6. return serializable
    return serializable_proof;
}
