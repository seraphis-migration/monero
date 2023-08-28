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

#pragma once

// local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_core/jamtis_payment_proposal.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_impl/enote_store.h"
#include "seraphis_impl/serialization_demo_types.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/sp_knowledge_proof_types.h"
#include "seraphis_main/sp_knowledge_proof_utils.h"

// third party headers
#include <boost/range.hpp>

#include "boost/range/iterator_range.hpp"
#include "seraphis_main/tx_component_types.h"
#include "seraphis_mocks/mock_ledger_context.h"
#include "serialization/binary_archive.h"
#include "serialization/containers.h"
#include "serialization/serialization.h"

// standard headers
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// forward declarations

// Statement of problem:
// - Find fastest way to go from txid to TransactionRecord
// - Find fastest way to go from a range of blocks or time to TransactionRecord

// Solution:
// - Scanning the enotes and filling the SpTransactionStore may be slow but can
// be done in the background or recovered from the wallet files. Not much room
// for improvement either.
// - Finding an entry (SpContextualEnoteRecord) is optimized by blockheight and
// txid (log n).

// New key_images are available whenever an update on the SpEnoteStore occurs
// An update on the SpTransactionStore should be done after that

// When a transfer is done:
// - Entry will be created to store outlays/key_images/amount/fee for a certain
// txid
// - Enote_store will be updated
// - Enote_store will issue a notification returning key_images of updated
// enotes
// - SpTransactionStore will update confirmed_txids(by
// blockheight)/unconfirmed_txids/offchain_txids

using namespace sp::jamtis;
using namespace sp;
using namespace sp::knowledge_proofs;

typedef boost::iterator_range<std::_Rb_tree_iterator<std::pair<const unsigned long, rct::key>>>
    range_txids_by_block_or_time;

enum class SpTxStatus
{
    CONFIRMED,
    UNCONFIRMED,
    OFFCHAIN
};

// (TEMPORARY)
// struct TxViewV1
// {
//     std::string block;
//     std::string direction;
//     std::string unlocked;
//     std::string timestamp;
//     std::string amount;
//     std::string hash;
//     std::string fee;
//     std::string destinations;
//     std::string note;
// };

struct EnoteOutInfo
{
    SpEnoteVariant enote;
    JamtisDestinationV1 destination;
    rct::xmr_amount amount;
    crypto::x25519_secret_key enote_ephemeral_privkey;
    rct::key sender_receiver_secret;
    crypto::secret_key amount_blinding_factor;
    bool selfsend;
};

struct TransactionRecordV1
{
    // key images of spent enotes for tracking purposes
    std::vector<crypto::key_image> legacy_spent_enotes;
    std::vector<crypto::key_image> sp_spent_enotes;

    // input proposal structs
    // - destination address - JamtisDestinationV1
    // - amount sent - xmr_amount
    // - enote ephemeral private key - x25519_secret_key
    std::vector<JamtisPaymentProposalSelfSendV1> selfsend_payments;
    std::vector<JamtisPaymentProposalV1> normal_payments;

    // fees and total sent:
    // useful to store here also instead of looking directly at the enotes and
    // blockchain
    rct::xmr_amount amount_sent;
    rct::xmr_amount fee_sent;
};

struct SpTransactionStoreV1
{
    // quickly find TransactionRecordV1 from txid
    serializable_unordered_map<rct::key, TransactionRecordV1> tx_records;

    // sort by blockheight to find last transactions or txs
    // in a specific time range
    serializable_multimap<std::uint64_t, rct::key, std::greater<std::uint64_t>> confirmed_txids;

    // sort by timestamp instead of blockheight
    serializable_multimap<std::uint64_t, rct::key, std::greater<std::uint64_t>> unconfirmed_txids;
    serializable_multimap<std::uint64_t, rct::key, std::greater<std::uint64_t>> offchain_txids;
};
//-----------------------------------------------------------------
/// Operators
bool operator==(const SpTransactionStoreV1 &a, const SpTransactionStoreV1 &b);
bool operator==(const TransactionRecordV1 &a, const TransactionRecordV1 &b);
//-----------------------------------------------------------------
class SpTransactionHistory
{
    SpTransactionStoreV1 m_sp_tx_store;

   public:
    // add entry to m_tx_records
    void add_entry_to_tx_records(const rct::key &txid, const TransactionRecordV1 &record);

    // add entry to m_confirmed_txids/m_unconfirmed_txids/m_offchain_txids
    void add_entry_txs(const SpTxStatus tx_status, const uint64_t block_or_timestamp, const rct::key &txid);

    // get pointer to m_confirmed_txids/m_unconfirmed_txids/m_offchain_txids
    serializable_multimap<std::uint64_t, rct::key, std::greater<std::uint64_t>> *get_pointer_to_tx_status(
        const SpTxStatus tx_status);

    //-----------------------------------------------------------------
    /// Update (TEMPORARY)
    // - Methods to update tx_statuses
    // - This component could be launched in a separated thread whenever a
    // notification to update is popped. So the confirmed/unconfirmed/offchain txs
    // will always be updated when the EnoteStore is updated.

    // get tx_store
    const SpTransactionStoreV1 get_tx_store();

    // set tx_store
    bool set_tx_store(const SpTransactionStoreV1 &tx_store);

    //-----------------------------------------------------------------
    /// Get range and enotes
    // get last N confirmed/unconfirmed/offchain txs (ordered by
    // blockheight/timestamp)
    const range_txids_by_block_or_time get_last_N_txs(const SpTxStatus tx_status, const uint64_t N);

    // get specific enotes by txid
    bool get_enotes_from_tx(const rct::key &txid,
        const SpEnoteStore &enote_store,
        std::pair<std::vector<LegacyContextualEnoteRecordV1>, std::vector<SpContextualEnoteRecordV1>> &enotes_out);

    // get an enote with tx_info
    bool get_representing_enote_from_tx(
        const std::pair<std::vector<LegacyContextualEnoteRecordV1>, std::vector<SpContextualEnoteRecordV1>>
            &enotes_in_tx,
        ContextualRecordVariant &contextual_enote_out);

    bool try_get_tx_record_from_txid(const rct::key &txid, TransactionRecordV1 &tx_record_out) const;

    //-----------------------------------------------------------------
    /// Show out transfers. Maybe useful for showing failed transfers.
    // (TEMPORARY)

    // // Exhibit txs chronologically
    // bool get_tx_view(const ContextualRecordVariant &contextual_enote, TxViewV1 &tx_view_out);

    // // Print transactions to screen
    // void print_tx_view(const TxViewV1 tx_view);
    // void show_txs(SpEnoteStore &enote_store, uint64_t N);
    // void show_tx_hashes(uint64_t N);

    //-----------------------------------------------------------------
    /// Save/read data to/from file

    bool write_sp_tx_history(std::string path, const epee::wipeable_string &password);
    bool read_sp_tx_history(std::string path, const epee::wipeable_string &password, SpTransactionStoreV1 &sp_tx_store);

    //-----------------------------------------------------------------
    /// Get Knowledge proofs
    // (TEMPORARY)
    std::string get_address_ownership_proof(const jamtis::address_index_t &j,
        const crypto::secret_key &sp_spend_privkey,
        const crypto::secret_key &k_view_balance,
        const bool bool_Ks_K1,
        const std::string message_in,
        const boost::optional<std::string> filename);

    std::string get_address_index_proof(const rct::key &jamtis_spend_pubkey,
        const jamtis::address_index_t &j,
        const crypto::secret_key &s_ga,
        const boost::optional<std::string> filename);

    bool try_make_enote_ownership_proof_sender(const rct::key txid,
        const rct::key &onetime_address,
        const JamtisDestinationV1 &dest,
        const crypto::secret_key &k_vb,
        const bool selfsend,
        EnoteOwnershipProofV1 &proof);

    std::string get_enote_ownership_proof_sender(const rct::key txid,
        const rct::key &onetime_address,
        const JamtisDestinationV1 &dest,
        const crypto::secret_key &k_vb,
        const bool selfsend,
        const boost::optional<std::string> filename);

    std::string get_enote_ownership_proof_receiver(const SpEnoteRecordV1 &enote_record,
        const rct::key &jamtis_spend_pubkey,
        const crypto::secret_key &k_vb,
        const boost::optional<std::string> filename);

    bool try_make_amount_proof(const rct::xmr_amount &amount,
        const crypto::secret_key &mask,
        const rct::key &commitment,
        EnoteAmountProofV1 &amount_proof);

    std::string get_amount_proof(const rct::xmr_amount &amount,
        const crypto::secret_key &mask,
        const rct::key &commitment,
        const boost::optional<std::string> filename);

    std::string get_enote_key_image_proof(const SpEnoteStore &enote_store,
        const crypto::key_image &key_image,
        const crypto::secret_key &k_m,
        const crypto::secret_key &k_vb,
        const boost::optional<std::string> filename);

    std::string get_enote_sent_proof(const rct::key txid,
        const rct::key &onetime_address,
        const JamtisDestinationV1 &dest,
        const crypto::secret_key &k_vb,
        const bool selfsend,
        const rct::xmr_amount &amount,
        const crypto::secret_key &mask,
        const rct::key &commitment,
        const boost::optional<std::string> filename);

    std::string get_tx_funded_proof(const rct::key &txid,
        const SpEnoteStore &enote_store,
        const crypto::secret_key &sp_spend_privkey,
        const crypto::secret_key &k_view_balance,
        const std::string &message_in,
        const boost::optional<std::string> filename);

    std::string get_enote_reserve_proof(const std::string &message_in,
        const std::vector<SpContextualEnoteRecordV1> &reserved_enote_records,
        const rct::key &jamtis_spend_pubkey,
        const crypto::secret_key &sp_spend_privkey,
        const crypto::secret_key &k_view_balance,
        const rct::xmr_amount proof_amount,
        const boost::optional<std::string> filename);
};

bool read_address_ownership_proof(const boost::optional<std::string> filename,
    const boost::optional<std::string> proof_str,
    const std::string &message_in,
    const rct::key &K);

bool read_address_index_proof(const boost::optional<std::string> filename,
    const boost::optional<std::string> proof_str,
    const rct::key &K_1);

bool read_enote_ownership_proof(const boost::optional<std::string> filename,
    const boost::optional<std::string> proof_str,
    const rct::key &expected_amount_commitment,
    const rct::key &expected_onetime_address);

bool read_amount_proof(const boost::optional<std::string> filename,
    const boost::optional<std::string> proof_str,
    const rct::key &expected_amount_commitment);

bool read_enote_key_image_proof(const boost::optional<std::string> filename,
    const boost::optional<std::string> proof_str,
    const rct::key &expected_onetime_address,
    const crypto::key_image &expected_KI);

bool read_enote_sent_proof(const boost::optional<std::string> filename,
    const boost::optional<std::string> proof_str,
    const rct::key &expected_amount_commitment,
    const rct::key &expected_onetime_address);

bool read_tx_funded_proof(const boost::optional<std::string> filename,
    const boost::optional<std::string> proof_str,
    const rct::key &tx_id,
    const std::string &message_in,
    const std::vector<crypto::key_image> &key_images);

bool read_enote_reserve_proof(const boost::optional<std::string> filename,
    const boost::optional<std::string> proof_str,
    const std::string &expected_message,
    const TxValidationContext &validation_context);

bool get_enote_out_info(std::vector<SpEnoteVariant> &enotes_out,
    const std::vector<JamtisPaymentProposalV1> &normal_payments,
    const std::vector<JamtisPaymentProposalSelfSendV1> &selfsend_payments,
    const rct::key &input_context,
    const crypto::secret_key &k_vb,
    std::vector<EnoteOutInfo> &enote_info);

template <typename T>
std::string proof_to_str(T &serializable_proof, std::string prefix);

template <typename T>
T str_to_proof(const std::string prefix,
    const boost::optional<std::string> filename,
    const boost::optional<std::string> proof_str);
