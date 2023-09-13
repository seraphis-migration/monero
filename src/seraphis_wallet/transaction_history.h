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
#include "seraphis_main/tx_component_types.h"
#include "seraphis_mocks/mock_ledger_context.h"
#include "serialization/binary_archive.h"
#include "serialization/containers.h"
#include "serialization/serialization.h"

// third party headers
#include <boost/range.hpp>
#include "boost/range/iterator_range.hpp"

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

// The goal of this component (SpTransactionHistory) is to store all the relevant information (SpTransactionStoreV1)
// from transactions made by the wallet and allow the user to efficiently access these information later (to visualize
// specific info from enotes or generate knowledge proofs for example). 

using namespace sp::jamtis;
using namespace sp;
using namespace sp::knowledge_proofs;

typedef boost::iterator_range<std::_Rb_tree_iterator<std::pair<const unsigned long, rct::key>>>
    range_txids_by_block_or_time;


// struct to store the relevant info from a tx
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
    // useful to store here also instead of looking directly at the enotes and blockchain
    rct::xmr_amount amount_sent;
    rct::xmr_amount fee_sent;
};

// struct to efficiently store/sort records
struct SpTransactionStoreV1
{
    // quickly find TransactionRecordV1 from txid
    serializable_unordered_map<rct::key, TransactionRecordV1> tx_records;

    // sort by timestamp (does not need to be a multimap)
    serializable_multimap<std::uint64_t, rct::key, std::greater<std::uint64_t>> txs_by_timestamp;
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
    //-----------------------------------------------------------------
    /// Add entries to SpTransactionStore
    //-----------------------------------------------------------------

    // add entry to tx_records
    void add_entry_to_tx_records(const rct::key &txid, const TransactionRecordV1 &record);

    // add entry to txs_by_timestamp
    void add_entry_to_txs_by_timestamp(const uint64_t timestamp, const rct::key &txid);

    // add entries to SpTransactionStore from single_tx
    void add_single_tx_to_tx_history(const SpTxSquashedV1 &single_tx,
        const std::vector<JamtisPaymentProposalSelfSendV1> &selfsend_payments,
        const std::vector<JamtisPaymentProposalV1> &normal_payments);

    //-----------------------------------------------------------------
    /// Get/Set SpTransactionStore
    //-----------------------------------------------------------------

    // get tx_store
    const SpTransactionStoreV1 get_tx_store() const;

    // set tx_store
    bool set_tx_store(const SpTransactionStoreV1 &tx_store);

    //-----------------------------------------------------------------
    /// Get info from enotes and txs
    //-----------------------------------------------------------------

    // get range and enotes
    const range_txids_by_block_or_time get_last_N_txs(const uint64_t N);

    // get specific enotes by txid
    bool get_enotes_from_tx(const rct::key &txid,
        const SpEnoteStore &enote_store,
        std::pair<std::vector<LegacyContextualEnoteRecordV1>, std::vector<SpContextualEnoteRecordV1>> &enotes_out) const;

    // get an enote from the enote_records in a tx
    bool get_representing_enote_from_tx(
        const std::pair<std::vector<LegacyContextualEnoteRecordV1>, std::vector<SpContextualEnoteRecordV1>>
            &enotes_in_tx,
        ContextualRecordVariant &contextual_enote_out) const;

    // get an enote from the enote_records in a tx
    bool try_get_tx_record_from_txid(const rct::key &txid, TransactionRecordV1 &tx_record_out) const;

    //-----------------------------------------------------------------
    /// Save/read data to/from file - useful to import/export tx_history
    //-----------------------------------------------------------------
    // TODO: change encryption function to store data on disk

    bool write_sp_tx_history(std::string path, const epee::wipeable_string &password);
    bool read_sp_tx_history(std::string path, const epee::wipeable_string &password, SpTransactionStoreV1 &sp_tx_store);

    //-----------------------------------------------------------------
    /// Get Knowledge proofs
    //-----------------------------------------------------------------
    // All proofs have an optional 'filename' field which if specified saves the proof (output string) into it. 

//     std::string get_address_ownership_proof(const jamtis::address_index_t &j,
//         const crypto::secret_key &sp_spend_privkey,
//         const crypto::secret_key &k_view_balance,
//         const bool bool_Ks_K1,
//         const std::string message_in,
//         const boost::optional<std::string> filename);

//     std::string get_address_index_proof(const rct::key &jamtis_spend_pubkey,
//         const jamtis::address_index_t &j,
//         const crypto::secret_key &s_ga,
//         const boost::optional<std::string> filename);

//     bool try_make_enote_ownership_proof_sender(const rct::key txid,
//         const rct::key &onetime_address,
//         const JamtisDestinationV1 &dest,
//         const crypto::secret_key &k_vb,
//         const bool selfsend,
//         EnoteOwnershipProofV1 &proof);

//     std::string get_enote_ownership_proof_sender(const rct::key txid,
//         const rct::key &onetime_address,
//         const JamtisDestinationV1 &dest,
//         const crypto::secret_key &k_vb,
//         const bool selfsend,
//         const boost::optional<std::string> filename);

//     std::string get_enote_ownership_proof_receiver(const SpEnoteRecordV1 &enote_record,
//         const rct::key &jamtis_spend_pubkey,
//         const crypto::secret_key &k_vb,
//         const boost::optional<std::string> filename);

//     bool try_make_amount_proof(const rct::xmr_amount &amount,
//         const crypto::secret_key &mask,
//         const rct::key &commitment,
//         EnoteAmountProofV1 &amount_proof);

//     std::string get_amount_proof(const rct::xmr_amount &amount,
//         const crypto::secret_key &mask,
//         const rct::key &commitment,
//         const boost::optional<std::string> filename);

//     std::string get_enote_key_image_proof(const SpEnoteStore &enote_store,
//         const crypto::key_image &key_image,
//         const crypto::secret_key &k_m,
//         const crypto::secret_key &k_vb,
//         const boost::optional<std::string> filename);

//     std::string get_enote_sent_proof(const rct::key txid,
//         const rct::key &onetime_address,
//         const JamtisDestinationV1 &dest,
//         const crypto::secret_key &k_vb,
//         const bool selfsend,
//         const rct::xmr_amount &amount,
//         const crypto::secret_key &mask,
//         const rct::key &commitment,
//         const boost::optional<std::string> filename);

//     std::string get_tx_funded_proof(const rct::key &txid,
//         const SpEnoteStore &enote_store,
//         const crypto::secret_key &sp_spend_privkey,
//         const crypto::secret_key &k_view_balance,
//         const std::string &message_in,
//         const boost::optional<std::string> filename);

//     std::string get_enote_reserve_proof(const std::string &message_in,
//         const std::vector<SpContextualEnoteRecordV1> &reserved_enote_records,
//         const rct::key &jamtis_spend_pubkey,
//         const crypto::secret_key &sp_spend_privkey,
//         const crypto::secret_key &k_view_balance,
//         const rct::xmr_amount proof_amount,
//         const boost::optional<std::string> filename);
// };

// //-----------------------------------------------------------------
// /// Read/Verify Knowledge proofs
// /// These functions dont need to be inside a class as they can be called by anyone.
// //-----------------------------------------------------------------
// // All reading functions have a 'filename' and a 'proof_str' field. The proof considered will be from the 'filename' if specified.

// bool read_address_ownership_proof(const boost::optional<std::string> filename,
//     const boost::optional<std::string> proof_str,
//     const std::string &message_in,
//     const rct::key &K);

// bool read_address_index_proof(const boost::optional<std::string> filename,
//     const boost::optional<std::string> proof_str,
//     const rct::key &K_1);

// bool read_enote_ownership_proof(const boost::optional<std::string> filename,
//     const boost::optional<std::string> proof_str,
//     const rct::key &expected_amount_commitment,
//     const rct::key &expected_onetime_address);

// bool read_amount_proof(const boost::optional<std::string> filename,
//     const boost::optional<std::string> proof_str,
//     const rct::key &expected_amount_commitment);

// bool read_enote_key_image_proof(const boost::optional<std::string> filename,
//     const boost::optional<std::string> proof_str,
//     const rct::key &expected_onetime_address,
//     const crypto::key_image &expected_KI);

// bool read_enote_sent_proof(const boost::optional<std::string> filename,
//     const boost::optional<std::string> proof_str,
//     const rct::key &expected_amount_commitment,
//     const rct::key &expected_onetime_address);

// bool read_tx_funded_proof(const boost::optional<std::string> filename,
//     const boost::optional<std::string> proof_str,
//     const rct::key &tx_id,
//     const std::string &message_in,
//     const std::vector<crypto::key_image> &key_images);

// bool read_enote_reserve_proof(const boost::optional<std::string> filename,
//     const boost::optional<std::string> proof_str,
//     const std::string &expected_message,
//     const TxValidationContext &validation_context);


// template <typename T>
// std::string proof_to_str(T &serializable_proof, std::string prefix);

// template <typename T>
// T str_to_proof(const std::string prefix,
//     const boost::optional<std::string> filename,
//     const boost::optional<std::string> proof_str);
};