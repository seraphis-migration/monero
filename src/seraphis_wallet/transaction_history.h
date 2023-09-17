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

// The goal of this component (SpTransactionHistory) is to store all the relevant information (SpTransactionStoreV1)
// from transactions made by the wallet and allow the user to efficiently access these information later (to visualize
// specific info from enotes or generate knowledge proofs for example).

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

using namespace sp::jamtis;
using namespace sp;
using namespace sp::knowledge_proofs;

// struct to store the relevant info from a tx
struct TransactionRecordV1
{
    // key images of spent enotes for tracking purposes
    std::vector<crypto::key_image> legacy_spent_enotes;
    std::vector<crypto::key_image> sp_spent_enotes;

    // JamtisPaymentProposals
    std::vector<JamtisPaymentProposalSelfSendV1> selfsend_payments;
    std::vector<JamtisPaymentProposalV1> normal_payments;

    // fees and total sent
    // useful to store here also instead of looking directly at the enotes and blockchain
    rct::xmr_amount amount_sent;
    rct::xmr_amount fee_sent;
};

// struct to efficiently store/sort records
struct SpTransactionStoreV1
{
    // quickly find TransactionRecordV1 from txid
    serializable_unordered_map<rct::key, TransactionRecordV1> tx_records;

    // sort by timestamp
    std::vector<std::pair<uint64_t, rct::key>> txs_by_timestamp;
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

    /**
     * brief: add entry to tx_records
     * param: txid - transaction id
     * param: record - transaction record
     */
    void add_entry_to_tx_records(const rct::key &txid, const TransactionRecordV1 &record);

    /**
     * brief: add entry to txs_by_timestamp
     * param: timestamp - timestamp when transaction is created
     * param: txid - transaction id
     */
    void add_entry_to_txs_by_timestamp(const uint64_t timestamp, const rct::key &txid);

    /**
     * brief: add entries to SpTransactionStore from single_tx
     * param: single_tx - transaction
     * param: selfsend_payments - selfsend payments
     * param: normal_payments - normal payments
     */
    void add_single_tx_to_tx_history(const SpTxSquashedV1 &single_tx,
        const std::vector<JamtisPaymentProposalSelfSendV1> &selfsend_payments,
        const std::vector<JamtisPaymentProposalV1> &normal_payments);

    //-----------------------------------------------------------------
    /// Get/Set SpTransactionStore (useful for import/export functions)
    //-----------------------------------------------------------------

    /**
     * brief: get tx_store
     * return : tx_store (SpTransactonStoreV1)
     */
    const SpTransactionStoreV1 get_tx_store() const;

    /**
     * brief: set tx_store
     * param: tx_store - tx_store to be set
     * return : true if succeeds
     */
    bool set_tx_store(const SpTransactionStoreV1 &tx_store);

    //-----------------------------------------------------------------
    /// Get info from enotes and txs
    //-----------------------------------------------------------------

    /**
     * brief: get last N tx_ids created by wallet
     * param: N - number of previous tx_ids to acquire
     * return : pair with timestamp and tx_id
     */
    const std::vector<std::pair<uint64_t, rct::key>> get_last_N_txs(const uint64_t N);

    /**
     * brief: get specific enotes by txid
     * param: txid - transaction id
     * param: enote_store - enote_store from user
     * outparam: enotes_out - pair with contextual records of legacy and sp enotes
     * return : true if succeeds
     */
    bool get_enotes_from_tx(const rct::key &txid,
        const SpEnoteStore &enote_store,
        std::pair<std::vector<LegacyContextualEnoteRecordV1>, std::vector<SpContextualEnoteRecordV1>> &enotes_out)
        const;

    /**
     * brief: get an enote from the enote_records in a tx
     * param: enotes_in_tx - pair with contextual records of legacy and sp enotes
     * outparam: contextual_enote_out - contextual record of a representing enote in tx (sp if exists otherwise legacy)
     * return : true if succeeds
     */
    bool get_representing_enote_from_tx(
        const std::pair<std::vector<LegacyContextualEnoteRecordV1>, std::vector<SpContextualEnoteRecordV1>>
            &enotes_in_tx,
        ContextualRecordVariant &contextual_enote_out) const;

    /**
     * brief: get an enote from the enote_records in a tx
     * param: txid - transaction id
     * outparam: tx_record_out - transaction_record from tx_id
     * return : true if succeeds
     */
    bool try_get_tx_record_from_txid(const rct::key &txid, TransactionRecordV1 &tx_record_out) const;

    //-----------------------------------------------------------------
    /// Save/read data to/from file - useful to import/export tx_history
    //-----------------------------------------------------------------
    // TODO: change encryption function to store data on disk

    bool write_sp_tx_history(std::string path, const epee::wipeable_string &password);
    bool read_sp_tx_history(std::string path, const epee::wipeable_string &password, SpTransactionStoreV1 &sp_tx_store);
};
