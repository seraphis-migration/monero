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


#include "serialization_types.h"

// local headers
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_impl/enote_store.h"
#include "seraphis_impl/serialization_demo_utils.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/sp_knowledge_proof_utils.h"
#include "seraphis_main/sp_knowledge_proof_types.h"
#include "ringct/rctTypes.h"
#include "seraphis_impl/serialization_demo_types.h"

//third party headers
#include "boost/range/iterator_range.hpp"
#include "seraphis_wallet/transaction_history.h"
#include "serialization/containers.h"
#include "serialization/serialization.h"
#include <boost/range.hpp>
#include "serialization/binary_archive.h"

//standard headers
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <unordered_map>
#include <tuple>
#include <unordered_set>
#include <vector>



void make_serializable_transaction_record_v1(const TransactionRecordV1 &tx_rec, ser_TransactionRecordV1 &ser_tx_rec)
{
    ser_tx_rec.legacy_spent_enotes = tx_rec.legacy_spent_enotes;
    ser_tx_rec.sp_spent_enotes = tx_rec.sp_spent_enotes;
    sp::serialization::ser_JamtisDestinationV1 ser_dest{};
    std::vector<std::pair<sp::serialization::ser_JamtisDestinationV1, rct::xmr_amount>> outlays_aux{};
    for (auto &r: tx_rec.outlays)
    {
        make_serializable_sp_destination_v1(r.first, ser_dest); 
        outlays_aux.emplace_back(ser_dest,r.second);
    }
    ser_tx_rec.outlays = outlays_aux;
    ser_tx_rec.amount_sent = tx_rec.amount_sent;
    ser_tx_rec.fee_sent = tx_rec.fee_sent;
    outlays_aux.clear();
}


void make_serializable_sp_transaction_store_v1(const SpTransactionStoreV1 &tx_store, ser_SpTransactionStoreV1 &ser_tx_store)
{
    ser_TransactionRecordV1 ser_tx_rec{};
    for (auto &r: tx_store.tx_records)
    {
        make_serializable_transaction_record_v1(r.second, ser_tx_rec);
        ser_tx_store.tx_records[r.first] = ser_tx_rec;
    }
    ser_tx_store.confirmed_txids = tx_store.confirmed_txids;
    ser_tx_store.unconfirmed_txids = tx_store.unconfirmed_txids;
    ser_tx_store.offchain_txids = tx_store.offchain_txids;
}

void recover_transaction_record_v1(const ser_TransactionRecordV1 &ser_tx_rec,TransactionRecordV1 &tx_rec)
{
    tx_rec.legacy_spent_enotes = ser_tx_rec.legacy_spent_enotes;
    tx_rec.sp_spent_enotes = ser_tx_rec.sp_spent_enotes;

    JamtisDestinationV1 dest{};
    std::vector<std::pair<JamtisDestinationV1, rct::xmr_amount>> outlays_aux{};
    for (auto &r: ser_tx_rec.outlays)
    {
        recover_sp_destination_v1(r.first, dest); 
        outlays_aux.emplace_back(dest,r.second);
    }
    tx_rec.outlays = outlays_aux;
    tx_rec.amount_sent = ser_tx_rec.amount_sent;
    tx_rec.fee_sent = ser_tx_rec.fee_sent;
    outlays_aux.clear();
}


void recover_sp_transaction_store_v1(const ser_SpTransactionStoreV1 &ser_tx_store,SpTransactionStoreV1 &tx_store)
{
    TransactionRecordV1 tx_rec;
    for (auto &r: ser_tx_store.tx_records)
    {
        recover_transaction_record_v1(r.second, tx_rec);
        tx_store.tx_records[r.first] = tx_rec;
    }
    tx_store.confirmed_txids = ser_tx_store.confirmed_txids;
    tx_store.unconfirmed_txids = ser_tx_store.unconfirmed_txids;
    tx_store.offchain_txids = ser_tx_store.offchain_txids;
}


void make_serializable_tx_funded_proof_v1(const TxFundedProofV1 &proof, ser_TxFundedProofV1 &ser_proof)
{
    ser_proof.message = proof.message;
    ser_proof.masked_address = proof.masked_address;
    ser_proof.KI = proof.KI;
    make_serializable_sp_composition_proof(proof.composition_proof, ser_proof.composition_proof);
}

void recover_tx_funded_proof_v1(const ser_TxFundedProofV1 &ser_proof, TxFundedProofV1 &proof)
{
    proof.message = ser_proof.message;
    proof.masked_address = ser_proof.masked_address;
    proof.KI = ser_proof.KI;
    recover_sp_composition_proof(ser_proof.composition_proof, proof.composition_proof);
}
