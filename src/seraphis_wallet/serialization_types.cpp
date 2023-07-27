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
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_core/jamtis_payment_proposal.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_impl/enote_store.h"
#include "seraphis_impl/serialization_demo_types.h"
#include "seraphis_impl/serialization_demo_utils.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/sp_knowledge_proof_types.h"
#include "seraphis_main/sp_knowledge_proof_utils.h"

// third party headers
#include <boost/range.hpp>

#include "boost/range/iterator_range.hpp"
#include "seraphis_wallet/transaction_history.h"
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

void make_serializable_transaction_record_v1(const TransactionRecordV1 &tx_rec, ser_TransactionRecordV1 &ser_tx_rec)
{
    ser_tx_rec.legacy_spent_enotes = tx_rec.legacy_spent_enotes;
    ser_tx_rec.sp_spent_enotes = tx_rec.sp_spent_enotes;
    ser_tx_rec.normal_payments.clear();
    for (auto payment:tx_rec.normal_payments)
    {
        ser_tx_rec.normal_payments.emplace_back();
        make_serializable_jamtis_payment_proposal_v1(payment,ser_tx_rec.normal_payments.back());
    }
    ser_tx_rec.selfsend_payments.clear();
    for (auto payment:tx_rec.selfsend_payments)
    {
        ser_tx_rec.selfsend_payments.emplace_back();
        make_serializable_jamtis_payment_proposal_selfsend_v1(payment,ser_tx_rec.selfsend_payments.back());
    }
    ser_tx_rec.amount_sent = tx_rec.amount_sent;
    ser_tx_rec.fee_sent = tx_rec.fee_sent;
}

void make_serializable_sp_transaction_store_v1(const SpTransactionStoreV1 &tx_store,
                                               ser_SpTransactionStoreV1 &ser_tx_store)
{
    ser_TransactionRecordV1 ser_tx_rec{};
    for (auto &r : tx_store.tx_records)
    {
        make_serializable_transaction_record_v1(r.second, ser_tx_rec);
        ser_tx_store.tx_records[r.first] = ser_tx_rec;
    }
    ser_tx_store.confirmed_txids = tx_store.confirmed_txids;
    ser_tx_store.unconfirmed_txids = tx_store.unconfirmed_txids;
    ser_tx_store.offchain_txids = tx_store.offchain_txids;
}

void recover_transaction_record_v1(const ser_TransactionRecordV1 &ser_tx_rec, TransactionRecordV1 &tx_rec)
{
    tx_rec.legacy_spent_enotes = ser_tx_rec.legacy_spent_enotes;
    tx_rec.sp_spent_enotes = ser_tx_rec.sp_spent_enotes;
    tx_rec.normal_payments.clear();
    for (auto payment: ser_tx_rec.normal_payments)
    {
        tx_rec.normal_payments.emplace_back();
        recover_jamtis_payment_proposal_v1(payment,tx_rec.normal_payments.back());
    }
    tx_rec.selfsend_payments.clear();
    for (auto payment: ser_tx_rec.selfsend_payments)
    {
        tx_rec.selfsend_payments.emplace_back();
        recover_jamtis_payment_proposal_selfsend_v1(payment,tx_rec.selfsend_payments.back());
    }
    tx_rec.amount_sent = ser_tx_rec.amount_sent;
    tx_rec.fee_sent = ser_tx_rec.fee_sent;
}

void recover_sp_transaction_store_v1(const ser_SpTransactionStoreV1 &ser_tx_store, SpTransactionStoreV1 &tx_store)
{
    TransactionRecordV1 tx_rec;
    for (auto &r : ser_tx_store.tx_records)
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

void make_serializable_address_ownership_proof_v1(const AddressOwnershipProofV1 &proof,
                                                  ser_AddressOwnershipProofV1 &ser_proof)
{
    ser_proof.message = proof.message;
    ser_proof.K = proof.K;
    ser_proof.addr_key_image = proof.addr_key_image;
    make_serializable_sp_composition_proof(proof.composition_proof, ser_proof.composition_proof);
}

void recover_address_ownership_proof_v1(const ser_AddressOwnershipProofV1 &ser_proof, AddressOwnershipProofV1 &proof)
{
    proof.message = ser_proof.message;
    proof.K = ser_proof.K;
    proof.addr_key_image = ser_proof.addr_key_image;
    recover_sp_composition_proof(ser_proof.composition_proof, proof.composition_proof);
}

void make_serializable_address_index_proof_v1(const AddressIndexProofV1 &proof, ser_AddressIndexProofV1 &ser_proof)
{
    ser_proof.generator = proof.generator;
    ser_proof.K_1 = proof.K_1;
    ser_proof.K_s = proof.K_s;
    memcpy(ser_proof.j.bytes, proof.j.bytes, sizeof(proof.j));
}

void recover_address_index_proof_v1(const ser_AddressIndexProofV1 &ser_proof, AddressIndexProofV1 &proof)
{
    proof.generator = ser_proof.generator;
    proof.K_1 = ser_proof.K_1;
    proof.K_s = ser_proof.K_s;
    memcpy(proof.j.bytes, ser_proof.j.bytes, sizeof(ser_proof.j));
}

void make_serializable_enote_ownership_proof_v1(const EnoteOwnershipProofV1 &proof, ser_EnoteOwnershipProofV1 &ser_proof)
{
    ser_proof.K_1 = proof.K_1;
    ser_proof.C = proof.C;
    ser_proof.Ko = proof.Ko;
    ser_proof.q = proof.q;
}

void recover_enote_ownership_proof_v1(ser_EnoteOwnershipProofV1 &ser_proof, EnoteOwnershipProofV1 &proof)
{
    proof.K_1 = ser_proof.K_1;
    proof.C = ser_proof.C;
    proof.Ko = ser_proof.Ko;
    proof.q = ser_proof.q;
}
