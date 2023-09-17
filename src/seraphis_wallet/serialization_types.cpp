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

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_wallet"

void make_serializable_transaction_record_v1(const TransactionRecordV1 &tx_rec, ser_TransactionRecordV1 &ser_tx_rec_out)
{
    ser_tx_rec_out.legacy_spent_enotes = tx_rec.legacy_spent_enotes;
    ser_tx_rec_out.sp_spent_enotes     = tx_rec.sp_spent_enotes;
    ser_tx_rec_out.normal_payments.clear();
    for (auto payment : tx_rec.normal_payments)
    {
        ser_tx_rec_out.normal_payments.emplace_back();
        make_serializable_jamtis_payment_proposal_v1(payment, ser_tx_rec_out.normal_payments.back());
    }
    ser_tx_rec_out.selfsend_payments.clear();
    for (auto payment : tx_rec.selfsend_payments)
    {
        ser_tx_rec_out.selfsend_payments.emplace_back();
        make_serializable_jamtis_payment_proposal_selfsend_v1(payment, ser_tx_rec_out.selfsend_payments.back());
    }
    ser_tx_rec_out.amount_sent = tx_rec.amount_sent;
    ser_tx_rec_out.fee_sent    = tx_rec.fee_sent;
}

void make_serializable_sp_transaction_store_v1(const SpTransactionStoreV1 &tx_store,
    ser_SpTransactionStoreV1 &ser_tx_store_out)
{
    ser_TransactionRecordV1 ser_tx_rec{};
    for (auto &r : tx_store.tx_records)
    {
        make_serializable_transaction_record_v1(r.second, ser_tx_rec);
        ser_tx_store_out.tx_records[r.first] = ser_tx_rec;
    }
    ser_tx_store_out.txs_by_timestamp = tx_store.txs_by_timestamp;
}

void recover_transaction_record_v1(const ser_TransactionRecordV1 &ser_tx_rec, TransactionRecordV1 &tx_rec_out)
{
    tx_rec_out.legacy_spent_enotes = ser_tx_rec.legacy_spent_enotes;
    tx_rec_out.sp_spent_enotes     = ser_tx_rec.sp_spent_enotes;
    tx_rec_out.normal_payments.clear();
    for (auto payment : ser_tx_rec.normal_payments)
    {
        tx_rec_out.normal_payments.emplace_back();
        recover_jamtis_payment_proposal_v1(payment, tx_rec_out.normal_payments.back());
    }
    tx_rec_out.selfsend_payments.clear();
    for (auto payment : ser_tx_rec.selfsend_payments)
    {
        tx_rec_out.selfsend_payments.emplace_back();
        recover_jamtis_payment_proposal_selfsend_v1(payment, tx_rec_out.selfsend_payments.back());
    }
    tx_rec_out.amount_sent = ser_tx_rec.amount_sent;
    tx_rec_out.fee_sent    = ser_tx_rec.fee_sent;
}

void recover_sp_transaction_store_v1(const ser_SpTransactionStoreV1 &ser_tx_store, SpTransactionStoreV1 &tx_store_out)
{
    TransactionRecordV1 tx_rec;
    for (auto &r : ser_tx_store.tx_records)
    {
        recover_transaction_record_v1(r.second, tx_rec);
        tx_store_out.tx_records[r.first] = tx_rec;
    }
    tx_store_out.txs_by_timestamp = ser_tx_store.txs_by_timestamp;
}

void make_serializable_tx_funded_proof_v1(const TxFundedProofV1 &proof, ser_TxFundedProofV1 &ser_proof_out)
{
    ser_proof_out.message        = proof.message;
    ser_proof_out.masked_address = proof.masked_address;
    ser_proof_out.KI             = proof.KI;
    make_serializable_sp_composition_proof(proof.composition_proof, ser_proof_out.composition_proof_out);
}

void recover_tx_funded_proof_v1(const ser_TxFundedProofV1 &ser_proof, TxFundedProofV1 &proof_out)
{
    proof_out.message        = ser_proof.message;
    proof_out.masked_address = ser_proof.masked_address;
    proof_out.KI             = ser_proof.KI;
    recover_sp_composition_proof(ser_proof.composition_proof_out, proof_out.composition_proof);
}

void make_serializable_address_ownership_proof_v1(const AddressOwnershipProofV1 &proof,
    ser_AddressOwnershipProofV1 &ser_proof_out)
{
    ser_proof_out.message        = proof.message;
    ser_proof_out.K              = proof.K;
    ser_proof_out.addr_key_image = proof.addr_key_image;
    make_serializable_sp_composition_proof(proof.composition_proof, ser_proof_out.composition_proof);
}

void recover_address_ownership_proof_v1(const ser_AddressOwnershipProofV1 &ser_proof,
    AddressOwnershipProofV1 &proof_out)
{
    proof_out.message        = ser_proof.message;
    proof_out.K              = ser_proof.K;
    proof_out.addr_key_image = ser_proof.addr_key_image;
    recover_sp_composition_proof(ser_proof.composition_proof, proof_out.composition_proof);
}

void make_serializable_address_index_proof_v1(const AddressIndexProofV1 &proof, ser_AddressIndexProofV1 &ser_proof_out)
{
    ser_proof_out.generator = proof.generator;
    ser_proof_out.K_1       = proof.K_1;
    ser_proof_out.K_s       = proof.K_s;
    memcpy(ser_proof_out.j.bytes, proof.j.bytes, sizeof(proof.j));
}

void recover_address_index_proof_v1(const ser_AddressIndexProofV1 &ser_proof, AddressIndexProofV1 &proof_out)
{
    proof_out.generator = ser_proof.generator;
    proof_out.K_1       = ser_proof.K_1;
    proof_out.K_s       = ser_proof.K_s;
    memcpy(proof_out.j.bytes, ser_proof.j.bytes, sizeof(ser_proof.j));
}

void make_serializable_enote_ownership_proof_v1(const EnoteOwnershipProofV1 &proof,
    ser_EnoteOwnershipProofV1 &ser_proof_out)
{
    ser_proof_out.K_1 = proof.K_1;
    ser_proof_out.C   = proof.C;
    ser_proof_out.Ko  = proof.Ko;
    ser_proof_out.q   = proof.q;
}

void recover_enote_ownership_proof_v1(const ser_EnoteOwnershipProofV1 &ser_proof, EnoteOwnershipProofV1 &proof_out)
{
    proof_out.K_1 = ser_proof.K_1;
    proof_out.C   = ser_proof.C;
    proof_out.Ko  = ser_proof.Ko;
    proof_out.q   = ser_proof.q;
}

void make_serializable_enote_amount_proof_v1(const EnoteAmountProofV1 &proof, ser_EnoteAmountProofV1 &ser_proof_out)
{
    ser_proof_out.a = proof.a;
    ser_proof_out.x = proof.x;
    ser_proof_out.C = proof.C;
}

void recover_enote_amount_proof_v1(const ser_EnoteAmountProofV1 &ser_proof, EnoteAmountProofV1 &proof_out)
{
    proof_out.a = ser_proof.a;
    proof_out.x = ser_proof.x;
    proof_out.C = ser_proof.C;
}

void make_serializable_enote_key_image_proof_v1(const EnoteKeyImageProofV1 &proof,
    ser_EnoteKeyImageProofV1 &ser_proof_out)
{
    ser_proof_out.Ko = proof.Ko;
    ser_proof_out.KI = proof.KI;
    make_serializable_sp_composition_proof(proof.composition_proof, ser_proof_out.composition_proof);
}

void recover_enote_key_image_proof_v1(const ser_EnoteKeyImageProofV1 &ser_proof, EnoteKeyImageProofV1 &proof_out)
{
    proof_out.Ko = ser_proof.Ko;
    proof_out.KI = ser_proof.KI;
    recover_sp_composition_proof(ser_proof.composition_proof, proof_out.composition_proof);
}

void make_serializable_enote_sent_proof_v1(const EnoteSentProofV1 &proof, ser_EnoteSentProofV1 &ser_proof_out)
{
    make_serializable_enote_ownership_proof_v1(proof.enote_ownership_proof, ser_proof_out.enote_ownership_proof);
    make_serializable_enote_amount_proof_v1(proof.amount_proof, ser_proof_out.amount_proof);
}

void recover_enote_sent_proof_v1(const ser_EnoteSentProofV1 &ser_proof, EnoteSentProofV1 &proof_out)
{
    recover_enote_ownership_proof_v1(ser_proof.enote_ownership_proof, proof_out.enote_ownership_proof);
    recover_enote_amount_proof_v1(ser_proof.amount_proof, proof_out.amount_proof);
}

void make_serializable_reserved_enote_proof_v1(const ReservedEnoteProofV1 &proof,
    ser_ReservedEnoteProofV1 &ser_proof_out)
{
    make_serializable_enote_ownership_proof_v1(proof.enote_ownership_proof, ser_proof_out.enote_ownership_proof);
    make_serializable_enote_amount_proof_v1(proof.amount_proof, ser_proof_out.amount_proof);
    make_serializable_enote_key_image_proof_v1(proof.KI_proof, ser_proof_out.KI_proof);
    ser_proof_out.enote_ledger_index = proof.enote_ledger_index;
}

void recover_reserved_enote_proof_v1(const ser_ReservedEnoteProofV1 &ser_proof, ReservedEnoteProofV1 &proof_out)
{
    recover_enote_ownership_proof_v1(ser_proof.enote_ownership_proof, proof_out.enote_ownership_proof);
    recover_enote_amount_proof_v1(ser_proof.amount_proof, proof_out.amount_proof);
    recover_enote_key_image_proof_v1(ser_proof.KI_proof, proof_out.KI_proof);
    proof_out.enote_ledger_index = ser_proof.enote_ledger_index;
}

void make_serializable_reserve_proof_v1(const ReserveProofV1 &proof, ser_ReserveProofV1 &ser_proof_out)
{
    ser_proof_out.address_ownership_proofs.clear();
    for (auto address : proof.address_ownership_proofs)
    {
        ser_proof_out.address_ownership_proofs.emplace_back();
        make_serializable_address_ownership_proof_v1(address, ser_proof_out.address_ownership_proofs.back());
    }
    ser_proof_out.reserved_enote_proofs.clear();
    for (auto reserved : proof.reserved_enote_proofs)
    {
        ser_proof_out.reserved_enote_proofs.emplace_back();
        make_serializable_reserved_enote_proof_v1(reserved, ser_proof_out.reserved_enote_proofs.back());
    }
}

void recover_reserve_proof_v1(const ser_ReserveProofV1 &ser_proof, ReserveProofV1 &proof_out)
{
    proof_out.address_ownership_proofs.clear();
    for (auto address : ser_proof.address_ownership_proofs)
    {
        proof_out.address_ownership_proofs.emplace_back();
        recover_address_ownership_proof_v1(address, proof_out.address_ownership_proofs.back());
    }
    proof_out.reserved_enote_proofs.clear();
    for (auto reserved : ser_proof.reserved_enote_proofs)
    {
        proof_out.reserved_enote_proofs.emplace_back();
        recover_reserved_enote_proof_v1(reserved, proof_out.reserved_enote_proofs.back());
    }
}
