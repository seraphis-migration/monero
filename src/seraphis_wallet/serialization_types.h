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
#include "cryptonote_config.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_impl/enote_store.h"
#include "seraphis_impl/serialization_demo_types.h"
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

using namespace sp::knowledge_proofs;
using namespace sp::serialization;

struct ser_TransactionRecordV1
{
    // key images of spent enotes for tracking purposes
    std::vector<crypto::key_image> legacy_spent_enotes;
    std::vector<crypto::key_image> sp_spent_enotes;

    // sent funds
    std::vector<ser_JamtisPaymentProposalSelfSendV1> selfsend_payments;
    std::vector<ser_JamtisPaymentProposalV1> normal_payments;

    // fees and total sent:
    rct::xmr_amount amount_sent;
    rct::xmr_amount fee_sent;

    BEGIN_SERIALIZE_OBJECT()
    FIELD(legacy_spent_enotes)
    FIELD(sp_spent_enotes)
    FIELD(selfsend_payments)
    FIELD(normal_payments)
    FIELD(amount_sent)
    FIELD(fee_sent)
    END_SERIALIZE()
};

struct ser_SpTransactionStoreV1
{
    // quickly find TransactionRecordV1 from txid
    serializable_unordered_map<rct::key, ser_TransactionRecordV1> tx_records;

    // sort by blockheight to find last transactions or txs
    // in a specific time range
    serializable_multimap<std::uint64_t, rct::key, std::greater<std::uint64_t>> confirmed_txids;

    // sort by timestamp instead of blockheight
    serializable_multimap<std::uint64_t, rct::key, std::greater<std::uint64_t>> unconfirmed_txids;
    serializable_multimap<std::uint64_t, rct::key, std::greater<std::uint64_t>> offchain_txids;

    BEGIN_SERIALIZE_OBJECT()
    FIELD(tx_records)
    FIELD(confirmed_txids)
    FIELD(unconfirmed_txids)
    FIELD(offchain_txids)
    END_SERIALIZE()
};

struct ser_AddressOwnershipProofV1
{
    rct::key message;
    rct::key K;
    crypto::key_image addr_key_image;  //'key image' of the address used in this proof
    ser_SpCompositionProof composition_proof;

    BEGIN_SERIALIZE_OBJECT()
    FIELD(message)
    FIELD(K)
    FIELD(addr_key_image)
    FIELD(composition_proof)
    END_SERIALIZE()
};

struct ser_AddressIndexProofV1
{
    rct::key K_s;
    ser_address_index_t j;
    rct::key generator;
    rct::key K_1;

    BEGIN_SERIALIZE_OBJECT()
    FIELD(K_s)
    FIELD(j)
    FIELD(generator)
    FIELD(K_1)
    END_SERIALIZE()
};

struct ser_EnoteOwnershipProofV1
{
    rct::key K_1;
    rct::key q;
    rct::key C;
    rct::key Ko;

    BEGIN_SERIALIZE_OBJECT()
    FIELD(K_1)
    FIELD(q)
    FIELD(C)
    FIELD(Ko)
    END_SERIALIZE()
};

struct ser_EnoteAmountProofV1
{
    rct::xmr_amount a;
    rct::key x;
    rct::key C;

    BEGIN_SERIALIZE_OBJECT()
    FIELD(a)
    FIELD(x)
    FIELD(C)
    END_SERIALIZE()
};

struct ser_EnoteKeyImageProofV1
{
    rct::key Ko;
    crypto::key_image KI;
    ser_SpCompositionProof composition_proof;

    BEGIN_SERIALIZE_OBJECT()
    FIELD(Ko)
    FIELD(KI)
    FIELD(composition_proof)
    END_SERIALIZE()
};

struct ser_EnoteSentProofV1
{
    ser_EnoteOwnershipProofV1 enote_ownership_proof;
    ser_EnoteAmountProofV1 amount_proof;

    BEGIN_SERIALIZE_OBJECT()
    FIELD(enote_ownership_proof)
    FIELD(amount_proof)
    END_SERIALIZE()
};

struct ser_TxFundedProofV1
{
    rct::key message;
    rct::key masked_address;
    crypto::key_image KI;
    ser_SpCompositionProof composition_proof_out;

    BEGIN_SERIALIZE_OBJECT()
    FIELD(message)
    FIELD(masked_address)
    FIELD(KI)
    FIELD(composition_proof_out)
    END_SERIALIZE()
};

struct ser_ReservedEnoteProofV1
{
    ser_EnoteOwnershipProofV1 enote_ownership_proof;
    ser_EnoteAmountProofV1 amount_proof;
    ser_EnoteKeyImageProofV1 KI_proof;
    std::uint64_t enote_ledger_index;

    BEGIN_SERIALIZE_OBJECT()
    FIELD(enote_ownership_proof)
    FIELD(amount_proof)
    FIELD(KI_proof)
    FIELD(enote_ledger_index)
    END_SERIALIZE()
};

struct ser_ReserveProofV1
{
    std::vector<ser_AddressOwnershipProofV1> address_ownership_proofs;
    std::vector<ser_ReservedEnoteProofV1> reserved_enote_proofs;

    BEGIN_SERIALIZE_OBJECT()
    FIELD(address_ownership_proofs)
    FIELD(reserved_enote_proofs)
    END_SERIALIZE()
};

void make_serializable_transaction_record_v1(const TransactionRecordV1 &tx_rec,
    ser_TransactionRecordV1 &ser_tx_rec_out);
void make_serializable_sp_transaction_store_v1(const SpTransactionStoreV1 &tx_store,
    ser_SpTransactionStoreV1 &ser_tx_store_out);

void recover_transaction_record_v1(const ser_TransactionRecordV1 &ser_tx_rec, TransactionRecordV1 &tx_rec_out);
void recover_sp_transaction_store_v1(const ser_SpTransactionStoreV1 &ser_tx_store, SpTransactionStoreV1 &tx_store_out);

void make_serializable_address_ownership_proof_v1(const AddressOwnershipProofV1 &proof,
    ser_AddressOwnershipProofV1 &ser_proof_out);
void recover_address_ownership_proof_v1(const ser_AddressOwnershipProofV1 &ser_proof,
    AddressOwnershipProofV1 &proof_out);

void make_serializable_address_index_proof_v1(const AddressIndexProofV1 &proof, ser_AddressIndexProofV1 &ser_proof_out);
void recover_address_index_proof_v1(const ser_AddressIndexProofV1 &ser_proof, AddressIndexProofV1 &proof_out);

void make_serializable_enote_ownership_proof_v1(const EnoteOwnershipProofV1 &proof,
    ser_EnoteOwnershipProofV1 &ser_proof_out);
void recover_enote_ownership_proof_v1(const ser_EnoteOwnershipProofV1 &ser_proof, EnoteOwnershipProofV1 &proof_out);

void make_serializable_enote_amount_proof_v1(const EnoteAmountProofV1 &proof, ser_EnoteAmountProofV1 &ser_proof_out);
void recover_enote_amount_proof_v1(const ser_EnoteAmountProofV1 &ser_proof, EnoteAmountProofV1 &proof_out);

void make_serializable_enote_key_image_proof_v1(const EnoteKeyImageProofV1 &proof,
    ser_EnoteKeyImageProofV1 &ser_proof_out);
void recover_enote_key_image_proof_v1(const ser_EnoteKeyImageProofV1 &ser_proof, EnoteKeyImageProofV1 &proof_out);

void make_serializable_enote_sent_proof_v1(const EnoteSentProofV1 &proof, ser_EnoteSentProofV1 &ser_proof_out);
void recover_enote_sent_proof_v1(const ser_EnoteSentProofV1 &ser_proof, EnoteSentProofV1 &proof_out);

void make_serializable_tx_funded_proof_v1(const TxFundedProofV1 &proof, ser_TxFundedProofV1 &ser_proof_out);
void recover_tx_funded_proof_v1(const ser_TxFundedProofV1 &ser_proof, TxFundedProofV1 &proof_out);

void make_serializable_reserved_enote_proof_v1(const ReservedEnoteProofV1 &proof,
    ser_ReservedEnoteProofV1 &ser_proof_out);
void recover_reserved_enote_proof_v1(const ser_ReservedEnoteProofV1 &ser_proof, ReservedEnoteProofV1 &proof_out);

void make_serializable_reserve_proof_v1(const ReserveProofV1 &proof, ser_ReserveProofV1 &ser_proof_out);
void recover_reserve_proof_v1(const ser_ReserveProofV1 &ser_proof, ReserveProofV1 &proof_out);
