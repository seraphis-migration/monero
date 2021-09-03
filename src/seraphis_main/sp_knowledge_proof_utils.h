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

// Utilities for making and verifying seraphis knowledge proofs.

#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/enote_record_types.h"
#include "seraphis_main/sp_knowledge_proof_types.h"
#include "seraphis_main/tx_validation_context.h"

//third party headers
#include <boost/multiprecision/cpp_int.hpp>

//standard headers
#include <vector>

//forward declarations


namespace sp
{
namespace knowledge_proofs
{

/**
* brief: make an address ownership proof
* param: message - message provided by verifier
* param: address - address with the format xG + yX + zU (e.g. K_1 or K_s)
* param: x - secret key corresponding to base G
* param: y - secret key corresponding to base X
* param: z - secret key corresponding to base U
* outparam: proof_out - proof created
*/
void make_address_ownership_proof_v1(const rct::key &message,
    const rct::key &address,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z,
    AddressOwnershipProofV1 &proof_out);
void make_address_ownership_proof_v1(const rct::key &message,  //for K_s
    const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_view_balance,
    AddressOwnershipProofV1 &proof_out);
void make_address_ownership_proof_v1(const rct::key &message,  //for K_1
    const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_view_balance,
    const jamtis::address_index_t &j,
    AddressOwnershipProofV1 &proof_out);
/**
* brief: verify address ownership proof
* param: proof - proof to verify
* param: expected_message - message expected in the proof
* param: expected_address - address expected in the proof
* return: true/false according to proof validity 
*/
bool verify_address_ownership_proof_v1(const AddressOwnershipProofV1 &proof,
    const rct::key &expected_message,
    const rct::key &expected_address);
/**
* brief: make an address index proof
* param: jamtis_spend_pubkey - K_s
* param: j - address index
* param: s_generate_address - s_ga
* outparam: proof_out - proof created
*/
void make_address_index_proof_v1(const rct::key &jamtis_spend_pubkey,
    const jamtis::address_index_t &j,
    const crypto::secret_key &s_generate_address,
    AddressIndexProofV1 &proof_out);
/**
* brief: verify address index proof
* param: proof - proof to verify
* param: expected_address - address this proof should be about
* return: true/false according to proof validity 
*/
bool verify_address_index_proof_v1(const AddressIndexProofV1 &proof, const rct::key &expected_address);
/**
* brief: make an enote ownership proof
* param: jamtis_address_spend_key - K_1
* param: sender_receiver_secret - q
* param: amount_commitment - C
* param: onetime_address - Ko
* outparam: proof_out - proof created
*/
void make_enote_ownership_proof_v1(const rct::key &jamtis_address_spend_key,
    const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    const rct::key &onetime_address,
    EnoteOwnershipProofV1 &proof_out);
void make_enote_ownership_proof_v1_sender_plain(const crypto::x25519_secret_key &enote_ephemeral_privkey,
    const jamtis::JamtisDestinationV1 &recipient_destination,
    const rct::key &input_context,
    const rct::key &amount_commitment,
    const rct::key &onetime_address,
    EnoteOwnershipProofV1 &proof_out);
void make_enote_ownership_proof_v1_sender_selfsend(const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &jamtis_address_spend_key,
    const rct::key &input_context,
    const crypto::secret_key &k_view_balance,
    const jamtis::JamtisSelfSendType self_send_type,
    const rct::key &amount_commitment,
    const rct::key &onetime_address,
    EnoteOwnershipProofV1 &proof_out);
void make_enote_ownership_proof_v1_receiver(const SpEnoteRecordV1 &enote_record,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    EnoteOwnershipProofV1 &proof_out);
/**
* brief: verify enote ownership proof
* param: proof - proof to verify
* param: expected_amount_commitment - expected amount commitment of the proof enote
* param: expected_onetime_address - expected onetime address of the proof enote
* return: true/false according to proof validity 
*/
bool verify_enote_ownership_proof_v1(const EnoteOwnershipProofV1 &proof,
    const rct::key &expected_amount_commitment,
    const rct::key &expected_onetime_address);
/**
* brief: make an enote amount proof
* param: amount - xmr amount a
* param: mask - blinding factor x
* param: commitment - C = xG+aH
* outparam: proof_out - proof created
*/
void make_enote_amount_proof_v1(const rct::xmr_amount &amount,
    const crypto::secret_key &mask,
    const rct::key &commitment,
    EnoteAmountProofV1 &proof_out);
/**
* brief: verify enote amount proof
* param: proof - proof to verify
* param: expected_commitment - commitment expected to be in the proof
* return: true/false according to proof validity 
*/
bool verify_enote_amount_proof_v1(const EnoteAmountProofV1 &proof, const rct::key &expected_commitment);
/**
* brief: make an enote key image proof
* param: onetime_address - address which has the format xG + yX + zU. 
* param: x - secret key corresponding to base G
* param: y - secret key corresponding to base X
* param: z - secret key corresponding to base U
* outparam: proof_out - proof created
*/
void make_enote_key_image_proof_v1(const rct::key &onetime_address,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z,
    EnoteKeyImageProofV1 &proof_out);
void make_enote_key_image_proof_v1(const SpEnoteRecordV1 &enote_record,
    const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_view_balance,
    EnoteKeyImageProofV1 &proof_out);
/**
* brief: verify enote key image proof
* param: proof - proof to verify
* param: expected_onetime_address - expected Ko in the proof
* param: expected_KI - expected KI in the proof
* return: true/false according to proof validity 
*/
bool verify_enote_key_image_proof_v1(const EnoteKeyImageProofV1 &proof,
    const rct::key &expected_onetime_address,
    const crypto::key_image &expected_KI);
/**
* brief: make an enote unspent proof
* param: enote_record - record of the enote for this proof
* param: sp_spend_privkey - k_m
* param: k_view_balance - k_vb
* param: test_KI - key image this proof shows does NOT correspond to the proof enote
* outparam: proof_out - proof created
*/
void make_enote_unspent_proof_v1(const SpEnoteRecordV1 &enote_record,
    const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_view_balance,
    const crypto::key_image &test_KI,
    EnoteUnspentProofV1 &proof_out);
/**
* brief: verify enote unspent proof
* param: proof - proof to verify
* param: expected_onetime_address - expected onetime address of the proof enote
* param: expected_test_KI - expected test key image
* return: true/false according to proof validity 
*/
bool verify_enote_unspent_proof_v1(const EnoteUnspentProofV1 &proof,
    const rct::key &expected_onetime_address,
    const crypto::key_image &expected_test_KI);
/**
* brief: make a funded tx proof
* param: message - message provided by verifier
* param: enote_record - enote_record containing all the mask openings 
* param: onetime_address - address which has the format xG + yX + zU. 
* param: k_vb - view_balance secret key 
* param: k_m - master secret key 
* outparam: proof_out - proof created
*/
void make_tx_funded_proof_v1(const rct::key &message,
    const SpEnoteRecordV1 &enote_record,
    const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_view_balance,
    TxFundedProofV1 &proof_out);
/**
* brief: verify funded tx proof
* param: proof - proof to verify
* param: expected_message - expected message to be signed by the proof
* param: expected_KI - expected key image for the proof
* return: true/false according to proof validity 
*/
bool verify_tx_funded_proof_v1(const TxFundedProofV1 &proof,
    const rct::key &expected_message,
    const crypto::key_image &expected_KI);
/**
* brief: make an enote sent proof
* param: ownership_proof - proof of enote ownership
* param: amount_proof - proof of enote amount
* outparam: proof_out - proof created
*/
void make_enote_sent_proof_v1(const EnoteOwnershipProofV1 &ownership_proof,
    const EnoteAmountProofV1 &amount_proof,
    EnoteSentProofV1 &proof_out);
/**
* brief: verify enote sent proof
* param: proof - proof to verify
* param: expected_amount_commitment - expected amount commitment of the proof enote
* param: expected_onetime_address - expected onetime address of the proof enote
* return: true/false according to proof validity 
*/
bool verify_enote_sent_proof_v1(const EnoteSentProofV1 &proof,
    const rct::key &expected_amount_commitment,
    const rct::key &expected_onetime_address);
/**
* brief: make a reserved enote proof
* param: enote_ownership_proof - component proof
* param: amount_proof - component proof
* param: key_image_proof - component proof
* param: enote_ledger_index - ledger index of the reserved enote
* outparam: proof_out - proof created
*/
void make_reserved_enote_proof_v1(const EnoteOwnershipProofV1 &enote_ownership_proof,
    const EnoteAmountProofV1 &amount_proof,
    const EnoteKeyImageProofV1 &key_image_proof,
    const std::uint64_t enote_ledger_index,
    ReservedEnoteProofV1 &proof_out);
void make_reserved_enote_proof_v1(const SpContextualEnoteRecordV1 &contextual_record,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_view_balance,
    ReservedEnoteProofV1 &proof_out);
/**
* brief: verify reserved enote proof
* param: proof - proof to verify
* param: expected_amount_commitment - commitment that should be in the proof
* param: expected_onetime_address - onetime address that should be in the proof
* return: true/false according to proof validity 
*/
bool verify_reserved_enote_proof_v1(const ReservedEnoteProofV1 &proof,
    const rct::key &expected_amount_commitment,
    const rct::key &expected_onetime_address,
    const std::uint64_t expected_enote_ledger_index);
/**
* brief: check if the reserved enote in a reserved enote proof is onchain and unspent
*   NOTE: does not verify the reserved enote proof
* param: proof - proof to check
* param: validation_context - context to check the proof against
* return: true if the enote is reserved (onchain and unspent)
*/
bool reserved_enote_is_reserved_v1(const ReservedEnoteProofV1 &proof, const TxValidationContext &validation_context);
/**
* brief: make a reserve proof
* param: message - message provided by the verifier
* param: reserved_enote_records - enotes for the proof
* param: jamtis_spend_pubkey - K_s
* param: sp_spend_privkey - k_m
* param: k_view_balance - k_vb
* outparam: proof_out - proof created
*/
void make_reserve_proof_v1(const rct::key &message,
    const std::vector<SpContextualEnoteRecordV1> &reserved_enote_records,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_view_balance,
    ReserveProofV1 &proof_out);
/**
* brief: verify reserve proof
* param: proof - proof to verify
* param: expected_message - message that should be signed in the proof's address ownership proofs
* param: validation_context - context to check the reserved enotes against (to see if they are onchain and unspent)
* return: true/false according to proof validity 
*/
bool verify_reserve_proof_v1(const ReserveProofV1 &proof,
    const rct::key &expected_message,
    const TxValidationContext &validation_context);
/**
* brief: get the total amount in a reserve proof
* param: proof - proof to get amounts from
* return: total reserved amount
*/
boost::multiprecision::uint128_t total_reserve_amount(const ReserveProofV1 &proof);

} //namespace knowledge_proofs
} //namespace sp
