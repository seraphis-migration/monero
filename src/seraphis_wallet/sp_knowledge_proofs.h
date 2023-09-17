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
#include "seraphis_wallet/transaction_history.h"
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

// struct to get info from JamtisPaymentProposal (normal and selfsend)
struct EnoteInfo
{
    SpEnoteVariant enote;
    JamtisDestinationV1 destination;
    rct::xmr_amount amount;
    crypto::x25519_secret_key enote_ephemeral_privkey;
    rct::key sender_receiver_secret;
    crypto::secret_key amount_blinding_factor;
    bool selfsend;
};

//-----------------------------------------------------------------
/// Get Knowledge proofs
//-----------------------------------------------------------------
// All proofs have an optional 'filename' field which if specified saves the proof (output string) into it.

/**
* brief: get address ownership proof
* param: j - address index j
* param: sp_spend_privkey - private sp_spend key
* param: k_view_balance - private view_balance key
* param: bool_Ks_K1 - true if Ks / false if K1
* param: message_in - input message
* param: filename - filename to save proof
* return: string with base58 encoded proof
*/
std::string get_address_ownership_proof(const jamtis::address_index_t &j,
    const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_view_balance,
    const bool bool_Ks_K1,
    const std::string message_in,
    const boost::optional<std::string> filename);

/**
* brief: get address index proof
* param: jamtis_spend_pubkey - Ks
* param: j - address index j
* param: s_ga - private generate_address key
* param: filename - filename to save proof
* return: string with base58 encoded proof
*/
std::string get_address_index_proof(const rct::key &jamtis_spend_pubkey,
    const jamtis::address_index_t &j,
    const crypto::secret_key &s_ga,
    const boost::optional<std::string> filename);

/**
* brief: try make enote_ownership_proof_sender
* param: txid - transaction id
* param: onetime_address - onetime_address of enote
* param: dest - jamtis destination
* param: k_vb - private view_balance key
* param: selfsend - true if selfsend
* param: transaction_history - transaction_history component
* outparam: - enote_ownership_proof out
* return: true if succeeds making proofs
*/
bool try_make_enote_ownership_proof_sender(const rct::key txid,
    const rct::key &onetime_address,
    const JamtisDestinationV1 &dest,
    const crypto::secret_key &k_vb,
    const bool selfsend,
    const SpTransactionHistory &transaction_history,
    EnoteOwnershipProofV1 &proof);

/**
* brief: get enote_ownership_proof_sender
* param: txid - transaction id
* param: onetime_address - onetime_address of enote
* param: dest - jamtis destination
* param: k_vb - private view_balance key
* param: selfsend - true if selfsend
* param: transaction_history - transaction_history component
* param: filename - filename to save proof
* return: string with base58 encoded proof
*/
std::string get_enote_ownership_proof_sender(const rct::key txid,
    const rct::key &onetime_address,
    const JamtisDestinationV1 &dest,
    const crypto::secret_key &k_vb,
    const bool selfsend,
    const SpTransactionHistory &transaction_history,
    const boost::optional<std::string> filename);

/**
* brief: get enote_ownership_proof_receiver
* param: enote_record - enote_record from enote
* param: jamtis_spend_pubkey - Ks
* param: k_vb - private view_balance key
* param: filename - filename to save proof
* return: string with base58 encoded proof
*/
std::string get_enote_ownership_proof_receiver(const SpEnoteRecordV1 &enote_record,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_vb,
    const boost::optional<std::string> filename);

/**
* brief: try make amount_proof 
* param: amount - amount of enote
* param: mask - mask of commitment
* param: commitment - commitment
* outparam: - enote_amount_proof out
* return: true if succeeds making proofs
*/
bool try_make_amount_proof(const rct::xmr_amount &amount,
    const crypto::secret_key &mask,
    const rct::key &commitment,
    EnoteAmountProofV1 &amount_proof);

/**
* brief: get amount_proof 
* param: amount - amount of enote
* param: mask - mask of commitment
* param: commitment - commitment
* param: filename - filename to save proof
* return: string with base58 encoded proof
*/
std::string get_amount_proof(const rct::xmr_amount &amount,
    const crypto::secret_key &mask,
    const rct::key &commitment,
    const boost::optional<std::string> filename);

/**
* brief: get key_image_proof 
* param: enote_store - enote_store component
* param: key_image - key_image of enote
* param: k_m - private sp_spend key
* param: k_vb - private view_balance key
* param: filename - filename to save proof
* return: string with base58 encoded proof
*/
std::string get_enote_key_image_proof(const SpEnoteStore &enote_store,
    const crypto::key_image &key_image,
    const crypto::secret_key &k_m,
    const crypto::secret_key &k_vb,
    const boost::optional<std::string> filename);

/**
* brief: get enote_sent_proof 
* param: txid - transaction id
* param: onetime_address - onetime_address of enote
* param: dest - jamtis destination
* param: k_vb - private view_balance key
* param: selfsend - true if selfsend
* param: amount - amount of enote
* param: mask - mask of commitment
* param: commitment - commitment
* param: transaction_history - transaction_history component
* param: filename - filename to save proof
* return: string with base58 encoded proof
*/
std::string get_enote_sent_proof(const rct::key txid,
    const rct::key &onetime_address,
    const JamtisDestinationV1 &dest,
    const crypto::secret_key &k_vb,
    const bool selfsend,
    const rct::xmr_amount &amount,
    const crypto::secret_key &mask,
    const rct::key &commitment,
    const SpTransactionHistory &transaction_history,
    const boost::optional<std::string> filename);

/**
* brief: get tx_funded_proof 
* param: txid - transaction id
* param: enote_store - enote_store component
* param: transaction_history - transaction_history component
* param: sp_spend_privkey - private sp_spend key
* param: k_view_balance - private view_balance key
* param: message_in - input message
* param: filename - filename to save proof
* return: string with base58 encoded proof
*/
std::string get_tx_funded_proof(const rct::key &txid,
    const SpEnoteStore &enote_store,
    const SpTransactionHistory &transaction_history,
    const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_view_balance,
    const std::string &message_in,
    const boost::optional<std::string> filename);

/**
* brief: get enote_reserve_proof 
* param: message_in - input message
* param: reserved_enote_records - vector with contextual record of enotes
* param: jamtis_spend_pubkey - Ks
* param: sp_spend_privkey - private sp_spend key
* param: k_view_balance - private view_balance key
* param: proof_amount - minimal amount
* param: filename - filename to save proof
* return: string with base58 encoded proof
*/
std::string get_enote_reserve_proof(const std::string &message_in,
    const std::vector<SpContextualEnoteRecordV1> &reserved_enote_records,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_view_balance,
    const rct::xmr_amount proof_amount,
    const boost::optional<std::string> filename);

//-----------------------------------------------------------------
/// Read/Verify Knowledge proofs
//-----------------------------------------------------------------
// All reading functions have a 'filename' and a 'proof_str' field. The proof considered will be from the 'filename' if
// specified.

/**
* brief: read address ownership proof
* param: filename - filename to save proof
* param: proof_str - encoded string with proof
* param: message_in - input message
* param: expected_address - expected address
* return: true if proof is valid
*/
bool read_address_ownership_proof(const boost::optional<std::string> filename,
    const boost::optional<std::string> proof_str,
    const std::string &message_in,
    const rct::key &expected_address);

/**
* brief: read address index proof
* param: filename - filename to save proof
* param: proof_str - encoded string with proof
* param: K_1 - expected_address K_1
* return: true if proof is valid
*/
bool read_address_index_proof(const boost::optional<std::string> filename,
    const boost::optional<std::string> proof_str,
    const rct::key &K_1);

/**
* brief: read enote ownership proof
* param: filename - filename to save proof
* param: proof_str - encoded string with proof
* param: expected_amount_commitment - expected amount_commitment
* param: expected_onetime_address - expected onetime_address
* return: true if proof is valid
*/
bool read_enote_ownership_proof(const boost::optional<std::string> filename,
    const boost::optional<std::string> proof_str,
    const rct::key &expected_amount_commitment,
    const rct::key &expected_onetime_address);

/**
* brief: read enote amount proof
* param: filename - filename to save proof
* param: proof_str - encoded string with proof
* param: expected_amount_commitment - expected amount_commitment
* return: true if proof is valid
*/
bool read_amount_proof(const boost::optional<std::string> filename,
    const boost::optional<std::string> proof_str,
    const rct::key &expected_amount_commitment);

/**
* brief: read enote key image proof
* param: filename - filename to save proof
* param: proof_str - encoded string with proof
* param: expected_onetime_address - expected onetime_address
* param: expected_KI- expected key_image
* return: true if proof is valid
*/
bool read_enote_key_image_proof(const boost::optional<std::string> filename,
    const boost::optional<std::string> proof_str,
    const rct::key &expected_onetime_address,
    const crypto::key_image &expected_KI);

/**
* brief: read enote sent proof
* param: filename - filename to save proof
* param: proof_str - encoded string with proof
* param: expected_amount_commitment - expected amount_commitment
* param: expected_onetime_address - expected onetime_address
* return: true if proof is valid
*/
bool read_enote_sent_proof(const boost::optional<std::string> filename,
    const boost::optional<std::string> proof_str,
    const rct::key &expected_amount_commitment,
    const rct::key &expected_onetime_address);

/**
* brief: read tx funded proof
* param: filename - filename to save proof
* param: proof_str - encoded string with proof
* param: tx_id - transaction id
* param: message_in - input message
* param: key_images - vector with key_images of tx
* return: true if proof is valid
*/
bool read_tx_funded_proof(const boost::optional<std::string> filename,
    const boost::optional<std::string> proof_str,
    const rct::key &tx_id,
    const std::string &message_in,
    const std::vector<crypto::key_image> &key_images);

/**
* brief: read enote reserve proof 
* param: filename - filename to save proof
* param: proof_str - encoded string with proof
* param: expected_message - input message
* param: validation_context - validation context
* return: true if proof is valid
*/
bool read_enote_reserve_proof(const boost::optional<std::string> filename,
    const boost::optional<std::string> proof_str,
    const std::string &expected_message,
    const TxValidationContext &validation_context);
//-----------------------------------------------------------------

/**
* brief: find correspondence between enote and destination
* param: enotes - enotes to match
* param: normal_payments - normal_payments
* param: selfsend_payments - selfsend_payments
* param: input_context - input_context
* param: k_vb - private view_balance key
* outparam: enote_info - enote_info struct out 
* return: true if possible to match enotes with payment proposals
*/
bool try_get_enote_out_info(std::vector<SpEnoteVariant> &enotes,
    const std::vector<JamtisPaymentProposalV1> &normal_payments,
    const std::vector<JamtisPaymentProposalSelfSendV1> &selfsend_payments,
    const rct::key &input_context,
    const crypto::secret_key &k_vb,
    std::vector<EnoteInfo> &enote_info);

/**
* brief: insert prefix and encode serializable string
* param: serializable_proof - serializable proof
* param: prefix - proof prefix
* return: encoded string with prefix using base58
*/
template <typename T>
std::string proof_to_str(T &serializable_proof, std::string prefix);

/**
* brief: read encoded proof and return serializable
* param: prefix - proof prefix
* param: filename - filename of proof
* param: proof_str - string with proof
* return: serializable struct
*/
template <typename T>
T str_to_proof(const std::string prefix,
    const boost::optional<std::string> filename,
    const boost::optional<std::string> proof_str);
