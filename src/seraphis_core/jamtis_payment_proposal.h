// Copyright (c) 2022, The Monero Project
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

// A 'payment proposal' is a proposal to make an enote sending funds to a Jamtis address.
// NOTE: Coinbase output proposals cannot be made from selfsend payment proposals because selfsend balance recovery
//       depends on looking in txs with known key images, but coinbase txs don't have key images.

#pragma once

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "jamtis_destination.h"
#include "jamtis_support_types.h"
#include "ringct/rctTypes.h"
#include "sp_core_types.h"
#include "tx_extra.h"

//third party headers

//standard headers

//forward declarations


namespace sp
{
namespace jamtis
{

////
// JamtisPaymentProposalV1
// - for creating an output proposal to send an amount to someone
///
struct JamtisPaymentProposalV1 final
{
    /// user address
    JamtisDestinationV1 destination;
    /// b
    rct::xmr_amount amount;

    /// enote ephemeral privkey: xr
    crypto::x25519_secret_key enote_ephemeral_privkey;

    /// memo elements to add to the tx memo
    TxExtra partial_memo;
};

////
// JamtisPaymentProposalSelfSendV1
// - for creating an output proposal to send an amount to the tx author
///
struct JamtisPaymentProposalSelfSendV1 final
{
    /// user address
    JamtisDestinationV1 destination;
    /// b
    rct::xmr_amount amount;

    /// self-send type
    JamtisSelfSendType type;
    /// enote ephemeral privkey: xr
    crypto::x25519_secret_key enote_ephemeral_privkey;

    /// memo elements to add to the tx memo
    TxExtra partial_memo;
};

/// equality operators
bool operator==(const JamtisPaymentProposalV1 a, const JamtisPaymentProposalV1 b);
bool operator==(const JamtisPaymentProposalSelfSendV1 a, const JamtisPaymentProposalSelfSendV1 b);

/**
* brief: get_enote_ephemeral_pubkey - get the proposal's enote ephemeral pubkey xK_e
* param: proposal -
* outparam: enote_ephemeral_pubkey_out -
*/
void get_enote_ephemeral_pubkey(const JamtisPaymentProposalV1 &proposal,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out);
/**
* brief: get_enote_ephemeral_pubkey - get the proposal's enote ephemeral pubkey xK_e
* outparam: enote_ephemeral_pubkey_out -
*/
void get_enote_ephemeral_pubkey(const JamtisPaymentProposalSelfSendV1 &proposal,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out);
/**
* brief: get_coinbase_output_proposal_v1 - convert the jamtis proposal to a coinbase output proposal
* param: proposal -
* param: block_height - height of the coinbase tx's block
* outparam: output_enote_core_out -
* outparam: enote_ephemeral_pubkey_out -
* outparam: addr_tag_enc_out -
* outparam: view_tag_out -
* outparam: partial_memo_out -
*/
void get_coinbase_output_proposal_v1(const JamtisPaymentProposalV1 &proposal,
    const std::uint64_t block_height,
    SpCoinbaseEnoteCore &output_enote_core_out,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out,
    encrypted_address_tag_t &addr_tag_enc_out,
    view_tag_t &view_tag_out,
    TxExtra &partial_memo_out);
/**
* brief: get_output_proposal_v1 - convert the jamtis proposal to an output proposal
* param: proposal -
* param: input_context -
* outparam: output_proposal_core_out -
* outparam: enote_ephemeral_pubkey_out -
* outparam: encoded_amount_out -
* outparam: addr_tag_enc_out -
* outparam: view_tag_out -
* outparam: partial_memo_out -
*/
void get_output_proposal_v1(const JamtisPaymentProposalV1 &proposal,
    const rct::key &input_context,
    SpOutputProposalCore &output_proposal_core_out,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out,
    encoded_amount_t &encoded_amount_out,
    encrypted_address_tag_t &addr_tag_enc_out,
    view_tag_t &view_tag_out,
    TxExtra &partial_memo_out);
/**
* brief: get_output_proposal_v1 - convert the jamtis selfsend proposal to an output proposal
* param: proposal -
* param: k_view_balance -
* param: input_context -
* outparam: output_proposal_core_out -
* outparam: enote_ephemeral_pubkey_out -
* outparam: encoded_amount_out -
* outparam: addr_tag_enc_out -
* outparam: view_tag_out -
* outparam: partial_memo_out -
*/
void get_output_proposal_v1(const JamtisPaymentProposalSelfSendV1 &proposal,
    const crypto::secret_key &k_view_balance,
    const rct::key &input_context,
    SpOutputProposalCore &output_proposal_core_out,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out,
    encoded_amount_t &encoded_amount_out,
    encrypted_address_tag_t &addr_tag_enc_out,
    view_tag_t &view_tag_out,
    TxExtra &partial_memo_out);
/**
* brief: gen_jamtis_payment_proposal_v1 - generate a random proposal
* param: amount -
* param: num_random_memo_elements -
* return: a random proposal
*/
JamtisPaymentProposalV1 gen_jamtis_payment_proposal_v1(const rct::xmr_amount amount,
    const std::size_t num_random_memo_elements);
/**
* brief: gen_jamtis_selfsend_payment_proposal_v1 - generate a random selfsend proposal (with specified parameters)
* param: amount -
* param: type -
* param: num_random_memo_elements
* return: a random proposal
*/
JamtisPaymentProposalSelfSendV1 gen_jamtis_selfsend_payment_proposal_v1(const rct::xmr_amount amount,
    const JamtisSelfSendType type,
    const std::size_t num_random_memo_elements);

} //namespace jamtis
} //namespace sp
