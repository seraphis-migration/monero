// Copyright (c) 2021, The Monero Project
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

// NOT FOR PRODUCTION

// Core implementation details for making and finding enotes with Jamtis address privkeys.


#pragma once

//local headers
#include "crypto/crypto.h"
#include "device/device.hpp"
#include "jamtis_support_types.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers

//forward declarations


namespace sp
{
namespace jamtis
{

/**
* brief: make_jamtis_enote_ephemeral_pubkey - enote ephemeral pubkey K_e
*   K_e = r K_3
* param: enote_privkey - r
* param: DH_base - K_3
* outparam: enote_ephemeral_pubkey_out - K_e
*/
void make_jamtis_enote_ephemeral_pubkey(const crypto::secret_key &enote_privkey,
    const rct::key &DH_base,
    rct::key &enote_ephemeral_pubkey_out);
/**
* brief: make_jamtis_view_tag - view tag for optimized identification of owned enotes
*    view_tag = H_1(K_d, Ko)
* param: sender_receiver_DH_derivation - K_d
* param: onetime_address - Ko
* outparam: view_tag_out - view_tag
*/
void make_jamtis_view_tag(const crypto::key_derivation &sender_receiver_DH_derivation,
    const rct::key &onetime_address,
    view_tag_t &view_tag_out);
/**
* brief: make_jamtis_view_tag - view tag for optimized identification of owned enotes
*    view_tag = H_1(8 * privkey * DH_key, Ko)
* param: privkey - [sender: r] [recipient: k_fr]
* param: DH_key - [sender: K_2] [sender-change-2out: k_fr * K_3_other] [recipient: K_e = r K_3]
* param: hwdev - abstract reference to a hardware-specific implemention of key derivation
* param: onetime_address - Ko
* outparam: view_tag_out - view_tag
*/
void make_jamtis_view_tag(const crypto::secret_key &privkey,
    const rct::key &DH_key,
    hw::device &hwdev,
    const rct::key &onetime_address,
    view_tag_t &view_tag_out);
/**
* brief: make_jamtis_sender_receiver_secret_plain - sender-receiver secret q for a normal enote
*    q = H_32(DH_derivation, input_context)
* param: sender_receiver_DH_derivation - K_d = 8 * privkey * DH_key
* param: input_context - [normal: H({input KI}); coinbase: H(block height)]
* outparam: sender_receiver_secret_out - q
*   - note: this is 'rct::key' instead of 'crypto::secret_key' for better performance in multithreaded environments
*/
void make_jamtis_sender_receiver_secret_plain(const crypto::key_derivation &sender_receiver_DH_derivation,
    const rct::key &input_context,
    rct::key &sender_receiver_secret_out);
/**
* brief: make_jamtis_sender_receiver_secret_plain - sender-receiver secret q for a normal enote
*    q = H_32(8 * r * k_fr * G, input_context) => H_32(8 * privkey * DH_key, input_context)
* param: privkey - [sender: r] [recipient: k_fr]
* param: DH_key - [sender: K_2] [sender-change-2out: k_fr * K_3_other] [recipient: K_e = r K_3]
* param: input_context - [normal: H({input KI}); coinbase: H(block height)]
* param: hwdev - abstract reference to a hardware-specific implemention of key derivation
* outparam: sender_receiver_secret_out - q
*   - note: this is 'rct::key' instead of 'crypto::secret_key' for better performance in multithreaded environments
*/
void make_jamtis_sender_receiver_secret_plain(const crypto::secret_key &privkey,
    const rct::key &DH_key,
    const rct::key &input_context,
    hw::device &hwdev,
    rct::key &sender_receiver_secret_out);
/**
* brief: make_jamtis_sender_receiver_secret_selfsend - sender-receiver secret q for a self-send enote of a specific type
*    q = H_32[k_vb](K_e)
* param: k_view_balance - k_vb
* param: enote_ephemeral_pubkey - K_e
* param: input_context - [normal: H({input KI}); coinbase: H(block height)]
* param: self_send_type - type of the self-send enote, used to select the domain separator
* outparam: sender_receiver_secret_out - q
*   - note: this is 'rct::key' instead of 'crypto::secret_key' for better performance in multithreaded environments
*/
void make_jamtis_sender_receiver_secret_selfsend(const crypto::secret_key &k_view_balance,
    const rct::key &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const jamtis::JamtisSelfSendType self_send_type,
    rct::key &sender_receiver_secret_out);
/**
* brief: make_jamtis_onetime_address_extension - extension for transforming a recipient spendkey into an
*        enote one-time address
*    k_{a, sender} = H_n(q)
* param: sender_receiver_secret - q
* outparam: sender_extension_out - k_{a, sender}
*/
void make_jamtis_onetime_address_extension(const rct::key &sender_receiver_secret,
    crypto::secret_key &sender_extension_out);
/**
* brief: make_jamtis_onetime_address - create a onetime address
*    Ko = H_n(q) X + K_1
* param: sender_receiver_secret - q
* param: recipient_spend_key - K_1
* outparam: onetime_address_out - Ko
*/
void make_jamtis_onetime_address(const rct::key &sender_receiver_secret,
    const rct::key &recipient_spend_key,
    rct::key &onetime_address_out);
/**
* brief: make_jamtis_amount_baked_key_plain_sender - key baked into amount encodings of plain enotes, to provide
*    fine-tuned control over read rights to the amount
*    [sender] baked_key = 8 r G
* param: enote_privkey - r
* outparam: baked_key_out - 8 r G
*/
void make_jamtis_amount_baked_key_plain_sender(const crypto::secret_key &enote_privkey,
    crypto::key_derivation &baked_key_out);
/**
* brief: make_jamtis_amount_baked_key_plain_recipient - key baked into amount encodings of plain enotes, to provide
*    fine-tuned control over read rights to the amount
*    [recipient] baked_key = 8 (1/k^j_a) K_e
* param: address_privkey - k^j_a
* param: enote_ephemeral_pubkey - K_e
* outparam: baked_key_out - 8 (1/k^j_a) K_e
*/
void make_jamtis_amount_baked_key_plain_recipient(const crypto::secret_key &address_privkey,
    const rct::key &enote_ephemeral_pubkey,
    crypto::key_derivation &baked_key_out);
/**
* brief: make_jamtis_amount_blinding_factor_plain - x for a normal enote's amount commitment C = x G + a H
*   x = H_n(q, 8 r G)
* param: sender_receiver_secret - q
* param: baked_key - 8 r G
* outparam: mask_out - x
*/
void make_jamtis_amount_blinding_factor_plain(const rct::key &sender_receiver_secret,
    const crypto::key_derivation &baked_key,
    crypto::secret_key &mask_out);
/**
* brief: make_jamtis_amount_blinding_factor_selfsend - x for a self-spend enote's amount commitment C = x G + a H
*   x = H_n(q)
* param: sender_receiver_secret - q
* outparam: mask_out - x
*/
void make_jamtis_amount_blinding_factor_selfsend(const rct::key &sender_receiver_secret,
    crypto::secret_key &mask_out);
/**
* brief: encode_jamtis_amount_plain - encode an amount for a normal enote
*   a_enc = a XOR H_8(q, 8 r G)
* param: amount - a
* param: sender_receiver_secret - q
* param: baked_key - 8 r G
* return: a_enc
*/
rct::xmr_amount encode_jamtis_amount_plain(const rct::xmr_amount amount,
    const rct::key &sender_receiver_secret,
    const crypto::key_derivation &baked_key);
/**
* brief: decode_jamtis_amount_plain - decode an amount froma normal enote
*   a = a_enc XOR H_8(q, 8 r G)
* param: encoded_amount - a_enc
* param: sender_receiver_secret - q
* param: baked_key - 8 r G
* return: a
*/
rct::xmr_amount decode_jamtis_amount_plain(const rct::xmr_amount encoded_amount,
    const rct::key &sender_receiver_secret,
    const crypto::key_derivation &baked_key);
/**
* brief: encode_jamtis_amount_selfsend - encode an amount for a self-send enote
*   a_enc = a XOR H_8(q)
* param: amount - a
* param: sender_receiver_secret - q
* return: a_enc
*/
rct::xmr_amount encode_jamtis_amount_selfsend(const rct::xmr_amount amount,
    const rct::key &sender_receiver_secret);
/**
* brief: decode_jamtis_amount_selfsend - decode an amount from a self-send enote
*   a = a_enc XOR H_8(q)
* param: encoded_amount - a_enc
* param: sender_receiver_secret - q
* return: a
*/
rct::xmr_amount decode_jamtis_amount_selfsend(const rct::xmr_amount encoded_amount,
    const rct::key &sender_receiver_secret);
/**
* brief: make_jamtis_nominal_spend_key - make a nominal spend key from a onetime address
*   K'_1 = Ko - H_n(q) X
* param: sender_receiver_secret - q
* param: onetime_address - Ko
* outparam: nominal_spend_key_out - K'_1
*/
void make_jamtis_nominal_spend_key(const rct::key &sender_receiver_secret,
    const rct::key &onetime_address,
    rct::key &nominal_spend_key_out);
/**
* brief: try_get_jamtis_nominal_spend_key_plain - test view tag; if it passes, compute and return the nominal spend key
*    and sender-receiver secret (for a normal enote)
* param: sender_receiver_DH_derivation - 8 * privkey * DH_key
* param: input_context - [normal: H({input KI}); coinbase: H(block height)]
* param: onetime_address - Ko
* param: view_tag - view_tag
* outparam: sender_receiver_secret_out - q
* outparam: nominal_spend_key_out - K'_1 = Ko - H(q) X
* return: true if successfully recomputed the view tag
*/
bool try_get_jamtis_nominal_spend_key_plain(const crypto::key_derivation &sender_receiver_DH_derivation,
    const rct::key &input_context,
    const rct::key &onetime_address,
    const view_tag_t view_tag,
    rct::key &sender_receiver_secret_out,
    rct::key &nominal_spend_key_out);
/**
* brief: try_get_jamtis_amount_plain - test recreating the amount commitment; if it is recreate-able, return the amount
*    (for a normal enote)
* param: sender_receiver_secret - q
* param: baked_key - 8 r G
* param: amount_commitment - C = x G + a H
* param: encoded_amount - enc_a
* outparam: amount_out - a' = dec(enc_a)
* outparam: amount_blinding_factor_out - x'
* return: true if successfully recomputed the amount commitment (C' = x' G + a' H ?= C)
*/
bool try_get_jamtis_amount_plain(const rct::key &sender_receiver_secret,
    const crypto::key_derivation &baked_key,
    const rct::key &amount_commitment,
    const rct::xmr_amount encoded_amount,
    rct::xmr_amount &amount_out,
    crypto::secret_key &amount_blinding_factor_out);
/**
* brief: try_get_jamtis_amount_selfsend - test recreating the amount commitment; if it is recreate-able, return the amount
*    (for a self-send enote)
* param: sender_receiver_secret - q
* param: amount_commitment - C = x G + a H
* param: encoded_amount - enc_a
* outparam: amount_out - a' = dec(enc_a)
* outparam: amount_blinding_factor_out - x'
* return: true if successfully recomputed the amount commitment (C' = x' G + a' H ?= C)
*/
bool try_get_jamtis_amount_selfsend(const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    const rct::xmr_amount encoded_amount,
    rct::xmr_amount &amount_out,
    crypto::secret_key &amount_blinding_factor_out);

} //namespace jamtis
} //namespace sp
