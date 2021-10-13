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

// Core implementation details for Seraphis (key images, enote pieces, address pieces, ...)


#pragma once

//local headers
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace mock_tx
{

/**
* brief: make_seraphis_key_image - create a Seraphis key image from private keys 'y' and 'z'
*   KI = (z/y)*U
*      = (k_{b, recipient} / (k_{a, sender} + k_{a, recipient}))*U
* param: y - private key '(k_{a, sender} + k_{a, recipient}))' (e.g. created from private view key secrets)
* param: z - private key 'k_{b, recipient}' (e.g. the private spend key 'ks')
* outparam: key_image_out - KI
*/
void make_seraphis_key_image(const crypto::secret_key &y, const crypto::secret_key &z, crypto::key_image &key_image_out);
/**
* brief: make_seraphis_key_image - create a Seraphis key image from 'y' and spend key base 'zU'
*   KI = (1/y) * z U
* param: y - private key 'y' (e.g created from private view key secrets)
* param: zU - pubkey z U (e.g. the base spend key 'ks U')
* outparam: key_image_out - KI
*/
void make_seraphis_key_image(const crypto::secret_key &y, const rct::key &zU, crypto::key_image &key_image_out);
/**
* brief: make_seraphis_onetime_address_spendbase - create the spendbase part of a Seraphis address
*   spendbase = k_{b, recipient} U
* param: spendbase_privkey - k_{b, recipient}
* outparam: spendbase_pubkey_out - k_{b, recipient} U
*/
void make_seraphis_address_spendbase(const crypto::secret_key &spendbase_privkey, rct::key &spendbase_pubkey_out);
/**
* brief: make_seraphis_address - create a Seraphis address (or onetime address)
*   K = k_a X + k_b U
* param: view_privkey - k_a
* param: spendbase_privkey - k_b
* outparam: address_out - k_a X + k_b U
*/
void make_seraphis_address(const crypto::secret_key &k_a, const crypto::secret_key &k_b, rct::key &address_out);
/**
* brief: make_seraphis_address_extend - extend/create a Seraphis address (or onetime address)
*   K = k_a_extender X + K_original
* param: k_a_extender - extends the existing pubkey
* inoutparam: address_inout - [in: K_original] [out: k_a_extender X + K_original]
*/
void extend_seraphis_address(const crypto::secret_key &k_a_extender, rct::key &address_inout);
/**
* brief: make_seraphis_enote_pubkey - enote pubkey R_t
*   R_t = r_t K^{DH}_recipient
* param: enote_privkey - r_t
* param: DH_base - K^{DH}_recipient
* outparam: enote_pubkey_out - R_t
*/
void make_seraphis_enote_pubkey(const crypto::secret_key &enote_privkey, const rct::key &DH_base, rct::key &enote_pubkey_out);
/**
* brief: make_seraphis_sender_receiver_secret - sender-receiver secret q_t for an output at index 't' in the tx that created it
*    q_t = H(r_t * k^{vr} * K^{DH}, t) => H("domain sep", enote_index, privkey * DH_key)
* param: privkey - [sender: r_t] [recipient: k^{vr}]
* param: DH_key - [sender: K^{vr}] [sender-change-2out: k^{vr}*K^{DH}_other] [recipient: R_t]
* param: enote_index - t (index of the enote within its tx)
* outparam: sender_receiver_secret_out - q_t
*/
void make_seraphis_sender_receiver_secret(const crypto::secret_key &privkey,
    const rct::key &DH_key,
    const std::size_t enote_index,
    crypto::secret_key &sender_receiver_secret_out);
/**
* brief: make_seraphis_sender_address_extension - extension for transforming a recipient address into an enote one-time address
*    k_{a, sender} = H("domain-sep", q_t)
* param: sender_receiver_secret - q_t
* outparam: sender_address_extension_out - k_{a, sender}
*/
void make_seraphis_sender_address_extension(const crypto::secret_key &sender_receiver_secret,
    crypto::secret_key &sender_address_extension_out);
/**
* brief: make_seraphis_view_tag - view tag for optimized identification of owned enotes
*    tag_t = H("domain-sep", q_t)
* param: sender_receiver_secret - q_t
* return: tag_t
*/
unsigned char make_seraphis_view_tag(const crypto::secret_key &sender_receiver_secret);
/**
* brief: enc_dec_seraphis_amount - encode/decode an amount
* param: sender_receiver_secret - q_t
* return: H(q_t) XOR_64 original
*/
rct::xmr_amount enc_dec_seraphis_amount(const crypto::secret_key &sender_receiver_secret, const rct::xmr_amount original);
/**
* brief: make_seraphis_amount_commitment_mask - x_t for an enote's amount commitment C = x_t G + a_t H
*   x_t = H("domain-sep", q_t)
* param: sender_receiver_secret - q_t
* outparam: mask_out - x_t
*/
void make_seraphis_amount_commitment_mask(const crypto::secret_key &sender_receiver_secret, crypto::secret_key &mask_out);
/**
* brief: try_get_seraphis_nominal_spend_key - test view tag; if it passes, compute and return the nominal spend key
* param: sender_receiver_secret - q_t
* param: onetime_address - Ko_t
* param: view_tag - tag_t
* outparam: nominal_spend_key_out - K'^s_t = Ko_t - H(q_t) X
* return: true if successfully recomputed the view tag
*/
bool try_get_seraphis_nominal_spend_key(const crypto::secret_key &sender_receiver_secret,
    const rct::key &onetime_address,
    const unsigned char view_tag,
    rct::key &nominal_spend_key_out);
/**
* brief: try_get_seraphis_amount - test recreating the amount commitment; if it is recreate-able, return the amount
* param: sender_receiver_secret - q_t
* param: amount_commitment - C = x G + a H
* param: encoded_amount - enc(a)
* outparam: amount_out - a' = dec(enc(a))
* return: true if successfully recomputed the amount commitment (C' = H(q_t) G + a' H ?= C)
*/
bool try_get_seraphis_amount(const crypto::secret_key &sender_receiver_secret,
    const rct::key &amount_commitment,
    const rct::xmr_amount encoded_amount,
    rct::xmr_amount &amount_out);

} //namespace sp
