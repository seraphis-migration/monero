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

// Core implementation details for making and finding enotes with Jamtis address privkeys
// - Jamtis is a specification for Seraphis-compatible addresses


#pragma once

//local headers
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "device/device.hpp"
#include "jamtis_support_types.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace sp
{
namespace jamtis
{

/*
enote recovery:
1. view tag checking
2. address tag checking
3. nominal spend key checking
4. amount commitment checking
5. spent status checking
6. loop back to 2 for all unowned enotes created in txs with spent enotes (self-send style checks)


*/

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
* return: view_tag
*/
view_tag_t make_jamtis_view_tag(const crypto::key_derivation &sender_receiver_DH_derivation,
    const rct::key &onetime_address);
/**
* brief: make_jamtis_view_tag - view tag for optimized identification of owned enotes
*    view_tag = H_1(8 * privkey * DH_key, Ko)
* param: privkey - [sender: r] [recipient: k_fr]
* param: DH_key - [sender: K_2] [sender-change-2out: k_fr * K_2_other] [recipient: K_e]
* param: hwdev - abstract reference to a hardware-specific implemention of crypto ops
* param: onetime_address - Ko
* return: view_tag
*/
view_tag_t make_jamtis_view_tag(const crypto::secret_key &privkey,
    const rct::key &DH_key,
    hw::device &hwdev,
    const rct::key &onetime_address);
/**
* brief: make_jamtis_sender_receiver_secret - sender-receiver secret q for a normal enote
*    q = H_32(DH_derivation)
* param: sender_receiver_DH_derivation - 8 * privkey * DH_key
* outparam: sender_receiver_secret_out - q
*   - note: this is 'rct::key' instead of 'crypto::secret_key' for better performance in multithreaded environments
*/
void make_jamtis_sender_receiver_secret_plain(const crypto::key_derivation &sender_receiver_DH_derivation,
    rct::key &sender_receiver_secret_out);
/**
* brief: make_jamtis_sender_receiver_secret_plain - sender-receiver secret q for a normal enote
*    q = H_32(8 * r * k_fr * G) => H_32(8 * privkey * DH_key)
* param: privkey - [sender: r] [recipient: k_fr]
* param: DH_key - [sender: K_2] [sender-change-2out: k_fr * K_2_other] [recipient: K_e]
* param: hwdev - abstract reference to a hardware-specific implemention of crypto ops
* outparam: sender_receiver_secret_out - q
*   - note: this is 'rct::key' instead of 'crypto::secret_key' for better performance in multithreaded environments
*/
void make_jamtis_sender_receiver_secret_plain(const crypto::secret_key &privkey,
    const rct::key &DH_key,
    hw::device &hwdev,
    rct::key &sender_receiver_secret_out);
/**
* brief: make_jamtis_sender_receiver_secret - sender-receiver secret q for a self-send enote
*    q = H_32(Pad136(k_vb), K_e)
* param: k_view_balance - k_vb
* param: enote_ephemeral_pubkey - K_e
* outparam: sender_receiver_secret_out - q
*   - note: this is 'rct::key' instead of 'crypto::secret_key' for better performance in multithreaded environments
*/
void make_jamtis_sender_receiver_secret_selfsend(const crypto::secret_key &k_view_balance,
    const rct::key &enote_ephemeral_pubkey,
    rct::key &sender_receiver_secret_out);
/**
* brief: make_jamtis_sender_address_extension - extension for transforming a recipient spendkey into an enote one-time address
*    k_{a, sender} = H_n(q)
* param: sender_receiver_secret - q
* outparam: sender_address_extension_out - k_{a, sender}
*/
void make_jamtis_sender_address_extension(const rct::key &sender_receiver_secret,
    crypto::secret_key &sender_address_extension_out);
/**
* brief: make_jamtis_sender_address_extension - extension for transforming a recipient spendkey into an enote one-time address
*    Ko = H_n(q) X + K_1
* param: sender_receiver_secret - q
* param: recipient_spend_key - K_1
* outparam: onetime_address_out - Ko
*/
void make_jamtis_onetime_address(const rct::key &sender_receiver_secret,
    const rct::key &recipient_spend_key,
    rct::key &onetime_address_out);
/**
* brief: make_jamtis_amount_blinding_factor_selfsend - x for an enote's amount commitment C = x G + a H
*   x = H_n(q, r G)
* param: sender_receiver_secret - q
* param: baked_key - r G (enote ephemeral base key)
* outparam: mask_out - x
*/
void make_jamtis_amount_blinding_factor_plain(const rct::key &sender_receiver_secret,
    const rct::key &baked_key,
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
* brief: make_jamtis_encoded_amount_plain - encode an amount
*   a_enc = a XOR H_8(q, r G)
* param: amount - a
* param: sender_receiver_secret - q
* param: baked_key - r G
* return: a_enc
*/
rct::xmr_amount make_jamtis_encoded_amount_plain(const rct::xmr_amount amount,
    const rct::key &sender_receiver_secret,
    const rct::key &baked_key);
/**
* brief: make_jamtis_encoded_amount_plain - encode an amount
*   a = a_enc XOR H_8(q, r G)
* param: encoded_amount - a_enc
* param: sender_receiver_secret - q
* param: baked_key - r G
* return: a
*/
rct::xmr_amount decode_jamtis_amount_plain(const rct::xmr_amount encoded_amount,
    const rct::key &sender_receiver_secret,
    const rct::key &baked_key);
/**
* brief: make_jamtis_encoded_amount_plain - encode an amount
*   a_enc = a XOR H_8(q)
* param: amount - a
* param: sender_receiver_secret - q
* return: a_enc
*/
rct::xmr_amount make_jamtis_encoded_amount_selfsend(const rct::xmr_amount amount,
    const rct::key &sender_receiver_secret);
/**
* brief: make_jamtis_encoded_amount_plain - encode an amount
*   a = a_enc XOR H_8(q)
* param: encoded_amount - a_enc
* param: sender_receiver_secret - q
* return: a
*/
rct::xmr_amount decode_jamtis_amount_selfsend(const rct::xmr_amount encoded_amount,
    const rct::key &sender_receiver_secret);
/**
* brief: get_jamtis_nominal_spend_key - get a nominal spend key from a onetime address
*   K'_1 = Ko - H_n(q) X
* param: sender_receiver_secret - q
* param: onetime_address - K0
* outparam: nominal_spend_key_out - K'_1
*/
void get_jamtis_nominal_spend_key(const rct::key &sender_receiver_secret,
    const rct::key &onetime_address
    rct::key &nominal_spend_key_out);
/**
* brief: try_get_jamtis_nominal_spend_key - test view tag; if it passes, compute and return the nominal spend key
*    and sender-receiver secret
* param: sender_receiver_DH_derivation - 8 * privkey * DH_key
* param: output_index - t
* param: onetime_address - Ko_t
* param: view_tag - tag_t
* outparam: sender_receiver_secret_out - q_t
*   - note: this is 'rct::key' instead of 'crypto::secret_key' for better performance in multithreaded environments
* outparam: nominal_spend_key_out - K'^s_t = Ko_t - H(q_t) X
* return: true if successfully recomputed the view tag
*/
bool try_get_jamtis_nominal_spend_key(const crypto::key_derivation &sender_receiver_DH_derivation,
    const std::size_t output_index,
    const rct::key &onetime_address,
    const view_tag_t view_tag,
    rct::key &sender_receiver_secret_out,
    rct::key &nominal_spend_key_out);
/**
* brief: try_get_jamtis_amount - test recreating the amount commitment; if it is recreate-able, return the amount
* param: sender_receiver_secret - q_t
* param: baked_key - extra key baked into amount encoding and amount commitment mask [OPTIONAL: set to zero if unwanted]
* param: amount_commitment - C = x G + a H
* param: encoded_amount - enc(a)
* outparam: amount_out - a' = dec(enc(a))
* return: true if successfully recomputed the amount commitment (C' = H(q_t) G + a' H ?= C)
*/
bool try_get_jamtis_amount(const crypto::secret_key &sender_receiver_secret,
    const rct::key &baked_key,
    const rct::key &amount_commitment,
    const rct::xmr_amount encoded_amount,
    rct::xmr_amount &amount_out);

} //namespace jamtis
} //namespace sp
