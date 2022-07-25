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

// Miscellaneous legacy utilities.
// Note: these are the bare minimum for unit testing and legacy enote recovery, so are not fully-featured.


#pragma once

//local headers
#include "crypto/crypto.h"
#include "cryptonote_basic/subaddress_index.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers

//forward declarations


namespace sp
{

/**
* brief: make_legacy_subaddress_spendkey - make a legacy subaddress's spendkey
*   - (Hn(k^v, i) + k^s) G
*   - note: Hn(k^v, i) = Hn("SubAddr || k^v || index_major || index_minor)
* param: legacy_base_spend_pubkey - k^s G
* param: legacy_view_privkey - k^v
* param: subaddress_index - i
* outparam: subaddress_spendkey_out - (Hn(k^v, i) + k^s) G
*/
void make_legacy_subaddress_spendkey(const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_view_privkey,
    const cryptonote::subaddress_index &subaddress_index,
    rct::key &subaddress_spendkey_out);
/**
* brief: make_legacy_sender_receiver_secret - make a legacy sender-receiver secret
*   - [sender: r_t K^v] [recipient: k^v R_t]
* param: base_key - [sender: K^v] [recipient: R_t]
* param: tx_output_index - t
* param: DH_privkey - [sender: r_t] [recipient: k^v]
* outparam: legacy_sender_receiver_secret_out - [sender: r_t K^v] [recipient: k^v R_t]
*/
void make_legacy_sender_receiver_secret(const rct::key &base_key,
    const std::uint64_t tx_output_index,
    const crypto::secret_key &DH_privkey,
    crypto::secret_key &legacy_sender_receiver_secret_out);
/**
* brief: make_legacy_enote_view_privkey - make a legacy enote's view privkey
*   - component of onetime address privkey involving view key
*   - Hn(k^v R_t, t) + (if subaddress enote owner then Hn(k^v, i) else 0)
* param: tx_output_index - t
* param: sender_receiver_DH_derivation - k^v R_t
* param: legacy_view_privkey - k^v
* param: subaddress_index - optional(i)
* outparam: enote_view_privkey_out - Hn(k^v R_t, t) + (if (i) then Hn(k^v, i) else 0)
*/
void make_legacy_enote_view_privkey(const std::uint64_t tx_output_index,
    const crypto::key_derivation &sender_receiver_DH_derivation,
    const crypto::secret_key &legacy_view_privkey,
    const boost::optional<cryptonote::subaddress_index> &subaddress_index,
    crypto::secret_key &enote_view_privkey_out);
/**
* brief: make_legacy_onetime_address - make a legacy onetime address for the enote at index 't' in a tx's output set
*   - Ko_t = Hn(r_t K^v, t) G + K^s
* param: destination_spendkey - [normal address: k^s G] [subaddress: (Hn(k^v, i) + k^s) G]
* param: destination_viewkey - [normal address: k^v G] [subaddress: k^v K^{s,i}]
* param: tx_output_index - t
* param: enote_ephemeral_privkey - r_t  (note: r_t may be the same for all values of 't' if it is shared)
* outparam: onetime_address_out - Ko_t
*/
void make_legacy_onetime_address(const rct::key &destination_spendkey,
    const rct::key &destination_viewkey,
    const std::uint64_t tx_output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    rct::key &onetime_address_out);
/**
* brief: make_legacy_key_image - make a legacy cryptonote-style key image
*   - (k^{o,v} + k^s) * Hp(Ko)
* param: enote_view_privkey - k^{o,v}
* param: legacy_spend_privkey - k^s
* param: onetime_address - Ko
* outparam: key_image_out - (k^{o,v} + k^s) * Hp(Ko)
*/
void make_legacy_key_image(const crypto::secret_key &enote_view_privkey,
    const crypto::secret_key &legacy_spend_privkey,
    const rct::key &onetime_address,
    crypto::key_image &key_image_out);
/**
* brief: make_legacy_amount_blinding_factor_v2 - make a legacy amount blinding factor (v2 is deterministic)
*   - Hn("commitment_mask", Hn(r K^v, t))
* param: sender_receiver_secret - Hn(r K^v, t)
* outparam: amount_blinding_factor_out - Hn("commitment_mask", Hn(r K^v, t))
*/
void make_legacy_amount_blinding_factor_v2(const crypto::secret_key &sender_receiver_secret,
    crypto::secret_key &amount_blinding_factor_out);
void make_legacy_amount_blinding_factor_v2(const rct::key &destination_viewkey,
    const std::uint64_t tx_output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    crypto::secret_key &amount_blinding_factor_out);
/**
* brief: make_legacy_amount_encoding_factor_v2 - make a legacy amount encoding factor (v2 is the 8-byte encoded amount)
*   - H32("amount", Hn(r K^v, t)))
* param: sender_receiver_secret - Hn(r K^v, t)
* outparam: amount_encoding_factor_out - H32("amount", Hn(r K^v, t))
*/
void make_legacy_amount_encoding_factor_v2(const crypto::secret_key &sender_receiver_secret,
    rct::key &amount_encoding_factor_out);
/**
* brief: legacy_xor_amount - encode a legacy amount (8-byte encoding)
*   - enc(a) = little_endian(a) XOR8 encoding_factor
* param: amount - a
* param: encoding_factor - H32("amount", Hn(r K^v, t)))
* return: enc(a)
*/
rct::xmr_amount legacy_xor_amount(const rct::xmr_amount amount, const rct::key &encoding_factor);
/**
* brief: legacy_xor_encoded_amount - decode a legacy amount (8-byte encoding)
*   - little_endian(enc(a) XOR8 encoding_factor)
* param: encoded_amount - enc(a)
* param: encoding_factor - H32("amount", Hn(r K^v, t)))
* return: a
*/
rct::xmr_amount legacy_xor_encoded_amount(const rct::xmr_amount encoded_amount, const rct::key &encoding_factor);
/**
* brief: make_legacy_encoded_amount_v1 - make a legacy encoded amount with encoded amount mask (v1: 32 byte encodings)
*   - enc(x) = x + Hn(Hn(r_t K^v, t))
*   - enc(a) = to_key(little_endian(a)) + Hn(Hn(Hn(r_t K^v, t)))
* param: destination_viewkey - K^v
* param: tx_output_index - t
* param: enote_ephemeral_privkey - r_t
* param: amount_mask - x
* param: amount - a
* outparam: encoded_amount_blinding_factor_out - enc(x)
* outparam: encoded_amount_out - enc(a)
*/
void make_legacy_encoded_amount_v1(const rct::key &destination_viewkey,
    const std::uint64_t tx_output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    const crypto::secret_key &amount_mask,
    const rct::xmr_amount amount,
    rct::key &encoded_amount_blinding_factor_out,
    rct::key &encoded_amount_out);
/**
* brief: make_legacy_encoded_amount_v2 - make a legacy encoded amount (v2: 8-byte encoding) (note: mask is deterministic)
*   - enc(a) = a XOR8 H32("amount", Hn(r_t K^v, t))
* param: destination_viewkey - K^v
* param: tx_output_index - t
* param: enote_ephemeral_privkey - r_t
* param: amount - a
* outparam: encoded_amount_out - enc(a)
*/
void make_legacy_encoded_amount_v2(const rct::key &destination_viewkey,
    const std::uint64_t tx_output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    const rct::xmr_amount amount,
    rct::xmr_amount &encoded_amount_out);
/**
* brief: make_legacy_view_tag - make a legacy view tag
*   - view_tag = H1("view_tag", r_t K^v, t)
* param: destination_viewkey - K^v
* param: tx_output_index - t
* param: enote_ephemeral_privkey - r_t
* outparam: view_tag_out - H1("view_tag", r_t K^v, t)
*/
void make_legacy_view_tag(const rct::key &destination_viewkey,
    const std::uint64_t tx_output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    crypto::view_tag &view_tag_out);


} //namespace sp
