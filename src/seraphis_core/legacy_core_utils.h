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

// Miscellaneous legacy utilities.
// Note: these are the bare minimum for unit testing and legacy enote recovery, so are not fully-featured.

#pragma once

//local headers
#include "crypto/crypto.h"
#include "cryptonote_basic/subaddress_index.h"
#include "device/device.hpp"
#include "jamtis_support_types.h"
#include "ringct/rctTypes.h"
#include "tx_extra.h"

//third party headers

//standard headers

//forward declarations


namespace sp
{

/**
* brief: make_legacy_subaddress_spendkey - make a legacy subaddress's spendkey
*   - K^{s,i} = (Hn(k^v, i) + k^s) G
*   - note: Hn(k^v, i) = Hn("SubAddr || k^v || index_major || index_minor)
* param: legacy_base_spend_pubkey - k^s G
* param: legacy_view_privkey - k^v
* param: subaddress_index - i
* inoutparam: hwdev -
* outparam: subaddress_spendkey_out - K^{s,i} = (Hn(k^v, i) + k^s) G
*/
void make_legacy_subaddress_spendkey(const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_view_privkey,
    const cryptonote::subaddress_index &subaddress_index,
    hw::device &hwdev,
    rct::key &subaddress_spendkey_out);
/**
* brief: make_legacy_sender_receiver_secret - make a legacy sender-receiver secret
*   - Hn([sender: r_t K^v] [recipient: k^v R_t], t)
* param: base_key - [sender: K^v] [recipient: R_t]
* param: tx_output_index - t
* param: DH_privkey - [sender: r_t] [recipient: k^v]
* inoutparam: hwdev -
* outparam: legacy_sender_receiver_secret_out - Hn([sender: r_t K^v] [recipient: k^v R_t], t)
*/
void make_legacy_sender_receiver_secret(const rct::key &base_key,
    const std::uint64_t tx_output_index,
    const crypto::secret_key &DH_privkey,
    hw::device &hwdev,
    crypto::secret_key &legacy_sender_receiver_secret_out);
/**
* brief: make_legacy_enote_view_extension - make a legacy enote's view extension
*   - component of onetime address privkey involving view key
*   - Hn(k^v R_t, t) + (IF subaddress enote owner THEN Hn(k^v, i) ELSE 0)
* param: tx_output_index - t
* param: sender_receiver_DH_derivation - k^v R_t
* param: legacy_view_privkey - k^v
* param: subaddress_index - optional(i)
* inoutparam: hwdev -
* outparam: enote_view_extension_out - Hn(k^v R_t, t) + (IF (i) THEN Hn(k^v, i) ELSE 0)
*/
void make_legacy_enote_view_extension(const std::uint64_t tx_output_index,
    const crypto::key_derivation &sender_receiver_DH_derivation,
    const crypto::secret_key &legacy_view_privkey,
    const boost::optional<cryptonote::subaddress_index> &subaddress_index,
    hw::device &hwdev,
    crypto::secret_key &enote_view_extension_out);
/**
* brief: make_legacy_onetime_address - make a legacy onetime address for the enote at index 't' in a tx's output set
*   - Ko_t = Hn(r_t K^v, t) G + K^s
* param: destination_spendkey - [normal address: k^s G] [subaddress: (Hn(k^v, i) + k^s) G]
* param: destination_viewkey - [normal address: k^v G] [subaddress: k^v K^{s,i}]
* param: tx_output_index - t
* param: enote_ephemeral_privkey - r_t  (note: r_t may be the same for all values of 't' if it is shared)
* inoutparam: hwdev -
* outparam: onetime_address_out - Ko_t
*/
void make_legacy_onetime_address(const rct::key &destination_spendkey,
    const rct::key &destination_viewkey,
    const std::uint64_t tx_output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    hw::device &hwdev,
    rct::key &onetime_address_out);
/**
* brief: make_legacy_key_image - make a legacy cryptonote-style key image
*   - KI = (k^{o,v} + k^s) * Hp(Ko)
*   - note: we pass Ko by value instead of computing it (Ko = (k^{o,v} + k^s) G) for performance reasons (even though
*     skipping that step is less robust)
* param: enote_view_extension - k^{o,v}
* param: legacy_spend_privkey - k^s
* param: onetime_address - Ko
* inoutparam: hwdev -
* outparam: key_image_out - KI = (k^{o,v} + k^s) * Hp(Ko)
*/
void make_legacy_key_image(const crypto::secret_key &enote_view_extension,
    const crypto::secret_key &legacy_spend_privkey,
    const rct::key &onetime_address,
    hw::device &hwdev,
    crypto::key_image &key_image_out);
/**
* brief: make_legacy_auxilliary_key_image_v1 - make a legacy cryptonote-style auxilliary key image (e.g. for use in a
*      CLSAG proof)
*   - KI_aux = z * Hp(Ko)
*   - note: in CLSAG proofs, the commitment to zero is computed as 'C - C_offset = z G', where 'C_offset = -z G + C'
* param: commitment_mask - (-z)
* param: onetime_address - Ko
* inoutparam: hwdev -
* outparam: auxilliary_key_image_out - z * Hp(Ko)
*/
void make_legacy_auxilliary_key_image_v1(const crypto::secret_key &commitment_mask,
    const rct::key &onetime_address,
    hw::device &hwdev,
    crypto::key_image &auxilliary_key_image_out);
/**
* brief: make_legacy_amount_blinding_factor_v2 - make a legacy amount blinding factor (v2 is deterministic, v1 is not)
*   - x = Hn("commitment_mask", Hn(r K^v, t))
* param: sender_receiver_secret - Hn(r K^v, t)
* inoutparam: hwdev -
* outparam: amount_blinding_factor_out - x = Hn("commitment_mask", Hn(r K^v, t))
*/
void make_legacy_amount_blinding_factor_v2(const crypto::secret_key &sender_receiver_secret,
    hw::device &hwdev,
    crypto::secret_key &amount_blinding_factor_out);
void make_legacy_amount_blinding_factor_v2(const rct::key &destination_viewkey,
    const std::uint64_t tx_output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    hw::device &hwdev,
    crypto::secret_key &amount_blinding_factor_out);
/**
* brief: make_legacy_encoded_amount_v1 - make a legacy encoded amount with encoded amount mask (v1: 32 byte encodings)
*   - enc(x) = x + Hn(Hn(r_t K^v, t))
*   - enc(a) = to_key(little_endian(a)) + Hn(Hn(Hn(r_t K^v, t)))
* param: destination_viewkey - K^v
* param: tx_output_index - t
* param: enote_ephemeral_privkey - r_t
* param: amount_mask - x
* param: amount - a
* inoutparam: hwdev -
* outparam: encoded_amount_blinding_factor_out - enc(x)
* outparam: encoded_amount_out - enc(a)
*/
void make_legacy_encoded_amount_v1(const rct::key &destination_viewkey,
    const std::uint64_t tx_output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    const crypto::secret_key &amount_mask,
    const rct::xmr_amount amount,
    hw::device &hwdev,
    rct::key &encoded_amount_blinding_factor_out,
    rct::key &encoded_amount_out);
/**
* brief: make_legacy_encoded_amount_v2 - make a legacy encoded amount (v2: 8-byte encoding) (note: mask is deterministic)
*   - enc(a) = a XOR_8 H32("amount", Hn(r_t K^v, t))
* param: destination_viewkey - K^v
* param: tx_output_index - t
* param: enote_ephemeral_privkey - r_t
* param: amount - a
* inoutparam: hwdev -
* outparam: encoded_amount_out - enc(a)
*/
void make_legacy_encoded_amount_v2(const rct::key &destination_viewkey,
    const std::uint64_t tx_output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    const rct::xmr_amount amount,
    hw::device &hwdev,
    jamtis::encoded_amount_t &encoded_amount_out);
/**
* brief: try_get_legacy_amount_v1 - try to decode a legacy encoded amount (v1: 32-byte encoding)
*   - fails if amount commitment can't be reproduced
*   - x = enc(x) - Hn(Hn(r K^v, t))
*   - a = system_endian(trunc_8(enc(a) - Hn(Hn(Hn(r K^v, t)))))
* param: expected_amount_commitment - C' = x G + a H
* param: sender_receiver_secret - Hn(r_t K^v, t)
* param: encoded_amount_blinding_factor - enc(x)
* param: encoded_amount - enc(a)
* inoutparam: hwdev -
* outparam: amount_blinding_factor_out - x
* outparam: amount_out - a
* return: true if amount was successfully recovered
*/
bool try_get_legacy_amount_v1(const rct::key &expected_amount_commitment,
    const crypto::secret_key &sender_receiver_secret,
    const rct::key &encoded_amount_blinding_factor,
    const rct::key &encoded_amount,
    hw::device &hwdev,
    crypto::secret_key &amount_blinding_factor_out,
    rct::xmr_amount &amount_out);
bool try_get_legacy_amount_v1(const rct::key &expected_amount_commitment,
    const rct::key &destination_viewkey,
    const std::uint64_t tx_output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    const rct::key &encoded_amount_blinding_factor,
    const rct::key &encoded_amount,
    hw::device &hwdev,
    crypto::secret_key &amount_blinding_factor_out,
    rct::xmr_amount &amount_out);
/**
* brief: try_get_legacy_amount_v2 - try to decode a legacy encoded amount (v2: 8-byte encoding) (mask is deterministic)
*   - fails if amount commitment can't be reproduced
*   - x = Hn("commitment_mask", Hn(r K^v, t))
*   - a = enc(a) XOR_8 H32("amount", Hn(r K^v, t))
* param: expected_amount_commitment - C' = x G + a H
* param: sender_receiver_secret - Hn(r_t K^v, t)
* param: encoded_amount - enc(a)
* inoutparam: hwdev -
* outparam: amount_blinding_factor_out - x
* outparam: amount_out - a
* return: true if amount was successfully recovered
*/
bool try_get_legacy_amount_v2(const rct::key &expected_amount_commitment,
    const crypto::secret_key &sender_receiver_secret,
    const jamtis::encoded_amount_t &encoded_amount,
    hw::device &hwdev,
    crypto::secret_key &amount_blinding_factor_out,
    rct::xmr_amount &amount_out);
bool try_get_legacy_amount_v2(const rct::key &expected_amount_commitment,
    const rct::key &destination_viewkey,
    const std::uint64_t tx_output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    const jamtis::encoded_amount_t &encoded_amount,
    hw::device &hwdev,
    crypto::secret_key &amount_blinding_factor_out,
    rct::xmr_amount &amount_out);
/**
* brief: make_legacy_view_tag - make a legacy view tag
*   - view_tag = H1("view_tag", r_t K^v, t)
* param: destination_viewkey - K^v
* param: tx_output_index - t
* param: enote_ephemeral_privkey - r_t
* inoutparam: hwdev -
* outparam: view_tag_out - H1("view_tag", r_t K^v, t)
*/
void make_legacy_view_tag(const rct::key &destination_viewkey,
    const std::uint64_t tx_output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    hw::device &hwdev,
    crypto::view_tag &view_tag_out);
/**
* brief: try_append_legacy_enote_ephemeral_pubkeys_to_tx_extra - try to add legacy enote ephemeral pubkeys to a tx extra
* param: enote_ephemeral_pubkeys - {R_t}
* outparam: tx_extra_inout - the tx extra to append to
*/
bool try_append_legacy_enote_ephemeral_pubkeys_to_tx_extra(const std::vector<rct::key> &enote_ephemeral_pubkeys,
    TxExtra &tx_extra_inout);
/**
* brief: extract_legacy_enote_ephemeral_pubkeys_from_tx_extra - find legacy enote ephemeral pubkeys in a tx extra field
* param: tx_extra - memo field (byte vector)
* outparam: legacy_main_enote_ephemeral_pubkey_out - r G  (this should always be present, because yucky legacy tx gen code)
* outparam: legacy_additional_enote_ephemeral_pubkeys_out - [empty if no subaddress destinations]
*                                                           [otherwise r_0 K^v_0, ..., r_n K^v_n]
*/
void extract_legacy_enote_ephemeral_pubkeys_from_tx_extra(const TxExtra &tx_extra,
    crypto::public_key &legacy_main_enote_ephemeral_pubkey_out,
    std::vector<crypto::public_key> &legacy_additional_enote_ephemeral_pubkeys_out);

} //namespace sp
