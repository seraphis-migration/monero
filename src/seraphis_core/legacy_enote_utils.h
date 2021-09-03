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

// Utilities for making legacy (cryptonote) enotes.
// These are not fully-featured.
// - does not support encrypted payment ids
// - does not support nuanced output creation rules (w.r.t. change outputs and subaddresses in txs with normal addresses)
// - only works for hw::device "default"
// Note: The legacy hash functions Hn(), Hx(), Hp() are built on the keccak hash function.

#pragma once

//local headers
#include "crypto/crypto.h"
#include "legacy_enote_types.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers

//forward declarations


namespace sp
{

/**
* brief: get_legacy_enote_identifier - identifier for legacy enotes (for handling enotes with duplicate onetime addresses)
*   identifier = H_32(Ko, a)
*   note: legacy enotes with identical Ko and a are assumed to be interchangeable
* param: onetime_address - Ko
* param: amount - a
* outparam: identifier_out - H_32(Ko, a)
*/
void get_legacy_enote_identifier(const rct::key &onetime_address, const rct::xmr_amount amount, rct::key &identifier_out);
/**
* brief: make_legacy_enote_v1 - make a v1 legacy enote sending to an address or subaddress
* param: destination_spendkey - [address: K^s = k^s G] [subaddress: K^{s,i} = (Hn(k^v, i) + k^s) G]
* param: destination_viewkey - [address: K^v = k^v G] [subaddress: K^{v,i} = k^v*(Hn(k^v, i) + k^s) G]
* param: amount - a
* param: output_index - t
* param: enote_ephemeral_privkey - [address: r] [subaddres: r_t]
* outparam: enote_out - [K^o, a]
*/
void make_legacy_enote_v1(const rct::key &destination_spendkey,
    const rct::key &destination_viewkey,
    const rct::xmr_amount amount,
    const std::uint64_t output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    LegacyEnoteV1 &enote_out);
/**
* brief: make_legacy_enote_v2 - make a v2 legacy enote sending to an address or subaddress
...
* outparam: enote_out - [K^o, C, enc(x), enc(a)]
*/
void make_legacy_enote_v2(const rct::key &destination_spendkey,
    const rct::key &destination_viewkey,
    const rct::xmr_amount amount,
    const std::uint64_t output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    LegacyEnoteV2 &enote_out);
/**
* brief: make_legacy_enote_v3 - make a v3 legacy enote sending to an address or subaddress
...
* outparam: enote_out - [K^o, C, enc(a)]
*/
void make_legacy_enote_v3(const rct::key &destination_spendkey,
    const rct::key &destination_viewkey,
    const rct::xmr_amount amount,
    const std::uint64_t output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    LegacyEnoteV3 &enote_out);
/**
* brief: make_legacy_enote_v4 - make a v4 legacy enote sending to an address or subaddress
...
* outparam: enote_out - [K^o, a, view_tag]
*/
void make_legacy_enote_v4(const rct::key &destination_spendkey,
    const rct::key &destination_viewkey,
    const rct::xmr_amount amount,
    const std::uint64_t output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    LegacyEnoteV4 &enote_out);
/**
* brief: make_legacy_enote_v5 - make a v5 legacy enote sending to an address or subaddress
...
* outparam: enote_out - [K^o, C, enc(a), view_tag]
*/
void make_legacy_enote_v5(const rct::key &destination_spendkey,
    const rct::key &destination_viewkey,
    const rct::xmr_amount amount,
    const std::uint64_t output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    LegacyEnoteV5 &enote_out);
/**
* brief: make_legacy_ephemeral_pubkey_shared - make an ephemeral pubkey for an enote (shared by all enotes in a tx)
* param: enote_ephemeral_privkey - r
* outparam: enote_ephemeral_pubkey_out - r G
*/
void make_legacy_ephemeral_pubkey_shared(const crypto::secret_key &enote_ephemeral_privkey,
    rct::key &enote_ephemeral_pubkey_out);
/**
* brief: make_legacy_ephemeral_pubkey_subaddress - make an ephemeral pubkey for a single enote in a tx
* param: destination_spendkey - [address: K^s = k^s G] [subaddress: K^{s,i} = (Hn(k^v, i) + k^s) G]
* param: enote_ephemeral_privkey - r_t
* outparam: enote_ephemeral_pubkey_out - r_t K^s
*/
void make_legacy_ephemeral_pubkey_single(const rct::key &destination_spendkey,
    const crypto::secret_key &enote_ephemeral_privkey,
    rct::key &enote_ephemeral_pubkey_out);

} //namespace sp
