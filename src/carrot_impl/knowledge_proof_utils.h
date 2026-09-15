// Copyright (c) 2026, The Monero Project
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

//local headers
#include "address_device.h"
#include "knowledge_proof_types.h"
#include "output_opening_types.h"

//third party headers

//standard headers

//forward declarations

namespace carrot
{
/**
 * @brief Prove one-time address <-> key image association on generic output for hybrid account
 * @param opening_hint
 * @param addr_dev address device
 * @param s_view_balance_dev device for s_vb (optional)
 * @param k_view_incoming_dev device for k_v
 * @param account_privkey_g [legacy] k_s [carrot] k_gi
 * @param account_privkey_t [legacy] 0 [carrot] k_ps
 * @param[out] ki_proof_out key image association proof
 * @param[out] key_image_out key image
 */
void prove_key_image_proof(const OutputOpeningHintVariant &opening_hint,
    const address_device &addr_dev,
    const view_balance_secret_device *s_view_balance_dev,
    const view_incoming_key_device &k_view_incoming_dev,
    const crypto::secret_key &account_privkey_g,
    const crypto::secret_key &account_privkey_t,
    KeyImageProofVariant &ki_proof_out,
    crypto::key_image &key_image_out);
/**
 * @brief Validate a one-time address <-> key image association proof for a pre-Carrot output
 * @param onetime_address
 * @param key_image
 * @param ki_proof key image association proof
 * @return true iff association proof passes validation
 */
bool validate_ring_signature_key_image_proof(const crypto::public_key &onetime_address,
    const crypto::key_image &key_image,
    const crypto::signature &ki_proof);
/**
 * @brief Validate a one-time address <-> key image association proof (SA/L variant) for a Carrot output
 * @param onetime_address
 * @param use_biased_hash_to_point
 * @param key_image
 * @param ki_proof key image association proof
 * @return true iff association proof passes validation
 */
bool validate_fcmp_pp_sal_key_image_proof(const crypto::public_key &onetime_address,
    const bool use_biased_hash_to_point,
    const crypto::key_image &key_image,
    const fcmp_pp::FcmpPpSalProof &ki_proof);
/**
 * @brief Validate a one-time address <-> key image association proof for a generic output
 * @param onetime_address
 * @param use_biased_hash_to_point
 * @param key_image
 * @param ki_proof key image association proof
 * @return true iff association proof passes validation
 */
bool validate_key_image_proof(const crypto::public_key &onetime_address,
    const bool use_biased_hash_to_point,
    const crypto::key_image &key_image,
    const KeyImageProofVariant &ki_proof);
/**
 * @brief Encode key image association proof into a hex string
 * @param ki_proof key key image association proof
 * @return hex string representing `ki_proof`
 */
std::string key_image_proof_to_readable_string(const KeyImageProofVariant &ki_proof);
/**
 * @brief Decode key image association proof from a hex string
 * @param str hex string
 * @param[out] ki_proof_out key key image association proof
 * @return true iff hex string successfully decodes as a key image association proof
 */
bool try_key_image_proof_from_readable_string(const std::string &str, KeyImageProofVariant &ki_proof_out);
} //namespace carrot
