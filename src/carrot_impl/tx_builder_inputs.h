// Copyright (c) 2024-2026, The Monero Project
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

/// @file Utilities for proving input information for Carrot transactions

#pragma once

//local headers
#include "address_device_hierarchies.h"
#include "fcmp_pp/fcmp_pp_types.h"
#include "output_opening_types.h"

//third party headers

//standard headers

//forward declarations
namespace carrot
{
struct RCTOutputEnoteProposal;
}

namespace carrot
{
/**
 * @brief Generate rerandomized outputs (with non-refundable r_o) for given inputs in input proposals
 * @param output_enote_proposals output enotes for spending tx, used to calculate r_c imbalance
 * @param input_proposals inputs for spending tx, used to extract (O, I, C) tuples and calculate r_c imbalance
 * @param addr_dev =
 * @param s_view_balance_dev -
 * @param k_view_incoming_dev -
 * @return Rerandomized inputs in order of `input_proposals`
 */
std::vector<FcmpRerandomizedOutputCompressed> generate_rerandomized_inputs_nonrefundable(
    epee::span<const carrot::RCTOutputEnoteProposal> output_enote_proposals,
    epee::span<const carrot::OutputOpeningHintVariant> input_proposals,
    const address_device &addr_dev,
    const carrot::view_balance_secret_device *s_view_balance_dev,
    const carrot::view_incoming_key_device &k_view_incoming_dev);
/**
 * @brief Verify that rerandomized output and openings are correctly calculated for given (O, C)
 * @param rerandomized_output -
 * @param onetime_address O
 * @param amount_commitment C
 * @param use_biased_hash_to_point -
 * @return true iff O~ = O + r_o T, I~ = Hp(O) + r_i U, R = r_i V + r_r_i T, and C~ = C + r_c G
 */
bool verify_rerandomized_output_basic(const FcmpRerandomizedOutputCompressed &rerandomized_output,
    const crypto::public_key &onetime_address,
    const amount_commitment_t &amount_commitment,
    const bool use_biased_hash_to_point);
/**
 * @brief Get full openings for one-time address O = x g + y T given account private keys
 * @param opening_hint -
 * @param addr_dev address device
 * @param s_view_balance_dev device for s_vb (optional)
 * @param k_view_incoming_dev device for k_v
 * @param account_privkey_g [legacy] k_s [carrot] k_gi
 * @param account_privkey_t [legacy] 0 [carrot] k_ps
 * @param[out] x_out x
 * @param[out] y_out y
 * @throw if scannot scan opening hint, or if full openings don't re-compute correctly
 */
void get_onetime_address_full_openings(const OutputOpeningHintVariant &opening_hint,
    const address_device &addr_dev,
    const view_balance_secret_device *s_view_balance_dev,
    const view_incoming_key_device &k_view_incoming_dev,
    const crypto::secret_key &account_privkey_g,
    const crypto::secret_key &account_privkey_t,
    crypto::secret_key &x_out,
    crypto::secret_key &y_out);
/**
 * @brief Prove FCMP++ SA/L signature for an enote addressed to legacy key hierarchy
 * @param signable_tx_hash FCMP++/Carrot v1 signable tx hash
 * @param rerandomized_output rerandomization of output represented by `opening_hint`
 * @param opening_hint -
 * @param k_spend k_s
 * @param addr_dev address device
 * @param[out] sal_proof_out FCMP++ SA/L sig authorizing spending said output in tx represented by `signable_tx_hash`
 * @param[out] key_image_out key image corresponding to the one-time address of `opening_hint`
 */
void make_sal_proof_any_to_legacy_v1(const crypto::hash &signable_tx_hash,
    const FcmpRerandomizedOutputCompressed &rerandomized_output,
    const OutputOpeningHintVariant &opening_hint,
    const crypto::secret_key &k_spend,
    const cryptonote_hierarchy_address_device &addr_dev,
    fcmp_pp::FcmpPpSalProof &sal_proof_out,
    crypto::key_image &key_image_out);
/**
 * @brief Prove FCMP++ SA/L signature for an enote addressed to new key hierarchy
 * @param signable_tx_hash FCMP++/Carrot v1 signable tx hash
 * @param rerandomized_output rerandomization of output represented by `opening_hint`
 * @param opening_hint -
 * @param k_prove_spend k_ps
 * @param k_generate_image k_gi
 * @param addr_dev address device
 * @param s_view_balance_dev device for s_vb
 * @param k_view_incoming_dev device for k_v
 * @param s_generate_address_dev device for s_ga
 * @param[out] sal_proof_out FCMP++ SA/L sig authorizing spending said output in tx represented by `signable_tx_hash`
 * @param[out] key_image_out key image corresponding to the one-time address of `opening_hint`
 */
void make_sal_proof_any_to_carrot_v1(const crypto::hash &signable_tx_hash,
    const FcmpRerandomizedOutputCompressed &rerandomized_output,
    const OutputOpeningHintVariant &opening_hint,
    const crypto::secret_key &k_prove_spend,
    const crypto::secret_key &k_generate_image,
    const address_device &addr_dev,
    const view_balance_secret_device &s_view_balance_dev,
    const view_incoming_key_device &k_view_incoming_dev,
    fcmp_pp::FcmpPpSalProof &sal_proof_out,
    crypto::key_image &key_image_out);
/**
 * @brief Prove FCMP++ SA/L signature for an enote addressed to hybrid key hierarchy
 * @param signable_tx_hash FCMP++/Carrot v1 signable tx hash
 * @param rerandomized_output rerandomization of output represented by `opening_hint`
 * @param opening_hint -
 * @param k_privkey_g [legacy] k_s [new] k_gi
 * @param k_privkey_t [legacy] 0 [new] k_ps
 * @param s_view_balance_dev device for s_vb (optional)
 * @param k_view_incoming_dev device for k_v (optional)
 * @param addr_dev address device
 * @param[out] sal_proof_out FCMP++ SA/L sig authorizing spending said output in tx represented by `signable_tx_hash`
 * @param[out] key_image_out key image corresponding to the one-time address of `opening_hint`
 */
void make_sal_proof_any_to_hybrid_v1(const crypto::hash &signable_tx_hash,
    const FcmpRerandomizedOutputCompressed &rerandomized_output,
    const OutputOpeningHintVariant &opening_hint,
    const crypto::secret_key &k_privkey_g,
    const crypto::secret_key &k_privkey_t,
    const view_balance_secret_device *s_view_balance_dev,
    const view_incoming_key_device &k_view_incoming_dev,
    const address_device &addr_dev,
    fcmp_pp::FcmpPpSalProof &sal_proof_out,
    crypto::key_image &key_image_out);

} //namespace carrot
