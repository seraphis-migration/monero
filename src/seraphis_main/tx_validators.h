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

// Seraphis tx validator implementations.

#pragma once

//local headers
#include "crypto/x25519.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/discretized_fee.h"
#include "seraphis_core/tx_extra.h"
#include "tx_component_types.h"
#include "tx_component_types_legacy.h"

//third party headers

//standard headers
#include <list>
#include <vector>

//forward declarations
namespace sp
{
    class SpMultiexpBuilder;
    class TxValidationContext;
}

namespace sp
{

/// semantic validation config: component counts
struct SemanticConfigCoinbaseComponentCountsV1 final
{
    std::size_t min_outputs;
    std::size_t max_outputs;
};

/// semantic validation config: component counts
struct SemanticConfigComponentCountsV1 final
{
    std::size_t min_inputs;
    std::size_t max_inputs;
    std::size_t min_outputs;
    std::size_t max_outputs;
};

/// semantic validation config: legacy reference sets
struct SemanticConfigLegacyRefSetV1 final
{
    std::size_t ring_size_min;
    std::size_t ring_size_max;
};

/// semantic validation config: seraphis reference sets
struct SemanticConfigSpRefSetV1 final
{
    std::size_t decomp_n_min;
    std::size_t decomp_n_max;
    std::size_t decomp_m_min;
    std::size_t decomp_m_max;
    std::size_t bin_radius_min;
    std::size_t bin_radius_max;
    std::size_t num_bin_members_min;
    std::size_t num_bin_members_max;
};

/**
* brief: validate_sp_semantics_coinbase_component_counts_v1 - check coinbase tx component counts are valid
*   - min_outputs <= num(outputs) <= max_outputs
*   - num(enote pubkeys) == num(outputs)
*
* param: config -
* param: num_outputs -
* param: num_enote_pubkeys -
* return: true/false on validation result
*/
bool validate_sp_semantics_coinbase_component_counts_v1(const SemanticConfigCoinbaseComponentCountsV1 &config,
    const std::size_t num_outputs,
    const std::size_t num_enote_pubkeys);
/**
* brief: validate_sp_semantics_component_counts_v1 - check tx component counts are valid
*   - min_inputs <= num(legacy and seraphis input images) <= max_inputs
*   - num(legacy ring signatures) == num(legacy input images)
*   - num(seraphis membership proofs) == num(seraphis image proofs) == num(seraphis input images)
*   - min_outputs <= num(outputs) <= max_outputs
*   - num(range proofs) == num(seraphis input images) + num(outputs)
*   - if (num(outputs) == 2), num(enote pubkeys) == 1, else num(enote pubkeys) == num(outputs)
*
* param: config -
* param: num_legacy_input_images -
* param: num_sp_input_images -
* param: num_legacy_ring_signatures -
* param: num_sp_membership_proofs -
* param: num_sp_image_proofs -
* param: num_outputs -
* param: num_enote_pubkeys -
* param: num_range_proofs -
* return: true/false on validation result
*/
bool validate_sp_semantics_component_counts_v1(const SemanticConfigComponentCountsV1 &config,
    const std::size_t num_legacy_input_images,
    const std::size_t num_sp_input_images,
    const std::size_t num_legacy_ring_signatures,
    const std::size_t num_sp_membership_proofs,
    const std::size_t num_sp_image_proofs,
    const std::size_t num_outputs,
    const std::size_t num_enote_pubkeys,
    const std::size_t num_range_proofs);
/**
* brief: validate_sp_semantics_legacy_reference_sets_v1 - check legacy ring signatures have consistent and
*   valid reference sets
*   - ring_size_min <= ring_size <= ring_size_max
*   - CLSAG proof matches the stored ring member indices
* param: config
* param: legacy_ring_signatures -
* return: true/false on validation result
*/
bool validate_sp_semantics_legacy_reference_sets_v1(const SemanticConfigLegacyRefSetV1 &config,
    const std::vector<LegacyRingSignatureV4> &legacy_ring_signatures);
/**
* brief: validate_sp_semantics_sp_reference_sets_v1 - check seraphis membership proofs have consistent and
*   valid reference sets
*   - decomp_n_min <= decomp_n <= decom_n_max
*   - decomp_m_min <= decomp_m <= decom_m_max
*   - bin_radius_min <= bin_radius <= bin_radius_max
*   - num_bin_members_min <= num_bin_members <= num_bin_members_max
*   - ref set size from decomposition == ref set size from binned reference set
* param: config
* param: sp_membership_proofs -
* return: true/false on validation result
*/
bool validate_sp_semantics_sp_reference_sets_v1(const SemanticConfigSpRefSetV1 &config,
    const std::vector<SpMembershipProofV1> &sp_membership_proofs);
/**
* brief: validate_sp_semantics_output_serialization_v1 - check output enotes are properly serialized
*   - onetime addresses are deserializable (note: amount commitment serialization is checked in the balance proof)
* param: output_enotes -
* return: true/false on validation result
*/
bool validate_sp_semantics_output_serialization_v1(const std::vector<SpCoinbaseEnoteV1> &output_enotes);
bool validate_sp_semantics_output_serialization_v2(const std::vector<SpEnoteV1> &output_enotes);
/**
* brief: validate_sp_semantics_input_images_v1 - check input images are well-formed
*   - key images are in the prime-order EC subgroup: l*KI == identity
*   - key images, masked addresses, and masked commitments are not identity
* param: legacy_input_images -
* param: sp_input_images -
* return: true/false on validation result
*/
bool validate_sp_semantics_input_images_v1(const std::vector<LegacyEnoteImageV2> &legacy_input_images,
    const std::vector<SpEnoteImageV1> &sp_input_images);
/**
* brief: validate_sp_semantics_coinbase_layout_v1 - check coinbase tx components have the proper layout
*   - output enotes sorted by onetime addresses with byte-wise comparisons (ascending)
*   - onetime addresses are all unique
*   - enote ephemeral pubkeys are unique
*   - extra field is in sorted TLV (Type-Length-Value) format
* param: outputs -
* param: enote_ephemeral_pubkeys -
* param: tx_extra -
* return: true/false on validation result
*/
bool validate_sp_semantics_coinbase_layout_v1(const std::vector<SpCoinbaseEnoteV1> &outputs,
    const std::vector<crypto::x25519_pubkey> &enote_ephemeral_pubkeys,
    const TxExtra &tx_extra);
/**
* brief: validate_sp_semantics_layout_v1 - check tx components have the proper layout
*   - legacy reference sets are sorted (ascending)
*   - legacy reference set indices are unique
*   - seraphis membership proof binned reference set bins are sorted (ascending)
*   - legacy input images sorted by key image with byte-wise comparisons (ascending)
*   - seraphis input images sorted by key image with byte-wise comparisons (ascending)
*   - legacy and seraphis input key images are all unique
*   - output enotes sorted by onetime addresses with byte-wise comparisons (ascending)
*   - onetime addresses are all unique
*   - enote ephemeral pubkeys are unique
*   - extra field is in sorted TLV (Type-Length-Value) format
* param: legacy_ring_signatures -
* param: sp_membership_proofs -
* param: legacy_input_images -
* param: sp_input_images -
* param: outputs -
* param: enote_ephemeral_pubkeys -
* param: tx_extra -
* return: true/false on validation result
*/
bool validate_sp_semantics_layout_v1(const std::vector<LegacyRingSignatureV4> &legacy_ring_signatures,
    const std::vector<SpMembershipProofV1> &sp_membership_proofs,
    const std::vector<LegacyEnoteImageV2> &legacy_input_images,
    const std::vector<SpEnoteImageV1> &sp_input_images,
    const std::vector<SpEnoteV1> &outputs,
    const std::vector<crypto::x25519_pubkey> &enote_ephemeral_pubkeys,
    const TxExtra &tx_extra);
/**
* brief: validate_sp_semantics_fee_v1 - check that a discretized fee is a valid fee representation
* param: discretized_transaction_fee
* return: true/false on validation result
*/
bool validate_sp_semantics_fee_v1(const DiscretizedFee discretized_transaction_fee);
/**
* brief: validate_sp_key_images_v1 - check tx does not double spend
*   - no key image duplicates in ledger
* param: legacy_input_images -
* param: sp_input_images -
* param: tx_validation_context -
* return: true/false on validation result
*/
bool validate_sp_key_images_v1(const std::vector<LegacyEnoteImageV2> &legacy_input_images,
    const std::vector<SpEnoteImageV1> &sp_input_images,
    const TxValidationContext &tx_validation_context);
/**
* brief: validate_sp_coinbase_amount_balance_v1 - check that amounts balance in the coinbase tx (block reward == outputs)
*   - check block_reward == sum(output amounts)
* param: block_reward -
* param: outputs -
* return: true/false on validation result
*/
bool validate_sp_coinbase_amount_balance_v1(const rct::xmr_amount block_reward,
    const std::vector<SpCoinbaseEnoteV1> &outputs);
/**
* brief: validate_sp_amount_balance_v1 - check that amounts balance in the tx (inputs == outputs)
*   - check sum(input image masked commitments) == sum(output commitments) + fee*H + remainder*G
*   - note: BP+ verification is NOT done here (deferred for batch-verification)
* param: legacy_input_images -
* param: sp_input_images -
* param: outputs -
* param: discretized_transaction_fee -
* param: balance_proof -
* return: true/false on validation result
*/
bool validate_sp_amount_balance_v1(const std::vector<LegacyEnoteImageV2> &legacy_input_images,
    const std::vector<SpEnoteImageV1> &sp_input_images,
    const std::vector<SpEnoteV1> &outputs,
    const DiscretizedFee discretized_transaction_fee,
    const SpBalanceProofV1 &balance_proof);
/**
* brief: validate_sp_composition_proofs_v1 - check that spending legacy tx inputs is authorized by their owners,
*   key images are properly constructed, and the legacy inputs exist in the ledger
*   - check legacy CLSAG proofs
* param: legacy_ring_signatures -
* param: legacy_input_images -
* param: tx_proposal_prefix -
* param: tx_validation_context -
* return: true/false on validation result
*/
bool validate_sp_legacy_input_proofs_v1(const std::vector<LegacyRingSignatureV4> &legacy_ring_signatures,
    const std::vector<LegacyEnoteImageV2> &legacy_input_images,
    const rct::key &tx_proposal_prefix,
    const TxValidationContext &tx_validation_context);
/**
* brief: validate_sp_composition_proofs_v1 - check that spending seraphis tx inputs is authorized by their owners,
*   and that key images are properly constructed
*   - check seraphis composition proofs
* param: sp_image_proofs -
* param: sp_input_images -
* param: tx_proposal_prefix -
* return: true/false on validation result
*/
bool validate_sp_composition_proofs_v1(const std::vector<SpImageProofV1> &sp_image_proofs,
    const std::vector<SpEnoteImageV1> &sp_input_images,
    const rct::key &tx_proposal_prefix);
/**
* brief: try_get_sp_membership_proofs_v1_validation_data - get verification data to verify that seraphis tx inputs
*   exist in the ledger
*   - try to get referenced enotes from the ledger in 'squashed enote' form
*   - get verification data for grootle proofs (membership proofs)
* param: membership_proofs -
* param: input_images -
* param: tx_validation_context -
* outparam: validation_data_out -
*/
bool try_get_sp_membership_proofs_v1_validation_data(const std::vector<const SpMembershipProofV1*> &membership_proofs,
    const std::vector<const SpEnoteImageCore*> &input_images,
    const TxValidationContext &tx_validation_context,
    std::list<SpMultiexpBuilder> &validation_data_out);

} //namespace sp
