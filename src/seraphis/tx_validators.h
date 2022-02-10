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

// Seraphis tx validator implementations
// NOT FOR PRODUCTION

#pragma once

//local headers
#include "ringct/rctTypes.h"
#include "tx_component_types.h"

//third party headers

//standard headers
#include <memory>
#include <vector>

//forward declarations
namespace sp { class LedgerContext; }


namespace sp
{

/// semantic validation config: component counts
struct SemanticConfigComponentCountsV1 final
{
    std::size_t m_min_inputs;
    std::size_t m_max_inputs;
    std::size_t m_min_outputs;
    std::size_t m_max_outputs;
};

/// semantic validation config: reference set size
struct SemanticConfigRefSetSizeV1 final
{
    std::size_t m_decom_n_min;
    std::size_t m_decom_n_max;
    std::size_t m_decom_m_min;
    std::size_t m_decom_m_max;
};

/**
* brief: validate_sp_semantics_component_counts_v1 - check tx component counts are valid
*   - num(membership proofs) == num(image proofs) == num(input images)
*   - num(outputs) >= 1
*   - num(range proofs) == num(input images) + num(outputs)
*   - num(enote pubkeys) == num(outputs)  // TODO: if (num(outputs) == 2), num(enote pubkeys) ?= 1
* 
*   - differences from v1:
*     - input image amount commitments also have range proofs
* param: config -
* param: num_input_images -
* param: num_membership_proofs -
* param: num_image_proofs -
* param: num_outputs -
* param: num_enote_pubkeys -
* param: num_range_proofs -
* return: true/false on validation result
*/
bool validate_sp_semantics_component_counts_v1(const SemanticConfigComponentCountsV1 &config,
    const std::size_t num_input_images,
    const std::size_t num_membership_proofs,
    const std::size_t num_image_proofs,
    const std::size_t num_outputs,
    const std::size_t num_enote_pubkeys,
    const std::size_t num_range_proofs);
/**
* brief: validate_sp_semantics_ref_set_size_v1 - check membership proofs have consistent reference set sizes
*   - num(refd enotes) == ref set size
* param: config
* param: membership_proofs -
* return: true/false on validation result
*/
bool validate_sp_semantics_ref_set_size_v1(const SemanticConfigRefSetSizeV1 &config,
    const std::vector<SpMembershipProofV1> &membership_proofs);
/**
* brief: validate_sp_semantics_input_images_v1 - check key images are well-formed
*   - key images are in the prime-order EC subgroup: l*KI == identity
*   - masked address and masked commitment are not identity
* param: input_images -
* return: true/false on validation result
*/
bool validate_sp_semantics_input_images_v1(const std::vector<SpEnoteImageV1> &input_images);
/**
* brief: validate_sp_semantics_sorting_v1 - check tx components are properly sorted
*   - membership proof referenced enote indices are sorted (ascending)
*   - input images sorted by key image with byte-wise comparisons (ascending)
*   - output enotes sorted by onetime addresses with byte-wise comparisons (ascending)
* param: membership_proofs -
* param: input_images -
* param: outputs -
* return: true/false on validation result
*/
bool validate_sp_semantics_sorting_v1(const std::vector<SpMembershipProofV1> &membership_proofs,
    const std::vector<SpEnoteImageV1> &input_images,
    const std::vector<SpEnoteV1> &outputs);
/**
* brief: validate_sp_linking_tags_v1 - check tx does not double spend
*   - no key image duplicates in ledger
*   - no key image duplicates in tx
* note: checking duplicates in tx pool could be embedded in the ledger context implementation
*       - e.g. derive from the main ledger context a 'tx pool and ledger context', then virtual overload the key image
*         check to also check the tx pool
* note2: similarly, when appending a block, you could have a derived ledger context that checks for in-block duplicates
* param: input_images -
* param: ledger_context -
* return: true/false on validation result
*/
bool validate_sp_linking_tags_v1(const std::vector<SpEnoteImageV1> &input_images, const LedgerContext &ledger_context);
/**
* brief: validate_sp_amount_balance_v1 - check that amounts balance in the tx (inputs = outputs)
*   - check BP+ range proofs on input image amount commitments and output commitments (e.g. for squashed enote model)
*     - do not check these if 'defer_batchable' is set; BP+ range proofs can be batch-verified
*   - check sum(input image masked commitments) == sum(output commitments) + remainder*G
* param: input_images -
* param: outputs -
* param: balance_proof -
* param: defer_batchable -
* return: true/false on validation result
*/
bool validate_sp_amount_balance_v1(const std::vector<SpEnoteImageV1> &input_images,
    const std::vector<SpEnoteV1> &outputs,
    const std::shared_ptr<const SpBalanceProofV1> balance_proof,
    const bool defer_batchable);
/**
* brief: validate_sp_membership_proofs_v1 - check that tx inputs exist in the ledger
*   - try to get referenced enotes from ledger in 'squashed enote' form (NOT txpool)
*   - check concise grootle proofs (membership proofs)
* param: membership_proofs -
* param: input_images -
* param: ledger_context -
* return: true/false on validation result
*/
bool validate_sp_membership_proofs_v1(const std::vector<const SpMembershipProofV1*> &membership_proofs,
    const std::vector<const SpEnoteImage*> &input_images,
    const LedgerContext &ledger_context);
/**
* brief: validate_sp_composition_proofs_v1 - check that spending tx inputs is authorized by their owners,
*        and key images are properly constructed
*   - check Seraphis composition proofs
* param: image_proofs -
* param: input_images -
* param: image_proofs_message -
* return: true/false on validation result
*/
bool validate_sp_composition_proofs_v1(const std::vector<SpImageProofV1> &image_proofs,
    const std::vector<SpEnoteImageV1> &input_images,
    const rct::key &image_proofs_message);

} //namespace sp
