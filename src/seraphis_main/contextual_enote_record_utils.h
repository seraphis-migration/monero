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

// Utilities for interacting with contextual enote records.

#pragma once

//local headers
#include "contextual_enote_record_types.h"
#include "ringct/rctTypes.h"
#include "tx_input_selection.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <functional>
#include <unordered_set>
#include <vector>

//forward declarations


namespace sp
{

/**
* brief: onchain_legacy_enote_is_locked - check if an on-chain legacy enote is locked (can't be spent)
* param: enote_origin_block_index -
* param: enote_unlock_time -
* param: top_block_index -
* param: default_spendable_age -
* param: current_time -
* return: true if the enote is locked
*/
bool onchain_legacy_enote_is_locked(const std::uint64_t enote_origin_block_index,
    const std::uint64_t enote_unlock_time,
    const std::uint64_t top_block_index,
    const std::uint64_t default_spendable_age,
    const std::uint64_t current_time);
/**
* brief: onchain_sp_enote_is_locked - check if an on-chain seraphis enote is locked (can't be spent)
* param: enote_origin_block_index -
* param: top_block_index -
* param: default_spendable_age -
* return: true if the enote is locked
*/
bool onchain_sp_enote_is_locked(const std::uint64_t enote_origin_block_index,
    const std::uint64_t top_block_index,
    const std::uint64_t default_spendable_age);
/**
* brief: legacy_enote_has_highest_amount_in_set - check if a specified legacy enote has the highest amount in
*   a set of legacy enotes (e.g. a set of legacy enotes with the same onetime address)
*   - note: it is fine if identifiers in the set have the same amount
* param: specified_enote_identifier -
* param: specified_enote_amount -
* param: allowed_origin_statuses -
* param: enote_identifier_set -
* param: get_record_origin_status_for_identifier_func - return an origin status associated with a specified identifier
* param: get_record_amount_for_identifier_func - return an amount associated with a specified identifier
* return: true if the specified legacy enote has the highest amount in the requested set
*/
bool legacy_enote_has_highest_amount_in_set(const rct::key &specified_enote_identifier,
    const rct::xmr_amount specified_enote_amount,
    const std::unordered_set<SpEnoteOriginStatus> &allowed_origin_statuses,
    const std::unordered_set<rct::key> &enote_identifier_set,
    const std::function<const SpEnoteOriginStatus&(const rct::key&)> &get_record_origin_status_for_identifier_func,
    const std::function<rct::xmr_amount(const rct::key&)> &get_record_amount_for_identifier_func);
/**
* brief: split_selected_input_set - split an input set tracker into legacy and seraphis contextual records
* param: input_set -
* outparam: legacy_contextual_records_out -
* outparam: sp_contextual_records_out -
*/
void split_selected_input_set(const input_set_tracker_t &input_set,
    std::vector<LegacyContextualEnoteRecordV1> &legacy_contextual_records_out,
    std::vector<SpContextualEnoteRecordV1> &sp_contextual_records_out);
/**
* brief: total_amount - get the total amount in a set of contextual records
* param: contextual_records -
* return: the sum of amounts in the records
*/
boost::multiprecision::uint128_t total_amount(const std::vector<LegacyContextualEnoteRecordV1> &contextual_records);
boost::multiprecision::uint128_t total_amount(const std::vector<SpContextualEnoteRecordV1> &contextual_records);
/**
* brief: try_get_membership_proof_real_reference_mappings - map a set of records' key images to the on-chain enote indices
*   of those records' enotes (useful for when making membership proofs)
* param: contextual_records -
* outparam: enote_ledger_mappings_out -
*/
bool try_get_membership_proof_real_reference_mappings(const std::vector<LegacyContextualEnoteRecordV1> &contextual_records,
    std::unordered_map<crypto::key_image, std::uint64_t> &enote_ledger_mappings_out);
bool try_get_membership_proof_real_reference_mappings(const std::vector<SpContextualEnoteRecordV1> &contextual_records,
    std::unordered_map<crypto::key_image, std::uint64_t> &enote_ledger_mappings_out);
/**
* brief: try_update_enote_origin_context_v1 - try to update an origin context with another origin context
*   - only update our origin context if the fresh context is 'older than' our origin context
* param: fresh_origin_context -
* inoutparam: current_origin_context_inout -
*/
bool try_update_enote_origin_context_v1(const SpEnoteOriginContextV1 &fresh_origin_context,
    SpEnoteOriginContextV1 &current_origin_context_inout);
/**
* brief: try_update_enote_spent_context_v1 - try to update a spent context with another spent context
*   - only update our spent context if the fresh context is 'older than' our spent context
* param: fresh_spent_context -
* inoutparam: current_spent_context_inout -
*/
bool try_update_enote_spent_context_v1(const SpEnoteSpentContextV1 &fresh_spent_context,
    SpEnoteSpentContextV1 &current_spent_context_inout);
/**
* brief: try_update_contextual_enote_record_spent_context_v1 - try to update the spent context of a contextual record
*   with the spent context of a contextual key image set if the record's key image exists in that set
* param: contextual_key_image_set -
* inoutparam: contextual_enote_record_inout -
*/
bool try_update_contextual_enote_record_spent_context_v1(const SpContextualKeyImageSetV1 &contextual_key_image_set,
    SpContextualEnoteRecordV1 &contextual_enote_record_inout);
/**
* brief: origin_status_from_spent_status_v1 - infer an origin status from a spent status
*   - i.e. if an enote is spent on-chain, then it must originate on-chain
* param: spent_status -
* return: inferred origin status
*/
SpEnoteOriginStatus origin_status_from_spent_status_v1(const SpEnoteSpentStatus spent_status);
/**
* brief: try_bump_enote_record_origin_status_v1 - 'bump up' an origin status if lower than the origin status inferred from
*   an associated spent status
* param: spent_status -
* inoutparam: origin_status_inout -
*/
bool try_bump_enote_record_origin_status_v1(const SpEnoteSpentStatus spent_status,
    SpEnoteOriginStatus &origin_status_inout);
/**
* brief: update_contextual_enote_record_contexts_v1 - update a pair of origin/spent contexts with new contexts
* param: new_origin_context -
* param: new_spent_context -
* inoutparam: origin_context_inout -
* inoutparam: spent_context_inout -
*/
void update_contextual_enote_record_contexts_v1(const SpEnoteOriginContextV1 &new_origin_context,
    const SpEnoteSpentContextV1 &new_spent_context,
    SpEnoteOriginContextV1 &origin_context_inout,
    SpEnoteSpentContextV1 &spent_context_inout);
void update_contextual_enote_record_contexts_v1(const SpContextualEnoteRecordV1 &fresh_record,
    SpContextualEnoteRecordV1 &existing_record_inout);

} //namespace sp
