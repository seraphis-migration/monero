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

// Utilities for selecting tx inputs from an enote storage.

#pragma once

//local headers
#include "contextual_enote_record_types.h"
#include "ringct/rctTypes.h"
#include "tx_fee_calculator.h"
#include "tx_input_selection_output_context.h"

//third party headers
#include "boost/container/map.hpp"
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <unordered_map>

//forward declarations


namespace sp
{

enum class InputSelectionType
{
    LEGACY,
    SERAPHIS
};

using input_set_tracker_t =
    std::unordered_map<InputSelectionType, boost::container::multimap<rct::xmr_amount, ContextualRecordVariant>>;

class InputSelectorV1
{
public:
//destructor
    virtual ~InputSelectorV1() = default;

//overloaded operators
    /// disable copy/move (this is a pure virtual base class)
    InputSelectorV1& operator=(InputSelectorV1&&) = delete;

//member functions
    /// select an available input
    virtual bool try_select_input_candidate_v1(const boost::multiprecision::uint128_t desired_total_amount,
        const input_set_tracker_t &added_inputs,
        const input_set_tracker_t &candidate_inputs,
        ContextualRecordVariant &selected_input_out) const = 0;
};

/**
* brief: try_get_input_set_v1 - try to select a set of inputs for a tx
*   - This algorithm will fail to find a possible solution if there exist combinations that lead to 0-change successes,
*     but the combination that was found has non-zero change that doesn't cover the differential fee of adding a change
*     output (and there are no solutions that can cover that additional change output differential fee). Only an O(N!)
*     brute force search can find the success solution(s) to that problem (e.g. on complete failures you could fall-back
*     to brute force search on the 0-change case). However, that failure case will be extremely rare, so it probably
*     isn't worthwhile to implement a brute force fall-back.
*   - This algorithm includes a 'select range of inputs' trial pass that is implemented naively - only ranges of same-type
*     candidate inputs are considered. A no-fail algorithm would use brute force to test all possible combinations of
*     candiate inputs of different types. Brute force is O(N^2) instead of O(N) (for N = max inputs allowed), so it was
*     not implemented here for efficiency.
*       - The naive approach will have lower rates of false negatives as the proportion of seraphis to legacy enotes
*         increases.
* param: output_set_context -
* param: max_inputs_allowed -
* param: input_selector -
* param: fee_per_tx_weight -
* param: tx_fee_calculator -
* outparam: final_fee_out -
* outparam: input_set_out -
*/
bool try_get_input_set_v1(const OutputSetContextForInputSelection &output_set_context,
    const std::size_t max_inputs_allowed,
    const InputSelectorV1 &input_selector,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    rct::xmr_amount &final_fee_out,
    input_set_tracker_t &input_set_out);

} //namespace sp
