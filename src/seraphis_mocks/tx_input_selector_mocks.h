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

// NOT FOR PRODUCTION

// Utilities for selecting tx inputs from an enote storage (mock-ups for unit testing).

#pragma once

//local headers
#include "enote_store_mock_simple_v1.h"
#include "seraphis_impl/enote_store.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/tx_input_selection.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers

//forward declarations


namespace sp
{
namespace mocks
{

/// simple input selector
/// - select the next available input in the enote store (input selection with this is not thread-safe)
class InputSelectorMockSimpleV1 final : public InputSelectorV1
{
public:
//constructors
    /// normal constructor
    InputSelectorMockSimpleV1(const SpEnoteStoreMockSimpleV1 &enote_store) :
        m_enote_store{enote_store}
    {
        // in practice, lock the enote store with an 'input selection' mutex here for thread-safe input selection that
        //   prevents two tx attempts from using the same inputs (take a reader-writer lock when selecting an input)
    }

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    InputSelectorMockSimpleV1& operator=(InputSelectorMockSimpleV1&&) = delete;

//member functions
    /// select the next available input
    bool try_select_input_candidate_v1(const boost::multiprecision::uint128_t desired_total_amount,
        const input_set_tracker_t &added_inputs,
        const input_set_tracker_t &candidate_inputs,
        ContextualRecordVariant &selected_input_out) const override;

//member variables
private:
    /// read-only reference to an enote storage
    const SpEnoteStoreMockSimpleV1 &m_enote_store;
};

/// mock input selector
/// - select a pseudo-random available input in the enote store (input selection with this is not thread-safe)
class InputSelectorMockV1 final : public InputSelectorV1
{
public:
//constructors
    /// normal constructor
    InputSelectorMockV1(const SpEnoteStore &enote_store) :
        m_enote_store{enote_store}
    {
        // in practice, lock the enote store with an 'input selection' mutex here for thread-safe input selection that
        //   prevents two tx attempts from using the same inputs (take a reader-writer lock when selecting an input)
    }

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    InputSelectorMockV1& operator=(InputSelectorMockV1&&) = delete;

//member functions
    /// select the next available input
    /// NOTE: this is a mock-up; a real input selector would contain many complicated mechanisms, e.g. the option to ignore
    ///       locked enotes, heuristics to avoid input timing correlations, etc.
    bool try_select_input_candidate_v1(const boost::multiprecision::uint128_t desired_total_amount,
        const input_set_tracker_t &added_inputs,
        const input_set_tracker_t &candidate_inputs,
        ContextualRecordVariant &selected_input_out) const override;

//member variables
private:
    /// read-only reference to an enote storage
    const SpEnoteStore &m_enote_store;
};

} //namespace mocks
} //namespace sp
