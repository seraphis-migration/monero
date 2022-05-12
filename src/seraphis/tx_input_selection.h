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

// Utilities for selecting tx inputs from an enote storage.


#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
#include "tx_builder_types.h"
#include "tx_enote_record_types.h"
#include "tx_fee_calculator.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <list>
#include <vector>

//forward declarations


namespace sp
{

class InputSelectorV1
{
public:
//constructors: default
//destructor
    virtual ~InputSelectorV1() = default;

//overloaded operators
    /// disable copy/move (this is a pure virtual base class)
    InputSelectorV1& operator=(InputSelectorV1&&) = delete;

//member functions
    /// select an available input
    virtual bool try_select_input_v1(const boost::multiprecision::uint128_t desired_total_amount,
        const std::list<SpContextualEnoteRecordV1> &already_added_inputs,
        const std::list<SpContextualEnoteRecordV1> &already_excluded_inputs,
        SpContextualEnoteRecordV1 &selected_input_out) const = 0;
};

//todo
bool try_get_input_set_v1(const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const std::vector<SpOutputProposalV1> &output_proposals,
    const std::size_t max_inputs_allowed,
    const InputSelectorV1 &input_selector,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    std::list<SpContextualEnoteRecordV1> &contextual_enote_records_out);

} //namespace sp
