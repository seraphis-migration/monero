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

// Simple mock enote store that just stores enote records.

#pragma once

//local headers
#include "crypto/crypto.h"
#include "seraphis_main/contextual_enote_record_types.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <list>

//forward declarations


namespace sp
{
namespace mocks
{

////
// SpEnoteStoreMockSimpleV1
// - records are stored in the order they are added (useful for deterministic input selection for unit tests)
///
class SpEnoteStoreMockSimpleV1 final
{
    friend class InputSelectorMockSimpleV1;

public:
    /// add a record
    void add_record(const LegacyContextualEnoteRecordV1 &new_record);
    void add_record(const SpContextualEnoteRecordV1 &new_record);

//member variables
protected:
    /// legacy enotes
    std::list<LegacyContextualEnoteRecordV1> m_legacy_contextual_enote_records;
    /// seraphis enotes
    std::list<SpContextualEnoteRecordV1> m_sp_contextual_enote_records;
};

} //namespace mocks
} //namespace sp
