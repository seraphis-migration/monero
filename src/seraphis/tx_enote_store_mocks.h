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

//todo


#pragma once

//local headers
#include "crypto/crypto.h"
#include "tx_enote_record_types.h"
#include "tx_enote_record_utils.h"
#include "tx_enote_store.h"

//third party headers

//standard headers
#include <list>
#include <unordered_map>

//forward declarations


namespace sp
{

////
// SpEnoteStoreMockSimpleV1
///
class SpEnoteStoreMockSimpleV1 final : public SpEnoteStoreV1
{
    friend class InputSelectorMockSimpleV1;

public:
    /// add a record
    void add_record(const SpContextualEnoteRecordV1 &new_record) override
    {
        m_contextual_enote_records.emplace_back(new_record);
    }

//member variables
protected:
    /// the enotes
    std::list<SpContextualEnoteRecordV1> m_contextual_enote_records;
};

////
// SpEnoteStoreMockV1
///
class SpEnoteStoreMockV1 final : public SpEnoteStoreV1
{
    friend class InputSelectorMockV1;

public:
    /// add a record
    void add_record(const SpContextualEnoteRecordV1 &new_record) override
    {
        crypto::key_image record_key_image;
        new_record.get_key_image(record_key_image);

        // add the record or update an existing record's contexts
        if (m_mapped_contextual_enote_records.find(record_key_image) == m_mapped_contextual_enote_records.end())
        {
            m_mapped_contextual_enote_records[record_key_image] = new_record;
        }
        else
        {
            update_contextual_enote_record_contexts_v1(new_record, m_mapped_contextual_enote_records[record_key_image]);
        }
    }

//member variables
protected:
    /// the enotes
    std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> m_mapped_contextual_enote_records;
};

} //namespace sp
