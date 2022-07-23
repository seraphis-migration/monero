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

//paired header
#include "tx_contextual_enote_record_utils.h"

//local headers
#include "crypto/crypto.h"
#include "tx_contextual_enote_record_types.h"

//third party headers

//standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
bool try_update_enote_origin_context_v1(const SpEnoteOriginContextV1 &origin_context,
    SpEnoteOriginContextV1 &current_origin_context_inout)
{
    // note: overwrite the context if the status is equal (in case existing context is incomplete)
    if (origin_context.m_origin_status < current_origin_context_inout.m_origin_status)
        return false;

    current_origin_context_inout = origin_context;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_update_enote_spent_context_v1(const SpEnoteSpentContextV1 &spent_context,
    SpEnoteSpentContextV1 &current_spent_context_inout)
{
    // note: overwrite the context if the status is equal (in case existing context is incomplete)
    if (spent_context.m_spent_status < current_spent_context_inout.m_spent_status)
        return false;

    current_spent_context_inout = spent_context;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_update_contextual_enote_record_spent_context_v1(const SpContextualKeyImageSetV1 &contextual_key_image_set,
    SpContextualEnoteRecordV1 &contextual_enote_record_inout)
{
    crypto::key_image record_key_image;
    contextual_enote_record_inout.get_key_image(record_key_image);

    if (!contextual_key_image_set.has_key_image(record_key_image))
        return false;

    return try_update_enote_spent_context_v1(contextual_key_image_set.m_spent_context,
        contextual_enote_record_inout.m_spent_context);
}
//-------------------------------------------------------------------------------------------------------------------
SpEnoteOriginStatus origin_status_from_spent_status_v1(const SpEnoteSpentStatus spent_status)
{
    switch (spent_status)
    {
        case (SpEnoteSpentStatus::UNSPENT) :
            return SpEnoteOriginStatus::OFFCHAIN;

        case (SpEnoteSpentStatus::SPENT_OFFCHAIN) :
            return SpEnoteOriginStatus::OFFCHAIN;

        case (SpEnoteSpentStatus::SPENT_UNCONFIRMED) :
            return SpEnoteOriginStatus::UNCONFIRMED;

        case (SpEnoteSpentStatus::SPENT_ONCHAIN) :
            return SpEnoteOriginStatus::ONCHAIN;

        default :
            return SpEnoteOriginStatus::OFFCHAIN;
    }
}
//-------------------------------------------------------------------------------------------------------------------
bool try_bump_enote_record_origin_status_v1(const SpEnoteSpentStatus spent_status,
    SpEnoteOriginStatus &origin_status_inout)
{
    const SpEnoteOriginStatus implied_origin_status{origin_status_from_spent_status_v1(spent_status)};

    if (origin_status_inout > implied_origin_status)
        return false;

    origin_status_inout = implied_origin_status;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void update_contextual_enote_record_contexts_v1(const SpEnoteOriginContextV1 &new_origin_context,
    const SpEnoteSpentContextV1 &new_spent_context,
    SpContextualEnoteRecordV1 &existing_record_inout)
{
    try_update_enote_spent_context_v1(new_spent_context, existing_record_inout.m_spent_context);
    try_update_enote_origin_context_v1(new_origin_context, existing_record_inout.m_origin_context);
    try_bump_enote_record_origin_status_v1(existing_record_inout.m_spent_context.m_spent_status,
        existing_record_inout.m_origin_context.m_origin_status);
}
//-------------------------------------------------------------------------------------------------------------------
void update_contextual_enote_record_contexts_v1(const SpContextualEnoteRecordV1 &fresh_record,
    SpContextualEnoteRecordV1 &existing_record_inout)
{
    CHECK_AND_ASSERT_THROW_MES(fresh_record.m_record.m_key_image == existing_record_inout.m_record.m_key_image,
        "updating a contextual enote record: the fresh record doesn't represent the same enote.");

    update_contextual_enote_record_contexts_v1(fresh_record.m_origin_context,
        fresh_record.m_spent_context,
        existing_record_inout);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
