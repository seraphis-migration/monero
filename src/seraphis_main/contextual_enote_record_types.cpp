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

//paired header
#include "contextual_enote_record_types.h"

//local headers
#include "common/variant.h"
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <algorithm>


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
const rct::key& onetime_address_ref(const LegacyContextualIntermediateEnoteRecordV1 &record)
{
    return onetime_address_ref(record.record.enote);
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount amount_ref(const LegacyContextualIntermediateEnoteRecordV1 &record)
{
    return record.record.amount;
}
//-------------------------------------------------------------------------------------------------------------------
const crypto::key_image& key_image_ref(const LegacyContextualEnoteRecordV1 &record)
{
    return record.record.key_image;
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount amount_ref(const LegacyContextualEnoteRecordV1 &record)
{
    return record.record.amount;
}
//-------------------------------------------------------------------------------------------------------------------
const rct::key& onetime_address_ref(const SpContextualIntermediateEnoteRecordV1 &record)
{
    return onetime_address_ref(record.record.enote);
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount amount_ref(const SpContextualIntermediateEnoteRecordV1 &record)
{
    return record.record.amount;
}
//-------------------------------------------------------------------------------------------------------------------
const crypto::key_image& key_image_ref(const SpContextualEnoteRecordV1 &record)
{
    return record.record.key_image;
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount amount_ref(const SpContextualEnoteRecordV1 &record)
{
    return record.record.amount;
}
//-------------------------------------------------------------------------------------------------------------------
const SpEnoteOriginContextV1& origin_context_ref(const ContextualBasicRecordVariant &variant)
{
    struct visitor final : public tools::variant_static_visitor<const SpEnoteOriginContextV1&>
    {
        using variant_static_visitor::operator();  //for blank overload
        const SpEnoteOriginContextV1& operator()(const LegacyContextualBasicEnoteRecordV1 &record) const
        { return record.origin_context; }
        const SpEnoteOriginContextV1& operator()(const SpContextualBasicEnoteRecordV1 &record) const
        { return record.origin_context; }
    };

    return variant.visit(visitor());
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount amount_ref(const ContextualRecordVariant &variant)
{
    struct visitor final : public tools::variant_static_visitor<rct::xmr_amount>
    {
        using variant_static_visitor::operator();  //for blank overload
        rct::xmr_amount operator()(const LegacyContextualEnoteRecordV1 &record) const { return amount_ref(record); }
        rct::xmr_amount operator()(const SpContextualEnoteRecordV1 &record)     const { return amount_ref(record); }
    };

    return variant.visit(visitor());
}
//-------------------------------------------------------------------------------------------------------------------
const SpEnoteOriginContextV1& origin_context_ref(const ContextualRecordVariant &variant)
{
    struct visitor final : public tools::variant_static_visitor<const SpEnoteOriginContextV1&>
    {
        using variant_static_visitor::operator();  //for blank overload
        const SpEnoteOriginContextV1& operator()(const LegacyContextualEnoteRecordV1 &record) const
        { return record.origin_context; }
        const SpEnoteOriginContextV1& operator()(const SpContextualEnoteRecordV1 &record) const
        { return record.origin_context; }
    };

    return variant.visit(visitor());
}
//-------------------------------------------------------------------------------------------------------------------
const SpEnoteSpentContextV1& spent_context_ref(const ContextualRecordVariant &variant)
{
    struct visitor final : public tools::variant_static_visitor<const SpEnoteSpentContextV1&>
    {
        using variant_static_visitor::operator();  //for blank overload
        const SpEnoteSpentContextV1& operator()(const LegacyContextualEnoteRecordV1 &record) const
        { return record.spent_context; }
        const SpEnoteSpentContextV1& operator()(const SpContextualEnoteRecordV1 &record) const
        { return record.spent_context; }
    };

    return variant.visit(visitor());
}
//-------------------------------------------------------------------------------------------------------------------
bool is_older_than(const SpEnoteOriginContextV1 &context, const SpEnoteOriginContextV1 &other_context)
{
    // 1. origin status (higher statuses are assumed to be 'older')
    if (context.origin_status > other_context.origin_status)
        return true;
    if (context.origin_status < other_context.origin_status)
        return false;

    // 2. block index
    if (context.block_index < other_context.block_index)
        return true;
    if (context.block_index > other_context.block_index)
        return false;

    // note: don't assess the tx output index

    // 3. enote ledger index
    if (context.enote_ledger_index < other_context.enote_ledger_index)
        return true;
    if (context.enote_ledger_index > other_context.enote_ledger_index)
        return false;

    // 4. block timestamp
    if (context.block_timestamp < other_context.block_timestamp)
        return true;
    if (context.block_timestamp > other_context.block_timestamp)
        return false;

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
bool is_older_than(const SpEnoteSpentContextV1 &context, const SpEnoteSpentContextV1 &other_context)
{
    // 1. spent status (higher statuses are assumed to be 'older')
    if (context.spent_status > other_context.spent_status)
        return true;
    if (context.spent_status < other_context.spent_status)
        return false;

    // 2. block index
    if (context.block_index < other_context.block_index)
        return true;
    if (context.block_index > other_context.block_index)
        return false;

    // 3. block timestamp
    if (context.block_timestamp < other_context.block_timestamp)
        return true;
    if (context.block_timestamp > other_context.block_timestamp)
        return false;

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
bool have_same_destination(const LegacyContextualBasicEnoteRecordV1 &a, const LegacyContextualBasicEnoteRecordV1 &b)
{
    return onetime_address_ref(a.record.enote) == onetime_address_ref(b.record.enote);
}
//-------------------------------------------------------------------------------------------------------------------
bool have_same_destination(const LegacyContextualIntermediateEnoteRecordV1 &a,
    const LegacyContextualIntermediateEnoteRecordV1 &b)
{
    return onetime_address_ref(a.record.enote) == onetime_address_ref(b.record.enote);
}
//-------------------------------------------------------------------------------------------------------------------
bool have_same_destination(const LegacyContextualEnoteRecordV1 &a, const LegacyContextualEnoteRecordV1 &b)
{
    return onetime_address_ref(a.record.enote) == onetime_address_ref(b.record.enote);
}
//-------------------------------------------------------------------------------------------------------------------
bool have_same_destination(const SpContextualBasicEnoteRecordV1 &a, const SpContextualBasicEnoteRecordV1 &b)
{
    return onetime_address_ref(a.record.enote) == onetime_address_ref(b.record.enote);
}
//-------------------------------------------------------------------------------------------------------------------
bool have_same_destination(const SpContextualIntermediateEnoteRecordV1 &a, const SpContextualIntermediateEnoteRecordV1 &b)
{
    return onetime_address_ref(a) == onetime_address_ref(b);
}
//-------------------------------------------------------------------------------------------------------------------
bool have_same_destination(const SpContextualEnoteRecordV1 &a, const SpContextualEnoteRecordV1 &b)
{
    return onetime_address_ref(a.record.enote) == onetime_address_ref(b.record.enote);
}
//-------------------------------------------------------------------------------------------------------------------
bool has_origin_status(const LegacyContextualIntermediateEnoteRecordV1 &record, const SpEnoteOriginStatus test_status)
{
    return record.origin_context.origin_status == test_status;
}
//-------------------------------------------------------------------------------------------------------------------
bool has_origin_status(const LegacyContextualEnoteRecordV1 &record, const SpEnoteOriginStatus test_status)
{
    return record.origin_context.origin_status == test_status;
}
//-------------------------------------------------------------------------------------------------------------------
bool has_origin_status(const SpContextualIntermediateEnoteRecordV1 &record, const SpEnoteOriginStatus test_status)
{
    return record.origin_context.origin_status == test_status;
}
//-------------------------------------------------------------------------------------------------------------------
bool has_origin_status(const SpContextualEnoteRecordV1 &record, const SpEnoteOriginStatus test_status)
{
    return record.origin_context.origin_status == test_status;
}
//-------------------------------------------------------------------------------------------------------------------
bool has_spent_status(const LegacyContextualEnoteRecordV1 &record, const SpEnoteSpentStatus test_status)
{
    return record.spent_context.spent_status == test_status;
}
//-------------------------------------------------------------------------------------------------------------------
bool has_spent_status(const SpContextualEnoteRecordV1 &record, const SpEnoteSpentStatus test_status)
{
    return record.spent_context.spent_status == test_status;
}
//-------------------------------------------------------------------------------------------------------------------
bool has_key_image(const SpContextualKeyImageSetV1 &key_image_set, const crypto::key_image &test_key_image)
{
    return std::find(key_image_set.legacy_key_images.begin(), key_image_set.legacy_key_images.end(), test_key_image) !=
            key_image_set.legacy_key_images.end() ||
        std::find(key_image_set.sp_key_images.begin(), key_image_set.sp_key_images.end(), test_key_image) !=
            key_image_set.sp_key_images.end();
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
