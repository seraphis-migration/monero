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

// Records of Seraphis enotes with context about their origin and their spent status.

#pragma once

//local headers
#include "common/variant.h"
#include "crypto/crypto.h"
#include "enote_record_types.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_core/sp_core_types.h"
#include "seraphis_core/tx_extra.h"
#include "tx_component_types.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace sp
{

////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////// Contexts ///////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

////
// SpEnoteOriginStatus
// - flag indicating where an enote is located
///
enum class SpEnoteOriginStatus : unsigned char
{
    // is only located outside the mining network and blockchain (e.g. is sitting on the user's machine)
    OFFCHAIN,
    // is submitted to the mining network but not yet added to the blockchain (e.g. is in some node's tx pool)
    UNCONFIRMED,
    // is in a block in the blockchain
    ONCHAIN
};

////
// SpEnoteSpentStatus
// - flag indicating where an enote was spent
///
enum class SpEnoteSpentStatus : unsigned char
{
    // has not been spent anywhere
    UNSPENT,
    // is spent in an off-chain tx
    SPENT_OFFCHAIN,
    // is spent in a tx submitted to the mining network but not yet added to the blockchain
    SPENT_UNCONFIRMED,
    // is spent in a tx in a block in the blockchain
    SPENT_ONCHAIN
};

////
// SpEnoteOriginContextV1
// - info related to the transaction where an enote was found
// - note that an enote may originate off-chain in a partial tx where the tx id is unknown
///
struct SpEnoteOriginContextV1 final
{
    /// block index of tx (-1 if index is unknown)
    std::uint64_t block_index{static_cast<std::uint64_t>(-1)};
    /// timestamp of tx's block (-1 if timestamp is unknown)
    std::uint64_t block_timestamp{static_cast<std::uint64_t>(-1)};
    /// tx id of the tx (0 if tx is unknown)
    rct::key transaction_id{rct::zero()};
    /// index of the enote in the tx's output set (-1 if index is unknown)
    std::uint64_t enote_tx_index{static_cast<std::uint16_t>(-1)};
    /// ledger index of the enote (-1 if index is unknown)
    std::uint64_t enote_ledger_index{static_cast<std::uint64_t>(-1)};
    /// origin status (off-chain by default)
    SpEnoteOriginStatus origin_status{SpEnoteOriginStatus::OFFCHAIN};

    /// associated memo field (none by default)
    TxExtra memo{};
};

////
// SpEnoteSpentContextV1
// - info related to where an enote was spent
// - note that an enote may be spent off-chain in a partial tx where the tx id is unknown
///
struct SpEnoteSpentContextV1 final
{
    /// block index of tx where it was spent (-1 if unspent or index is unknown)
    std::uint64_t block_index{static_cast<std::uint64_t>(-1)};
    /// timestamp of tx's block (-1 if timestamp is unknown)
    std::uint64_t block_timestamp{static_cast<std::uint64_t>(-1)};
    /// tx id of the tx where it was spent (0 if unspent or tx is unknown)
    rct::key transaction_id{rct::zero()};
    /// spent status (unspent by default)
    SpEnoteSpentStatus spent_status{SpEnoteSpentStatus::UNSPENT};
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////// Legacy ////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

////
// LegacyContextualBasicEnoteRecordV1
// - a legacy basic enote record, with additional info related to where it was found
///
struct LegacyContextualBasicEnoteRecordV1 final
{
    /// basic info about the enote
    LegacyBasicEnoteRecord record;
    /// info about where the enote was found
    SpEnoteOriginContextV1 origin_context;
};

////
// LegacyContextualIntermediateEnoteRecordV1
// - a legacy intermediate enote record, with additional info related to where it was found
// - the key image is unknown, so spent status is also unknown
///
struct LegacyContextualIntermediateEnoteRecordV1 final
{
    /// intermediate info about the enote
    LegacyIntermediateEnoteRecord record;
    /// info about where the enote was found
    SpEnoteOriginContextV1 origin_context;
};

/// get the record's onetime address
const rct::key& onetime_address_ref(const LegacyContextualIntermediateEnoteRecordV1 &record);
/// get the record's amount
rct::xmr_amount amount_ref(const LegacyContextualIntermediateEnoteRecordV1 &record);

////
// LegacyContextualEnoteRecordV1
// - a legacy full enote record with all related contextual information, including spent status
///
struct LegacyContextualEnoteRecordV1 final
{
    /// info about the enote
    LegacyEnoteRecord record;
    /// info about where the enote was found
    SpEnoteOriginContextV1 origin_context;
    /// info about where the enote was spent
    SpEnoteSpentContextV1 spent_context;
};

/// get the record's key image
const crypto::key_image& key_image_ref(const LegacyContextualEnoteRecordV1 &record);
/// get the record's amount
rct::xmr_amount amount_ref(const LegacyContextualEnoteRecordV1 &record);

////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////// Seraphis ///////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

////
// SpContextualBasicEnoteRecordV1
// - a seraphis basic enote record, with additional info related to where it was found
///
struct SpContextualBasicEnoteRecordV1 final
{
    /// basic info about the enote
    SpBasicEnoteRecordV1 record;
    /// info about where the enote was found
    SpEnoteOriginContextV1 origin_context;
};

////
// SpContextualIntermediateEnoteRecordV1
// - a seraphis intermediate enote record, with additional info related to where it was found
// - the key image is unknown, so spent status is also unknown
///
struct SpContextualIntermediateEnoteRecordV1 final
{
    /// intermediate info about the enote
    SpIntermediateEnoteRecordV1 record;
    /// info about where the enote was found
    SpEnoteOriginContextV1 origin_context;
};

/// get the record's onetime address
const rct::key& onetime_address_ref(const SpContextualIntermediateEnoteRecordV1 &record);
/// get the enote's amount
rct::xmr_amount amount_ref(const SpContextualIntermediateEnoteRecordV1 &record);

////
// SpContextualEnoteRecordV1
// - a seraphis full enote record with all related contextual information, including spent status
///
struct SpContextualEnoteRecordV1 final
{
    /// info about the enote
    SpEnoteRecordV1 record;
    /// info about where the enote was found
    SpEnoteOriginContextV1 origin_context;
    /// info about where the enote was spent
    SpEnoteSpentContextV1 spent_context;
};

/// get the record's key image
const crypto::key_image& key_image_ref(const SpContextualEnoteRecordV1 &record);
/// get the record's amount
rct::xmr_amount amount_ref(const SpContextualEnoteRecordV1 &record);

////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////// Joint /////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

////
// ContextualBasicRecordVariant
// - variant of all contextual basic enote record types
//
// origin_context_ref(): get the record's origin context
///
using ContextualBasicRecordVariant = tools::variant<LegacyContextualBasicEnoteRecordV1, SpContextualBasicEnoteRecordV1>;
const SpEnoteOriginContextV1& origin_context_ref(const ContextualBasicRecordVariant &variant);

////
// ContextualRecordVariant
// - variant of all contextual full enote record types
//
// amount_ref(): get the record's amount
// origin_context_ref(): get the record's origin context
// spent_context_ref(): get the record's spent context
///
using ContextualRecordVariant = tools::variant<LegacyContextualEnoteRecordV1, SpContextualEnoteRecordV1>;
rct::xmr_amount amount_ref(const ContextualRecordVariant &variant);
const SpEnoteOriginContextV1& origin_context_ref(const ContextualRecordVariant &variant);
const SpEnoteSpentContextV1& spent_context_ref(const ContextualRecordVariant &variant);

////
// SpContextualKeyImageSetV1
// - info about the tx where a set of key images was found
///
struct SpContextualKeyImageSetV1 final
{
    /// a set of legacy key images found in a single tx
    std::vector<crypto::key_image> legacy_key_images;
    /// a set of seraphis key images found in a single tx
    std::vector<crypto::key_image> sp_key_images;
    /// info about where the corresponding inputs were spent
    SpEnoteSpentContextV1 spent_context;
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////// Free Functions ////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

/// check if a context is older than another (returns false if apparently the same age, or younger)
bool is_older_than(const SpEnoteOriginContextV1 &context, const SpEnoteOriginContextV1 &other_context);
bool is_older_than(const SpEnoteSpentContextV1 &context, const SpEnoteSpentContextV1 &other_context);
/// check if records have onetime address equivalence
bool have_same_destination(const LegacyContextualBasicEnoteRecordV1 &a,
    const LegacyContextualBasicEnoteRecordV1 &b);
bool have_same_destination(const LegacyContextualIntermediateEnoteRecordV1 &a,
    const LegacyContextualIntermediateEnoteRecordV1 &b);
bool have_same_destination(const LegacyContextualEnoteRecordV1 &a, const LegacyContextualEnoteRecordV1 &b);
bool have_same_destination(const SpContextualBasicEnoteRecordV1 &a, const SpContextualBasicEnoteRecordV1 &b);
bool have_same_destination(const SpContextualIntermediateEnoteRecordV1 &a,
    const SpContextualIntermediateEnoteRecordV1 &b);
bool have_same_destination(const SpContextualEnoteRecordV1 &a, const SpContextualEnoteRecordV1 &b);
/// check origin status
bool has_origin_status(const LegacyContextualIntermediateEnoteRecordV1 &record, const SpEnoteOriginStatus test_status);
bool has_origin_status(const LegacyContextualEnoteRecordV1 &record, const SpEnoteOriginStatus test_status);
bool has_origin_status(const SpContextualIntermediateEnoteRecordV1 &record, const SpEnoteOriginStatus test_status);
bool has_origin_status(const SpContextualEnoteRecordV1 &record, const SpEnoteOriginStatus test_status);
/// check spent status
bool has_spent_status(const LegacyContextualEnoteRecordV1 &record, const SpEnoteSpentStatus test_status);
bool has_spent_status(const SpContextualEnoteRecordV1 &record, const SpEnoteSpentStatus test_status);
/// check if a key image is present in a key image set
bool has_key_image(const SpContextualKeyImageSetV1 &key_image_set, const crypto::key_image &test_key_image);

} //namespace sp
