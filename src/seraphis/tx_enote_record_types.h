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

// Records of Seraphis enotes owned by some wallet.


#pragma once

//local headers
#include "crypto/crypto.h"
#include "jamtis_support_types.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_core_types.h"
#include "tx_component_types.h"
#include "tx_extra.h"

//third party headers

//standard headers
#include <algorithm>
#include <vector>

//forward declarations


namespace sp
{

////
// SpBasicEnoteRecordV1  (jamtis 'plain' enote type only)
// - info extracted from a v1 enote using a jamtis find-received key
// - does not have: a, x, j, k_a, KI
///
struct SpBasicEnoteRecordV1 final
{
    /// original enote
    SpEnoteV1 m_enote;
    /// the enote's ephemeral pubkey
    rct::key m_enote_ephemeral_pubkey;
    /// context of the tx input(s) associated with this enote
    rct::key m_input_context;
    /// q': nominal shared secret
    rct::key m_nominal_sender_receiver_secret;
    /// K'_1: nominal spend key
    rct::key m_nominal_spend_key;
    /// t'_addr: nominal address tag
    jamtis::address_tag_t m_nominal_address_tag;
};

////
// SpIntermediateEnoteRecordV1  (jamtis 'plain' enote type only)
// - info extracted from a v1 enote using a jamtis find-received key and generate-address secret
// - does not have: k_a, KI
///
struct SpIntermediateEnoteRecordV1 final
{
    /// original enote
    SpEnoteV1 m_enote;
    /// the enote's ephemeral pubkey
    rct::key m_enote_ephemeral_pubkey;
    /// context of the tx input(s) associated with this enote
    rct::key m_input_context;
    /// q': nominal shared secret
    rct::key m_nominal_sender_receiver_secret;
    /// a: amount
    rct::xmr_amount m_amount;
    /// x: amount blinding factor
    crypto::secret_key m_amount_blinding_factor;
    /// j: jamtis account index
    jamtis::address_index_t m_address_index;
};

////
// SpEnoteRecordV1
// - info extracted from a v1 enote
///
struct SpEnoteRecordV1 final
{
    /// original enote
    SpEnoteV1 m_enote;
    /// the enote's ephemeral pubkey
    rct::key m_enote_ephemeral_pubkey;
    /// context of the tx input(s) associated with this enote
    rct::key m_input_context;
    /// k_a: enote view privkey
    crypto::secret_key m_enote_view_privkey;
    /// a: amount
    rct::xmr_amount m_amount;
    /// x: amount blinding factor
    crypto::secret_key m_amount_blinding_factor;
    /// KI: key image
    crypto::key_image m_key_image;
    /// j: jamtis account index
    jamtis::address_index_t m_address_index;
    /// jamtis enote type
    jamtis::JamtisEnoteType m_type;
};

////
// SpEnoteRecordContextV1
// - info related to where an enote record was found
///
struct SpEnoteRecordContextV1 final
{
    enum class OriginStatus
    {
        // location unknown
        UNKNOWN,
        // is only located off-chain
        OFF_CHAIN,
        // is in the tx pool (but not the blockchain)
        UNCONFIRMED,
        // is in the blockchain in a locked block
        CONFIRMED_LOCKED,
        // is in the blockchain in an unlocked block
        CONFIRMED_UNLOCKED
    };

    /// associated memo fields (none by default)
    TxExtra m_memo{};
    /// tx id (0 if tx is unknown)
    rct::key m_transaction_id{rct::zero()};
    /// block height of transaction (-1 if height is unknown)
    std::uint64_t m_transaction_height{static_cast<std::uint64_t>(-1)};
    /// ledger index of the enote (-1 if index is unknown)
    std::uint64_t m_enote_ledger_index{static_cast<std::uint64_t>(-1)};

    /// origin status (unknown by default)
    OriginStatus m_origin_status{OriginStatus::UNKNOWN};
};

////
// SpEnoteRecordSpentContextV1
// - info related to where an enote was spent
///
struct SpEnoteRecordSpentContextV1 final
{
    enum class SpentStatus
    {
        // spent status is unknown
        UNKNOWN,
        // is spent in an off-chain tx
        SPENT_OFF_CHAIN,
        // is spent in a tx in the mempool
        SPENT_UNCONFIRMED,
        // is spent in a locked block
        SPENT_LOCKED,
        // is spent in an unlocked block
        SPENT_UNLOCKED
    };

    /// tx id where it was spent (0 if tx is unknown)
    rct::key m_transaction_id{rct::zero()};
    /// block height of transaction where it was spent (-1 if height is unknown)
    std::uint64_t m_transaction_height{static_cast<std::uint64_t>(-1)};

    /// spent status (unknown by default)
    SpentStatus m_spent_status{SpentStatus::UNKNOWN};
};

////
// SpContextualBasicEnoteRecordV1
// - info extracted from a v1 enote, with additional info related to where it was found
///
struct SpContextualBasicEnoteRecordV1 final
{
    /// basic info about the enote
    SpBasicEnoteRecordV1 m_record;
    /// info about where the enote was found
    SpEnoteRecordContextV1 m_context;

    /// onetime address equivalence
    static bool same_destination(const SpContextualBasicEnoteRecordV1 &record1,
        const SpContextualBasicEnoteRecordV1 &record2)
    {
        return record1.m_record.m_enote.m_core.m_onetime_address == record2.m_record.m_enote.m_core.m_onetime_address;
    }
};

////
// SpContextualIntermediateEnoteRecordV1
// - info extracted from a v1 enote, with additional info related to where it was found
///
struct SpContextualIntermediateEnoteRecordV1 final
{
    /// intermediate info about the enote
    SpIntermediateEnoteRecordV1 m_record;
    /// info about where the enote was found
    SpEnoteRecordContextV1 m_context;

    /// onetime address equivalence
    static bool same_destination(const SpContextualIntermediateEnoteRecordV1 &record1,
        const SpContextualIntermediateEnoteRecordV1 &record2)
    {
        return record1.m_record.m_enote.m_core.m_onetime_address == record2.m_record.m_enote.m_core.m_onetime_address;
    }

    /// get this enote's amount
    rct::xmr_amount get_amount() const { return m_record.m_amount; }
};

////
// SpContextualEnoteRecordV1
// - info extracted from a v1 enote, with additional info related to where it was found
///
struct SpContextualEnoteRecordV1 final
{
    /// info about the enote
    SpEnoteRecordV1 m_record;
    /// info about where the enote was found
    SpEnoteRecordContextV1 m_context;

    /// onetime address equivalence
    static bool same_destination(const SpContextualEnoteRecordV1 &record1, const SpContextualEnoteRecordV1 &record2)
    {
        return record1.m_record.m_enote.m_core.m_onetime_address == record2.m_record.m_enote.m_core.m_onetime_address;
    }

    /// get this enote's amount
    rct::xmr_amount get_amount() const { return m_record.m_amount; }
};

////
// SpContextualKeyImageSetV1
// - info about the tx where a set of key images was found
///
struct SpContextualKeyImageSetV1 final
{
    /// a set of key images found in a single tx
    std::vector<crypto::key_image> m_key_images;
    /// info about where the corresponding inputs were spent
    SpEnoteRecordSpentContextV1 m_spent_context;

    bool has_key_image(const crypto::key_image &test_key_image) const
    {
        return std::find(m_key_images.begin(), m_key_images.end(), test_key_image) != m_key_images.end();
    }
};

////
// SpSpentEnoteV1
// - a spent enote with all related contextual information
///
struct SpSpentEnoteV1 final
{
    /// info about the enote and where it was found
    SpContextualEnoteRecordV1 m_contextual_enote_record;
    /// info about where the enote was spent
    SpEnoteRecordSpentContextV1 m_spent_context;
};

} //namespace sp
