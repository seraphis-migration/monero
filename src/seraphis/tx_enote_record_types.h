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

    bool operator==(const SpEnoteRecordV1 &other_record) const
    {
        return
            m_enote == other_record.m_enote &&
            m_enote_ephemeral_pubkey == other_record.m_enote_ephemeral_pubkey &&
            m_input_context == other_record.m_input_context &&
            m_enote_view_privkey == other_record.m_enote_view_privkey &&
            m_amount == other_record.m_amount &&
            m_amount_blinding_factor == other_record.m_amount_blinding_factor &&
            m_key_image == other_record.m_key_image &&
            m_address_index == other_record.m_address_index &&
            m_type == other_record.m_type;
    }
};

////
// SpEnoteOriginContextV1
// - info related to where an enote record was found
///
struct SpEnoteOriginContextV1 final
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
// SpEnoteSpentContextV1
// - info related to where an enote was spent
///
struct SpEnoteSpentContextV1 final
{
    enum class SpentStatus
    {
        // has not been spent anywhere
        UNSPENT,
        // is spent in an off-chain tx
        SPENT_OFF_CHAIN,
        // is spent in a tx in the mempool
        SPENT_UNCONFIRMED,
        // is spent in a locked block
        SPENT_LOCKED,
        // is spent in an unlocked block
        SPENT_UNLOCKED
    };

    /// tx id where it was spent (0 if unspent or tx is unknown)
    rct::key m_transaction_id{rct::zero()};
    /// block height of transaction where it was spent (-1 if unspent or height is unknown)
    std::uint64_t m_transaction_height{static_cast<std::uint64_t>(-1)};

    /// spent status (unspent by default)
    SpentStatus m_spent_status{SpentStatus::UNSPENT};
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
    SpEnoteOriginContextV1 m_origin_context;

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
    SpEnoteOriginContextV1 m_origin_context;

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
// - an enote with all related contextual information, including spent status
///
struct SpContextualEnoteRecordV1 final
{
    /// info about the enote
    SpEnoteRecordV1 m_record;
    /// info about where the enote was found
    SpEnoteOriginContextV1 m_origin_context;
    /// info about where the enote was spent
    SpEnoteSpentContextV1 m_spent_context;

    /// onetime address equivalence
    static bool same_destination(const SpContextualEnoteRecordV1 &record1, const SpContextualEnoteRecordV1 &record2)
    {
        return record1.m_record.m_enote.m_core.m_onetime_address == record2.m_record.m_enote.m_core.m_onetime_address;
    }

    /// get this enote's key image
    void get_key_image(crypto::key_image &key_image_out) const
    {
        key_image_out = m_record.m_key_image;
    }

    /// get this enote's amount
    rct::xmr_amount get_amount() const { return m_record.m_amount; }

    /// check spent status
    bool has_spent_status(const SpEnoteSpentContextV1::SpentStatus test_status) const
    {
        return m_spent_context.m_spent_status == test_status;
    }
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
    SpEnoteSpentContextV1 m_spent_context;

    bool has_key_image(const crypto::key_image &test_key_image) const
    {
        return std::find(m_key_images.begin(), m_key_images.end(), test_key_image) != m_key_images.end();
    }
};

} //namespace sp
