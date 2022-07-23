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
#include "legacy_enote_types.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_core_types.h"
#include "tx_component_types.h"
#include "tx_extra.h"

//third party headers
#include <boost/optional/optional.hpp>

//standard headers
#include <algorithm>
#include <vector>

//forward declarations


namespace sp
{

////
// LegacyBasicEnoteRecord
// - a cryptonote/ringct enote that has been identified as owned by view-key scanning
///
struct LegacyBasicEnoteRecord final
{
    /// original enote
    LegacyEnoteVariant m_enote;
    /// the enote's ephemeral pubkey
    rct::key m_enote_ephemeral_pubkey;
    /// i: legacy address index (if true, then it's owned by a subaddress)
    boost::optional<std::uint64_t> m_address_index;
    /// t: the enote's index in its transaction
    std::uint64_t m_tx_ouput_index;
    /// u: the enote's unlock time
    std::uint64_t m_unlock_time;
};

////
// LegacyIntermediateEnoteRecord
// - a cryptonote/ringct enote that has been view-key scanned
///
struct LegacyIntermediateEnoteRecord final
{
    /// original enote
    LegacyEnoteVariant m_enote;
    /// the enote's ephemeral pubkey
    rct::key m_enote_ephemeral_pubkey;
    /// enote view privkey = [address: Hn(r K^v, t)] [subaddress: Hn(r K^{v,i}, t) + Hn(k^v, i)]
    crypto::secret_key m_enote_view_privkey;
    /// a: amount
    rct::xmr_amount m_amount;
    /// x: amount blinding factor
    crypto::secret_key m_amount_blinding_factor;
    /// i: legacy address index (if true, then it's owned by a subaddress)
    boost::optional<std::uint64_t> m_address_index;
    /// t: the enote's index in its transaction
    std::uint64_t m_tx_ouput_index;
    /// u: the enote's unlock time
    std::uint64_t m_unlock_time;
};

////
// LegacyEnoteRecord
// - a cryptonote/ringct enote that has been view-key scanned + key image computed
///
struct LegacyEnoteRecord final
{
    /// original enote
    LegacyEnoteVariant m_enote;
    /// the enote's ephemeral pubkey
    rct::key m_enote_ephemeral_pubkey;
    /// enote view privkey = [address: Hn(r K^v, t)] [subaddress: Hn(r K^{v,i}, t) + Hn(k^v, i)]
    crypto::secret_key m_enote_view_privkey;
    /// a: amount
    rct::xmr_amount m_amount;
    /// x: amount blinding factor
    crypto::secret_key m_amount_blinding_factor;
    /// KI: key image
    crypto::key_image m_key_image;
    /// i: legacy address index (if true, then it's owned by a subaddress)
    boost::optional<std::uint64_t> m_address_index;
    /// t: the enote's index in its transaction
    std::uint64_t m_tx_ouput_index;
    /// u: the enote's unlock time
    std::uint64_t m_unlock_time;
};

////
// SpBasicEnoteRecordV1  (jamtis 'plain' enote type only)
// - nominal address tag extracted from a v1 enote using a jamtis find-received key
///
struct SpBasicEnoteRecordV1 final
{
    /// original enote
    SpEnoteV1 m_enote;
    /// the enote's ephemeral pubkey
    rct::key m_enote_ephemeral_pubkey;
    /// context of the tx input(s) associated with this enote
    rct::key m_input_context;
    /// t'_addr: nominal address tag
    jamtis::address_tag_t m_nominal_address_tag;
};

////
// SpIntermediateEnoteRecordV1  (jamtis 'plain' enote type only)
// - info extracted from a v1 enote using a jamtis find-received key and generate-address secret
///
struct SpIntermediateEnoteRecordV1 final
{
    /// original enote
    SpEnoteV1 m_enote;
    /// the enote's ephemeral pubkey
    rct::key m_enote_ephemeral_pubkey;
    /// context of the tx input(s) associated with this enote
    rct::key m_input_context;
    /// a: amount
    rct::xmr_amount m_amount;
    /// x: amount blinding factor
    crypto::secret_key m_amount_blinding_factor;
    /// j: jamtis address index
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
    /// j: jamtis address index
    jamtis::address_index_t m_address_index;
    /// jamtis enote type
    jamtis::JamtisEnoteType m_type;
};

} //namespace sp
