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
#include "legacy_enote_types.h"

//local headers
#include "crypto/crypto.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void LegacyEnoteV1::gen()
{
    m_onetime_address = rct::pkGen();
    m_amount = crypto::rand_idx(static_cast<rct::xmr_amount>(-1));
}
//-------------------------------------------------------------------------------------------------------------------
void LegacyEnoteV2::gen()
{
    m_onetime_address = rct::pkGen();
    m_amount_commitment = rct::pkGen();
    m_encoded_amount_mask = rct::skGen();
    m_encoded_amount = rct::skGen();
}
//-------------------------------------------------------------------------------------------------------------------
void LegacyEnoteV3::gen()
{
    m_onetime_address = rct::pkGen();
    m_amount_commitment = rct::pkGen();
    m_encoded_amount = crypto::rand_idx(static_cast<rct::xmr_amount>(-1));
}
//-------------------------------------------------------------------------------------------------------------------
void LegacyEnoteV4::gen()
{
    m_onetime_address = rct::pkGen();
    m_amount_commitment = rct::pkGen();
    m_encoded_amount = crypto::rand_idx(static_cast<rct::xmr_amount>(-1));
    m_view_tag.data = static_cast<char>(crypto::rand_idx(static_cast<unsigned char>(-1)));
}
//-------------------------------------------------------------------------------------------------------------------
const rct::key& LegacyEnoteVariant::onetime_address() const
{
    if (is_type<LegacyEnoteV1>())
        return get_enote<LegacyEnoteV1>().m_onetime_address;
    else if (is_type<LegacyEnoteV2>())
        return get_enote<LegacyEnoteV2>().m_onetime_address;
    else if (is_type<LegacyEnoteV3>())
        return get_enote<LegacyEnoteV3>().m_onetime_address;
    else if (is_type<LegacyEnoteV4>())
        return get_enote<LegacyEnoteV4>().m_onetime_address;
    else
    {
        static const rct::key temp{};
        return temp;
    }
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
