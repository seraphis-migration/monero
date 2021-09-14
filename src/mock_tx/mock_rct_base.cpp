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
#include "mock_rct_base.h"

//local headers
#include "crypto/crypto.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <vector>


namespace mock_tx
{
//-----------------------------------------------------------------
void MockENoteRct::make_base(const crypto::secret_key &onetime_privkey,
    const crypto::secret_key &amount_blinding_factor,
    const rct::xmr_amount amount)
{
    // Ko = ko G
    CHECK_AND_ASSERT_THROW_MES(crypto::secret_key_to_public_key(onetime_privkey, m_onetime_address),
        "Failed to derive public key");

    // C = x G + a H
    m_amount_commitment = rct::rct2pk(rct::commit(amount, rct::sk2rct(amount_blinding_factor)));
}
//-----------------------------------------------------------------
void MockENoteRct::gen_base()
{
    // all random
    m_onetime_address = rct::rct2pk(rct::pkGen());
    m_amount_commitment = rct::rct2pk(rct::pkGen());
}
//-----------------------------------------------------------------
void MockDestRct::gen_base(const rct::xmr_amount amount)
{
    // all random except amount
    m_onetime_address = rct::rct2pk(rct::pkGen());
    m_amount_blinding_factor = rct::rct2sk(rct::skGen());
    m_amount = amount;
}
//-----------------------------------------------------------------
void MockDestRct::to_enote_rct_base(MockENoteRct &enote_inout) const
{
    enote_inout.m_onetime_address = m_onetime_address;

    // C = x G + a H
    enote_inout.m_amount_commitment = rct::rct2pk(rct::commit(m_amount, rct::sk2rct(m_amount_blinding_factor)));
}
//-----------------------------------------------------------------
} //namespace mock_tx
