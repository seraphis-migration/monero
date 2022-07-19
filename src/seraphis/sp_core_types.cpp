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
#include "sp_core_types.h"

//local headers
#include "crypto/crypto.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_core_enote_utils.h"
#include "sp_crypto_utils.h"
#include "sp_transcript.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
bool SpEnote::onetime_address_is_canonical() const
{
    return key_domain_is_prime_subgroup(m_onetime_address);
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpEnote &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("Ko", container.m_onetime_address);
    transcript_inout.append("C", container.m_amount_commitment);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnote::gen()
{
    // all random
    m_onetime_address = rct::pkGen();
    m_amount_commitment = rct::pkGen();
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpEnoteImage &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("K_masked", container.m_masked_address);
    transcript_inout.append("C_masked", container.m_masked_commitment);
    transcript_inout.append("KI", container.m_key_image);
}
//-------------------------------------------------------------------------------------------------------------------
void SpInputProposal::get_enote_image_core(SpEnoteImage &image_out) const
{
    // {Ko, C}
    SpEnote enote_temp;
    this->get_enote_core(enote_temp);

    // K" = t_k G + H_n(Ko,C) Ko
    // C" = t_c G + C
    make_seraphis_enote_image_masked_keys(enote_temp.m_onetime_address,
        enote_temp.m_amount_commitment,
        m_address_mask,
        m_commitment_mask,
        image_out.m_masked_address,
        image_out.m_masked_commitment);

    // KI = k_b/k_a U
    this->get_key_image(image_out.m_key_image);
}
//-------------------------------------------------------------------------------------------------------------------
void SpInputProposal::gen(const crypto::secret_key &spendbase_privkey, const rct::xmr_amount amount)
{
    m_enote_view_privkey = rct::rct2sk(rct::skGen());
    make_seraphis_key_image(m_enote_view_privkey, spendbase_privkey, m_key_image);
    m_amount_blinding_factor = rct::rct2sk(rct::skGen());
    m_amount = amount;
    make_seraphis_enote_core(m_enote_view_privkey, spendbase_privkey, m_amount_blinding_factor, m_amount, m_enote_core);
    m_address_mask = rct::rct2sk(rct::skGen());;
    m_commitment_mask = rct::rct2sk(rct::skGen());;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpOutputProposal::onetime_address_is_canonical() const
{
    return key_domain_is_prime_subgroup(m_onetime_address);
}
//-------------------------------------------------------------------------------------------------------------------
void SpOutputProposal::get_enote_core(SpEnote &enote_out) const
{
    make_seraphis_enote_core(m_onetime_address, m_amount_blinding_factor, m_amount, enote_out);
}
//-------------------------------------------------------------------------------------------------------------------
void SpOutputProposal::gen(const rct::xmr_amount amount)
{
    // all random except amount
    m_onetime_address = rct::pkGen();
    m_amount_blinding_factor = rct::rct2sk(rct::skGen());
    m_amount = amount;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
