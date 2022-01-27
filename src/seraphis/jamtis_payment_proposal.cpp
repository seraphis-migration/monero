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
#include "jamtis_payment_proposal.h"

//local headers
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_config.h"
#include "jamtis_address_tags.h"
#include "jamtis_address_utils.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "ringct/rctTypes.h"
#include "sp_core_utils.h"
#include "sp_crypto_utils.h"
#include "wipeable_string.h"

//third party headers

//standard headers
#include <string>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
namespace jamtis
{
//-------------------------------------------------------------------------------------------------------------------
void JamtisPaymentProposalV1::get_output_proposal_v1(SpOutputProposalV1 &output_proposal_out,
    rct::key &enote_pubkey_out) const
{
    // derived key: K_d = 8*r*K_2 (generate_key_derivation())
    // enote ephemeral pubkey: K_e = r K_3
    // view tag: view_tag = H1(K_d)
    // sender-receiver shared secret: q = H_32(K_d)
    // encrypt address tag: addr_tag_enc = addr_tag(blowfish(j, mac)) ^ H8(q)
    // onetime address: Ko = H_n(q) X + K_1
    // enote base pubkey: r G
    // amount blinding factor: y = H_n(q, r G)
    // encrypted amount: enc_amount = a ^ H8(q, r G)
}
//-------------------------------------------------------------------------------------------------------------------
void JamtisPaymentProposalV1::gen(const rct::xmr_amount amount)
{
    m_destination.gen();
    m_amount = amount;
    m_enote_privkey = rct::rct2sk(rct::skGen());
}
//-------------------------------------------------------------------------------------------------------------------
void JamtisPaymentProposalSelfSendV1::get_output_proposal_v1(SpOutputProposalV1 &output_proposal_out,
    rct::key &enote_pubkey_out) const
{
    // derived key: K_d = 8*r*K_2 (generate_key_derivation())
    // enote ephemeral pubkey: K_e = r K_3
    // view tag: view_tag = H1(K_d)
    // sender-receiver shared secret: q = H_32(k_vb, K_e)  //note: K_e not K_d, so q can be computed immediately by recipient
    // encrypt address tag: addr_tag_enc = addr_tag(j, mac) ^ H_8(q)
    // onetime address: Ko = H_n(q) X + K_1
    // enote base pubkey: r G
    // amount blinding factor: y = Hn(q)
    // encrypted amount: enc_amount = a ^ H8(q)
}
//-------------------------------------------------------------------------------------------------------------------
void JamtisPaymentProposalSelfSendV1::gen(const rct::xmr_amount amount, const JamtisSelfSendType type)
{
    m_destination.gen();
    m_amount = amount;
    m_type = type;
    m_enote_privkey = rct::rct2sk(rct::skGen());
    m_viewbalance_privkey = rct::rct2sk(rct::skGen());
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp
