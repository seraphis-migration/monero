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
#include "jamtis_address_tags.h"
#include "jamtis_address_utils.h"
#include "jamtis_enote_utils.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

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
void JamtisPaymentProposalV1::get_output_proposal_v1(SpOutputProposalV1 &output_proposal_out) const
{
    // derived key: K_d = 8*r*K_2 (generate_key_derivation())
    crypto::key_derivation K_d;
    crypto::generate_key_derivation(rct::rct2pk(m_destination.m_addr_K2), m_enote_ephemeral_privkey, K_d);

    // enote ephemeral pubkey: K_e = r K_3
    output_proposal_out.m_enote_ephemeral_pubkey{
            rct::scalarmultKey(m_destination.m_addr_K3, rct::sk2rct(m_enote_ephemeral_privkey))
        };

    // view tag: view_tag = H1(K_d)
    output_proposal_out.m_view_tag{make_jamtis_view_tag(K_d)};

    // sender-receiver shared secret: q = H_32(K_d)
    crypto::secret_key q;
    make_jamtis_sender_receiver_secret_simple(K_d, q);

    // encrypt address tag: addr_tag_enc = addr_tag(blowfish(j, mac)) ^ H8(q)
    output_proposal_out.m_addr_tag_enc{make_encrypted_address_tag(q, m_destination.m_addr_tag)};

    // onetime address: Ko = H_n(q) X + K_1
    make_jamtis_onetime_address(m_destination.m_addr_K1,
            q,
            output_proposal_out.m_proposal_core.m_onetime_address
        );

    // enote ephemeral base pubkey: r G
    rct::key ephemeral_base_pubkey{rct::scalarmultBase(m_enote_ephemeral_privkey)};

    // amount blinding factor: y = H_n(q, r G)
    make_jamtis_amount_blinding_factor_simple(q,
            ephemeral_base_pubkey,
            output_proposal_out.m_proposal_core.m_amount_blinding_factor
        );

    // amount: a
    output_proposal_out.m_proposal_core.m_amount = m_amount;

    // encrypted amount: enc_amount = a ^ H8(q, r G)
    output_proposal_out.m_encoded_amount{
            make_jamtis_encoded_amount_simple(m_amount, q, ephemeral_base_pubkey)
        };
}
//-------------------------------------------------------------------------------------------------------------------
void JamtisPaymentProposalV1::gen(const rct::xmr_amount amount)
{
    m_destination.gen();
    m_amount = amount;
    m_enote_privkey = rct::rct2sk(rct::skGen());
}
//-------------------------------------------------------------------------------------------------------------------
void JamtisPaymentProposalSelfSendV1::get_output_proposal_v1(SpOutputProposalV1 &output_proposal_out) const
{
    // derived key: K_d = 8*r*K_2 (generate_key_derivation())
    crypto::key_derivation K_d;
    crypto::generate_key_derivation(rct::rct2pk(m_destination.m_addr_K2), m_enote_ephemeral_privkey, K_d);

    // enote ephemeral pubkey: K_e = r K_3
    output_proposal_out.m_enote_ephemeral_pubkey{
            rct::scalarmultKey(m_destination.m_addr_K3, rct::sk2rct(m_enote_ephemeral_privkey))
        };

    // view tag: view_tag = H1(K_d)
    output_proposal_out.m_view_tag{make_jamtis_view_tag(K_d)};

    // sender-receiver shared secret: q = H_32(K_e, k_vb)  //note: K_e not K_d, so recipient can get q immediately
    crypto::secret_key q;
    make_jamtis_sender_receiver_secret_selfsend(output_proposal_out.m_enote_ephemeral_pubkey,
            m_viewbalance_privkey,
            q
        );

    // encrypt address index and mac: addr_tag_enc = addr_tag(j, mac) ^ H_8(q)

    // 1. extract the address index from the destination address's address tag
    crypto::secret_key ciphertag_secret;
    make_jamtis_ciphertag_secret(m_viewbalance_privkey, ciphertag_secret);
    address_index_t j;
    CHECK_AND_ASSERT_THROW_MES(
        try_get_address_index_with_key(ciphertag_secret, m_destination.m_addr_tag, j) == address_tag_MAC_t{0},
        "Failed to create a self-send-type output proposal: could not decipher the address tag.");

    // 2. make a raw address tag (not ciphered) from {j || selfspend_type} (with the type as mac)
    address_tag_t raw_addr_tag{address_index_to_tag(j, m_type)};

    // 3. encrypt the raw address tag
    output_proposal_out.m_addr_tag_enc{make_encrypted_address_tag(q, raw_addr_tag)};


    // onetime address: Ko = H_n(q) X + K_1
    make_jamtis_onetime_address(m_destination.m_addr_K1,
            q,
            output_proposal_out.m_proposal_core.m_onetime_address
        );

    // enote base pubkey: r G
    // NOT USED HERE (the adjusted 'q' computation makes 'r G' unnecessary)

    // amount blinding factor: y = Hn(q)
    make_jamtis_amount_blinding_factor_selfsend(q,
            output_proposal_out.m_proposal_core.m_amount_blinding_factor
        );

    // amount: a
    output_proposal_out.m_proposal_core.m_amount = m_amount;

    // encrypted amount: enc_amount = a ^ H8(q)
    output_proposal_out.m_encoded_amount{
            make_jamtis_encoded_amount_selfsend(m_amount, q)
        };
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
