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
#include "jamtis_core_utils.h"
#include "jamtis_enote_utils.h"
#include "jamtis_support_types.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "tx_builder_types.h"

//third party headers

//standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
namespace jamtis
{
//-------------------------------------------------------------------------------------------------------------------
void JamtisPaymentProposalV1::get_output_proposal_v1(SpOutputProposalV1 &output_proposal_out) const
{
    // enote ephemeral pubkey: K_e = r K_3
    make_jamtis_enote_ephemeral_pubkey(m_enote_ephemeral_privkey,
            m_destination.m_addr_K3,
            output_proposal_out.m_enote_ephemeral_pubkey
        );

    // derived key: K_d = 8*r*K_2
    crypto::key_derivation K_d;  //TODO: add wiper?
    crypto::generate_key_derivation(rct::rct2pk(m_destination.m_addr_K2), m_enote_ephemeral_privkey, K_d);

    // sender-receiver shared secret: q = H_32(K_d)
    rct::key q;  //TODO: add wiper?
    make_jamtis_sender_receiver_secret_plain(K_d, q);

    // encrypt address tag: addr_tag_enc = addr_tag(blowfish(j || mac)) ^ H_8(q)
    output_proposal_out.m_addr_tag_enc = encrypt_address_tag(q, m_destination.m_addr_tag);

    // onetime address: Ko = H_n(q) X + K_1
    make_jamtis_onetime_address(q,
            m_destination.m_addr_K1,
            output_proposal_out.m_proposal_core.m_onetime_address
        );

    // view tag: view_tag = H_1(K_d, Ko)
    output_proposal_out.m_view_tag = make_jamtis_view_tag(K_d, output_proposal_out.m_proposal_core.m_onetime_address);

    // enote amount baked key: 8 r G
    crypto::key_derivation amount_baked_key;  //TODO: add wiper?
    make_jamtis_amount_baked_key_plain_sender(m_enote_ephemeral_privkey, amount_baked_key);

    // amount blinding factor: y = H_n(q, 8 r G)
    make_jamtis_amount_blinding_factor_plain(q,
            amount_baked_key,
            output_proposal_out.m_proposal_core.m_amount_blinding_factor
        );

    // amount: a
    output_proposal_out.m_proposal_core.m_amount = m_amount;

    // encrypted amount: enc_amount = a ^ H_8(q, 8 r G)
    output_proposal_out.m_encoded_amount = encode_jamtis_amount_plain(m_amount, q, amount_baked_key);
}
//-------------------------------------------------------------------------------------------------------------------
void JamtisPaymentProposalV1::gen(const rct::xmr_amount amount)
{
    m_destination.gen();
    m_amount = amount;
    m_enote_ephemeral_privkey = rct::rct2sk(rct::skGen());
}
//-------------------------------------------------------------------------------------------------------------------
void JamtisPaymentProposalSelfSendV1::get_output_proposal_v1(SpOutputProposalV1 &output_proposal_out) const
{
    // enote ephemeral pubkey: K_e = r K_3
    make_jamtis_enote_ephemeral_pubkey(m_enote_ephemeral_privkey,
            m_destination.m_addr_K3,
            output_proposal_out.m_enote_ephemeral_pubkey
        );

    // sender-receiver shared secret: q = H_32[k_vb](K_e)  //note: K_e not K_d
    crypto::secret_key q;
    make_jamtis_sender_receiver_secret_selfsend(m_viewbalance_privkey,
            output_proposal_out.m_enote_ephemeral_pubkey,
            q
        );

    // encrypt address index and mac: addr_tag_enc = addr_tag(j, mac) ^ H_8(q)

    // 1. extract the address index from the destination address's address tag
    crypto::secret_key generateaddress_secret;
    crypto::secret_key ciphertag_secret;
    make_jamtis_generateaddress_secret(m_viewbalance_privkey, generateaddress_secret);
    make_jamtis_ciphertag_secret(generateaddress_secret, ciphertag_secret);
    address_tag_MAC_t j_mac;
    address_index_t j{decipher_address_index(ciphertag_secret, m_destination.m_addr_tag, j_mac)};
    CHECK_AND_ASSERT_THROW_MES(j_mac == address_tag_MAC_t{0},
        "Failed to create a self-send-type output proposal: could not decipher the destination's address tag.");

    // 2. make a raw address tag (not ciphered) from {j || selfspend_type} (with the type as mac)
    address_tag_t raw_addr_tag{address_index_to_tag(j, m_type)};

    // 3. encrypt the raw address tag: addr_tag_enc = addr_tag(j || mac) ^ H_8(q)
    output_proposal_out.m_addr_tag_enc = encrypt_address_tag(q, raw_addr_tag);


    // derived key: K_d = 8*r*K_2
    crypto::key_derivation K_d;
    crypto::generate_key_derivation(rct::rct2pk(m_destination.m_addr_K2), m_enote_ephemeral_privkey, K_d);

    // onetime address: Ko = H_n(q) X + K_1
    make_jamtis_onetime_address(q,
            m_destination.m_addr_K1,
            output_proposal_out.m_proposal_core.m_onetime_address
        );

    // view tag: view_tag = H_1(K_d, Ko)
    output_proposal_out.m_view_tag = make_jamtis_view_tag(K_d, output_proposal_out.m_proposal_core.m_onetime_address);

    // amount blinding factor: y = H_n(q)  //note: no baked key
    make_jamtis_amount_blinding_factor_selfsend(q,
            output_proposal_out.m_proposal_core.m_amount_blinding_factor
        );

    // amount: a
    output_proposal_out.m_proposal_core.m_amount = m_amount;

    // encrypted amount: enc_amount = a ^ H_8(q)  //note: no baked key
    output_proposal_out.m_encoded_amount = encode_jamtis_amount_selfsend(m_amount, q);
}
//-------------------------------------------------------------------------------------------------------------------
void JamtisPaymentProposalSelfSendV1::gen(const rct::xmr_amount amount, const JamtisSelfSendMAC type)
{
    m_destination.gen();
    m_amount = amount;
    m_type = type;
    m_enote_ephemeral_privkey = rct::rct2sk(rct::skGen());
    m_viewbalance_privkey = rct::rct2sk(rct::skGen());
}
//-------------------------------------------------------------------------------------------------------------------
bool is_self_send_output_proposal(const SpOutputProposalV1 &proposal,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance)
{
    // find-received key
    crypto::secret_key findreceived_key;
    make_jamtis_findreceived_key(k_view_balance, findreceived_key);

    // get the sender-receiver shared secret and nominal spend key (if the view tag can be recomputed)
    crypto::key_derivation K_d;
    crypto::generate_key_derivation(rct::rct2pk(proposal.m_enote_ephemeral_pubkey), findreceived_key, K_d);

    crypto::secret_key q;
    rct::key nominal_spendkey;

    if(!try_get_jamtis_nominal_spend_key_selfsend(K_d,
            proposal.m_proposal_core.m_onetime_address,
            proposal.m_view_tag,
            k_view_balance,
            proposal.m_enote_ephemeral_pubkey,
            q,
            nominal_spendkey)
        )
    {
        return false;
    }

    // get the nominal raw address tag
    address_tag_t nominal_raw_address_tag{decrypt_address_tag(q, proposal.m_addr_tag_enc)};

    // check if the mac is a self-send type
    address_tag_MAC_t nominal_mac;
    address_index_t nominal_address_index{address_tag_to_index(nominal_raw_address_tag, nominal_mac)};

    if (nominal_mac != JamtisSelfSendMAC::CHANGE ||
        nominal_mac != JamtisSelfSendMAC::SELF_SPEND)
    {
        return false;
    }

    // generate-address secret
    crypto::secret_key generateaddress_secret;
    make_jamtis_generateaddress_secret(k_view_balance, generateaddress_secret);

    // check if the nominal spend key is owned by this wallet
    return test_jamtis_nominal_spend_key(wallet_spend_pubkey,
        generateaddress_secret,
        nominal_address_index,
        nominal_spendkey);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp
