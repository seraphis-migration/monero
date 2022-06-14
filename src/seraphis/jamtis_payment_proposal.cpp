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
#include "jamtis_address_tag_utils.h"
#include "jamtis_address_utils.h"
#include "jamtis_core_utils.h"
#include "jamtis_enote_utils.h"
#include "jamtis_support_types.h"
#include "memwipe.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "tx_builder_types.h"
#include "tx_enote_record_types.h"
#include "tx_enote_record_utils.h"
#include "tx_extra.h"

//third party headers

//standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
namespace jamtis
{
//-------------------------------------------------------------------------------------------------------------------
void JamtisPaymentProposalV1::get_enote_ephemeral_pubkey(rct::key &enote_ephemeral_pubkey_out) const
{
    // sanity checks
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(m_enote_ephemeral_privkey)),
        "jamtis payment proposal: invalid enote ephemeral privkey (zero).");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(m_enote_ephemeral_privkey)) == 0,
        "jamtis payment proposal: invalid enote ephemeral privkey (not canonical).");

    // enote ephemeral pubkey: K_e = r K_3
    make_jamtis_enote_ephemeral_pubkey(m_enote_ephemeral_privkey, m_destination.m_addr_K3, enote_ephemeral_pubkey_out);
}
//-------------------------------------------------------------------------------------------------------------------
void JamtisPaymentProposalV1::get_output_proposal_v1(const rct::key &input_context,
    SpOutputProposalV1 &output_proposal_out) const
{
    // sanity checks
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(m_enote_ephemeral_privkey)),
        "jamtis payment proposal: invalid enote ephemeral privkey (zero).");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(m_enote_ephemeral_privkey)) == 0,
        "jamtis payment proposal: invalid enote ephemeral privkey (not canonical).");

    // enote ephemeral pubkey: K_e = r K_3
    this->get_enote_ephemeral_pubkey(output_proposal_out.m_enote_ephemeral_pubkey);

    // derived key: K_d = 8*r*K_2
    crypto::key_derivation K_d;
    auto Kd_wiper = epee::misc_utils::create_scope_leave_handler([&]{ memwipe(&K_d, sizeof(K_d)); });
    crypto::generate_key_derivation(rct::rct2pk(m_destination.m_addr_K2), m_enote_ephemeral_privkey, K_d);

    // sender-receiver shared secret: q = H_32(K_d, K_e, input_context)
    rct::key q;
    auto q_wiper = epee::misc_utils::create_scope_leave_handler([&]{ memwipe(&q, sizeof(q)); });
    make_jamtis_sender_receiver_secret_plain(K_d, output_proposal_out.m_enote_ephemeral_pubkey, input_context, q);

    // encrypt address tag: addr_tag_enc = addr_tag(cipher(j || mac)) ^ H(q)
    output_proposal_out.m_addr_tag_enc = encrypt_address_tag(q, m_destination.m_addr_tag);

    // enote amount baked key: 8 r G
    crypto::key_derivation amount_baked_key;
    auto bk_wiper = epee::misc_utils::create_scope_leave_handler([&]{ memwipe(&amount_baked_key, sizeof(rct::key)); });
    make_jamtis_amount_baked_key_plain_sender(m_enote_ephemeral_privkey, amount_baked_key);

    // amount blinding factor: y = H_n(q, 8 r G)
    make_jamtis_amount_blinding_factor_plain(q, amount_baked_key, output_proposal_out.m_core.m_amount_blinding_factor);

    // amount: a
    output_proposal_out.m_core.m_amount = m_amount;

    // encrypted amount: enc_amount = a ^ H_8(q, 8 r G)
    output_proposal_out.m_encoded_amount = encode_jamtis_amount_plain(m_amount, q, amount_baked_key);

    // amount commitment (temporary)
    const rct::key temp_amount_commitment{
            rct::commit(m_amount, rct::sk2rct(output_proposal_out.m_core.m_amount_blinding_factor))
        };

    // onetime address: Ko = H_n(q, C) X + K_1
    make_jamtis_onetime_address(q,
        temp_amount_commitment,
        m_destination.m_addr_K1,
        output_proposal_out.m_core.m_onetime_address);

    // view tag: view_tag = H_1(K_d, Ko)
    make_jamtis_view_tag(K_d, output_proposal_out.m_core.m_onetime_address, output_proposal_out.m_view_tag);

    // memo elements
    output_proposal_out.m_partial_memo = m_partial_memo;
}
//-------------------------------------------------------------------------------------------------------------------
void JamtisPaymentProposalV1::gen(const rct::xmr_amount amount, const std::size_t num_random_memo_elements)
{
    m_destination.gen();
    m_amount = amount;
    m_enote_ephemeral_privkey = rct::rct2sk(rct::skGen());

    std::vector<ExtraFieldElement> memo_elements;
    memo_elements.resize(num_random_memo_elements);
    for (ExtraFieldElement &element: memo_elements)
        element.gen();
    make_tx_extra(std::move(memo_elements), m_partial_memo);
}
//-------------------------------------------------------------------------------------------------------------------
void JamtisPaymentProposalSelfSendV1::get_enote_ephemeral_pubkey(rct::key &enote_ephemeral_pubkey_out) const
{
    // sanity checks
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(m_enote_ephemeral_privkey)),
        "jamtis payment proposal self-send: invalid enote ephemeral privkey (zero).");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(m_enote_ephemeral_privkey)) == 0,
        "jamtis payment proposal self-send: invalid enote ephemeral privkey (not canonical).");

    // enote ephemeral pubkey: K_e = r K_3
    make_jamtis_enote_ephemeral_pubkey(m_enote_ephemeral_privkey, m_destination.m_addr_K3, enote_ephemeral_pubkey_out);
}
//-------------------------------------------------------------------------------------------------------------------
void JamtisPaymentProposalSelfSendV1::get_output_proposal_v1(const crypto::secret_key &viewbalance_privkey,
    const rct::key &input_context,
    SpOutputProposalV1 &output_proposal_out) const
{
    // sanity checks
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(m_enote_ephemeral_privkey)),
        "jamtis payment proposal self-send: invalid enote ephemeral privkey (zero).");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(m_enote_ephemeral_privkey)) == 0,
        "jamtis payment proposal self-send: invalid enote ephemeral privkey (not canonical).");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(viewbalance_privkey)),
        "jamtis payment proposal self-send: invalid view-balance privkey (zero).");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(viewbalance_privkey)) == 0,
        "jamtis payment proposal self-send: invalid view-balance privkey (not canonical).");
    CHECK_AND_ASSERT_THROW_MES(m_type <= JamtisSelfSendType::MAX,
        "jamtis payment proposal self-send: unknown self-send type.");

    // enote ephemeral pubkey: K_e = r K_3
    this->get_enote_ephemeral_pubkey(output_proposal_out.m_enote_ephemeral_pubkey);

    // sender-receiver shared secret: q = H_32[k_vb](K_e, input_context)  //note: K_e not K_d
    rct::key q;
    auto q_wiper = epee::misc_utils::create_scope_leave_handler([&]{ memwipe(&q, sizeof(q)); });
    make_jamtis_sender_receiver_secret_selfsend(viewbalance_privkey,
        output_proposal_out.m_enote_ephemeral_pubkey,
        input_context,
        m_type,
        q);

    // encrypt address index: addr_tag_enc = addr_tag(j, mac) ^ H(q)

    // 1. extract the address index from the destination address's address tag
    crypto::secret_key generateaddress_secret;
    crypto::secret_key ciphertag_secret;
    make_jamtis_generateaddress_secret(viewbalance_privkey, generateaddress_secret);
    make_jamtis_ciphertag_secret(generateaddress_secret, ciphertag_secret);
    address_index_t j;
    CHECK_AND_ASSERT_THROW_MES(try_decipher_address_index(rct::sk2rct(ciphertag_secret), m_destination.m_addr_tag, j),
        "Failed to create a self-send-type output proposal: could not decipher the destination's address tag.");

    // 2. make a raw address tag (not ciphered)
    const address_tag_t raw_address_tag{j};

    // 3. encrypt the raw address tag: addr_tag_enc = addr_tag(j || mac) ^ H(q)
    output_proposal_out.m_addr_tag_enc = encrypt_address_tag(q, raw_address_tag);


    // amount blinding factor: y = H_n(q)  //note: no baked key
    make_jamtis_amount_blinding_factor_selfsend(q, output_proposal_out.m_core.m_amount_blinding_factor);

    // amount: a
    output_proposal_out.m_core.m_amount = m_amount;

    // encrypted amount: enc_amount = a ^ H_8(q)  //note: no baked key
    output_proposal_out.m_encoded_amount = encode_jamtis_amount_selfsend(m_amount, q);

    // amount commitment (temporary)
    const rct::key temp_amount_commitment{
            rct::commit(m_amount, rct::sk2rct(output_proposal_out.m_core.m_amount_blinding_factor))
        };

    // onetime address: Ko = H_n(q, C) X + K_1
    make_jamtis_onetime_address(q,
        temp_amount_commitment,
        m_destination.m_addr_K1,
        output_proposal_out.m_core.m_onetime_address);

    // derived key: K_d = 8*r*K_2
    crypto::key_derivation K_d;
    crypto::generate_key_derivation(rct::rct2pk(m_destination.m_addr_K2), m_enote_ephemeral_privkey, K_d);

    // view tag: view_tag = H_1(K_d, Ko)
    make_jamtis_view_tag(K_d, output_proposal_out.m_core.m_onetime_address, output_proposal_out.m_view_tag);

    // memo elements
    output_proposal_out.m_partial_memo = m_partial_memo;
}
//-------------------------------------------------------------------------------------------------------------------
void JamtisPaymentProposalSelfSendV1::gen(const rct::xmr_amount amount,
    const JamtisSelfSendType type,
    const std::size_t num_random_memo_elements)
{
    m_destination.gen();
    m_amount = amount;
    m_type = type;
    m_enote_ephemeral_privkey = rct::rct2sk(rct::skGen());

    std::vector<ExtraFieldElement> memo_elements;
    memo_elements.resize(num_random_memo_elements);
    for (ExtraFieldElement &element: memo_elements)
        element.gen();
    make_tx_extra(std::move(memo_elements), m_partial_memo);
}
//-------------------------------------------------------------------------------------------------------------------
void check_jamtis_payment_proposal_selfsend_semantics_v1(const JamtisPaymentProposalSelfSendV1 &selfsend_payment_proposal,
    const rct::key &input_context,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance)
{
    // convert to an output proposal
    SpOutputProposalV1 output_proposal;
    selfsend_payment_proposal.get_output_proposal_v1(k_view_balance, input_context, output_proposal);

    // extract enote from output proposal
    SpEnoteV1 temp_enote;
    output_proposal.get_enote_v1(temp_enote);

    // try to get an enote record from the enote (via selfsend path)
    SpEnoteRecordV1 temp_enote_record;

    CHECK_AND_ASSERT_THROW_MES(try_get_enote_record_v1_selfsend(temp_enote,
            output_proposal.m_enote_ephemeral_pubkey,
            input_context,
            wallet_spend_pubkey,
            k_view_balance,
            temp_enote_record),
        "semantics check jamtis self-send payment proposal: failed to extract enote record from the proposal.");

    // convert to a self-send type
    JamtisSelfSendType dummy_type;
    CHECK_AND_ASSERT_THROW_MES(try_get_jamtis_self_send_type(temp_enote_record.m_type, dummy_type),
        "semantics check jamtis self-send payment proposal: failed to convert enote type to self-send type (bug).");
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp
