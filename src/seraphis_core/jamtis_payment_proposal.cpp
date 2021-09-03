// Copyright (c) 2022, The Monero Project
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

//paired header
#include "jamtis_payment_proposal.h"

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
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
#include "sp_core_types.h"
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
//-------------------------------------------------------------------------------------------------------------------
template <typename T>
static auto auto_wiper(T &obj)
{
    return epee::misc_utils::create_scope_leave_handler([&]{ memwipe(&obj, sizeof(T)); });
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void get_output_proposal_amount_parts_v1(const rct::key &q,
    const rct::key &amount_baked_key,
    const rct::xmr_amount output_amount,
    crypto::secret_key &amount_blinding_factor_out,
    encoded_amount_t &encoded_amount_out)
{
    // 1. amount blinding factor: y = H_n(q, baked_key)
    make_jamtis_amount_blinding_factor(q, amount_baked_key, amount_blinding_factor_out);

    // 2. encrypted amount: enc_amount = a ^ H_8(q, baked_key)
    encoded_amount_out = encode_jamtis_amount(output_amount, q, amount_baked_key);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void get_output_proposal_address_parts_v1(const rct::key &q,
    const crypto::x25519_pubkey &xK_d,
    const JamtisDestinationV1 &output_destination,
    const rct::key &amount_commitment,
    rct::key &onetime_address_out,
    encrypted_address_tag_t &addr_tag_enc_out,
    view_tag_t &view_tag_out)
{
    // 1. onetime address: Ko = k^o_g G + k^o_x X + k^o_u U + K_1
    make_jamtis_onetime_address(output_destination.addr_K1, q, amount_commitment, onetime_address_out);

    // 2. encrypt address tag: addr_tag_enc = addr_tag ^ H(q, Ko)
    addr_tag_enc_out = encrypt_address_tag(q, onetime_address_out, output_destination.addr_tag);

    // 3. view tag: view_tag = H_1(xK_d, Ko)
    make_jamtis_view_tag(xK_d, onetime_address_out, view_tag_out);
}
//-------------------------------------------------------------------------------------------------------------------    
//-------------------------------------------------------------------------------------------------------------------
void get_enote_ephemeral_pubkey(const JamtisPaymentProposalV1 &proposal,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out)
{
    // sanity checks
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(proposal.enote_ephemeral_privkey.data),
        "jamtis payment proposal: invalid enote ephemeral privkey (zero).");
    CHECK_AND_ASSERT_THROW_MES(x25519_scalar_is_canonical(proposal.enote_ephemeral_privkey),
        "jamtis payment proposal: invalid enote ephemeral privkey (not canonical).");

    // enote ephemeral pubkey: xK_e = xr xK_3
    make_jamtis_enote_ephemeral_pubkey(proposal.enote_ephemeral_privkey,
        proposal.destination.addr_K3,
        enote_ephemeral_pubkey_out);
}
//-------------------------------------------------------------------------------------------------------------------
void get_enote_ephemeral_pubkey(const JamtisPaymentProposalSelfSendV1 &proposal,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out)
{
    // sanity checks
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(proposal.enote_ephemeral_privkey.data),
        "jamtis payment proposal self-send: invalid enote ephemeral privkey (zero).");
    CHECK_AND_ASSERT_THROW_MES(x25519_scalar_is_canonical(proposal.enote_ephemeral_privkey),
        "jamtis payment proposal self-send: invalid enote ephemeral privkey (not canonical).");

    // enote ephemeral pubkey: xK_e = xr xK_3
    make_jamtis_enote_ephemeral_pubkey(proposal.enote_ephemeral_privkey,
        proposal.destination.addr_K3,
        enote_ephemeral_pubkey_out);
}
//-------------------------------------------------------------------------------------------------------------------
void get_coinbase_output_proposal_v1(const JamtisPaymentProposalV1 &proposal,
    const std::uint64_t block_height,
    SpCoinbaseEnoteCore &output_enote_core_out,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out,
    encrypted_address_tag_t &addr_tag_enc_out,
    view_tag_t &view_tag_out,
    TxExtra &partial_memo_out)
{
    // 1. sanity checks
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(proposal.enote_ephemeral_privkey.data),
        "jamtis payment proposal: invalid enote ephemeral privkey (zero).");
    CHECK_AND_ASSERT_THROW_MES(x25519_scalar_is_canonical(proposal.enote_ephemeral_privkey),
        "jamtis payment proposal: invalid enote ephemeral privkey (not canonical).");

    // 2. coinbase input context
    rct::key input_context;
    make_jamtis_input_context_coinbase(block_height, input_context);

    // 3. enote ephemeral pubkey: xK_e = xr xK_3
    get_enote_ephemeral_pubkey(proposal, enote_ephemeral_pubkey_out);

    // 4. derived key: xK_d = xr * xK_2
    crypto::x25519_pubkey xK_d; auto xKd_wiper = auto_wiper(xK_d);
    crypto::x25519_scmul_key(proposal.enote_ephemeral_privkey, proposal.destination.addr_K2, xK_d);

    // 5. sender-receiver shared secret (plain): q = H_32(xK_d, xK_e, input_context)
    rct::key q; auto q_wiper = auto_wiper(q);
    make_jamtis_sender_receiver_secret_plain(xK_d, enote_ephemeral_pubkey_out, input_context, q);

    // 6. build the output enote address pieces
    get_output_proposal_address_parts_v1(q,
        xK_d,
        proposal.destination,
        rct::commit(proposal.amount, rct::I),
        output_enote_core_out.onetime_address,
        addr_tag_enc_out,
        view_tag_out);

    // 7. save the amount and parial memo
    output_enote_core_out.amount = proposal.amount;
    partial_memo_out             = proposal.partial_memo;
}
//-------------------------------------------------------------------------------------------------------------------
void get_output_proposal_v1(const JamtisPaymentProposalV1 &proposal,
    const rct::key &input_context,
    SpOutputProposalCore &output_proposal_core_out,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out,
    encoded_amount_t &encoded_amount_out,
    encrypted_address_tag_t &addr_tag_enc_out,
    view_tag_t &view_tag_out,
    TxExtra &partial_memo_out)
{
    // 1. sanity checks
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(proposal.enote_ephemeral_privkey.data),
        "jamtis payment proposal: invalid enote ephemeral privkey (zero).");
    CHECK_AND_ASSERT_THROW_MES(x25519_scalar_is_canonical(proposal.enote_ephemeral_privkey),
        "jamtis payment proposal: invalid enote ephemeral privkey (not canonical).");

    // 2. enote ephemeral pubkey: xK_e = xr xK_3
    get_enote_ephemeral_pubkey(proposal, enote_ephemeral_pubkey_out);

    // 3. derived key: xK_d = xr * xK_2
    crypto::x25519_pubkey xK_d; auto xKd_wiper = auto_wiper(xK_d);
    crypto::x25519_scmul_key(proposal.enote_ephemeral_privkey, proposal.destination.addr_K2, xK_d);

    // 4. sender-receiver shared secret (plain): q = H_32(xK_d, xK_e, input_context)
    rct::key q; auto q_wiper = auto_wiper(q);
    make_jamtis_sender_receiver_secret_plain(xK_d, enote_ephemeral_pubkey_out, input_context, q);

    // 5. amount baked key (plain): H_32(xr xG)
    rct::key amount_baked_key; auto bk_wiper = auto_wiper(amount_baked_key);
    make_jamtis_amount_baked_key_plain_sender(proposal.enote_ephemeral_privkey, amount_baked_key);

    // 6. build the output enote amount pieces
    get_output_proposal_amount_parts_v1(q,
        amount_baked_key,
        proposal.amount,
        output_proposal_core_out.amount_blinding_factor,
        encoded_amount_out);

    // 7. build the output enote address pieces
    get_output_proposal_address_parts_v1(q,
        xK_d,
        proposal.destination,
        rct::commit(proposal.amount, rct::sk2rct(output_proposal_core_out.amount_blinding_factor)),
        output_proposal_core_out.onetime_address,
        addr_tag_enc_out,
        view_tag_out);

    // 8. save the amount and partial memo
    output_proposal_core_out.amount = proposal.amount;
    partial_memo_out                = proposal.partial_memo;
}
//-------------------------------------------------------------------------------------------------------------------
void get_output_proposal_v1(const JamtisPaymentProposalSelfSendV1 &proposal,
    const crypto::secret_key &k_view_balance,
    const rct::key &input_context,
    SpOutputProposalCore &output_proposal_core_out,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out,
    encoded_amount_t &encoded_amount_out,
    encrypted_address_tag_t &addr_tag_enc_out,
    view_tag_t &view_tag_out,
    TxExtra &partial_memo_out)
{
    // 1. sanity checks
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(proposal.enote_ephemeral_privkey.data),
        "jamtis payment proposal self-send: invalid enote ephemeral privkey (zero).");
    CHECK_AND_ASSERT_THROW_MES(x25519_scalar_is_canonical(proposal.enote_ephemeral_privkey),
        "jamtis payment proposal self-send: invalid enote ephemeral privkey (not canonical).");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(k_view_balance)),
        "jamtis payment proposal self-send: invalid view-balance privkey (zero).");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(k_view_balance)) == 0,
        "jamtis payment proposal self-send: invalid view-balance privkey (not canonical).");
    CHECK_AND_ASSERT_THROW_MES(proposal.type <= JamtisSelfSendType::MAX,
        "jamtis payment proposal self-send: unknown self-send type.");

    // 2. enote ephemeral pubkey: xK_e = xr xK_3
    get_enote_ephemeral_pubkey(proposal, enote_ephemeral_pubkey_out);

    // 3. derived key: xK_d = xr * xK_2
    crypto::x25519_pubkey xK_d; auto xKd_wiper = auto_wiper(xK_d);
    crypto::x25519_scmul_key(proposal.enote_ephemeral_privkey, proposal.destination.addr_K2, xK_d);

    // 4. sender-receiver shared secret (selfsend): q = H_32[k_vb](xK_e, input_context)  //note: xK_e not xK_d
    rct::key q; auto q_wiper = auto_wiper(q);
    make_jamtis_sender_receiver_secret_selfsend(k_view_balance,
        enote_ephemeral_pubkey_out,
        input_context,
        proposal.type,
        q);

    // 5. amount baked key (selfsend): H_32[k_vb](q)
    rct::key amount_baked_key; auto bk_wiper = auto_wiper(amount_baked_key);
    make_jamtis_amount_baked_key_selfsend(k_view_balance, q, amount_baked_key);

    // 6. build the output enote amount pieces
    get_output_proposal_amount_parts_v1(q,
        amount_baked_key,
        proposal.amount,
        output_proposal_core_out.amount_blinding_factor,
        encoded_amount_out);

    // 7. build the output enote address pieces
    get_output_proposal_address_parts_v1(q,
        xK_d,
        proposal.destination,
        rct::commit(proposal.amount, rct::sk2rct(output_proposal_core_out.amount_blinding_factor)),
        output_proposal_core_out.onetime_address,
        addr_tag_enc_out,
        view_tag_out);

    // 8. save the amount and partial memo
    output_proposal_core_out.amount = proposal.amount;
    partial_memo_out                = proposal.partial_memo;
}
//-------------------------------------------------------------------------------------------------------------------
JamtisPaymentProposalV1 gen_jamtis_payment_proposal_v1(const rct::xmr_amount amount,
    const std::size_t num_random_memo_elements)
{
    JamtisPaymentProposalV1 temp;

    temp.destination             = gen_jamtis_destination_v1();
    temp.amount                  = amount;
    temp.enote_ephemeral_privkey = crypto::x25519_secret_key_gen();

    std::vector<ExtraFieldElement> memo_elements;
    memo_elements.resize(num_random_memo_elements);
    for (ExtraFieldElement &element: memo_elements)
        element = gen_extra_field_element();
    make_tx_extra(std::move(memo_elements), temp.partial_memo);

    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
JamtisPaymentProposalSelfSendV1 gen_jamtis_selfsend_payment_proposal_v1(const rct::xmr_amount amount,
    const JamtisSelfSendType type,
    const std::size_t num_random_memo_elements)
{
    JamtisPaymentProposalSelfSendV1 temp;

    temp.destination             = gen_jamtis_destination_v1();
    temp.amount                  = amount;
    temp.type                    = type;
    temp.enote_ephemeral_privkey = crypto::x25519_secret_key_gen();

    std::vector<ExtraFieldElement> memo_elements;
    memo_elements.resize(num_random_memo_elements);
    for (ExtraFieldElement &element: memo_elements)
        element = gen_extra_field_element();
    make_tx_extra(std::move(memo_elements), temp.partial_memo);

    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp
