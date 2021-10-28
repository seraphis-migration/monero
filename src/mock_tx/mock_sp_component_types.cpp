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
#include "mock_sp_component_types.h"

//local headers
#include "crypto/crypto.h"
#include "device/device.hpp"
#include "misc_log_ex.h"
#include "mock_sp_base_types.h"
#include "mock_sp_core_utils.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <memory>
#include <vector>


namespace mock_tx
{
//-------------------------------------------------------------------------------------------------------------------
void MockENoteSpV1::make(const crypto::secret_key &enote_privkey,
    const rct::key &recipient_DH_base,
    const rct::key &recipient_view_key,
    const rct::key &recipient_spend_key,
    const rct::xmr_amount amount,
    const std::size_t enote_index,
    rct::key &enote_pubkey_out)
{
    // note: t = enote_index

    // r_t: sender-receiver shared secret
    crypto::secret_key sender_receiver_secret;
    make_seraphis_sender_receiver_secret(enote_privkey,
        recipient_view_key,
        enote_index,
        hw::get_device("default"),
        sender_receiver_secret);

    // x_t: amount commitment mask (blinding factor)
    crypto::secret_key amount_mask;
    make_seraphis_amount_commitment_mask(sender_receiver_secret, amount_mask);

    // k_{a, sender, t}: extension to add to user's spend key
    crypto::secret_key k_a_extender;
    make_seraphis_sender_address_extension(sender_receiver_secret, k_a_extender);

    // make the base of the enote (Ko_t, C_t)
    this->make_base_with_address_extension(k_a_extender, recipient_spend_key, amount_mask, amount);

    // enc(a_t): encoded amount
    m_encoded_amount = enc_dec_seraphis_amount(sender_receiver_secret, amount);

    // view_tag_t: view tag
    m_view_tag = make_seraphis_view_tag(enote_privkey,
        recipient_view_key,
        enote_index,
        hw::get_device("default"));

    // R_t: enote pubkey to send back to caller
    make_seraphis_enote_pubkey(enote_privkey, recipient_DH_base, enote_pubkey_out);
}
//-------------------------------------------------------------------------------------------------------------------
void MockENoteSpV1::gen()
{
    // generate a dummy enote: random pieces, completely unspendable

    // gen base of enote
    this->gen_base();

    // memo
    m_encoded_amount = rct::randXmrAmount(rct::xmr_amount{static_cast<rct::xmr_amount>(-1)});
    m_view_tag = crypto::rand_idx(static_cast<unsigned char>(-1));
}
//-------------------------------------------------------------------------------------------------------------------
void MockENoteSpV1::append_to_string(std::string &str_inout) const
{
    // append all enote contents to the string
    // - assume the input string has enouch capacity
    str_inout.append((const char*) m_onetime_address.bytes, sizeof(rct::key));
    str_inout.append((const char*) m_amount_commitment.bytes, sizeof(rct::key));
    for (int i{7}; i >= 0; --i)
    {
        str_inout += static_cast<char>(m_encoded_amount >> i*8);
    }
    str_inout += static_cast<char>(m_view_tag);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t MockMembershipProofSpV1::get_size_bytes() const
{
    std::size_t num_elements = m_concise_grootle_proof.X.size();  // X

    if (m_concise_grootle_proof.f.size() > 0)
        num_elements += num_elements * m_concise_grootle_proof.f[0].size();  // f

    num_elements += 7;  // A, B, C, D, zA, zC, z

    return 32 * num_elements;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t MockImageProofSpV1::get_size_bytes() const
{
    return 32 * (3 + m_composition_proof.r_i.size() + m_composition_proof.K_t1.size());
}
//-------------------------------------------------------------------------------------------------------------------
void MockBalanceProofSpV1::append_to_string(const bool include_commitments, std::string &str_inout) const
{
    // append all proof contents to the string
    // - assume the input string has enouch capacity
    for (const auto &bpp_proof : m_bpp_proofs)
    {
        if (include_commitments)
        {
            for (std::size_t i{0}; i < bpp_proof.V.size(); ++i)
                str_inout.append((const char*) bpp_proof.V[i].bytes, sizeof(rct::key));
        }
        str_inout.append((const char*) bpp_proof.A.bytes, sizeof(rct::key));
        str_inout.append((const char*) bpp_proof.A1.bytes, sizeof(rct::key));
        str_inout.append((const char*) bpp_proof.B.bytes, sizeof(rct::key));
        str_inout.append((const char*) bpp_proof.r1.bytes, sizeof(rct::key));
        str_inout.append((const char*) bpp_proof.s1.bytes, sizeof(rct::key));
        str_inout.append((const char*) bpp_proof.d1.bytes, sizeof(rct::key));
        for (std::size_t n = 0; n < bpp_proof.L.size(); ++n)
            str_inout.append((const char*) bpp_proof.L[n].bytes, sizeof(rct::key));
        for (std::size_t n = 0; n < bpp_proof.R.size(); ++n)
            str_inout.append((const char*) bpp_proof.R[n].bytes, sizeof(rct::key));
    }
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t MockBalanceProofSpV1::get_size_bytes(const bool include_commitments /*=false*/) const
{
    // note: ignore the amount commitment set stored in the range proofs, they are double counted by the output set
    //TODO? don't store amount commitment set in range proofs at all
    std::size_t size{0};

    for (const auto &proof : m_bpp_proofs)
    {
        if (include_commitments)
            size += 32 * proof.V.size();

        size += 32 * (6 + proof.L.size() + proof.R.size());;
    }

    return size;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t MockSupplementSpV1::get_size_bytes() const
{
    return 32 * m_output_enote_pubkeys.size();
}
//-------------------------------------------------------------------------------------------------------------------
void MockInputProposalSpV1::gen(const rct::xmr_amount amount)
{
    // generate a tx input: random secrets, random memo pieces (does not support info recovery)

    // input secrets
    this->gen_base(amount);

    // enote pubkey (these are stored separate from enotes)
    m_enote_pubkey = rct::pkGen();

    // enote
    rct::key recipient_spendbase;
    make_seraphis_spendbase(m_spendbase_privkey, recipient_spendbase);

    m_enote.make_base_with_address_extension(m_enote_view_privkey, recipient_spendbase, m_amount_blinding_factor, m_amount);

    m_enote.m_view_tag = crypto::rand_idx(static_cast<unsigned char>(-1));
    m_enote.m_encoded_amount = rct::randXmrAmount(rct::xmr_amount{static_cast<rct::xmr_amount>(-1)});
}
//-------------------------------------------------------------------------------------------------------------------
void MockDestinationSpV1::get_amount_blinding_factor(const std::size_t enote_index, crypto::secret_key &amount_blinding_factor) const
{
    // r_t: sender-receiver shared secret
    crypto::secret_key sender_receiver_secret;
    make_seraphis_sender_receiver_secret(m_enote_privkey,
        m_recipient_viewkey,
        enote_index,
        hw::get_device("default"),
        sender_receiver_secret);

    // x_t: amount commitment mask (blinding factor)
    make_seraphis_amount_commitment_mask(sender_receiver_secret, amount_blinding_factor);
}
//-------------------------------------------------------------------------------------------------------------------
MockENoteSpV1 MockDestinationSpV1::to_enote_v1(const std::size_t output_index, rct::key &enote_pubkey_out) const
{
    MockENoteSpV1 enote;

    enote.make(m_enote_privkey,
        m_recipient_DHkey,
        m_recipient_viewkey,
        m_recipient_spendkey,
        m_amount,
        output_index,
        enote_pubkey_out);

    return enote;
}
//-------------------------------------------------------------------------------------------------------------------
void MockDestinationSpV1::gen(const rct::xmr_amount amount)
{
    // gen base of destination
    this->gen_base(amount);

    m_enote_privkey = rct::rct2sk(rct::skGen());
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace mock_tx
