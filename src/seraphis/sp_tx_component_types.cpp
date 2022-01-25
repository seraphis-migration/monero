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
#include "sp_tx_component_types.h"

//local headers
#include "crypto/crypto.h"
#include "device/device.hpp"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_core_types.h"
#include "sp_core_utils.h"

//third party headers

//standard headers
#include <algorithm>
#include <memory>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteV1::make(const crypto::secret_key &enote_privkey,
    const rct::key &recipient_DH_base,
    const rct::key &recipient_view_key,
    const rct::key &recipient_spend_key,
    const rct::xmr_amount amount,
    const std::size_t enote_index,
    const bool lock_amounts_to_DH_key,
    rct::key &enote_pubkey_out)
{
    // note: t = enote_index

    // r_t: sender-receiver shared secret
    rct::key sender_receiver_secret;
    auto a_wiper = epee::misc_utils::create_scope_leave_handler([&]{
        memwipe(&sender_receiver_secret, sizeof(rct::key));
    });
    make_seraphis_sender_receiver_secret(enote_privkey,
        recipient_view_key,
        enote_index,
        hw::get_device("default"),
        sender_receiver_secret);

    // make extra key for locking ENote amounts to the recipient's DH base key (DH_base = DH_base_key * G)
    rct::key extra_key_amounts{rct::zero()};
    if (lock_amounts_to_DH_key)
        rct::scalarmultBase(extra_key_amounts, rct::sk2rct(enote_privkey));

    // x_t: amount commitment mask (blinding factor)
    crypto::secret_key amount_mask;
    make_seraphis_amount_commitment_mask(rct::rct2sk(sender_receiver_secret), extra_key_amounts, amount_mask);

    // k_{a, sender, t}: extension to add to user's spend key
    crypto::secret_key k_a_extender;
    make_seraphis_sender_address_extension(rct::rct2sk(sender_receiver_secret), k_a_extender);

    // make the base of the enote (Ko_t, C_t)
    this->make_base_with_address_extension(k_a_extender, recipient_spend_key, amount_mask, amount);

    // enc(a_t): encoded amount
    m_encoded_amount = enc_dec_seraphis_amount(rct::rct2sk(sender_receiver_secret), extra_key_amounts, amount);

    // view_tag_t: view tag
    m_view_tag = make_seraphis_view_tag(enote_privkey,
        recipient_view_key,
        enote_index,
        hw::get_device("default"));

    // R_t: enote pubkey to send back to caller
    make_seraphis_enote_pubkey(enote_privkey, recipient_DH_base, enote_pubkey_out);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteV1::gen()
{
    // generate a dummy enote: random pieces, completely unspendable

    // gen base of enote
    this->gen_base();

    // memo
    m_encoded_amount = rct::randXmrAmount(rct::xmr_amount{static_cast<rct::xmr_amount>(-1)});
    m_view_tag = crypto::rand_idx(static_cast<unsigned char>(-1));
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteV1::append_to_string(std::string &str_inout) const
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
std::size_t SpMembershipProofV1::get_size_bytes() const
{
    std::size_t num_elements = m_concise_grootle_proof.X.size();  // X

    if (m_concise_grootle_proof.f.size() > 0)
        num_elements += num_elements * m_concise_grootle_proof.f[0].size();  // f

    num_elements += 7;  // A, B, C, D, zA, zC, z

    return 32 * num_elements;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t SpImageProofV1::get_size_bytes() const
{
    return 32 * 5;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t SpBalanceProofV1::get_size_bytes(const bool include_commitments /*=false*/) const
{
    // note: ignore the amount commitment set stored in the range proofs, they are double counted by the output set
    //TODO? don't store amount commitment set in range proofs at all
    std::size_t size{0};

    // BP+ proof
    if (include_commitments)
        size += 32 * m_bpp_proof.V.size();
    size += 32 * (6 + m_bpp_proof.L.size() + m_bpp_proof.R.size());;

    // remainder blinding factor
    size += 32;

    return size;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t SpTxSupplementV1::get_size_bytes() const
{
    return 32 * m_output_enote_pubkeys.size();
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
