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
#include "legacy_enote_utils.h"

//local headers
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "device/device.hpp"
#include "int-util.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_crypto_utils.h"

//third party headers

//standard headers


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_encoded_amount_factor(const crypto::secret_key &sender_receiver_secret,
    rct::key &encoded_amount_factor_out)
{
    // Hn("amount", Hn(r K^v, t))
    char data[6 + sizeof(rct::key)];
    memcpy(data, "amount", 6);
    memcpy(data + 6, to_bytes(sender_receiver_secret), sizeof(rct::key));
    rct::cn_fast_hash(encoded_amount_factor_out, data, sizeof(data));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static rct::xmr_amount xor_amount(const rct::xmr_amount amount, const rct::key &encoding_factor)
{
    // a XOR_8 factor
    rct::xmr_amount factor;
    memcpy(&factor, encoding_factor.bytes, 8);

    return SWAP64LE(amount) ^ factor;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void compute_legacy_sender_receiver_secret(const rct::key &destination_viewkey,
    const std::uint64_t output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    crypto::secret_key &legacy_sender_receiver_secret_out)
{
    // r K^v
    crypto::key_derivation derivation;
    hw::get_device("default").generate_key_derivation(rct::rct2pk(destination_viewkey),
        enote_ephemeral_privkey,
        derivation);

    // Hn(r K^v, t)
    hw::get_device("default").derivation_to_scalar(derivation, output_index, legacy_sender_receiver_secret_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_legacy_onetime_address(const rct::key &destination_spendkey,
    const rct::key &destination_viewkey,
    const std::uint64_t output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    rct::key &onetime_address_out)
{
    // r K^v
    crypto::key_derivation derivation;
    hw::get_device("default").generate_key_derivation(rct::rct2pk(destination_viewkey),
        enote_ephemeral_privkey,
        derivation);

    // K^o = Hn(r K^v, t) G + K^s
    crypto::public_key onetime_address_temp;
    hw::get_device("default").derive_public_key(derivation,
        output_index,
        rct::rct2pk(destination_spendkey),
        onetime_address_temp);

    onetime_address_out = rct::pk2rct(onetime_address_temp);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void encode_legacy_amount_v1(const rct::key &destination_viewkey,
    const std::uint64_t output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    const crypto::secret_key &amount_mask,
    const rct::xmr_amount amount,
    rct::key &encoded_amount_mask_out,
    rct::key &encoded_amount_out)
{
    // Hn(r K^v, t)
    crypto::secret_key sender_receiver_secret;
    compute_legacy_sender_receiver_secret(destination_viewkey,
        output_index,
        enote_ephemeral_privkey,
        sender_receiver_secret);

    // encoded amount mask: enc(x) = x + Hn(Hn(r K^v, t))
    const rct::key mask_factor{rct::hash_to_scalar(rct::sk2rct(sender_receiver_secret))};  //Hn(Hn(r K^v, t))
    sc_add(encoded_amount_mask_out.bytes, to_bytes(amount_mask), mask_factor.bytes);

    // encoded amount: enc(a) = to_key(a) + Hn(Hn(Hn(r K^v, t)))
    const rct::key amount_factor{rct::hash_to_scalar(mask_factor)};           //Hn(Hn(Hn(r K^v, t)))
    d2h(encoded_amount_out, amount);
    sc_add(encoded_amount_out.bytes, encoded_amount_out.bytes, amount_factor.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void encode_legacy_amount_v2(const rct::key &destination_viewkey,
    const std::uint64_t output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    const rct::xmr_amount amount,
    rct::xmr_amount &encoded_amount_out)
{
    // Hn(r K^v, t)
    crypto::secret_key sender_receiver_secret;
    compute_legacy_sender_receiver_secret(destination_viewkey,
        output_index,
        enote_ephemeral_privkey,
        sender_receiver_secret);

    // encoded amount: enc(a) = a XOR_8 Hn("amount", Hn(r K^v, t))
    rct::key encoded_amount_factor;
    make_encoded_amount_factor(sender_receiver_secret, encoded_amount_factor);

    encoded_amount_out = xor_amount(amount, encoded_amount_factor);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_legacy_amount_mask_v2(const rct::key &destination_viewkey,
    const std::uint64_t output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    rct::key &amount_mask_out)
{
    // Hn(r K^v, t)
    crypto::secret_key sender_receiver_secret;
    compute_legacy_sender_receiver_secret(destination_viewkey,
        output_index,
        enote_ephemeral_privkey,
        sender_receiver_secret);

    // amount mask: Hn("commitment_mask", Hn(r K^v, t))
    char data[15 + sizeof(rct::key)];
    memcpy(data, "commitment_mask", 15);
    memcpy(data + 15, to_bytes(sender_receiver_secret), sizeof(rct::key));
    rct::cn_fast_hash(amount_mask_out, data, sizeof(data));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_legacy_view_tag(const rct::key &destination_viewkey,
    const std::uint64_t output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    crypto::view_tag &view_tag_out)
{
    // r K^v
    crypto::key_derivation derivation;
    hw::get_device("default").generate_key_derivation(rct::rct2pk(destination_viewkey),
        enote_ephemeral_privkey,
        derivation);

    // view_tag = H_1("view_tag", r K^v, t)
    crypto::derive_view_tag(derivation, output_index, view_tag_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_enote_v1(const rct::key &destination_spendkey,
    const rct::key &destination_viewkey,
    const rct::xmr_amount amount,
    const std::uint64_t output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    LegacyEnoteV1 &enote_out)
{
    // onetime address (normal address): K^o = Hn(r K^v, t) G + K^s
    make_legacy_onetime_address(destination_spendkey,
        destination_viewkey,
        output_index,
        enote_ephemeral_privkey,
        enote_out.m_onetime_address);

    // amount: a
    enote_out.m_amount = amount;
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_enote_v2(const rct::key &destination_spendkey,
    const rct::key &destination_viewkey,
    const rct::xmr_amount amount,
    const std::uint64_t output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    LegacyEnoteV2 &enote_out)
{
    // onetime address (normal address): K^o = Hn(r K^v, t) G + K^s
    make_legacy_onetime_address(destination_spendkey,
        destination_viewkey,
        output_index,
        enote_ephemeral_privkey,
        enote_out.m_onetime_address);

    // amount commitment: x G + a H
    const crypto::secret_key amount_mask{rct::rct2sk(rct::skGen())};
    enote_out.m_amount_commitment = rct::commit(amount, rct::sk2rct(amount_mask));

    // encoded amount mask: enc(x) = x + Hn(Hn(r K^v, t))
    // encoded amount: enc(a) = to_key(a) + Hn(Hn(Hn(r K^v, t)))
    encode_legacy_amount_v1(destination_viewkey,
        output_index,
        enote_ephemeral_privkey,
        amount_mask,
        amount,
        enote_out.m_encoded_amount_mask,
        enote_out.m_encoded_amount);
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_enote_v3(const rct::key &destination_spendkey,
    const rct::key &destination_viewkey,
    const rct::xmr_amount amount,
    const std::uint64_t output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    LegacyEnoteV3 &enote_out)
{
    // onetime address (normal address): K^o = Hn(r K^v, t) G + K^s
    make_legacy_onetime_address(destination_spendkey,
        destination_viewkey,
        output_index,
        enote_ephemeral_privkey,
        enote_out.m_onetime_address);

    // amount commitment: Hn("commitment_mask", Hn(r K^v, t)) G + a H
    rct::key amount_mask;
    make_legacy_amount_mask_v2(destination_viewkey, output_index, enote_ephemeral_privkey, amount_mask);

    enote_out.m_amount_commitment = rct::commit(amount, amount_mask);

    // encoded amount: enc(a) = a XOR_8 Hn("amount", Hn(r K^v, t))
    encode_legacy_amount_v2(destination_viewkey,
        output_index,
        enote_ephemeral_privkey,
        amount,
        enote_out.m_encoded_amount);
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_enote_v4(const rct::key &destination_spendkey,
    const rct::key &destination_viewkey,
    const rct::xmr_amount amount,
    const std::uint64_t output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    LegacyEnoteV4 &enote_out)
{
    // onetime address (normal address): K^o = Hn(r K^v, t) G + K^s
    make_legacy_onetime_address(destination_spendkey,
        destination_viewkey,
        output_index,
        enote_ephemeral_privkey,
        enote_out.m_onetime_address);

    // amount commitment: Hn("commitment_mask", Hn(r K^v, t)) G + a H
    rct::key amount_mask;
    make_legacy_amount_mask_v2(destination_viewkey, output_index, enote_ephemeral_privkey, amount_mask);

    enote_out.m_amount_commitment = rct::commit(amount, amount_mask);

    // encoded amount: enc(a) = a XOR_8 Hn("amount", Hn(r K^v, t))
    encode_legacy_amount_v2(destination_viewkey,
        output_index,
        enote_ephemeral_privkey,
        amount,
        enote_out.m_encoded_amount);

    // view tag: 
    make_legacy_view_tag(destination_viewkey, output_index, enote_ephemeral_privkey, enote_out.m_view_tag);
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_ephemeral_pubkey_shared(const crypto::secret_key &enote_ephemeral_privkey,
    rct::key &enote_ephemeral_pubkey_out)
{
    // enote ephemeral pubkey (basic): r G
    rct::scalarmultBase(enote_ephemeral_pubkey_out, rct::sk2rct(enote_ephemeral_privkey));
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_ephemeral_pubkey_single(const rct::key &destination_spendkey,
    const crypto::secret_key &enote_ephemeral_privkey,
    rct::key &enote_ephemeral_pubkey_out)
{
    // enote ephemeral pubkey (for single enote): r K^s
    rct::scalarmultKey(enote_ephemeral_pubkey_out, destination_spendkey, rct::sk2rct(enote_ephemeral_privkey));
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
