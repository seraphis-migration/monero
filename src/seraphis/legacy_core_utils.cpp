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
#include "legacy_core_utils.h"

//local headers
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_basic/subaddress_index.h"
#include "device/device.hpp"
#include "int-util.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_subaddress_spendkey(const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_view_privkey,
    const cryptonote::subaddress_index &subaddress_index,
    rct::key &subaddress_spendkey_out)
{
    // Hn(k^v, i) = Hn("SubAddr" || k^v || index_major || index_minor)
    const crypto::secret_key subaddress_modifier{
            hw::get_device("default").get_subaddress_secret_key(legacy_view_privkey, subaddress_index)
        };

    // Hn(k^v, i) G
    rct::key subaddress_extension;
    rct::scalarmultBase(subaddress_extension, rct::sk2rct(subaddress_modifier));

    // K^{s,i} = Hn(k^v, i) G + k^s G
    rct::addKeys(subaddress_spendkey_out, subaddress_extension, legacy_base_spend_pubkey);
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_sender_receiver_secret(const rct::key &base_key,
    const std::uint64_t tx_output_index,
    const crypto::secret_key &DH_privkey,
    crypto::secret_key &legacy_sender_receiver_secret_out)
{
    // r K^v
    crypto::key_derivation derivation;
    hw::get_device("default").generate_key_derivation(rct::rct2pk(base_key), DH_privkey, derivation);

    // Hn(r K^v, t)
    hw::get_device("default").derivation_to_scalar(derivation, tx_output_index, legacy_sender_receiver_secret_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_enote_view_privkey(const std::uint64_t tx_output_index,
    const crypto::key_derivation &sender_receiver_DH_derivation,
    const crypto::secret_key &legacy_view_privkey,
    const boost::optional<cryptonote::subaddress_index> &subaddress_index,
    crypto::secret_key &enote_view_privkey_out)
{
    // Hn(r K^v, t)
    crypto::derivation_to_scalar(sender_receiver_DH_derivation, tx_output_index, enote_view_privkey_out);

    // subaddress index modifier
    if (subaddress_index)
    {
        // Hn(k^v, i) = Hn(k^v || index_major || index_minor)
        const crypto::secret_key subaddress_modifier{
                hw::get_device("default").get_subaddress_secret_key(legacy_view_privkey, *subaddress_index)
            };

        // Hn(r K^v, t) + Hn(k^v, i)
        sc_add(to_bytes(enote_view_privkey_out), to_bytes(enote_view_privkey_out), to_bytes(subaddress_modifier));
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_onetime_address(const rct::key &destination_spendkey,
    const rct::key &destination_viewkey,
    const std::uint64_t tx_output_index,
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
        tx_output_index,
        rct::rct2pk(destination_spendkey),
        onetime_address_temp);

    onetime_address_out = rct::pk2rct(onetime_address_temp);
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_key_image(const crypto::secret_key &enote_view_privkey,
    const crypto::secret_key &legacy_spend_privkey,
    const rct::key &onetime_address,
    crypto::key_image &key_image_out)
{
    // KI = (view_key_stuff + k^s) * Hp(Ko)
    crypto::secret_key onetime_address_privkey;
    sc_add(to_bytes(onetime_address_privkey), to_bytes(enote_view_privkey), to_bytes(legacy_spend_privkey));

    crypto::generate_key_image(rct::rct2pk(onetime_address), onetime_address_privkey, key_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_amount_blinding_factor_v2(const crypto::secret_key &sender_receiver_secret,
    crypto::secret_key &amount_blinding_factor_out)
{
    // Hn("commitment_mask", Hn(r K^v, t))
    char data[15 + sizeof(rct::key)];
    memcpy(data, "commitment_mask", 15);
    memcpy(data + 15, to_bytes(sender_receiver_secret), sizeof(rct::key));
    crypto::hash_to_scalar(data, sizeof(data), amount_blinding_factor_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_amount_blinding_factor_v2(const rct::key &destination_viewkey,
    const std::uint64_t tx_output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    crypto::secret_key &amount_blinding_factor_out)
{
    // Hn(r K^v, t)
    crypto::secret_key sender_receiver_secret;
    make_legacy_sender_receiver_secret(destination_viewkey,
        tx_output_index,
        enote_ephemeral_privkey,
        sender_receiver_secret);

    // amount mask: Hn("commitment_mask", Hn(r K^v, t))
    make_legacy_amount_blinding_factor_v2(sender_receiver_secret, amount_blinding_factor_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_amount_encoding_factor_v2(const crypto::secret_key &sender_receiver_secret,
    rct::key &amount_encoding_factor_out)
{
    // H32("amount", Hn(r K^v, t))
    char data[6 + sizeof(rct::key)];
    memcpy(data, "amount", 6);
    memcpy(data + 6, to_bytes(sender_receiver_secret), sizeof(rct::key));
    rct::cn_fast_hash(amount_encoding_factor_out, data, sizeof(data));
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount legacy_xor_amount(const rct::xmr_amount amount, const rct::key &encoding_factor)
{
    // a XOR_8 factor
    rct::xmr_amount factor;
    memcpy(&factor, encoding_factor.bytes, 8);

    return SWAP64LE(amount) ^ factor;
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount legacy_xor_encoded_amount(const rct::xmr_amount encoded_amount, const rct::key &encoding_factor)
{
    // a XOR_8 factor
    rct::xmr_amount factor;
    memcpy(&factor, encoding_factor.bytes, 8);

    return SWAP64LE(encoded_amount ^ factor);
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_encoded_amount_v1(const rct::key &destination_viewkey,
    const std::uint64_t tx_output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    const crypto::secret_key &amount_mask,
    const rct::xmr_amount amount,
    rct::key &encoded_amount_blinding_factor_out,
    rct::key &encoded_amount_out)
{
    // Hn(r K^v, t)
    crypto::secret_key sender_receiver_secret;
    make_legacy_sender_receiver_secret(destination_viewkey,
        tx_output_index,
        enote_ephemeral_privkey,
        sender_receiver_secret);

    // encoded amount blinding factor: enc(x) = x + Hn(Hn(r K^v, t))
    const rct::key mask_factor{rct::hash_to_scalar(rct::sk2rct(sender_receiver_secret))};  //Hn(Hn(r K^v, t))
    sc_add(encoded_amount_blinding_factor_out.bytes, to_bytes(amount_mask), mask_factor.bytes);

    // encoded amount: enc(a) = to_key(little_endian(a)) + Hn(Hn(Hn(r K^v, t)))
    const rct::key amount_factor{rct::hash_to_scalar(mask_factor)};                        //Hn(Hn(Hn(r K^v, t)))
    d2h(encoded_amount_out, amount);
    sc_add(encoded_amount_out.bytes, encoded_amount_out.bytes, amount_factor.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_encoded_amount_v2(const rct::key &destination_viewkey,
    const std::uint64_t tx_output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    const rct::xmr_amount amount,
    rct::xmr_amount &encoded_amount_out)
{
    // Hn(r K^v, t)
    crypto::secret_key sender_receiver_secret;
    make_legacy_sender_receiver_secret(destination_viewkey,
        tx_output_index,
        enote_ephemeral_privkey,
        sender_receiver_secret);

    // encoded amount: enc(a) = a XOR_8 H32("amount", Hn(r K^v, t))
    rct::key encoded_amount_factor;
    make_legacy_amount_encoding_factor_v2(sender_receiver_secret, encoded_amount_factor);

    encoded_amount_out = legacy_xor_amount(amount, encoded_amount_factor);
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_view_tag(const rct::key &destination_viewkey,
    const std::uint64_t tx_output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    crypto::view_tag &view_tag_out)
{
    // r K^v
    crypto::key_derivation derivation;
    hw::get_device("default").generate_key_derivation(rct::rct2pk(destination_viewkey),
        enote_ephemeral_privkey,
        derivation);

    // view_tag = H_1("view_tag", r K^v, t)
    crypto::derive_view_tag(derivation, tx_output_index, view_tag_out);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
