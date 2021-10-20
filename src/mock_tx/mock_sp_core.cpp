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
#include "mock_sp_core.h"

//local headers
#include "common/varint.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_config.h"
#include "misc_log_ex.h"
#include "mock_tx_utils.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_crypto_utils.h"
#include "wipeable_string.h"

//third party headers

//standard headers
#include <string>
#include <vector>


namespace mock_tx
{
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_key_image(const crypto::secret_key &y, const crypto::secret_key &z, crypto::key_image &key_image_out)
{
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(&z), "z must be nonzero for making a key image!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(&y), "y must be nonzero for making a key image!");

    // KI = (z/y)*U
    rct::key temp = sp::invert(rct::sk2rct(y)); // 1/y
    sc_mul(temp.bytes, &z, temp.bytes); // z*(1/y)
    rct::scalarmultKey(temp, sp::get_U_gen(), temp); // (z/y)*U

    key_image_out = rct::rct2ki(temp);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_key_image(const crypto::secret_key &y, const rct::key &zU, crypto::key_image &key_image_out)
{
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(&y), "y must be nonzero for making a key image!");
    CHECK_AND_ASSERT_THROW_MES(!(zU == rct::identity()), "zU must not be identity element for making a key image!");

    // KI = (z/y)*U
    rct::key temp = sp::invert(rct::sk2rct(y)); // 1/y
    rct::scalarmultKey(temp, zU, temp); // (z/y)*U

    key_image_out = rct::rct2ki(temp);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_key_image_from_parts(const crypto::secret_key &k_a_sender,
    const crypto::secret_key &k_a_recipient,
    const rct::key &k_bU,
    crypto::key_image &key_image_out)
{
    // KI = (k_b/(k_a_sender + k_a_recipient))*U
    crypto::secret_key k_a_combined;
    sc_add(&k_a_combined, &k_a_sender, &k_a_recipient);

    make_seraphis_key_image(k_a_combined, k_bU, key_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_spendbase(const crypto::secret_key &spendbase_privkey, rct::key &spendbase_pubkey_out)
{
    // spendbase = k_{b, recipient} U
    rct::scalarmultKey(spendbase_pubkey_out, sp::get_U_gen(), rct::sk2rct(spendbase_privkey));
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_spendkey(const crypto::secret_key &k_a, const crypto::secret_key &k_b, rct::key &spendkey_out)
{
    // K = k_a X + k_b U
    make_seraphis_spendbase(k_b, spendkey_out);

    // finish address
    extend_seraphis_spendkey(k_a, spendkey_out);
}
//-------------------------------------------------------------------------------------------------------------------
void extend_seraphis_spendkey(const crypto::secret_key &k_a_extender, rct::key &spendkey_inout)
{
    // K = k_a_extender X + K_original
    rct::key address_temp;

    rct::scalarmultKey(address_temp, sp::get_X_gen(), rct::sk2rct(k_a_extender));
    rct::addKeys(spendkey_inout, address_temp, spendkey_inout);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_enote_pubkey(const crypto::secret_key &enote_privkey, const rct::key &DH_base, rct::key &enote_pubkey_out)
{
    // R_t = r_t K^{DH}_t
    rct::scalarmultKey(enote_pubkey_out, DH_base, rct::sk2rct(enote_privkey));
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_sender_receiver_secret(const crypto::secret_key &privkey,
    const rct::key &DH_key,
    const std::size_t enote_index,
    crypto::secret_key &sender_receiver_secret_out)
{
    // q_t = H(r_t * k^{vr} * K^{DH}, t) => H("domain sep", privkey * DH_key, enote_index)
    rct::key derivation;
    rct::scalarmultKey(derivation, DH_key, rct::sk2rct(privkey));  // privkey * DH_key

    epee::wipeable_string hash;
    hash.reserve(sizeof(config::HASH_KEY_SERAPHIS_SENDER_RECEIVER_SECRET) + sizeof(rct::key) +
        ((sizeof(std::size_t) * 8 + 6) / 7));
    // "domain-sep"
    hash = config::HASH_KEY_SERAPHIS_SENDER_RECEIVER_SECRET;
    // privkey*DH_key
    hash.append((const char*) derivation.bytes, sizeof(rct::key));
    // enote_index
    char converted_index[(sizeof(size_t) * 8 + 6) / 7];
    char* end = converted_index;
    tools::write_varint(end, enote_index);
    assert(end <= converted_index + sizeof(converted_index));
    hash.append(converted_index, end - converted_index);

    // q_t
    //TODO: is this inefficient use of hash_to_scalar? e.g. ringct has various seemingly optimized calls into keccak()
    crypto::hash_to_scalar(hash.data(), hash.size(), sender_receiver_secret_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_sender_address_extension(const crypto::secret_key &sender_receiver_secret,
    crypto::secret_key &sender_address_extension_out)
{
    // k_{a, sender} = H("domain-sep", q_t)
    std::string salt(config::HASH_KEY_SERAPHIS_SENDER_ADDRESS_EXTENSION);
    sp::domain_separate_rct_hash(salt, rct::sk2rct(sender_receiver_secret), sender_address_extension_out);
}
//-------------------------------------------------------------------------------------------------------------------
unsigned char make_seraphis_view_tag(const crypto::secret_key &sender_receiver_secret)
{
    // tag_t = H("domain-sep", q_t)
    crypto::secret_key hash_result;
    std::string salt(config::HASH_KEY_SERAPHIS_VIEW_TAG);
    sp::domain_separate_rct_hash(salt, rct::sk2rct(sender_receiver_secret), hash_result);

    return static_cast<unsigned char>(hash_result.data[0]);
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount enc_dec_seraphis_amount(const crypto::secret_key &sender_receiver_secret, const rct::xmr_amount original)
{
    // ret = H("domain-sep", q_t) XOR_64 original
    crypto::secret_key hash_result;
    std::string salt(config::HASH_KEY_SERAPHIS_AMOUNT_ENC);
    sp::domain_separate_rct_hash(salt, rct::sk2rct(sender_receiver_secret), hash_result);

    rct::xmr_amount mask{0};
    rct::xmr_amount temp{0};

    for (int i = 0; i < 8; ++i)
    {
        temp = hash_result.data[i];
        mask ^= (temp << i*8);
    }

    return original ^ mask;
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_amount_commitment_mask(const crypto::secret_key &sender_receiver_secret, crypto::secret_key &mask_out)
{
    // x_t = H("domain-sep", q_t)
    std::string salt(config::HASH_KEY_SERAPHIS_AMOUNT_COMMITMENT_BLINDING_FACTOR);
    sp::domain_separate_rct_hash(salt, rct::sk2rct(sender_receiver_secret), mask_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_seraphis_nominal_spend_key(const crypto::secret_key &sender_receiver_secret,
    const rct::key &onetime_address,
    const unsigned char view_tag,
    rct::key &nominal_spend_key_out)
{
    // tag'_t = H(q_t)
    unsigned char nominal_view_tag{make_seraphis_view_tag(sender_receiver_secret)};

    // check that recomputed tag matches original tag; short-circuit on failure
    if (nominal_view_tag != view_tag)
        return false;

    // K'^s_t = Ko_t - H(q_t) X
    crypto::secret_key k_a_extender;
    make_seraphis_sender_address_extension(sender_receiver_secret, k_a_extender);  // H(q_t)
    sc_mul(&k_a_extender, sp::MINUS_ONE.bytes, &k_a_extender);  // -H(q_t)
    nominal_spend_key_out = onetime_address;  // Ko_t
    extend_seraphis_spendkey(k_a_extender, nominal_spend_key_out); // (-H(q_t)) X + Ko_t

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_seraphis_amount(const crypto::secret_key &sender_receiver_secret,
    const rct::key &amount_commitment,
    const rct::xmr_amount encoded_amount,
    rct::xmr_amount &amount_out)
{
    // a' = dec(encoded_amount)
    rct::xmr_amount nominal_amount{enc_dec_seraphis_amount(sender_receiver_secret, encoded_amount)};

    // C' = x' G + a' H
    crypto::secret_key nominal_amount_commitment_mask;
    make_seraphis_amount_commitment_mask(sender_receiver_secret, nominal_amount_commitment_mask);  // x'
    rct::key nominal_amount_commitment = rct::commit(nominal_amount, rct::sk2rct(nominal_amount_commitment_mask));

    // check that recomputed commitment matches original commitment
    if (!(nominal_amount_commitment == amount_commitment))
        return false;
    else
    {
        amount_out = nominal_amount;
        return true;
    }
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace mock_tx
