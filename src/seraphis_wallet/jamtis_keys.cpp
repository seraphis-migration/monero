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
#include "jamtis_keys.h"

//local headers
#include "crypto/chacha.h"
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_account_secrets.h"
#include "seraphis_core/sp_core_enote_utils.h"
#include "seraphis_wallet/key_container.h"
#include <cassert>
#include <openssl/crypto.h>
#include <sodium/crypto_verify_32.h>

//third party headers

//standard headers


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_wallet"

namespace {

bool is_zero(crypto::secret_key k)
{
    return crypto_verify_32((unsigned char*)k.data, rct::zero().bytes);
}

bool is_zero(crypto::x25519_secret_key k)
{
    return crypto_verify_32(k.data, rct::zero().bytes);
}

bool is_one(crypto::secret_key k)
{
    return crypto_verify_32((unsigned char*)k.data, rct::identity().bytes);
}

bool is_one(crypto::x25519_secret_key k)
{
    return crypto_verify_32((unsigned char*)k.data, rct::identity().bytes);
}
void derive_key(const crypto::chacha_key &base_key, crypto::chacha_key &key)
{
    static_assert(sizeof(base_key) == sizeof(crypto::hash), "chacha key and hash should be the same size");

    epee::mlocked<tools::scrubbed_arr<char, sizeof(base_key) + 1>> data;
    memcpy(data.data(), &base_key, sizeof(base_key));
    data[sizeof(base_key)] = 'k';
    crypto::generate_chacha_key(data.data(), sizeof(data), key, 1);
}

epee::wipeable_string get_key_stream(const crypto::chacha_key &base_key, const crypto::chacha_iv &iv, size_t bytes)
{
    // derive a new key
    crypto::chacha_key key;
    derive_key(base_key, key);

    // chacha
    epee::wipeable_string buffer0(std::string(bytes, '\0'));
    epee::wipeable_string buffer1 = buffer0;
    crypto::chacha20(buffer0.data(), buffer0.size(), key, iv, buffer1.data());
    return buffer1;
}

} // namespace

namespace sp
{
namespace jamtis
{

//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_keys(JamtisKeys &keys_out)
{
    keys_out.k_m  = rct::rct2sk(rct::skGen());
    keys_out.k_vb = rct::rct2sk(rct::skGen());
    make_jamtis_viewreceived_key(keys_out.k_vb, keys_out.d_vr);
    make_jamtis_filterassist_key(keys_out.d_vr, keys_out.d_fa);
    make_jamtis_generateaddress_secret(keys_out.d_vr, keys_out.s_ga);
    make_jamtis_ciphertag_secret(keys_out.s_ga, keys_out.s_ct);
    make_seraphis_spendkey(keys_out.k_vb, keys_out.k_m, keys_out.K_s_base);
    make_jamtis_exchangebase_pubkey(keys_out.d_vr, keys_out.D_base);
    make_jamtis_viewreceived_pubkey(keys_out.d_vr, keys_out.D_base, keys_out.D_vr);
    make_jamtis_filterassist_pubkey(keys_out.d_fa, keys_out.D_base, keys_out.D_fa);
}
//-------------------------------------------------------------------------------------------------------------------
// See wiki page
seraphis_wallet::WalletType get_wallet_type(const JamtisKeys &keys) 
{
    if (!is_zero(keys.k_m))
    {
        assert(!is_zero(keys.k_vb));
        return seraphis_wallet::WalletType::Master;
    }

    if (!is_zero(keys.k_vb))
    {
        return seraphis_wallet::WalletType::ViewAll;
    }

    if (!is_zero(keys.d_vr)) {
        return seraphis_wallet::WalletType::PaymentValidator;
    }

    if (is_one(keys.d_fa) && is_one(keys.s_ga))
    {
        return seraphis_wallet::WalletType::FilterAssistAndAddressGen;
    }

    if (is_zero(keys.d_fa) && is_one(keys.s_ga))
    {
        return seraphis_wallet::WalletType::AddressGenerator;
    }
    
    if (is_zero(keys.d_fa) && is_zero(keys.s_ga))
    {
        return seraphis_wallet::WalletType::FilterAssist;
    }

    return seraphis_wallet::WalletType::Empty;
}
//-------------------------------------------------------------------------------------------------------------------
void derive_jamtis_keys_from_existing(JamtisKeys &keys)
{
    make_jamtis_viewreceived_key(keys.k_vb, keys.d_vr);
    make_jamtis_filterassist_key(keys.d_vr, keys.d_fa);
    make_jamtis_generateaddress_secret(keys.d_vr, keys.s_ga);
    make_jamtis_ciphertag_secret(keys.s_ga, keys.s_ct);
    make_seraphis_spendkey(keys.k_vb, keys.k_m, keys.K_s_base);
    make_jamtis_exchangebase_pubkey(keys.d_vr, keys.D_base);
    make_jamtis_viewreceived_pubkey(keys.d_vr, keys.D_base, keys.D_vr);
    make_jamtis_filterassist_pubkey(keys.d_fa, keys.D_base, keys.D_fa);
}
//-------------------------------------------------------------------------------------------------------------------
void make_address_for_user(const JamtisKeys &user_keys,
    const address_index_t &j,
    JamtisDestinationV1 &user_address_out)
{
    make_jamtis_destination_v1(user_keys.K_s_base,
        user_keys.D_fa,
        user_keys.D_vr,
        user_keys.D_base,
        user_keys.s_ga,
        j,
        user_address_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_random_address_for_user(const JamtisKeys &user_keys, JamtisDestinationV1 &user_address_out)
{
    const address_index_t random_j = gen_address_index();

    make_address_for_user(user_keys, random_j, user_address_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_amount(const JamtisKeys &user_keys, JamtisDestinationV1 &user_address_out)
{
    const address_index_t random_j = gen_address_index();

    make_address_for_user(user_keys, random_j, user_address_out);
}
//-------------------------------------------------------------------------------------------------------------------
void xor_with_key_stream(const crypto::chacha_key &chacha_key,
    const crypto::chacha_iv chacha_iv,
    JamtisKeys &keys)
{
    // we have 6 private keys
    epee::wipeable_string key_stream = get_key_stream(chacha_key, chacha_iv, 6 * sizeof(crypto::secret_key));
    const char *ptr = key_stream.data();

    for (size_t i = 0; i < sizeof(crypto::secret_key); ++i) keys.k_m.data[i] ^= *ptr++;
    for (size_t i = 0; i < sizeof(crypto::secret_key); ++i) keys.k_vb.data[i] ^= *ptr++;
    for (size_t i = 0; i < sizeof(crypto::secret_key); ++i) keys.d_fa.data[i] ^= *ptr++;
    for (size_t i = 0; i < sizeof(crypto::secret_key); ++i) keys.d_vr.data[i] ^= *ptr++;
    for (size_t i = 0; i < sizeof(crypto::secret_key); ++i) keys.s_ga.data[i] ^= *ptr++;
    for (size_t i = 0; i < sizeof(crypto::secret_key); ++i) keys.s_ct.data[i] ^= *ptr++;
}
//-------------------------------------------------------------------------------------------------------------------
bool jamtis_keys_equal(const JamtisKeys &keys, const JamtisKeys &other)
{
    return (keys.k_m == other.k_m) &&
           (keys.k_vb == other.k_vb) &&
           (keys.d_vr == other.d_vr) &&
           (keys.d_fa == other.d_fa) &&
           (keys.s_ga == other.s_ga) &&
           (keys.s_ct == other.s_ct) &&
           (keys.K_s_base == other.K_s_base) &&
           (keys.D_vr == other.D_vr) &&
           (keys.D_fa == other.D_fa) &&
           (keys.D_base == other.D_base);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp
