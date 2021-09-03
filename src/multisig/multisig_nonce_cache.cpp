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
#include "multisig_nonce_cache.h"

//local headers
#include "common/container_helpers.h"
#include "crypto/crypto.h"
#include "misc_log_ex.h"
#include "multisig_signer_set_filter.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_crypto/sp_transcript.h"

//third party headers
#include <boost/utility/string_ref.hpp>

//standard headers
#include <tuple>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "multisig"

namespace multisig
{
//-------------------------------------------------------------------------------------------------------------------
bool operator<(const MultisigPubNonces &a, const MultisigPubNonces &b)
{
    // sort by nonce pubkey 1 then nonce pubkey 2 if pubkey 1 is equal
    const int nonce_1_comparison{
            memcmp(a.signature_nonce_1_pub.bytes, &b.signature_nonce_1_pub.bytes, sizeof(rct::key))
        };

    if (nonce_1_comparison < 0)
        return true;

    if (nonce_1_comparison == 0 &&
        memcmp(a.signature_nonce_2_pub.bytes, &b.signature_nonce_2_pub.bytes, sizeof(rct::key)) < 0)
        return true;

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const MultisigPubNonces &a, const MultisigPubNonces &b)
{
    return !(a < b) && !(b < a);
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const MultisigPubNonces &container, sp::SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("nonce1", container.signature_nonce_1_pub);
    transcript_inout.append("nonce2", container.signature_nonce_2_pub);
}
//-------------------------------------------------------------------------------------------------------------------
MultisigNonceCache::MultisigNonceCache(const std::vector<
        std::tuple<rct::key, rct::key, signer_set_filter, MultisigNonces>
    > &raw_nonce_data)
{
    for (const auto &signature_attempt : raw_nonce_data)
    {
        // note: ignore failures
        this->try_add_nonces_impl(
                std::get<0>(signature_attempt),
                std::get<1>(signature_attempt),
                std::get<2>(signature_attempt),
                std::get<3>(signature_attempt)
            );
    }
}
//-------------------------------------------------------------------------------------------------------------------
bool MultisigNonceCache::has_record(const rct::key &message,
    const rct::key &proof_key,
    const signer_set_filter &filter) const
{
    return m_cache.find(message) != m_cache.end() &&
        m_cache.at(message).find(proof_key) != m_cache.at(message).end() &&
        m_cache.at(message).at(proof_key).find(filter) != m_cache.at(message).at(proof_key).end();
}
//-------------------------------------------------------------------------------------------------------------------
bool MultisigNonceCache::try_add_nonces(const rct::key &message,
    const rct::key &proof_key,
    const signer_set_filter &filter)
{
    if (!this->try_add_nonces_impl(message,
            proof_key,
            filter,
            MultisigNonces{rct::rct2sk(rct::skGen()), rct::rct2sk(rct::skGen())}))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool MultisigNonceCache::try_get_nonce_pubkeys_for_base(const rct::key &message,
    const rct::key &proof_key,
    const signer_set_filter &filter,
    const rct::key &pubkey_base,
    MultisigPubNonces &nonce_pubkeys_out) const
{
    CHECK_AND_ASSERT_THROW_MES(sp::key_domain_is_prime_subgroup(pubkey_base) && !(pubkey_base == rct::identity()),
        "multisig nonce record get nonce pubkeys: pubkey base is invalid.");

    if (!this->has_record(message, proof_key, filter))
        return false;

    const MultisigNonces &nonces{m_cache.at(message).at(proof_key).at(filter)};

    // pubkeys (store with (1/8))
    nonce_pubkeys_out.signature_nonce_1_pub =
        rct::scalarmultKey(rct::scalarmultKey(pubkey_base, rct::sk2rct(nonces.signature_nonce_1_priv)), rct::INV_EIGHT);
    nonce_pubkeys_out.signature_nonce_2_pub =
        rct::scalarmultKey(rct::scalarmultKey(pubkey_base, rct::sk2rct(nonces.signature_nonce_2_priv)), rct::INV_EIGHT);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool MultisigNonceCache::try_get_recorded_nonce_privkeys(const rct::key &message,
    const rct::key &proof_key,
    const signer_set_filter &filter,
    crypto::secret_key &nonce_privkey_1_out,
    crypto::secret_key &nonce_privkey_2_out) const
{
    if (!this->has_record(message, proof_key, filter))
        return false;

    // privkeys
    nonce_privkey_1_out = m_cache.at(message).at(proof_key).at(filter).signature_nonce_1_priv;
    nonce_privkey_2_out = m_cache.at(message).at(proof_key).at(filter).signature_nonce_2_priv;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool MultisigNonceCache::try_remove_record(const rct::key &message,
    const rct::key &proof_key,
    const signer_set_filter &filter)
{
    if (!this->has_record(message, proof_key, filter))
        return false;

    // cleanup
    m_cache[message][proof_key].erase(filter);
    if (m_cache[message][proof_key].empty())
        m_cache[message].erase(proof_key);
    if (m_cache[message].empty())
        m_cache.erase(message);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<std::tuple<rct::key, rct::key, signer_set_filter, MultisigNonces>> MultisigNonceCache::export_data() const
{
    // flatten the record and return it
    std::vector<std::tuple<rct::key, rct::key, signer_set_filter, MultisigNonces>> raw_data;

    for (const auto &message_map : m_cache)
    {
        for (const auto &key_map : message_map.second)
        {
            for (const auto &filter_map : key_map.second)
                raw_data.emplace_back(message_map.first, key_map.first, filter_map.first, filter_map.second);
        }
    }

    return raw_data;
}
//-------------------------------------------------------------------------------------------------------------------
bool MultisigNonceCache::try_add_nonces_impl(const rct::key &message,
    const rct::key &proof_key,
    const signer_set_filter &filter,
    const MultisigNonces &nonces)
{
    if (this->has_record(message, proof_key, filter))
        return false;

    if (!sp::key_domain_is_prime_subgroup(proof_key))
        return false;

    // add record
    m_cache[message][proof_key][filter] = nonces;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace multisig
