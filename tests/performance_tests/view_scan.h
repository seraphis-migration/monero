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

#pragma once

#include "crypto/crypto.h"
extern "C"
{
    #include "crypto/siphash.h"
    #include "blake2_temp.h"  //copied from randomx lib
}
#include "device/device.hpp"
#include "mock_tx/mock_sp_transaction_component_types.h"
#include "mock_tx/mock_sp_core_utils.h"
#include "mock_tx/mock_tx_utils.h"
#include "mock_tx/seraphis_crypto_utils.h"
#include "performance_tests.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"


/// cryptonote view key scanning
class test_view_scan_cn
{
public:
    static const size_t loop_count = 1000;

    bool init()
    {
        m_view_secret_key = rct::rct2sk(rct::skGen());
        m_spendkey = rct::rct2pk(rct::pkGen());
        m_tx_pub_key = rct::rct2pk(rct::pkGen());

        // kv*R_t (i.e. r_t*Kv)
        crypto::key_derivation derivation;
        crypto::generate_key_derivation(m_tx_pub_key, m_view_secret_key, derivation);

        // Ko
        crypto::derive_public_key(derivation, 0, m_spendkey, m_onetime_address);

        return true;
    }

    bool test()
    {
        // Ks_nom = Ko - H(kv*R_t)*G
        crypto::key_derivation derivation;
        crypto::public_key nominal_spendkey;
        crypto::generate_key_derivation(m_tx_pub_key, m_view_secret_key, derivation);
        crypto::derive_subaddress_public_key(m_onetime_address, derivation, 0, nominal_spendkey);

        return nominal_spendkey == m_spendkey;
    }

private:
    crypto::secret_key m_view_secret_key;
    crypto::public_key m_spendkey;

    crypto::public_key m_tx_pub_key;
    crypto::public_key m_onetime_address;
};


////
// cryptonote view key scanning using optimized crypto library
// note: this relies on 'default hwdev' to auto-find the supercop crypto library (I think?)
/// 
class test_view_scan_cn_opt
{
public:
    static const size_t loop_count = 1000;

    bool init()
    {
        m_view_secret_key = rct::rct2sk(rct::skGen());
        m_spendkey = rct::rct2pk(rct::pkGen());
        m_tx_pub_key = rct::rct2pk(rct::pkGen());

        // kv*R_t (i.e. r_t*Kv)
        crypto::key_derivation derivation;
        m_hwdev.generate_key_derivation(m_tx_pub_key, m_view_secret_key, derivation);

        // Ko
        m_hwdev.derive_public_key(derivation, 0, m_spendkey, m_onetime_address);

        return true;
    }

    bool test()
    {
        // Ks_nom = Ko - H(kv*R_t)*G
        crypto::key_derivation derivation;
        crypto::public_key nominal_spendkey;
        m_hwdev.generate_key_derivation(m_tx_pub_key, m_view_secret_key, derivation);
        m_hwdev.derive_subaddress_public_key(m_onetime_address, derivation, 0, nominal_spendkey);

        return nominal_spendkey == m_spendkey;
    }

private:
    hw::device &m_hwdev{hw::get_device("default")};

    crypto::secret_key m_view_secret_key;
    crypto::public_key m_spendkey;

    crypto::public_key m_tx_pub_key;
    crypto::public_key m_onetime_address;
};


/// seraphis view key scanning
struct ParamsShuttleViewScan final : public ParamsShuttle
{
    bool test_view_tag_check{false};
};

class test_view_scan_sp
{
public:
    static const size_t loop_count = 1000;

    bool init(const ParamsShuttleViewScan &params)
    {
        m_test_view_tag_check = params.test_view_tag_check;

        // user address
        rct::key recipient_DH_base{rct::pkGen()};
        m_recipient_view_privkey = rct::rct2sk(rct::skGen());
        crypto::secret_key recipient_spendbase_privkey{rct::rct2sk(rct::skGen())};
        rct::key recipient_view_key;

        rct::scalarmultKey(recipient_view_key, recipient_DH_base, rct::sk2rct(m_recipient_view_privkey));
        mock_tx::make_seraphis_spendkey(m_recipient_view_privkey, recipient_spendbase_privkey, m_recipient_spend_key);

        // make enote
        crypto::secret_key enote_privkey{rct::rct2sk(rct::skGen())};

        m_enote.make(enote_privkey,
            recipient_DH_base,
            recipient_view_key,
            m_recipient_spend_key,
            0, // no amount
            0, // 0 index
            false,
            m_enote_pubkey);

        // invalidate view tag to test the performance of short-circuiting on failed view tags
        if (m_test_view_tag_check)
            ++m_enote.m_view_tag;

        return true;
    }

    bool test()
    {
        rct::key sender_receiver_secret_dummy;
        crypto::key_derivation derivation;

        hw::get_device("default").generate_key_derivation(rct::rct2pk(m_enote_pubkey), m_recipient_view_privkey, derivation);

        rct::key nominal_recipient_spendkey;

        if (!mock_tx::try_get_seraphis_nominal_spend_key(derivation,
            0,
            m_enote.m_onetime_address,
            m_enote.m_view_tag,
            sender_receiver_secret_dummy,  //outparam not used
            nominal_recipient_spendkey))
        {
            return m_test_view_tag_check;  // only valid if trying to trigger view tag check
        }

        memwipe(&sender_receiver_secret_dummy, sizeof(rct::key));
        memwipe(&derivation, sizeof(derivation));

        return nominal_recipient_spendkey == m_recipient_spend_key;
    }

private:
    rct::key m_recipient_spend_key;
    crypto::secret_key m_recipient_view_privkey;

    mock_tx::MockENoteSpV1 m_enote;
    rct::key m_enote_pubkey;

    bool m_test_view_tag_check;
};



void domain_separate_derivation_hash_siphash(const std::string &domain_separator,
    const crypto::key_derivation &derivation,
    const std::size_t index,
    rct::key &hash_result_out)
{
    // derivation_hash = H("domain-sep", derivation, index)
    std::string hash;
    hash.reserve(domain_separator.size() + ((sizeof(std::size_t) * 8 + 6) / 7));
    // "domain-sep"
    hash = domain_separator;
    // index
    char converted_index[(sizeof(size_t) * 8 + 6) / 7];
    char* end = converted_index;
    tools::write_varint(end, index);
    assert(end <= converted_index + sizeof(converted_index));
    hash.append(converted_index, end - converted_index);

    // siphash key
    char siphash_key[16];
    for (std::size_t i{0}; i < 16; ++i)
        siphash_key[i] = derivation.data[i];

    // hash to the result
    siphash(hash.data(), hash.size(), siphash_key, hash_result_out.bytes, 8);

    memwipe(siphash_key, 16);
}

unsigned char make_seraphis_view_tag_siphash(const crypto::key_derivation &sender_receiver_DH_derivation,
    const std::size_t output_index)
{
    static std::string salt{config::HASH_KEY_SERAPHIS_VIEW_TAG};

    // tag_t = H("domain-sep", derivation, t)
    // TODO: consider using a simpler/cheaper hash function for view tags
    rct::key view_tag_scalar;

    domain_separate_derivation_hash_siphash(salt,
        sender_receiver_DH_derivation,
        output_index,
        view_tag_scalar);

    return static_cast<unsigned char>(view_tag_scalar.bytes[0]);
}

unsigned char make_seraphis_view_tag_siphash(const crypto::secret_key &privkey,
    const rct::key &DH_key,
    const std::size_t output_index,
    hw::device &hwdev)
{
    // privkey * DH_key
    crypto::key_derivation derivation;
    hwdev.generate_key_derivation(rct::rct2pk(DH_key), privkey, derivation);

    // tag_t = H("domain-sep", derivation, t)
    unsigned char view_tag{make_seraphis_view_tag_siphash(derivation, output_index)};

    memwipe(&derivation, sizeof(derivation));

    return view_tag;
}

bool try_get_seraphis_nominal_spend_key_siphash(const crypto::key_derivation &sender_receiver_DH_derivation,
    const std::size_t output_index,
    const rct::key &onetime_address,
    const unsigned char view_tag,
    rct::key &sender_receiver_secret_out,
    rct::key &nominal_spend_key_out)
{
    // tag'_t = H(q_t)
    unsigned char nominal_view_tag{make_seraphis_view_tag_siphash(sender_receiver_DH_derivation, output_index)};

    // check that recomputed tag matches original tag; short-circuit on failure
    if (nominal_view_tag != view_tag)
        return false;

    // q_t
    // note: computing this after view tag check is an optimization
    mock_tx::make_seraphis_sender_receiver_secret(sender_receiver_DH_derivation,
        output_index,
        sender_receiver_secret_out);

    // K'^s_t = Ko_t - H(q_t) X
    crypto::secret_key k_a_extender;
    mock_tx::make_seraphis_sender_address_extension(rct::rct2sk(sender_receiver_secret_out), k_a_extender);  // H(q_t)
    sc_mul(&k_a_extender, sp::MINUS_ONE.bytes, &k_a_extender);  // -H(q_t)
    nominal_spend_key_out = onetime_address;  // Ko_t
    mock_tx::extend_seraphis_spendkey(k_a_extender, nominal_spend_key_out); // (-H(q_t)) X + Ko_t

    return true;
}

// seraphis view-key scanning with siphash hsah function
class test_view_scan_sp_siphash
{
public:
    static const size_t loop_count = 1000;

    bool init()
    {
        // user address
        rct::key recipient_DH_base{rct::pkGen()};
        m_recipient_view_privkey = rct::rct2sk(rct::skGen());
        crypto::secret_key recipient_spendbase_privkey{rct::rct2sk(rct::skGen())};
        rct::key recipient_view_key;

        rct::scalarmultKey(recipient_view_key, recipient_DH_base, rct::sk2rct(m_recipient_view_privkey));
        mock_tx::make_seraphis_spendkey(m_recipient_view_privkey, recipient_spendbase_privkey, m_recipient_spend_key);

        // make enote
        crypto::secret_key enote_privkey{rct::rct2sk(rct::skGen())};

        m_enote.make(enote_privkey,
            recipient_DH_base,
            recipient_view_key,
            m_recipient_spend_key,
            0, // no amount
            0, // 0 index
            false,
            m_enote_pubkey);

        // kludge: use siphash to make view tag
        m_enote.m_view_tag = make_seraphis_view_tag_siphash(enote_privkey,
            recipient_view_key,
            0,
            hw::get_device("default"));
        // want view tag test to fail
        ++m_enote.m_view_tag;

        return true;
    }

    bool test()
    {
        rct::key sender_receiver_secret_dummy;
        crypto::key_derivation derivation;

        hw::get_device("default").generate_key_derivation(rct::rct2pk(m_enote_pubkey), m_recipient_view_privkey, derivation);

        rct::key nominal_recipient_spendkey;

        if (!try_get_seraphis_nominal_spend_key_siphash(derivation,
            0,
            m_enote.m_onetime_address,
            m_enote.m_view_tag,
            sender_receiver_secret_dummy,  //outparam not used
            nominal_recipient_spendkey))
        {
            return true; //expect it to fail on view tag
        }

        memwipe(&sender_receiver_secret_dummy, sizeof(rct::key));
        memwipe(&derivation, sizeof(derivation));

        return nominal_recipient_spendkey == m_recipient_spend_key;
    }

private:
    rct::key m_recipient_spend_key;
    crypto::secret_key m_recipient_view_privkey;

    mock_tx::MockENoteSpV1 m_enote;
    rct::key m_enote_pubkey;
};





////
// Plain perf test of hash functions eligible for making view tags
// - cn_fast_hash
// - siphash
// - blake2b
///
struct ParamsShuttleViewHash final : public ParamsShuttle
{
    std::string domain_separator;
};


class test_view_scan_hash_siphash
{
public:
    static const size_t loop_count = 1000;
    static const size_t re_loop = 100;

    bool init(const ParamsShuttleViewHash &params)
    {
        hw::get_device("default").generate_key_derivation(rct::rct2pk(rct::pkGen()),
            rct::rct2sk(rct::skGen()),
            m_derivation);

        m_domain_separator = params.domain_separator;

        return true;
    }

    bool test()
    {
        static std::size_t index{0};

        for (std::size_t i{0}; i < re_loop; ++i)
        {
            // derivation_hash = H[derivation]("domain-sep", index)
            std::string hash;
            hash.reserve(sizeof(m_domain_separator) + ((sizeof(std::size_t) * 8 + 6) / 7));
            // "domain-sep"
            hash = m_domain_separator;
            // index
            char converted_index[(sizeof(size_t) * 8 + 6) / 7];
            char* end = converted_index;
            tools::write_varint(end, index);
            assert(end <= converted_index + sizeof(converted_index));
            hash.append(converted_index, end - converted_index);

            // hash to the result
            // note: only the first 16 bytes of 'm_derivation' is used for the siphash key
            rct::key hash_result;
            siphash(hash.data(), hash.size(), &m_derivation, hash_result.bytes, 8);
        }

        return true;
    }

private:
    crypto::key_derivation m_derivation;
    std::string m_domain_separator;
};


class test_view_scan_hash_halfsiphash
{
public:
    static const size_t loop_count = 1000;
    static const size_t re_loop = 100;

    bool init(const ParamsShuttleViewHash &params)
    {
        hw::get_device("default").generate_key_derivation(rct::rct2pk(rct::pkGen()),
            rct::rct2sk(rct::skGen()),
            m_derivation);

        m_domain_separator = params.domain_separator;

        return true;
    }

    bool test()
    {
        static std::size_t index{0};

        for (std::size_t i{0}; i < re_loop; ++i)
        {
            // derivation_hash = H[derivation]("domain-sep", index)
            std::string hash;
            hash.reserve(sizeof(m_domain_separator) + ((sizeof(std::size_t) * 8 + 6) / 7));
            // "domain-sep"
            hash = m_domain_separator;
            // index
            char converted_index[(sizeof(size_t) * 8 + 6) / 7];
            char* end = converted_index;
            tools::write_varint(end, index);
            assert(end <= converted_index + sizeof(converted_index));
            hash.append(converted_index, end - converted_index);

            // siphash key
            char siphash_key[8];
            for (std::size_t i{0}; i < 8; ++i)
                siphash_key[i] = m_derivation.data[i];

            // hash to the result
            rct::key hash_result;
            halfsiphash(hash.data(), hash.size(), siphash_key, hash_result.bytes, 4);
        }

        return true;
    }

private:
    crypto::key_derivation m_derivation;
    std::string m_domain_separator;
};

class test_view_scan_hash_cnhash
{
public:
    static const size_t loop_count = 1000;
    static const size_t re_loop = 100;

    bool init(const ParamsShuttleViewHash &params)
    {
        hw::get_device("default").generate_key_derivation(rct::rct2pk(rct::pkGen()),
            rct::rct2sk(rct::skGen()),
            m_derivation);

        m_domain_separator = params.domain_separator;

        return true;
    }

    bool test()
    {
        static std::size_t index{0};

        for (std::size_t i{0}; i < re_loop; ++i)
        {
            // derivation_hash = H("domain-sep", derivation, index)
            std::string hash;
            hash.reserve(sizeof(m_domain_separator) + sizeof(rct::key) +
                ((sizeof(std::size_t) * 8 + 6) / 7));
            // "domain-sep"
            hash = m_domain_separator;
            // derivation (e.g. a DH shared key)
            hash.append((const char*) &m_derivation, sizeof(rct::key));
            // index
            char converted_index[(sizeof(size_t) * 8 + 6) / 7];
            char* end = converted_index;
            tools::write_varint(end, index);
            assert(end <= converted_index + sizeof(converted_index));
            hash.append(converted_index, end - converted_index);

            // hash to the result
            rct::key hash_result;
            rct::hash_to_scalar(hash_result, hash.data(), hash.size());
        }

        return true;
    }

private:
    crypto::key_derivation m_derivation;
    std::string m_domain_separator;
};


class test_view_scan_hash_b2bhash
{
public:
    static const size_t loop_count = 1000;
    static const size_t re_loop = 100;

    bool init(const ParamsShuttleViewHash &params)
    {
        hw::get_device("default").generate_key_derivation(rct::rct2pk(rct::pkGen()),
            rct::rct2sk(rct::skGen()),
            m_derivation);

        m_domain_separator = params.domain_separator;

        return true;
    }

    bool test()
    {
        static std::size_t index{0};

        for (std::size_t i{0}; i < re_loop; ++i)
        {
            // derivation_hash = H("domain-sep", derivation, index)
            std::string hash;
            hash.reserve(sizeof(m_domain_separator) + sizeof(rct::key) +
                ((sizeof(std::size_t) * 8 + 6) / 7));
            // "domain-sep"
            hash = m_domain_separator;
            // derivation (e.g. a DH shared key)
            hash.append((const char*) &m_derivation, sizeof(rct::key));
            // index
            char converted_index[(sizeof(size_t) * 8 + 6) / 7];
            char* end = converted_index;
            tools::write_varint(end, index);
            assert(end <= converted_index + sizeof(converted_index));
            hash.append(converted_index, end - converted_index);

            // hash to the result
            rct::key hash_result;
            blake2b(hash_result.bytes, 32, hash.data(), hash.size(), nullptr, 0);
        }

        return true;
    }

private:
    crypto::key_derivation m_derivation;
    std::string m_domain_separator;
};
