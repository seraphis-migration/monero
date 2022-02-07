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
#include "crypto/blake2b.h"
}
#include "device/device.hpp"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis/jamtis_destination.h"
#include "seraphis/jamtis_enote_utils.h"
#include "seraphis/jamtis_payment_proposal.h"
#include "seraphis/sp_core_enote_utils.h"
#include "seraphis/tx_builder_types.h"
#include "seraphis/tx_component_types.h"
#include "performance_tests.h"


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

        // user wallet keys (incomplete set)
        rct::key wallet_spend_pubkey{rct::pkGen()};
        crypto::secret_key s_generate_address{rct::rct2sk(rct::skGen())};
        m_recipient_findreceived_key = rct::rct2sk(rct::skGen());
        rct::key findreceived_pubkey{rct::scalarmultBase(rct::sk2rct(m_recipient_findreceived_key))};

        // user address
        sp::jamtis::JamtisDestinationV1 user_address;

        sp::jamtis::make_jamtis_destination_v1(wallet_spend_pubkey,
            findreceived_pubkey,
            s_generate_address,
            0, //address 0
            user_address);

        m_recipient_spend_key = user_address.m_addr_K1;

        // make enote paying to address
        crypto::secret_key enote_privkey{rct::rct2sk(rct::skGen())};
        sp::jamtis::JamtisPaymentProposalV1 payment_proposal{user_address, 0, enote_privkey};
        sp::SpOutputProposalV1 output_proposal;
        payment_proposal.get_output_proposal_v1(output_proposal);
        m_enote_pubkey = output_proposal.m_enote_ephemeral_pubkey;
        output_proposal.get_enote_v1(m_enote);

        // invalidate view tag to test the performance of short-circuiting on failed view tags
        if (m_test_view_tag_check)
            ++m_enote.m_view_tag;

        return true;
    }

    bool test()
    {
        rct::key sender_receiver_secret_dummy;
        crypto::key_derivation derivation;

        hw::get_device("default").generate_key_derivation(rct::rct2pk(m_enote_pubkey),
            m_recipient_findreceived_key,
            derivation);

        rct::key nominal_recipient_spendkey;

        if (!sp::jamtis::try_get_jamtis_nominal_spend_key_plain(derivation,
            m_enote.m_enote_core.m_onetime_address,
            m_enote.m_view_tag,
            sender_receiver_secret_dummy,  //outparam not used
            nominal_recipient_spendkey))
        {
            return m_test_view_tag_check;  // this branch is only valid if trying to trigger view tag check
        }

        memwipe(&sender_receiver_secret_dummy, sizeof(rct::key));
        memwipe(&derivation, sizeof(derivation));

        return nominal_recipient_spendkey == m_recipient_spend_key;
    }

private:
    rct::key m_recipient_spend_key;
    crypto::secret_key m_recipient_findreceived_key;

    sp::SpEnoteV1 m_enote;
    rct::key m_enote_pubkey;

    bool m_test_view_tag_check;
};



void domain_separate_derivation_hash_siphash(const std::string &domain_separator,
    const crypto::key_derivation &derivation,
    rct::key &hash_result_out)
{
    // derivation_hash = H("domain-sep", derivation)
    std::string hash;
    // "domain-sep"
    hash = domain_separator;

    // siphash key
    char siphash_key[16];
    for (std::size_t i{0}; i < 16; ++i)
        siphash_key[i] = derivation.data[i];

    // hash to the result
    siphash(hash.data(), hash.size(), siphash_key, hash_result_out.bytes, 8);

    memwipe(siphash_key, 16);
}

unsigned char make_seraphis_view_tag_siphash(const crypto::key_derivation &sender_receiver_DH_derivation)
{
    static std::string salt{config::HASH_KEY_JAMTIS_VIEW_TAG};

    // tag_t = H("domain-sep", derivation)
    rct::key view_tag_scalar;

    domain_separate_derivation_hash_siphash(salt,
        sender_receiver_DH_derivation,
        view_tag_scalar);

    return static_cast<unsigned char>(view_tag_scalar.bytes[0]);
}

unsigned char make_seraphis_view_tag_siphash(const crypto::secret_key &privkey,
    const rct::key &DH_key,
    hw::device &hwdev)
{
    // privkey * DH_key
    crypto::key_derivation derivation;
    hwdev.generate_key_derivation(rct::rct2pk(DH_key), privkey, derivation);

    // tag_t = H("domain-sep", derivation, t)
    unsigned char view_tag{make_seraphis_view_tag_siphash(derivation)};

    memwipe(&derivation, sizeof(derivation));

    return view_tag;
}

bool try_get_jamtis_nominal_spend_key_plain_siphash(const crypto::key_derivation &sender_receiver_DH_derivation,
    const rct::key &onetime_address,
    const unsigned char view_tag,
    rct::key &sender_receiver_secret_out,
    rct::key &nominal_spend_key_out)
{
    // tag'_t = H(q_t)
    unsigned char nominal_view_tag{make_seraphis_view_tag_siphash(sender_receiver_DH_derivation)};

    // check that recomputed tag matches original tag; short-circuit on failure
    if (nominal_view_tag != view_tag)
        return false;

    // q_t
    // note: computing this after view tag check is an optimization
    sp::jamtis::make_jamtis_sender_receiver_secret_plain(sender_receiver_DH_derivation,
        sender_receiver_secret_out);

    // K'^s_t = Ko_t - H(q_t) X
    crypto::secret_key k_a_extender;
    sp::jamtis::make_jamtis_onetime_address_extension(sender_receiver_secret_out, k_a_extender);  // H(q_t)
    sc_mul(&k_a_extender, sp::MINUS_ONE.bytes, &k_a_extender);  // -H(q_t)
    nominal_spend_key_out = onetime_address;  // Ko_t
    sp::extend_seraphis_spendkey(k_a_extender, nominal_spend_key_out); // (-H(q_t)) X + Ko_t

    return true;
}

// seraphis view-key scanning with siphash hsah function
class test_view_scan_sp_siphash
{
public:
    static const size_t loop_count = 1000;

    bool init()
    {
        // user wallet keys (incomplete set)
        rct::key wallet_spend_pubkey{rct::pkGen()};
        crypto::secret_key s_generate_address{rct::rct2sk(rct::skGen())};
        m_recipient_findreceived_key = rct::rct2sk(rct::skGen());
        rct::key findreceived_pubkey{rct::scalarmultBase(rct::sk2rct(m_recipient_findreceived_key))};

        // user address
        sp::jamtis::JamtisDestinationV1 user_address;

        sp::jamtis::make_jamtis_destination_v1(wallet_spend_pubkey,
            findreceived_pubkey,
            s_generate_address,
            0, //address 0
            user_address);

        m_recipient_spend_key = user_address.m_addr_K1;

        // make enote paying to address
        crypto::secret_key enote_privkey{rct::rct2sk(rct::skGen())};
        sp::jamtis::JamtisPaymentProposalV1 payment_proposal{user_address, 0, enote_privkey};
        sp::SpOutputProposalV1 output_proposal;
        payment_proposal.get_output_proposal_v1(output_proposal);
        m_enote_pubkey = output_proposal.m_enote_ephemeral_pubkey;
        output_proposal.get_enote_v1(m_enote);

        // kludge: use siphash to make view tag
        m_enote.m_view_tag = make_seraphis_view_tag_siphash(enote_privkey,
            user_address.m_addr_K3,
            hw::get_device("default"));
        // want view tag test to fail
        ++m_enote.m_view_tag;

        return true;
    }

    bool test()
    {
        rct::key sender_receiver_secret_dummy;
        crypto::key_derivation derivation;

        hw::get_device("default").generate_key_derivation(rct::rct2pk(m_enote_pubkey), m_recipient_findreceived_key, derivation);

        rct::key nominal_recipient_spendkey;

        if (!try_get_jamtis_nominal_spend_key_plain_siphash(derivation,
            m_enote.m_enote_core.m_onetime_address,
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
    crypto::secret_key m_recipient_findreceived_key;

    sp::SpEnoteV1 m_enote;
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
