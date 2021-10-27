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
#include "device/device.hpp"
#include "mock_tx/mock_sp_component_types.h"
#include "mock_tx/mock_sp_core_utils.h"
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
            m_enote_pubkey);

        // invalidate view tag to test the performance of short-circuiting on failed view tags
        if (m_test_view_tag_check)
            ++m_enote.m_view_tag;

        return true;
    }

    bool test()
    {
        crypto::secret_key sender_receiver_secret_dummy;
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
