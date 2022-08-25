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
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis/jamtis_address_tag_utils.h"
#include "seraphis/jamtis_core_utils.h"
#include "seraphis/jamtis_destination.h"
#include "seraphis/jamtis_enote_utils.h"
#include "seraphis/jamtis_payment_proposal.h"
#include "seraphis/jamtis_support_types.h"
#include "seraphis/legacy_core_utils.h"
#include "seraphis/seraphis_config_temp.h"
#include "seraphis/sp_core_enote_utils.h"
#include "seraphis/sp_crypto_utils.h"
#include "seraphis/tx_builder_types.h"
#include "seraphis/tx_component_types.h"
#include "seraphis/tx_enote_record_types.h"
#include "seraphis/tx_enote_record_utils.h"
#include "seraphis/tx_misc_utils.h"
#include "performance_tests.h"

//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------

struct ParamsShuttleViewScan final : public ParamsShuttle
{
    bool test_view_tag_check{false};
};

/// cryptonote view key scanning (with optional view tag check)
class test_view_scan_cn
{
public:
    static const size_t loop_count = 1000;

    bool init(const ParamsShuttleViewScan &params)
    {
        m_test_view_tag_check = params.test_view_tag_check;

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

        // view tag check: early return after computing a view tag
        crypto::view_tag mock_view_tag;
        crypto::derive_view_tag(derivation, 0, mock_view_tag);

        if (m_test_view_tag_check)
            return true;

        crypto::derive_subaddress_public_key(m_onetime_address, derivation, 0, nominal_spendkey);
        return nominal_spendkey == m_spendkey;
    }

private:
    crypto::secret_key m_view_secret_key;
    crypto::public_key m_spendkey;

    crypto::public_key m_tx_pub_key;
    crypto::public_key m_onetime_address;

    bool m_test_view_tag_check;
};

//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------

////
// cryptonote view key scanning using optimized crypto library (with optional view tag check)
// note: this relies on 'default hwdev' to auto-find the supercop crypto library (I think?)
/// 
class test_view_scan_cn_opt
{
public:
    static const size_t loop_count = 1000;

    bool init(const ParamsShuttleViewScan &params)
    {
        m_test_view_tag_check = params.test_view_tag_check;

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

        // view tag check: early return after computing a view tag
        crypto::view_tag mock_view_tag;
        crypto::derive_view_tag(derivation, 0, mock_view_tag);

        if (m_test_view_tag_check)
            return true;

        m_hwdev.derive_subaddress_public_key(m_onetime_address, derivation, 0, nominal_spendkey);
        return nominal_spendkey == m_spendkey;
    }

private:
    hw::device &m_hwdev{hw::get_device("default")};

    crypto::secret_key m_view_secret_key;
    crypto::public_key m_spendkey;

    crypto::public_key m_tx_pub_key;
    crypto::public_key m_onetime_address;

    bool m_test_view_tag_check;
};

//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------

/// seraphis view key scanning
class test_view_scan_sp
{
public:
    static const size_t loop_count = 1000;

    bool init(const ParamsShuttleViewScan &params)
    {
        m_test_view_tag_check = params.test_view_tag_check;

        // user wallet keys
        make_jamtis_mock_keys(m_keys);

        // user address
        sp::jamtis::JamtisDestinationV1 user_address;
        sp::jamtis::address_index_t j{0}; //address 0

        sp::jamtis::make_jamtis_destination_v1(m_keys.K_1_base,
            m_keys.xK_ua,
            m_keys.xK_fr,
            m_keys.s_ga,
            j,
            user_address);

        // make enote paying to address
        const sp::x25519_secret_key enote_privkey{sp::x25519_privkey_gen()};
        const sp::jamtis::JamtisPaymentProposalV1 payment_proposal{user_address, rct::xmr_amount{0}, enote_privkey};
        sp::SpOutputProposalV1 output_proposal;
        payment_proposal.get_output_proposal_v1(rct::zero(), output_proposal);
        m_enote_ephemeral_pubkey = output_proposal.m_enote_ephemeral_pubkey;
        output_proposal.get_enote_v1(m_enote);

        // invalidate view tag to test the performance of short-circuiting on failed view tags
        if (m_test_view_tag_check)
            ++m_enote.m_view_tag;

        return true;
    }

    bool test()
    {
        sp::SpBasicEnoteRecordV1 basic_enote_record;
        if (!sp::try_get_basic_enote_record_v1(m_enote,
                m_enote_ephemeral_pubkey,
                rct::zero(),
                m_keys.xk_fr,
                basic_enote_record))
            return m_test_view_tag_check;  // this branch is only valid if trying to trigger view tag check

        return true;
    }

private:
    sp::jamtis::jamtis_mock_keys m_keys;

    sp::SpEnoteV1 m_enote;
    sp::x25519_pubkey m_enote_ephemeral_pubkey;

    bool m_test_view_tag_check;
};

//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------

// performance of the client of a remote scanning service
// - takes a 'basic' enote record and tries to get a 'full record' out of it
enum class ScannerClientModes
{
    ALL_FAKE,
    ONE_FAKE_TAG_MATCH,
    ONE_OWNED
};

struct ParamsShuttleScannerClient final : public ParamsShuttle
{
    ScannerClientModes mode;
};

class test_remote_scanner_client_scan_sp
{
public:
    static const size_t num_records = sp::ref_set_size_from_decomp(2, sp::jamtis::ADDRESS_TAG_MAC_BYTES * 8);
    static const size_t loop_count = 256000 / num_records + 20;

    bool init(const ParamsShuttleScannerClient &params)
    {
        m_mode = params.mode;

        // make enote basic records for 1/(num bits in address tag mac) success rate
        m_basic_records.reserve(num_records);

        // user wallet keys
        make_jamtis_mock_keys(m_keys);

        // user address
        sp::jamtis::JamtisDestinationV1 user_address;
        m_real_address_index = sp::jamtis::address_index_t{0}; //address 0

        sp::jamtis::make_jamtis_destination_v1(m_keys.K_1_base,
            m_keys.xK_ua,
            m_keys.xK_fr,
            m_keys.s_ga,
            m_real_address_index,
            user_address);

        // prepare cipher context for the test
        m_cipher_context = std::make_shared<sp::jamtis::jamtis_address_tag_cipher_context>(rct::sk2rct(m_keys.s_ct));

        // make enote paying to address
        const sp::x25519_secret_key enote_privkey{sp::x25519_privkey_gen()};
        const sp::jamtis::JamtisPaymentProposalV1 payment_proposal{user_address, rct::xmr_amount{0}, enote_privkey};
        sp::SpOutputProposalV1 output_proposal;
        payment_proposal.get_output_proposal_v1(rct::zero(), output_proposal);
        sp::SpEnoteV1 real_enote;
        output_proposal.get_enote_v1(real_enote);

        // convert to basic enote record (just use a bunch of copies of this)
        sp::SpBasicEnoteRecordV1 basic_record;
        if (!sp::try_get_basic_enote_record_v1(real_enote,
                output_proposal.m_enote_ephemeral_pubkey,
                rct::zero(),
                m_keys.xk_fr,
                basic_record))
            return false;

        // make a pile of basic records
        // - only the last basic record should succeed
        sp::SpEnoteRecordV1 enote_record_dummy;

        for (std::size_t record_index{0}; record_index < num_records; ++record_index)
        {
            m_basic_records.emplace_back(basic_record);

            // ONE_OWNED: don't do anything else if we are on the last record
            if (m_mode == ScannerClientModes::ONE_OWNED &&
                record_index == num_records - 1)
                continue;

            // ONE_FAKE_TAG_MATCH: mangle the onetime address if we are the last record (don't modify the address tag)
            if (m_mode == ScannerClientModes::ONE_FAKE_TAG_MATCH &&
                record_index == num_records - 1)
            {
                m_basic_records.back().m_enote.m_core.m_onetime_address = rct::pkGen();
                continue;
            }

            // mangle the address tag
            // - re-do the fake ones if they succeed by accident
            sp::jamtis::address_index_t j_temp;
            do
            {
                sp::jamtis::gen_address_tag(m_basic_records.back().m_nominal_address_tag);
            } while(sp::jamtis::try_decipher_address_index(*m_cipher_context,
                m_basic_records.back().m_nominal_address_tag,
                j_temp));
        }

        return true;
    }

    bool test()
    {
        // sanity check
        if (!m_cipher_context)
            return false;

        sp::SpEnoteRecordV1 enote_record;

        for (std::size_t record_index{0}; record_index <  m_basic_records.size(); ++record_index)
        {
            const bool result{
                    try_get_enote_record_v1_plain(m_basic_records[record_index],
                        m_keys.K_1_base,
                        m_keys.k_vb,
                        m_keys.xk_ua,
                        m_keys.xk_fr,
                        m_keys.s_ga,
                        *m_cipher_context,
                        enote_record)
                };

            // only the last record of mode ONE_OWNED should succeed
            if (result &&
                m_mode == ScannerClientModes::ONE_OWNED &&
                record_index == m_basic_records.size() - 1)
            {
                return enote_record.m_address_index == m_real_address_index;  //should have succeeded
            }
            else if (result)
                return false;
        }

        return true;
    }

private:
    ScannerClientModes m_mode;

    sp::jamtis::jamtis_mock_keys m_keys;
    std::shared_ptr<sp::jamtis::jamtis_address_tag_cipher_context> m_cipher_context;

    sp::jamtis::address_index_t m_real_address_index;

    std::vector<sp::SpBasicEnoteRecordV1> m_basic_records;
};

//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------

enum class AddressTagDecryptModes
{
    ALL_SUCCESSFUL_DECRYPT,
    NO_SUCCESSFUL_DECRYPT
};

struct ParamsShuttleAddressTagDecrypt final : public ParamsShuttle
{
    AddressTagDecryptModes mode;
};

class test_jamtis_address_tag_decrypt_sp
{
public:
    static const size_t loop_count = 10000;

    bool init(const ParamsShuttleAddressTagDecrypt &params)
    {
        // user ciphertag secret
        rct::key ciphertag_secret = rct::skGen();

        // prepare cipher context for the test
        m_cipher_context = std::make_shared<sp::jamtis::jamtis_address_tag_cipher_context>(ciphertag_secret);

        // make a pile of address tags
        m_address_tags.resize(1000);
        sp::jamtis::address_index_t address_index_temp;

        for (sp::jamtis::address_tag_t &addr_tag : m_address_tags)
        {
            if (params.mode == AddressTagDecryptModes::NO_SUCCESSFUL_DECRYPT)
            {
                do
                {
                    address_index_temp.gen();
                    addr_tag = sp::jamtis::address_tag_t{address_index_temp};
                }
                while (sp::jamtis::try_decipher_address_index(*m_cipher_context, addr_tag, address_index_temp));
            }
            else
            {
                address_index_temp.gen();

                addr_tag = sp::jamtis::cipher_address_index(*m_cipher_context, address_index_temp);
            }
        }

        return true;
    }

    bool test()
    {
        // sanity check
        if (!m_cipher_context)
            return false;

        sp::jamtis::address_index_t address_index_temp;

        for (const sp::jamtis::address_tag_t &addr_tag : m_address_tags)
            sp::jamtis::try_decipher_address_index(*m_cipher_context, addr_tag, address_index_temp);

        return true;
    }

private:
    std::shared_ptr<sp::jamtis::jamtis_address_tag_cipher_context> m_cipher_context;

    std::vector<sp::jamtis::address_tag_t> m_address_tags;
};

//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------
