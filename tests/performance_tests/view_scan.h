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
#include "crypto/x25519.h"
#include "device/device.hpp"
#include "performance_tests.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_address_tag_utils.h"
#include "seraphis_core/jamtis_core_utils.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_core/jamtis_enote_utils.h"
#include "seraphis_core/jamtis_payment_proposal.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_core/legacy_core_utils.h"
#include "seraphis_core/sp_core_enote_utils.h"
#include "seraphis_crypto/math_utils.h"
#include "seraphis_main/enote_record_types.h"
#include "seraphis_main/enote_record_utils.h"
#include "seraphis_main/tx_builder_types.h"
#include "seraphis_main/tx_builders_outputs.h"
#include "seraphis_main/tx_component_types.h"
#include "seraphis_mocks/seraphis_mocks.h"

//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------

struct ParamsShuttleViewScan final : public ParamsShuttle
{
    bool test_view_tag_check{false};
};

/// cryptonote view key scanning (with optional view tag check)
/// test:
/// - sender-receiver secret: kv*R_t
/// - view tag: H1(kv*R_t)
/// - (optional): return here to mimick a view tag check failure
/// - Ks_nom = Ko - H(kv*R_t)*G
/// - Ks ?= Ks_nom
class test_view_scan_cn
{
public:
    static const size_t loop_count = 1000;

    bool init(const ParamsShuttleViewScan &params)
    {
        m_test_view_tag_check = params.test_view_tag_check;

        // kv, Ks = ks*G, R_t = r_t*G
        m_view_secret_key = rct::rct2sk(rct::skGen());
        m_spendkey = rct::rct2pk(rct::pkGen());
        m_tx_pub_key = rct::rct2pk(rct::pkGen());

        // kv*R_t (i.e. r_t*Kv)
        crypto::key_derivation derivation;
        crypto::generate_key_derivation(m_tx_pub_key, m_view_secret_key, derivation);

        // Ko = H(kv*R_t, t)*G + Ks
        crypto::derive_public_key(derivation, 0, m_spendkey, m_onetime_address);

        return true;
    }

    bool test()
    {
        // kv*R_t
        crypto::key_derivation derivation;
        crypto::generate_key_derivation(m_tx_pub_key, m_view_secret_key, derivation);

        // view tag: H1(kv*R_t, t)
        crypto::view_tag mock_view_tag;
        crypto::derive_view_tag(derivation, 0, mock_view_tag);

        // check: early return after computing a view tag (e.g. if nominal view tag doesn't match enote view tag)
        if (m_test_view_tag_check)
            return true;

        // Ks_nom = Ko - H(kv*R_t, t)*G
        crypto::public_key nominal_spendkey;
        crypto::derive_subaddress_public_key(m_onetime_address, derivation, 0, nominal_spendkey);

        // Ks_nom ?= Ks
        return nominal_spendkey == m_spendkey;
    }

private:
    /// kv
    crypto::secret_key m_view_secret_key;
    /// Ks = ks*G
    crypto::public_key m_spendkey;

    /// R_t = r_t*G
    crypto::public_key m_tx_pub_key;
    /// Ko = H(kv*R_t, t)*G + Ks
    crypto::public_key m_onetime_address;

    bool m_test_view_tag_check;
};

//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------

////
// cryptonote view key scanning using optimized crypto library (with optional view tag check)
// note: this relies on 'default hwdev' to auto-find the current machine's best available crypto implementation
/// 
class test_view_scan_cn_optimized
{
public:
    static const size_t loop_count = 1000;

    bool init(const ParamsShuttleViewScan &params)
    {
        m_test_view_tag_check = params.test_view_tag_check;

        // kv, Ks = ks*G, R_t = r_t*G
        m_view_secret_key = rct::rct2sk(rct::skGen());
        m_spendkey = rct::rct2pk(rct::pkGen());
        m_tx_pub_key = rct::rct2pk(rct::pkGen());

        // kv*R_t (i.e. r_t*Kv)
        crypto::key_derivation derivation;
        m_hwdev.generate_key_derivation(m_tx_pub_key, m_view_secret_key, derivation);

        // Ko = H(kv*R_t, t)*G + Ks
        m_hwdev.derive_public_key(derivation, 0, m_spendkey, m_onetime_address);

        return true;
    }

    bool test()
    {
        // kv*R_t
        crypto::key_derivation derivation;
        m_hwdev.generate_key_derivation(m_tx_pub_key, m_view_secret_key, derivation);

        // view tag: H1(kv*R_t, t)
        crypto::view_tag mock_view_tag;
        m_hwdev.derive_view_tag(derivation, 0, mock_view_tag);

        // check: early return after computing a view tag (e.g. if nominal view tag doesn't match enote view tag)
        if (m_test_view_tag_check)
            return true;

        // Ks_nom = Ko - H(kv*R_t, t)*G
        crypto::public_key nominal_spendkey;
        m_hwdev.derive_subaddress_public_key(m_onetime_address, derivation, 0, nominal_spendkey);

        // Ks_nom ?= Ks
        return nominal_spendkey == m_spendkey;
    }

private:
    hw::device &m_hwdev{hw::get_device("default")};

    /// kv
    crypto::secret_key m_view_secret_key;
    /// Ks = ks*G
    crypto::public_key m_spendkey;

    /// R_t = r_t*G
    crypto::public_key m_tx_pub_key;
    /// Ko = H(kv*R_t, t)*G + Ks
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
        sp::jamtis::address_index_t j{}; //address 0

        sp::jamtis::make_jamtis_destination_v1(m_keys.K_1_base,
            m_keys.xK_ua,
            m_keys.xK_fr,
            m_keys.s_ga,
            j,
            user_address);

        // make enote paying to address
        const crypto::x25519_secret_key enote_privkey{crypto::x25519_secret_key_gen()};
        const sp::jamtis::JamtisPaymentProposalV1 payment_proposal{user_address, rct::xmr_amount{0}, enote_privkey};
        sp::SpOutputProposalV1 output_proposal;
        make_v1_output_proposal_v1(payment_proposal, rct::zero(), output_proposal);
        m_enote_ephemeral_pubkey = output_proposal.enote_ephemeral_pubkey;
        get_enote_v1(output_proposal, m_enote);

        // invalidate the view tag to test the performance of short-circuiting on failed view tags
        if (m_test_view_tag_check)
            ++m_enote.view_tag;

        return true;
    }

    bool test()
    {
        // internally this computes the sender-receiver secret, computes the view tag, performs a view tag check, and
        //   decrypts the encrypted address tag
        sp::SpBasicEnoteRecordV1 basic_enote_record;
        if (!sp::try_get_basic_enote_record_v1(m_enote,
                m_enote_ephemeral_pubkey,
                rct::zero(),
                m_keys.xk_fr,
                basic_enote_record))
            return m_test_view_tag_check;  //note: this branch is only valid if trying to trigger the view tag check

        return true;
    }

private:
    sp::jamtis::mocks::jamtis_mock_keys m_keys;

    sp::SpEnoteV1 m_enote;
    crypto::x25519_pubkey m_enote_ephemeral_pubkey;

    bool m_test_view_tag_check;
};

//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------

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

// performance of a client that receives basic records from a remote scanning service
// - takes a 'basic' enote record and tries to get a 'full record' out of it
// - the number of records tested per test equals the number of bits in the jamtis address tag MAC
// - modes:
//   - ALL_FAKE: all records fail the jamtis address tag decipher step
//   - ONE_FAKE_TAG_MATCH: one record passes the jamtis address tag decipher step but fails when reproducing the onetime
//     address
//   - ONE_OWNED: one record fully converts from basic -> full
class test_remote_scanner_client_scan_sp
{
public:
    static const size_t num_records = sp::math::uint_pow(2, sp::jamtis::ADDRESS_TAG_HINT_BYTES * 8);
    static const size_t loop_count = 256000 / num_records + 20;

    bool init(const ParamsShuttleScannerClient &params)
    {
        m_mode = params.mode;

        // user wallet keys
        make_jamtis_mock_keys(m_keys);

        // user address
        sp::jamtis::JamtisDestinationV1 user_address;
        m_real_address_index = sp::jamtis::address_index_t{}; //address 0

        sp::jamtis::make_jamtis_destination_v1(m_keys.K_1_base,
            m_keys.xK_ua,
            m_keys.xK_fr,
            m_keys.s_ga,
            m_real_address_index,
            user_address);

        // prepare cipher context for the test
        m_cipher_context = std::make_shared<sp::jamtis::jamtis_address_tag_cipher_context>(m_keys.s_ct);

        // make enote paying to address
        const crypto::x25519_secret_key enote_privkey{crypto::x25519_secret_key_gen()};
        const sp::jamtis::JamtisPaymentProposalV1 payment_proposal{user_address, rct::xmr_amount{0}, enote_privkey};
        sp::SpOutputProposalV1 output_proposal;
        make_v1_output_proposal_v1(payment_proposal, rct::zero(), output_proposal);
        sp::SpEnoteV1 real_enote;
        get_enote_v1(output_proposal, real_enote);

        // convert to basic enote record (we will use a bunch of copies of this)
        sp::SpBasicEnoteRecordV1 basic_record;
        if (!sp::try_get_basic_enote_record_v1(real_enote,
                output_proposal.enote_ephemeral_pubkey,
                rct::zero(),
                m_keys.xk_fr,
                basic_record))
            return false;

        // make enough basic records for 1/(num bits in address tag mac) success rate
        // - only the last basic record should succeed
        m_basic_records.reserve(num_records);

        for (std::size_t record_index{0}; record_index < num_records; ++record_index)
        {
            m_basic_records.emplace_back(basic_record);

            // ONE_OWNED: don't mangle the last record
            if (m_mode == ScannerClientModes::ONE_OWNED &&
                record_index == num_records - 1)
                continue;

            // ONE_FAKE_TAG_MATCH: only mangle the onetime address of the last record (don't modify the address tag)
            if (m_mode == ScannerClientModes::ONE_FAKE_TAG_MATCH &&
                record_index == num_records - 1)
            {
                sp::SpEnoteV1 temp_enote{m_basic_records.back().enote.unwrap<sp::SpEnoteV1>()};
                temp_enote.core.onetime_address = rct::pkGen();
                m_basic_records.back().enote = temp_enote;
                continue;
            }

            // mangle the address tag
            // - re-do the fake ones if they succeed by accident
            sp::jamtis::address_index_t j_temp;
            do
            {
                sp::jamtis::gen_address_tag(m_basic_records.back().nominal_address_tag);
            } while(sp::jamtis::try_decipher_address_index(*m_cipher_context,
                m_basic_records.back().nominal_address_tag,
                j_temp));
        }

        return true;
    }

    bool test()
    {
        // sanity check
        if (!m_cipher_context)
            return false;

        // try to convert each record: basic -> full
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
                return enote_record.address_index == m_real_address_index;  //should have succeeded
            }
            else if (result)
                return false;
        }

        return true;
    }

private:
    ScannerClientModes m_mode;

    sp::jamtis::mocks::jamtis_mock_keys m_keys;
    std::shared_ptr<sp::jamtis::jamtis_address_tag_cipher_context> m_cipher_context;

    sp::jamtis::address_index_t m_real_address_index;

    std::vector<sp::SpBasicEnoteRecordV1> m_basic_records;
};

//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------

enum class AddressTagDecipherModes
{
    ALL_SUCCESSFUL_DECIPHER,
    NO_SUCCESSFUL_DECIPHER
};

struct ParamsShuttleAddressTagDecipher final : public ParamsShuttle
{
    AddressTagDecipherModes mode;
};

// decipher address tags
class test_jamtis_address_tag_decipher_sp
{
public:
    static const size_t loop_count = 10000;

    bool init(const ParamsShuttleAddressTagDecipher &params)
    {
        // user ciphertag secret
        crypto::secret_key ciphertag_secret = rct::rct2sk(rct::skGen());

        // prepare cipher context for the test
        m_cipher_context = std::make_shared<sp::jamtis::jamtis_address_tag_cipher_context>(ciphertag_secret);

        // make a pile of address tags
        m_address_tags.resize(1000);
        sp::jamtis::address_index_t address_index_temp;

        for (sp::jamtis::address_tag_t &addr_tag : m_address_tags)
        {
            if (params.mode == AddressTagDecipherModes::NO_SUCCESSFUL_DECIPHER)
            {
                do
                {
                    address_index_temp = sp::jamtis::gen_address_index();
                    addr_tag = sp::jamtis::make_address_tag(address_index_temp, sp::jamtis::address_tag_hint_t{});
                }
                while (sp::jamtis::try_decipher_address_index(*m_cipher_context, addr_tag, address_index_temp));
            }
            else
            {
                address_index_temp = sp::jamtis::gen_address_index();

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
