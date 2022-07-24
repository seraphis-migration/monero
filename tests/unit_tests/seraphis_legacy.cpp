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

#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "device/device.hpp"
#include "misc_language.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis/legacy_core_utils.h"
#include "seraphis/legacy_enote_types.h"
#include "seraphis/legacy_enote_utils.h"
#include "seraphis/tx_enote_record_types.h"
#include "seraphis/tx_legacy_enote_record_utils.h"

#include "boost/multiprecision/cpp_int.hpp"
#include "gtest/gtest.h"

#include <memory>
#include <vector>


//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static crypto::secret_key make_secret_key()
{
    return rct::rct2sk(rct::skGen());
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_legacy_subaddress(const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_view_privkey,
    rct::key &subaddr_spendkey_out,
    rct::key &subaddr_viewkey_out,
    cryptonote::subaddress_index &subaddr_index_out)
{
    // random subaddress index: i
    crypto::rand(sizeof(subaddr_index_out.minor), reinterpret_cast<unsigned char*>(&subaddr_index_out.minor));
    crypto::rand(sizeof(subaddr_index_out.major), reinterpret_cast<unsigned char*>(&subaddr_index_out.major));

    // subaddress spendkey: (Hn(k^v, i) + k^s) G
    sp::make_legacy_subaddress_spendkey(legacy_base_spend_pubkey,
        legacy_view_privkey,
        subaddr_index_out,
        subaddr_spendkey_out);

    // subaddress viewkey: k^v * K^{s,i}
    rct::scalarmultKey(subaddr_viewkey_out, subaddr_spendkey_out, rct::sk2rct(legacy_view_privkey));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void test_information_recovery(const crypto::secret_key &legacy_spend_privkey,
    const crypto::secret_key &legacy_view_privkey,
    const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const sp::LegacyEnoteVariant &legacy_enote,
    const rct::key &enote_ephemeral_pubkey,
    const std::uint64_t tx_output_index,
    const boost::optional<cryptonote::subaddress_index> &expected_recieving_index,
    const rct::xmr_amount &expected_amount)
{
    using namespace sp;

    // basic enote record: full
    LegacyBasicEnoteRecord basic_record_recovered;

    ASSERT_NO_THROW(ASSERT_TRUE(try_get_legacy_basic_enote_record(legacy_enote,
        enote_ephemeral_pubkey,
        tx_output_index,
        0,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        hw::get_device("default"),
        basic_record_recovered)));

    ASSERT_TRUE(basic_record_recovered.m_address_index == expected_recieving_index);

    // intermediate enote record: from basic record
    LegacyIntermediateEnoteRecord intermediate_record_recovered_from_basic;

    ASSERT_NO_THROW(ASSERT_TRUE(try_get_legacy_intermediate_enote_record(basic_record_recovered,
        legacy_base_spend_pubkey,
        legacy_view_privkey,
        intermediate_record_recovered_from_basic)));

    ASSERT_TRUE(intermediate_record_recovered_from_basic.m_address_index == expected_recieving_index);
    ASSERT_TRUE(intermediate_record_recovered_from_basic.m_amount == expected_amount);

    // intermediate enote record: full
    LegacyIntermediateEnoteRecord intermediate_record_recovered;

    ASSERT_NO_THROW(ASSERT_TRUE(try_get_legacy_intermediate_enote_record(legacy_enote,
        enote_ephemeral_pubkey,
        tx_output_index,
        0,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        intermediate_record_recovered)));

    ASSERT_TRUE(intermediate_record_recovered.m_address_index == expected_recieving_index);
    ASSERT_TRUE(intermediate_record_recovered.m_amount == expected_amount);

    // full enote record: from basic record
    LegacyEnoteRecord full_record_recovered_from_basic;

    ASSERT_NO_THROW(ASSERT_TRUE(try_get_legacy_enote_record(basic_record_recovered,
        legacy_base_spend_pubkey,
        legacy_spend_privkey,
        legacy_view_privkey,
        full_record_recovered_from_basic)));

    ASSERT_TRUE(full_record_recovered_from_basic.m_address_index == expected_recieving_index);
    ASSERT_TRUE(full_record_recovered_from_basic.m_amount == expected_amount);

    // full enote record: from intermediate record
    LegacyEnoteRecord full_record_recovered_from_intermediate;

    ASSERT_NO_THROW(get_legacy_enote_record(intermediate_record_recovered,
        legacy_spend_privkey,
        full_record_recovered_from_intermediate));

    ASSERT_TRUE(full_record_recovered_from_intermediate.m_address_index == expected_recieving_index);
    ASSERT_TRUE(full_record_recovered_from_intermediate.m_amount == expected_amount);
    ASSERT_TRUE(full_record_recovered_from_intermediate.m_key_image == full_record_recovered_from_basic.m_key_image);

    // full enote record: full
    LegacyEnoteRecord full_record_recovered;

    ASSERT_TRUE(try_get_legacy_enote_record(legacy_enote,
        enote_ephemeral_pubkey,
        tx_output_index,
        0,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        full_record_recovered));

    ASSERT_TRUE(full_record_recovered.m_address_index == expected_recieving_index);
    ASSERT_TRUE(full_record_recovered.m_amount == expected_amount);
    ASSERT_TRUE(full_record_recovered.m_key_image == full_record_recovered_from_basic.m_key_image);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_legacy, information_recovery_enote_v1)
{
    using namespace sp;

    // prepare user keys
    const crypto::secret_key legacy_spend_privkey{make_secret_key()};
    const crypto::secret_key legacy_view_privkey{make_secret_key()};
    const rct::key legacy_base_spend_pubkey{rct::scalarmultBase(rct::sk2rct(legacy_spend_privkey))};

    // prepare normal address
    const rct::key normal_addr_spendkey{legacy_base_spend_pubkey};
    const rct::key normal_addr_viewkey{rct::scalarmultBase(rct::sk2rct(legacy_view_privkey))};

    // prepare subaddress
    rct::key subaddr_spendkey;
    rct::key subaddr_viewkey;
    cryptonote::subaddress_index subaddr_index;

    make_legacy_subaddress(legacy_base_spend_pubkey, legacy_view_privkey, subaddr_spendkey, subaddr_viewkey, subaddr_index);

    // save subaddress
    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;
    legacy_subaddress_map[subaddr_spendkey] = subaddr_index;

    // send enote v1 (normal destination)
    LegacyEnoteV1 legacy_enote_normal_dest;
    const crypto::secret_key enote_ephemeral_privkey_normal_dest{make_secret_key()};
    const rct::key enote_ephemeral_pubkey_normal_dest{
            rct::scalarmultBase(rct::sk2rct(enote_ephemeral_privkey_normal_dest))
        };
    const rct::xmr_amount amount_normal_dest{100};

    ASSERT_NO_THROW(make_legacy_enote_v1(normal_addr_spendkey,
        normal_addr_viewkey,
        amount_normal_dest,
        0,
        enote_ephemeral_privkey_normal_dest,
        legacy_enote_normal_dest));

    // information recovery test
    test_information_recovery(legacy_spend_privkey,
        legacy_view_privkey,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_enote_normal_dest,
        enote_ephemeral_pubkey_normal_dest,
        0,
        boost::none,
        amount_normal_dest);

    // send enote v1 (subaddress destination)
    LegacyEnoteV1 legacy_enote_subaddr_dest;
    const crypto::secret_key enote_ephemeral_privkey_subaddr_dest{make_secret_key()};
    const rct::key enote_ephemeral_pubkey_subaddr_dest{
            rct::scalarmultKey(subaddr_spendkey, rct::sk2rct(enote_ephemeral_privkey_subaddr_dest))
        };
    const rct::xmr_amount amount_subaddr_dest{999999};

    ASSERT_NO_THROW(make_legacy_enote_v1(subaddr_spendkey,
        subaddr_viewkey,
        amount_subaddr_dest,
        0,
        enote_ephemeral_privkey_subaddr_dest,
        legacy_enote_subaddr_dest));

    // information recovery test
    test_information_recovery(legacy_spend_privkey,
        legacy_view_privkey,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_enote_subaddr_dest,
        enote_ephemeral_pubkey_subaddr_dest,
        0,
        subaddr_index,
        amount_subaddr_dest);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_legacy, information_recovery_enote_v2)
{
    using namespace sp;

    // prepare user keys
    const crypto::secret_key legacy_spend_privkey{make_secret_key()};
    const crypto::secret_key legacy_view_privkey{make_secret_key()};
    const rct::key legacy_base_spend_pubkey{rct::scalarmultBase(rct::sk2rct(legacy_spend_privkey))};

    // prepare normal address
    const rct::key normal_addr_spendkey{legacy_base_spend_pubkey};
    const rct::key normal_addr_viewkey{rct::scalarmultBase(rct::sk2rct(legacy_view_privkey))};

    // prepare subaddress
    rct::key subaddr_spendkey;
    rct::key subaddr_viewkey;
    cryptonote::subaddress_index subaddr_index;

    make_legacy_subaddress(legacy_base_spend_pubkey, legacy_view_privkey, subaddr_spendkey, subaddr_viewkey, subaddr_index);

    // save subaddress
    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;
    legacy_subaddress_map[subaddr_spendkey] = subaddr_index;

    // send enote v2 (normal destination)
    LegacyEnoteV2 legacy_enote_normal_dest;
    const crypto::secret_key enote_ephemeral_privkey_normal_dest{make_secret_key()};
    const rct::key enote_ephemeral_pubkey_normal_dest{
            rct::scalarmultBase(rct::sk2rct(enote_ephemeral_privkey_normal_dest))
        };
    const rct::xmr_amount amount_normal_dest{100};

    ASSERT_NO_THROW(make_legacy_enote_v2(normal_addr_spendkey,
        normal_addr_viewkey,
        amount_normal_dest,
        0,
        enote_ephemeral_privkey_normal_dest,
        legacy_enote_normal_dest));

    // information recovery test
    test_information_recovery(legacy_spend_privkey,
        legacy_view_privkey,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_enote_normal_dest,
        enote_ephemeral_pubkey_normal_dest,
        0,
        boost::none,
        amount_normal_dest);

    // send enote v2 (subaddress destination)
    LegacyEnoteV2 legacy_enote_subaddr_dest;
    const crypto::secret_key enote_ephemeral_privkey_subaddr_dest{make_secret_key()};
    const rct::key enote_ephemeral_pubkey_subaddr_dest{
            rct::scalarmultKey(subaddr_spendkey, rct::sk2rct(enote_ephemeral_privkey_subaddr_dest))
        };
    const rct::xmr_amount amount_subaddr_dest{999999};

    ASSERT_NO_THROW(make_legacy_enote_v2(subaddr_spendkey,
        subaddr_viewkey,
        amount_subaddr_dest,
        0,
        enote_ephemeral_privkey_subaddr_dest,
        legacy_enote_subaddr_dest));

    // information recovery test
    test_information_recovery(legacy_spend_privkey,
        legacy_view_privkey,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_enote_subaddr_dest,
        enote_ephemeral_pubkey_subaddr_dest,
        0,
        subaddr_index,
        amount_subaddr_dest);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_legacy, information_recovery_enote_v3)
{
    using namespace sp;

    // prepare user keys
    const crypto::secret_key legacy_spend_privkey{make_secret_key()};
    const crypto::secret_key legacy_view_privkey{make_secret_key()};
    const rct::key legacy_base_spend_pubkey{rct::scalarmultBase(rct::sk2rct(legacy_spend_privkey))};

    // prepare normal address
    const rct::key normal_addr_spendkey{legacy_base_spend_pubkey};
    const rct::key normal_addr_viewkey{rct::scalarmultBase(rct::sk2rct(legacy_view_privkey))};

    // prepare subaddress
    rct::key subaddr_spendkey;
    rct::key subaddr_viewkey;
    cryptonote::subaddress_index subaddr_index;

    make_legacy_subaddress(legacy_base_spend_pubkey, legacy_view_privkey, subaddr_spendkey, subaddr_viewkey, subaddr_index);

    // save subaddress
    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;
    legacy_subaddress_map[subaddr_spendkey] = subaddr_index;

    // send enote v3 (normal destination)
    LegacyEnoteV3 legacy_enote_normal_dest;
    const crypto::secret_key enote_ephemeral_privkey_normal_dest{make_secret_key()};
    const rct::key enote_ephemeral_pubkey_normal_dest{
            rct::scalarmultBase(rct::sk2rct(enote_ephemeral_privkey_normal_dest))
        };
    const rct::xmr_amount amount_normal_dest{100};

    ASSERT_NO_THROW(make_legacy_enote_v3(normal_addr_spendkey,
        normal_addr_viewkey,
        amount_normal_dest,
        0,
        enote_ephemeral_privkey_normal_dest,
        legacy_enote_normal_dest));

    // information recovery test
    test_information_recovery(legacy_spend_privkey,
        legacy_view_privkey,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_enote_normal_dest,
        enote_ephemeral_pubkey_normal_dest,
        0,
        boost::none,
        amount_normal_dest);

    // send enote v3 (subaddress destination)
    LegacyEnoteV3 legacy_enote_subaddr_dest;
    const crypto::secret_key enote_ephemeral_privkey_subaddr_dest{make_secret_key()};
    const rct::key enote_ephemeral_pubkey_subaddr_dest{
            rct::scalarmultKey(subaddr_spendkey, rct::sk2rct(enote_ephemeral_privkey_subaddr_dest))
        };
    const rct::xmr_amount amount_subaddr_dest{999999};

    ASSERT_NO_THROW(make_legacy_enote_v3(subaddr_spendkey,
        subaddr_viewkey,
        amount_subaddr_dest,
        0,
        enote_ephemeral_privkey_subaddr_dest,
        legacy_enote_subaddr_dest));

    // information recovery test
    test_information_recovery(legacy_spend_privkey,
        legacy_view_privkey,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_enote_subaddr_dest,
        enote_ephemeral_pubkey_subaddr_dest,
        0,
        subaddr_index,
        amount_subaddr_dest);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_legacy, information_recovery_enote_v4)
{
    using namespace sp;

    // prepare user keys
    const crypto::secret_key legacy_spend_privkey{make_secret_key()};
    const crypto::secret_key legacy_view_privkey{make_secret_key()};
    const rct::key legacy_base_spend_pubkey{rct::scalarmultBase(rct::sk2rct(legacy_spend_privkey))};

    // prepare normal address
    const rct::key normal_addr_spendkey{legacy_base_spend_pubkey};
    const rct::key normal_addr_viewkey{rct::scalarmultBase(rct::sk2rct(legacy_view_privkey))};

    // prepare subaddress
    rct::key subaddr_spendkey;
    rct::key subaddr_viewkey;
    cryptonote::subaddress_index subaddr_index;

    make_legacy_subaddress(legacy_base_spend_pubkey, legacy_view_privkey, subaddr_spendkey, subaddr_viewkey, subaddr_index);

    // save subaddress
    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;
    legacy_subaddress_map[subaddr_spendkey] = subaddr_index;

    // send enote v4 (normal destination)
    LegacyEnoteV4 legacy_enote_normal_dest;
    const crypto::secret_key enote_ephemeral_privkey_normal_dest{make_secret_key()};
    const rct::key enote_ephemeral_pubkey_normal_dest{
            rct::scalarmultBase(rct::sk2rct(enote_ephemeral_privkey_normal_dest))
        };
    const rct::xmr_amount amount_normal_dest{100};

    ASSERT_NO_THROW(make_legacy_enote_v4(normal_addr_spendkey,
        normal_addr_viewkey,
        amount_normal_dest,
        0,
        enote_ephemeral_privkey_normal_dest,
        legacy_enote_normal_dest));

    // information recovery test
    test_information_recovery(legacy_spend_privkey,
        legacy_view_privkey,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_enote_normal_dest,
        enote_ephemeral_pubkey_normal_dest,
        0,
        boost::none,
        amount_normal_dest);

    // send enote v4 (subaddress destination)
    LegacyEnoteV4 legacy_enote_subaddr_dest;
    const crypto::secret_key enote_ephemeral_privkey_subaddr_dest{make_secret_key()};
    const rct::key enote_ephemeral_pubkey_subaddr_dest{
            rct::scalarmultKey(subaddr_spendkey, rct::sk2rct(enote_ephemeral_privkey_subaddr_dest))
        };
    const rct::xmr_amount amount_subaddr_dest{999999};

    ASSERT_NO_THROW(make_legacy_enote_v4(subaddr_spendkey,
        subaddr_viewkey,
        amount_subaddr_dest,
        0,
        enote_ephemeral_privkey_subaddr_dest,
        legacy_enote_subaddr_dest));

    // information recovery test
    test_information_recovery(legacy_spend_privkey,
        legacy_view_privkey,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_enote_subaddr_dest,
        enote_ephemeral_pubkey_subaddr_dest,
        0,
        subaddr_index,
        amount_subaddr_dest);
}
//-------------------------------------------------------------------------------------------------------------------
