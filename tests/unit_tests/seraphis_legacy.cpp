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

#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_basic/subaddress_index.h"
#include "device/device.hpp"
#include "misc_language.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/legacy_core_utils.h"
#include "seraphis_core/legacy_enote_types.h"
#include "seraphis_core/legacy_enote_utils.h"
#include "seraphis_main/enote_record_types.h"
#include "seraphis_main/enote_record_utils_legacy.h"
#include "seraphis_mocks/seraphis_mocks.h"

#include "boost/multiprecision/cpp_int.hpp"
#include "gtest/gtest.h"

#include <memory>
#include <vector>

using namespace sp;
using namespace mocks;

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static crypto::secret_key make_secret_key()
{
    return rct::rct2sk(rct::skGen());
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void test_information_recovery(const crypto::secret_key &legacy_spend_privkey,
    const crypto::secret_key &legacy_view_privkey,
    const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const LegacyEnoteVariant &legacy_enote,
    const rct::key &enote_ephemeral_pubkey,
    const std::uint64_t tx_output_index,
    const boost::optional<cryptonote::subaddress_index> &expected_recieving_index,
    const rct::xmr_amount &expected_amount)
{
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

    ASSERT_TRUE(basic_record_recovered.address_index == expected_recieving_index);

    // intermediate enote record: from basic record
    LegacyIntermediateEnoteRecord intermediate_record_recovered_from_basic;

    ASSERT_NO_THROW(ASSERT_TRUE(try_get_legacy_intermediate_enote_record(basic_record_recovered,
        legacy_base_spend_pubkey,
        legacy_view_privkey,
        hw::get_device("default"),
        intermediate_record_recovered_from_basic)));

    ASSERT_TRUE(intermediate_record_recovered_from_basic.address_index == expected_recieving_index);
    ASSERT_TRUE(intermediate_record_recovered_from_basic.amount        == expected_amount);

    // intermediate enote record: full
    LegacyIntermediateEnoteRecord intermediate_record_recovered;

    ASSERT_NO_THROW(ASSERT_TRUE(try_get_legacy_intermediate_enote_record(legacy_enote,
        enote_ephemeral_pubkey,
        tx_output_index,
        0,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        hw::get_device("default"),
        intermediate_record_recovered)));

    ASSERT_TRUE(intermediate_record_recovered.address_index == expected_recieving_index);
    ASSERT_TRUE(intermediate_record_recovered.amount        == expected_amount);

    // full enote record: from basic record
    LegacyEnoteRecord full_record_recovered_from_basic;

    ASSERT_NO_THROW(ASSERT_TRUE(try_get_legacy_enote_record(basic_record_recovered,
        legacy_base_spend_pubkey,
        legacy_spend_privkey,
        legacy_view_privkey,
        hw::get_device("default"),
        full_record_recovered_from_basic)));

    ASSERT_TRUE(full_record_recovered_from_basic.address_index == expected_recieving_index);
    ASSERT_TRUE(full_record_recovered_from_basic.amount        == expected_amount);

    // full enote record: from intermediate record
    LegacyEnoteRecord full_record_recovered_from_intermediate;

    ASSERT_NO_THROW(get_legacy_enote_record(intermediate_record_recovered,
        legacy_spend_privkey,
        hw::get_device("default"),
        full_record_recovered_from_intermediate));

    ASSERT_TRUE(full_record_recovered_from_intermediate.address_index == expected_recieving_index);
    ASSERT_TRUE(full_record_recovered_from_intermediate.amount        == expected_amount);
    ASSERT_TRUE(full_record_recovered_from_intermediate.key_image     == full_record_recovered_from_basic.key_image);

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
        hw::get_device("default"),
        full_record_recovered));

    ASSERT_TRUE(full_record_recovered.address_index == expected_recieving_index);
    ASSERT_TRUE(full_record_recovered.amount        == expected_amount);
    ASSERT_TRUE(full_record_recovered.key_image     == full_record_recovered_from_basic.key_image);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename EnoteT, typename MakeEnoteFuncT>
static void legacy_enote_information_recovery_test(MakeEnoteFuncT make_enote_func)
{
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

    gen_legacy_subaddress(legacy_base_spend_pubkey, legacy_view_privkey, subaddr_spendkey, subaddr_viewkey, subaddr_index);

    // save subaddress
    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;
    legacy_subaddress_map[subaddr_spendkey] = subaddr_index;

    // send enote (normal destination)
    EnoteT legacy_enote_normal_dest;
    const crypto::secret_key enote_ephemeral_privkey_normal_dest{make_secret_key()};
    const rct::key enote_ephemeral_pubkey_normal_dest{
            rct::scalarmultBase(rct::sk2rct(enote_ephemeral_privkey_normal_dest))
        };
    const rct::xmr_amount amount_normal_dest{100};

    ASSERT_NO_THROW(make_enote_func(normal_addr_spendkey,
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

    // send enote (subaddress destination)
    EnoteT legacy_enote_subaddr_dest;
    const crypto::secret_key enote_ephemeral_privkey_subaddr_dest{make_secret_key()};
    const rct::key enote_ephemeral_pubkey_subaddr_dest{
            rct::scalarmultKey(subaddr_spendkey, rct::sk2rct(enote_ephemeral_privkey_subaddr_dest))
        };
    const rct::xmr_amount amount_subaddr_dest{999999};

    ASSERT_NO_THROW(make_enote_func(subaddr_spendkey,
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
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_legacy, enote_information_recovery)
{
    legacy_enote_information_recovery_test<LegacyEnoteV1>(make_legacy_enote_v1);
    legacy_enote_information_recovery_test<LegacyEnoteV2>(make_legacy_enote_v2);
    legacy_enote_information_recovery_test<LegacyEnoteV3>(make_legacy_enote_v3);
    legacy_enote_information_recovery_test<LegacyEnoteV4>(make_legacy_enote_v4);
    legacy_enote_information_recovery_test<LegacyEnoteV5>(make_legacy_enote_v5);
}
//-------------------------------------------------------------------------------------------------------------------
