// Copyright (c) 2024, The Monero Project
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

#include <string>

#include "gtest/gtest.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_wallet/address_utils.h"

TEST(sp_wallet, address_utils_random)
{
    static const JamtisAddressNetwork all_network[] = {JamtisAddressNetwork::FAKECHAIN,
        JamtisAddressNetwork::MAINNET,
        JamtisAddressNetwork::STAGENET,
        JamtisAddressNetwork::TESTNET};
    static const JamtisAddressVersion all_version[] = {JamtisAddressVersion::V1};

    std::string addr_str;
    sp::jamtis::JamtisDestinationV1 dest_recovered;

    for (size_t k = 0; k < 10; k++)
    {
        sp::jamtis::JamtisDestinationV1 dest{sp::jamtis::gen_jamtis_destination_v1()};
        for (const auto n : all_network)
        {
            for (const auto v : all_version)
            {
                get_str_from_destination(dest, v, n, addr_str);
                get_destination_from_str(addr_str, dest_recovered);
                ASSERT_EQ(dest, dest_recovered);
            }
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
TEST(sp_wallet, address_utils_fixed)
{
    std::string addr_fake =
        "xmra1f115jy2ffiwghufu5tb1n65cta13nc7qi47qujcdbjy535upbpxjb8eq8rb9m8e9uik3k0y4py0m3qhyxixbct7w9wykt7hg67xwwmpph"
        "rw7kc3qp8s63aeghk5468ph3kcxjbufec1ndi7fysjrf0jcpgb22rbfbi60qtwt4ye6ua916n8ey26s83shunt";
    std::string addr_main =
        "xmra1m115jy2ffiwghufu5tb1n65cta13nc7qi47qujcdbjy535upbpxjb8eq8rb9m8e9uik3k0y4py0m3qhyxixbct7w9wykt7hg67xwwmpph"
        "rw7kc3qp8s63aeghk5468ph3kcxjbufec1ndi7fysjrf0jcpgb22rbfbi60qtwt4ye6ua916n8ey266ge7bixi";
    std::string addr_stage =
        "xmra1s115jy2ffiwghufu5tb1n65cta13nc7qi47qujcdbjy535upbpxjb8eq8rb9m8e9uik3k0y4py0m3qhyxixbct7w9wykt7hg67xwwmpph"
        "rw7kc3qp8s63aeghk5468ph3kcxjbufec1ndi7fysjrf0jcpgb22rbfbi60qtwt4ye6ua916n8ey2659wduxdk";
    std::string addr_test =
        "xmra1t115jy2ffiwghufu5tb1n65cta13nc7qi47qujcdbjy535upbpxjb8eq8rb9m8e9uik3k0y4py0m3qhyxixbct7w9wykt7hg67xwwmpph"
        "rw7kc3qp8s63aeghk5468ph3kcxjbufec1ndi7fysjrf0jcpgb22rbfbi60qtwt4ye6ua916n8ey2605x9ie7x";

    sp::jamtis::JamtisDestinationV1 dest;
    std::string str_fake, str_main, str_stage, str_test;

    get_destination_from_str(addr_fake, dest);
    get_str_from_destination(dest, JamtisAddressVersion::V1, JamtisAddressNetwork::FAKECHAIN, str_fake);
    ASSERT_EQ(addr_fake, str_fake);

    get_destination_from_str(addr_main, dest);
    get_str_from_destination(dest, JamtisAddressVersion::V1, JamtisAddressNetwork::MAINNET, str_main);
    ASSERT_EQ(addr_main, str_main);

    get_destination_from_str(addr_stage, dest);
    get_str_from_destination(dest, JamtisAddressVersion::V1, JamtisAddressNetwork::STAGENET, str_stage);
    ASSERT_EQ(addr_stage, str_stage);

    get_destination_from_str(addr_test, dest);
    get_str_from_destination(dest, JamtisAddressVersion::V1, JamtisAddressNetwork::TESTNET, str_test);
    ASSERT_EQ(addr_test, str_test);

    ASSERT_NE(addr_test, str_main);
    ASSERT_NE(addr_main, str_fake);
    ASSERT_NE(addr_fake, str_stage);
    ASSERT_NE(addr_stage, str_main);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(sp_wallet, address_utils_size)
{
    std::string addr_str;
    sp::jamtis::JamtisDestinationV1 dest_recovered;
    for (size_t i = 0; i<100; i++)
    {
        sp::jamtis::JamtisDestinationV1 dest{sp::jamtis::gen_jamtis_destination_v1()};
        get_str_from_destination(dest, JamtisAddressVersion::V1, JamtisAddressNetwork::MAINNET, addr_str);
        get_destination_from_str(addr_str, dest_recovered);
        ASSERT_EQ(dest, dest_recovered);
        ASSERT_EQ(addr_str.size(),196);
    }
}
//-------------------------------------------------------------------------------------------------------------------
TEST(sp_wallet, address_utils_wrong_encoding)
{
    // Any X25519 point terminated with 1, ie P[31] = [1xxxxxxx], is an invalid point

    // dest_FF.addr_K2 and dest_FF.addr_K3 are invalid points of X25519
    sp::jamtis::JamtisDestinationV1 dest_FF;
    dest_FF.addr_K1 = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    dest_FF.addr_K2 = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    dest_FF.addr_K3 = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    dest_FF.addr_tag = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

    // Since it is an invalid point, the encoding/decoding will not retrieve the correct point
    // (as we assume that the last bit of addr_K2 and addr_K3 is always 0)
    std::string addr_FF;
    sp::jamtis::JamtisDestinationV1 dest_recovered;
    get_str_from_destination(dest_FF, JamtisAddressVersion::V1 ,JamtisAddressNetwork::MAINNET, addr_FF);
    get_destination_from_str(addr_FF, dest_recovered);
    ASSERT_FALSE(dest_FF == dest_recovered);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(sp_wallet, address_utils_specific_points)
{
    // ones everywhere except for the last bit of the X25519 pub keys
    sp::jamtis::JamtisDestinationV1 dest_ones;
    dest_ones.addr_K1 = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    dest_ones.addr_K2 = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x7F};
    dest_ones.addr_K3 = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x7F};
    dest_ones.addr_tag = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

    std::string addr_ones;
    get_str_from_destination(dest_ones, JamtisAddressVersion::V1 ,JamtisAddressNetwork::MAINNET, addr_ones);

    std::string addr_ones_std = {
        "xmra1m99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999"
        "999999999999999999999999999999999999999999999999999999999999999999999999999999mnmpr3rc"};
    ASSERT_EQ(addr_ones, addr_ones_std);


    // Every byte is 0x55 = [01010101]
    sp::jamtis::JamtisDestinationV1 dest_55;
    dest_55.addr_K1 = {0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55};
    dest_55.addr_K2 = {0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55};
    dest_55.addr_K3 = {0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55};
    dest_55.addr_tag = {0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55};

    std::string addr_55;
    get_str_from_destination(dest_55, JamtisAddressVersion::V1 ,JamtisAddressNetwork::MAINNET, addr_55);

    std::string addr_55_std = {
        "xmra1mdudududududududududududududududududududududududududududududududududududududududududududududududududududu"
        "dudududududududududududududududududududududududu4ududududududududududududududurm006eep"};
    ASSERT_EQ(addr_55, addr_55_std);

    // Every byte is 0x7F = [01111111]
    sp::jamtis::JamtisDestinationV1 dest_7F;
    dest_7F.addr_K1 = {0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F};
    dest_7F.addr_K2 = {0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F};
    dest_7F.addr_K3 = {0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F};
    dest_7F.addr_tag = {0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F,0x7F};

    std::string addr_7F;
    get_str_from_destination(dest_7F, JamtisAddressVersion::V1 ,JamtisAddressNetwork::MAINNET, addr_7F);

    std::string addr_7F_std = {
        "xmra1mj79y8959j79y8959j79y8959j79y8959j79y8959j79y8959j79y8959j79y8959j79y8959j79y8959j79y8959j79y8959j79y8959"
        "j79y8959j79y8959j79y8959j79y8959j79y8959j79y8959979y8959j79y8959j79y8959j79y99ngs96y7r"};
    ASSERT_EQ(addr_7F, addr_7F_std);
}
