// Copyright (c) 2023, The Monero Project
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


// paired header
#include "transaction_utils.h"

// local headers
#include "common/container_helpers.h"
#include "crypto/crypto.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_impl/enote_store.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/sp_knowledge_proof_types.h"
#include "seraphis_main/sp_knowledge_proof_utils.h"
#include "common/base32.h"
#include "seraphis_impl/serialization_demo_utils.h"
#include "seraphis_impl/serialization_demo_types.h"

// third party headers
#include <boost/range.hpp>
#include <boost/range/iterator_range_core.hpp>
#include "boost/range/iterator_range.hpp"

// standard headers
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace sp::serialization;

static const std::vector<int64_t> GEN{0x1ae45cd581, 0x359aad8f02, 0x61754f9b24, 0xc2ba1bb368, 0xcd2623e3f0};
static const int64_t M = 0xffffffffff;
static const std::string alphabet = "xmrbase32cdfghijknpqtuwy01456789";
//-----------------------------------------------------------------
//-----------------------------------------------------------------
int64_t jamtis_polymod(const std::vector<int> &data)
{
    int64_t c = 1;
    int64_t b = 0;
    for (const auto v : data)
    {
        b = (c >> 35);
        c = ((c & 0x07ffffffff) << 5) ^ v;
        for (int64_t j = 0; j < 5; j++)
        {
            if ((b >> j) & 1)
                c ^= GEN[j];
            else
                c ^= 0;
        }
    }
    return c;
}
//-----------------------------------------------------------------
bool jamtis_verify_checksum(const std::string &data)
{
    std::vector<int> addr_data;
    for (auto x : data)
        addr_data.push_back(alphabet.find(x));
    return jamtis_polymod(addr_data) == M;
}
//-----------------------------------------------------------------
std::string jamtis_add_checksum(const std::string &addr_without_checksum)
{
    std::vector<int> addr_data;
    for (auto x : addr_without_checksum)
        addr_data.push_back(alphabet.find(x));

    std::vector<int> data_extended{addr_data};
    data_extended.resize(addr_data.size() + 8);
    int64_t polymod = jamtis_polymod(data_extended) ^ M;
    for (int64_t i = 0; i < 8; i++)
        data_extended[addr_data.size() + i] = ((polymod >> 5 * (7 - i)) & 31);

    std::string addr_with_checksum{};
    for (uint64_t j = 0; j < data_extended.size(); j++)
        addr_with_checksum.push_back(alphabet[data_extended[j]]);

    return addr_with_checksum;
}
//-----------------------------------------------------------------
void get_destination_from_str(const std::string &address, JamtisDestinationV1 &dest_out)
{
    // TODO: make it general for all cases
    // 1. get checksum 
    std::string main_address = address.substr(6, address.length() - 14);
    std::string checksum = address.substr(address.length() - 8);
    std::string addr_with_checksum{jamtis_add_checksum(address.substr(0,address.length() - 8))};

    // 2. test checksum
    if (addr_with_checksum != address)
    {
        std::cout << "Address mismatch at get_destination_from_str!" << std::endl;
    }

    // 3. prepare to recover JamtisDestinationV1
    std::string serialized_address;
    tools::base32::decode(main_address,serialized_address);
    sp::serialization::ser_JamtisDestinationV1 serializable_destination_recovered;
    sp::serialization::try_get_serializable(epee::strspan<std::uint8_t>(serialized_address),
                                        serializable_destination_recovered);
    sp::serialization::recover_sp_destination_v1(serializable_destination_recovered, dest_out);

}
//-----------------------------------------------------------------
void get_str_from_destination(const JamtisDestinationV1 &dest, std::string &address_out)
{
    // TODO: make it general for all cases
    // 1. Initial fixed parameters
    std::string address_prefix = "xmr";
    std::string address_type = "a";
    std::string address_version = "1";
    std::string address_network = "m";

    // 2. prepare to encode string 
    sp::serialization::ser_JamtisDestinationV1 serializable_destination;
    make_serializable_sp_destination_v1(dest, serializable_destination);
    std::string serialized_address;
    sp::serialization::try_append_serializable(serializable_destination, serialized_address);
    std::string address_main;
    tools::base32::encode(serialized_address,address_main);
    std::string address = address_prefix + address_type + address_version + address_network + address_main;
    address_out = jamtis_add_checksum(address);
}
//-----------------------------------------------------------------