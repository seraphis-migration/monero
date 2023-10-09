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
#include "common/base32.h"
#include "common/container_helpers.h"
#include "crypto/crypto.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_impl/enote_store.h"
#include "seraphis_impl/jamtis_address_checksum.h"
#include "seraphis_impl/serialization_demo_types.h"
#include "seraphis_impl/serialization_demo_utils.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/sp_knowledge_proof_types.h"
#include "seraphis_main/sp_knowledge_proof_utils.h"

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

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_wallet"

using namespace sp::serialization;
using namespace std;

// Certainly there are faster ways to stringfy an enum
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static string address_version_to_string(JamtisAddressVersion version)
{
    switch (version)
    {
        case JamtisAddressVersion::V1:
            return string("1");
        default:
            return "";
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static string address_network_to_string(JamtisAddressNetwork network)
{
    switch (network)
    {
        case JamtisAddressNetwork::MAINNET:
            return string("m");
        case JamtisAddressNetwork::FAKECHAIN:
            return string("f");
        case JamtisAddressNetwork::STAGENET:
            return string("s");
        case JamtisAddressNetwork::TESTNET:
            return string("t");
        default:
            return "";
    }
}
//-----------------------------------------------------------------
//-----------------------------------------------------------------
void get_destination_from_str(const std::string &address, JamtisDestinationV1 &dest_out)
{
    // 1. get checksum
    std::string main_address = address.substr(6, address.length() - 14);
    std::string checksum     = address.substr(address.length() - 8);
    std::string checksum_calculated{sp::jamtis::create_address_checksum(address.substr(0, address.length() - 8))};

    // 2. test checksum
    CHECK_AND_ASSERT_THROW_MES(checksum != checksum_calculated, "Checksum mismatch at get_destination_from_str.");

    // 3. prepare to recover JamtisDestinationV1
    std::string serialized_address;
    serialized_address = base32::decode(main_address);
    sp::serialization::ser_JamtisDestinationV1 serializable_destination_recovered;
    sp::serialization::try_get_serializable(
        epee::strspan<std::uint8_t>(serialized_address), serializable_destination_recovered);

    // 4. get destination
    sp::serialization::recover_sp_destination_v1(serializable_destination_recovered, dest_out);
}
//-----------------------------------------------------------------
void get_str_from_destination(const JamtisDestinationV1 &dest,
    const JamtisAddressVersion address_version,
    const JamtisAddressNetwork address_network,
    std::string &address_out)
{
    // 1. Initial fixed parameters
    std::string address_prefix = "xmra";

    // 2. prepare to encode string
    sp::serialization::ser_JamtisDestinationV1 serializable_destination;
    make_serializable_sp_destination_v1(dest, serializable_destination);
    std::string serialized_address;
    sp::serialization::try_append_serializable(serializable_destination, serialized_address);
    
    // 3. encode string and add to address
    std::string address = address_prefix + address_version_to_string(address_version) +
                          address_network_to_string(address_network) + base32::encode(serialized_address);

    // 4. add checksum and get address_out
    address_out = address + sp::jamtis::create_address_checksum(address);
}
