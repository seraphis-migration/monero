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

#pragma once

// local headers
#include "seraphis_core/jamtis_destination.h"

// third party headers
#include <string>

// standard headers

// forward declarations

enum class JamtisAddressNetwork : char
{
    FAKECHAIN = 'f',
    MAINNET   = 'm',
    STAGENET  = 's',
    TESTNET   = 't',
};

enum class JamtisAddressVersion : char
{
    V1 = '1',
};

/**
* brief: Given the JamtisDestinationV1, JamtisAddressVersion and JamtisAddressNetwork
         get the human-readable address format 'xmra...'
* param: dest - JamtisDestinationV1
* param: address_version -
* param: address_network -
* return : string representing an human-readable jamtis address -
*/
std::string get_str_from_destination(const sp::jamtis::JamtisDestinationV1 &dest,
    const JamtisAddressVersion address_version,
    const JamtisAddressNetwork address_network);
void get_str_from_destination(const sp::jamtis::JamtisDestinationV1 &dest,
    const JamtisAddressVersion address_version,
    const JamtisAddressNetwork address_network,
    std::string &str_out);

/**
* brief: Given the human-readable address format 'xmra...'
         get the JamtisDestinationV1
* param: address -
* return : destination (JamtisDestinationV1)
*/
void get_destination_from_str(const std::string &address, sp::jamtis::JamtisDestinationV1 &dest_out);

// Encode a JamtisDestination into a human-readable string
// A Jamtis address is represented by the following keys
// [  K1   ][  K2   ][  K3   ][  addr_tag  ]
// [  256  ][  255  ][  255  ][  144       ]  -- number of bits
// Since base32 requires a multiple of 5 number of bits for the best compactness of the generated strings,
// the idea is to encode the last two bits of addr_tag into the last bits of K2 and K3 (since they have only
// 255 bits and the last bit of Curve25519 point is always 0).

/**
* brief: Given a JamtisDestinationV1, return the corresponding base32 encoded string
         using the algorithm described at the function implementation.
* param: destination -
* return : encoded string (std::string)
*/
std::string encode_jamtis_readable_address(const sp::jamtis::JamtisDestinationV1 &destination);

/**
* brief: Given a base32 encoded string, return JamtisDestinationV1 with the correspondent keys
         using the algorithm described at the function implementation.
* param: encoded_address-
* return : jamtis destination (JamtisDestinationV1)
*/
sp::jamtis::JamtisDestinationV1 decode_jamtis_readable_address(const std::string &encoded_address);
