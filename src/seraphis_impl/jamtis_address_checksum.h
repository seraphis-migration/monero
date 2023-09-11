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

/**
 * @brief: utilties for creating and verifying checksums on base32 encoded data
 *
 * This code uses tevador's GF32 checksum algorithm and can make checksums that recognize =< 5
 * corrupted characters on any base32 encoded data, regardless of alphabet.
 *
 * spec here: https://gist.github.com/tevador/50160d160d24cfc6c52ae02eb3d17024#63-checksum
 */

#pragma once

#include <cstddef>

#include "common/base32.h"

namespace sp
{
namespace jamtis
{
static constexpr const size_t ADDRESS_CHECKSUM_SIZE_ENCODED = 8;

/**
* brief: create_address_checksum - create an 8 character checksum on base32 encoded data
* param: encoded_data - base32 encoded data
* param: encoded_data_size -
* outparam: checksum_out - eight byte checksum, encoded with the same encoding as input buffer
* return: true on success, false if input string is invalid
*/
bool create_address_checksum(const char *encoded_data,
    size_t encoded_data_size,
    char checksum_out[ADDRESS_CHECKSUM_SIZE_ENCODED]);

/**
* brief: create_address_checksum - create an 8 character checksum on base32 encoded data
* param: encoded_data - base32 encoded data
* return: 8 character checksum string
* throw: std::runtime_error if encoded_data contains invalid characters
*/
std::string create_address_checksum(const std::string &encoded_data);

/**
* brief: verify_address_checksum - check whether a checksum verifies for given base32 encoded data
* param: encoded_data - base32 encoded data
* param: encoded_data_size -
* param: checksum - eight byte checksum, encoded with the same encoding as input buffer
* return: true on verification success, false if input string is invalid or checksum is bad
*/
bool verify_address_checksum(const char *encoded_data,
    size_t encoded_data_size,
    const char checksum[ADDRESS_CHECKSUM_SIZE_ENCODED]);

/**
* brief: verify_address_checksum - check whether a checksum verifies for given base32 encoded data
* param: encoded_data - base32 encoded data
* param: checksum - eight byte checksum, encoded as base32
* return: true on verification success, false if input string is invalid or checksum is bad
*/
bool verify_address_checksum(const std::string &encoded_data, const std::string &checksum);

/**
* brief: verify_address_checksum - check whether a checksum verifies for given base32 encoded data
* param: encoded_data_and_checksum - base32 encoded data with 8 byte checksum appended to the end
* return: true on verification success, false if input string is invalid or checksum is bad
*/
bool verify_address_checksum(const std::string &encoded_data_and_checksum);
} // namespace jamtis
} // namespace sp
