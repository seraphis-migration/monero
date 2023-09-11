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

#include <cstdint>
#include <cstring>
#include <stdexcept>

#include "jamtis_address_checksum.h"

namespace
{
static constexpr const uint64_t GEN[5] = {0x1ae45cd581, 0x359aad8f02, 0x61754f9b24, 0xc2ba1bb368, 0xcd2623e3f0};

static constexpr const uint64_t M = 0xffffffffff;

// pass c=1 to start the chain
static bool jamtis_checksum_polymod(const char *encoded_data, size_t encoded_data_size, uint64_t &c)
{
    for (const char *p = encoded_data; p < encoded_data + encoded_data_size; ++p)
    {
        const uint64_t v = (base32::JAMTIS_INVERTED_ALPHABET[static_cast<size_t>(*p)]);
        if (v == base32::IGNC) // if character to ignore
            continue;
        else if (v >= 32) // if invalid character in input string
            return false;

        // voodoo magic
        const uint64_t b = c >> 35;
        c = ((c & 0x07ffffffff) << 5) ^ v;
        for (uint64_t i = 0; i < 5; ++i)
            if ((b >> i) & 1)
                c ^= GEN[i];
    }

    return true;
}

// optimized version for updating c with 8-bytes of GF[0] when creating checksums
static inline uint64_t jamtis_checksum_polymod_zerosum(uint64_t c)
{
    for (int j = 0; j < sp::jamtis::ADDRESS_CHECKSUM_SIZE_ENCODED; ++j)
    {
        // voodoo magic with v=0
        const uint64_t b = c >> 35;
        c = ((c & 0x07ffffffff) << 5);
        for (uint64_t i = 0; i < 5; ++i)
            if ((b >> i) & 1)
                c ^= GEN[i];
    }
    return c;
}
} // anonymous namespace

namespace sp
{
namespace jamtis
{
bool create_address_checksum(const char *encoded_data,
    size_t encoded_data_size,
    char checksum_out[ADDRESS_CHECKSUM_SIZE_ENCODED])
{
    static_assert(ADDRESS_CHECKSUM_SIZE_ENCODED <= 8, "integer underflow will occur");

    // calculate checksum
    uint64_t c = 1;
    if (!jamtis_checksum_polymod(encoded_data, encoded_data_size, c))
        return false;
    c = jamtis_checksum_polymod_zerosum(c) ^ M;

    // write checksum to output
    for (uint64_t i = 0; i < ADDRESS_CHECKSUM_SIZE_ENCODED; ++i)
        checksum_out[i] = base32::JAMTIS_ALPHABET[(c >> (5 * (7 - i))) & 31];

    return true;
}

std::string create_address_checksum(const std::string &encoded_data)
{
    std::string res(ADDRESS_CHECKSUM_SIZE_ENCODED, '\0');
    if (!create_address_checksum(encoded_data.data(), encoded_data.size(), &res[0]))
        throw std::runtime_error("couldn't create Jamtis checksum due to invalid char in input");
    return res;
}

bool verify_address_checksum(const char *encoded_data,
    size_t encoded_data_size,
    const char checksum[ADDRESS_CHECKSUM_SIZE_ENCODED])
{
    // calculate checksum
    uint64_t c = 1;
    if (!jamtis_checksum_polymod(encoded_data, encoded_data_size, c))
        return false;
    if (!jamtis_checksum_polymod(checksum, ADDRESS_CHECKSUM_SIZE_ENCODED, c))
        return false;

    // verify
    return M == c;
}

bool verify_address_checksum(const std::string &encoded_data, const std::string &checksum)
{
    if (checksum.size() != ADDRESS_CHECKSUM_SIZE_ENCODED)
        return false;
    
    return verify_address_checksum(encoded_data.data(), encoded_data.size(), checksum.data());
}

bool verify_address_checksum(const std::string &encoded_data_and_checksum)
{
    if (encoded_data_and_checksum.size() < ADDRESS_CHECKSUM_SIZE_ENCODED)
        return false;
    
    const size_t data_len = encoded_data_and_checksum.size() - ADDRESS_CHECKSUM_SIZE_ENCODED;
    return verify_address_checksum(encoded_data_and_checksum.data(),
        data_len,
        encoded_data_and_checksum.data() + data_len);
}
} // namespace jamtis
} // namespace sp
