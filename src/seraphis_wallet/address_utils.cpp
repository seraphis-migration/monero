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

// paired header
#include "address_utils.h"

#include "misc_log_ex.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_impl/jamtis_address_checksum.h"

// local headers

// third party headers

// standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_wallet"

void get_destination_from_str(const std::string &address, sp::jamtis::JamtisDestinationV1 &dest_out)
{
    CHECK_AND_ASSERT_THROW_MES(address.substr(0,4) == "xmra", "Not a jamtis address at get_destination_from_str.");

    // 1. get checksum
    std::string main_address = address.substr(6, address.length() - 14);
    std::string checksum     = address.substr(address.length() - 8);
    std::string checksum_calculated{sp::jamtis::create_address_checksum(address.substr(0, address.length() - 8))};

    // 2. test checksum
    CHECK_AND_ASSERT_THROW_MES(checksum == checksum_calculated, "Checksum mismatch at get_destination_from_str.");

    // 3. recover JamtisDestinationV1
    dest_out = decode_jamtis_readable_address(main_address);
}
//-----------------------------------------------------------------
std::string get_str_from_destination(const sp::jamtis::JamtisDestinationV1 &dest,
    const JamtisAddressVersion address_version,
    const JamtisAddressNetwork address_network)
{
    // 1. initial fixed parameters
    const std::string address_prefix = "xmra";

    // 2. prepare to encode string
    std::string encoded_keys{encode_jamtis_readable_address(dest)};

    // 3. encode string and add to address
    std::string address = address_prefix;
    address += static_cast<char>(address_version);
    address += static_cast<char>(address_network);
    address += encoded_keys;

    // 4. add checksum and return address
    return address + sp::jamtis::create_address_checksum(address);
}
//-----------------------------------------------------------------
void get_str_from_destination(const sp::jamtis::JamtisDestinationV1 &dest,
    const JamtisAddressVersion address_version,
    const JamtisAddressNetwork address_network,
    std::string &str_out)
{
    str_out = get_str_from_destination(dest,address_version,address_network);
}
//-----------------------------------------------------------------
// Encoding algorithm:
// 1.  s is a string of size 114 bytes
// 2. copy bytes from destination into string
    // s = [ K1 K2 K3 addr_tag]
    // consider last byte of s = [JKxxxxxx]
// 3. clear last bit of K2
    // s[63] = [0xxxxxxx]
// 4. fill last bit of K2 with last bit of addr_tag
    // s[63] = [Jxxxxxxx]
// 5. clear last bit of K3
    // s[95] = [0xxxxxxx]
// 6. fill last bit of K3 with before last bit of addr_tag
    // s[95] = [Kxxxxxxx]
// 7. shifts addr_tag 2 bits
    // s[113] = [xxxxxx00]
// 8. return encoded base32 string
//-----------------------------------------------------------------
std::string encode_jamtis_readable_address(const sp::jamtis::JamtisDestinationV1 &destination)
{
    // 1. define output string
    std::string jamtis_address_raw(114,'\0');

    // 2. copy bytes from destination into string
    memcpy(&jamtis_address_raw[0], destination.addr_K1.bytes, 32);
    memcpy(&jamtis_address_raw[32], destination.addr_K2.data, 32);
    memcpy(&jamtis_address_raw[64], destination.addr_K3.data, 32);
    memcpy(&jamtis_address_raw[96], destination.addr_tag.bytes, 18);

    // 3. clear last bit of K2
    jamtis_address_raw[63] &= 0x7F;

    // 4. fill last bit of K2 with last bit of addr_tag
    jamtis_address_raw[63] |= (jamtis_address_raw[113] & 0x80);

    // 5. clear last bit of K3
    jamtis_address_raw[95] &= 0x7F;

    // 6. fill last bit of K3 with before last bit of addr_tag
    jamtis_address_raw[95] |= (jamtis_address_raw[113] & 0x40) << 1;

    // 7. shifts addr_tag 2 bits
    jamtis_address_raw[113] <<= 2;

    // 8. return encoded base32 string
    return base32::encode(jamtis_address_raw, base32::Mode::binary_lossy);
}
//-----------------------------------------------------------------
// Decoding algorithm:
// 1.  s is a string of size 114 bytes
// 2. decode base32 address into string
    // s = [ K1 K2' K3' addr_tag']
    // consider last byte of original address_tag = [JKxxxxxx]
// 3. shifts addr_tag 2 bits and set last two bits to 0
    // s[113] = [00xxxxxx]
// 4. fill last bit of addr_tag with last bit of K3
    // s[113] = [0Kxxxxxx]
// 5. clear last bit of K3
    // s[95] = [0xxxxxxx]
// 6. fill last bit of addr_tag with last bit of K2
    // s[113] = [JKxxxxxx]
// 7. clear last bit of K2
    // s[95] = [0xxxxxxx]
// 8. copy bytes of string to jamtis_destination
    // s = [ K1 K2 K3 addr_tag ]
//-----------------------------------------------------------------
sp::jamtis::JamtisDestinationV1 decode_jamtis_readable_address(const std::string &encoded_address)
{
    // 1. create recovered variables
    std::string recovered_address;
    sp::jamtis::JamtisDestinationV1 recovered_destination;

    // 2. decode base32 address into string
    recovered_address = base32::decode(encoded_address, base32::Mode::binary_lossy);

    // 3. shifts addr_tag 2 bits
    recovered_address[113] >>= 2;
    recovered_address[113] &= 0x3F;

    // 4. fill last bit of addr_tag with last bit of K3
    recovered_address[113] |= ((recovered_address[95] & 0x80) >> 1);

    // 5. clear last bit of K3
    recovered_address[95] &= 0x7F;

    // 6. fill last bit of addr_tag with last bit of K2
    recovered_address[113] |= (recovered_address[63] & 0x80);

    // 7. clear last bit of K2
    recovered_address[63] &= 0x7F;

    // 8. copy bytes of string to jamtis_destination
    memcpy(recovered_destination.addr_K1.bytes, &recovered_address[0], 32);
    memcpy(recovered_destination.addr_K2.data, &recovered_address[32], 32);
    memcpy(recovered_destination.addr_K3.data, &recovered_address[64], 32);
    memcpy(recovered_destination.addr_tag.bytes, &recovered_address[96], 18);

    // 9. return destination
    return recovered_destination;
}
