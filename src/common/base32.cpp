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

#include "base32.h"

#include <cstring>
#include <limits>
#include <stdexcept>

// you might see a lot of the syntax a / y * x + a % y * x / y used in the code below.
// this is an equivalent way to write the expression a * x / y, but without overflowing.

namespace
{
static constexpr const size_t ENCODED_MAX = static_cast<size_t>(std::numeric_limits<ssize_t>::max());
static constexpr const size_t RAW_MAX = ENCODED_MAX / 8 * 5 + ENCODED_MAX % 8 * 5 / 8;

//--------------------------------------------------------------------------------------------------
template <bool ALLOW_PARTIAL> // ALLOW_PARTIAL=false is faster b/c branches are trimmed
static void encode_block(const char *binary, const size_t binary_len, char *encoded, const base32::Mode mode)
{
    // this function looks complicated, but it's just the handwritten bit smashing operations for
    // a block of 5 binary bytes / 8 base32 symbols with `if` branches inserted to exit when
    // applicable. we encode bytes from left to right, from the MSB in each byte to the LSB. notice
    // that when mode == binary_lossy, we don't encode parts of bytes at the tail, we return early.
    // otherwise, when mode == encoded_lossy, we take the bits we can from the tail byte and use it
    // as the MSB of the alphabet index to the last symbol.
    using namespace base32;
    if (ALLOW_PARTIAL && 0 == binary_len) return;
    encoded[0] = JAMTIS_ALPHABET[(binary[0] & 0b11111000) >> 3];
    if (ALLOW_PARTIAL && 1 == binary_len)
    {
        if (mode == base32::Mode::binary_lossy) { return; }
        else { encoded[1] = JAMTIS_ALPHABET[(binary[0] & 0b00000111) << 2]; return; }
    }
    encoded[1] = JAMTIS_ALPHABET[((binary[0] & 0b00000111) << 2) | ((binary[1] & 0b11000000) >> 6)];
    encoded[2] = JAMTIS_ALPHABET[(binary[1] & 0b00111110) >> 1];
    if (ALLOW_PARTIAL && 2 == binary_len)
    {
        if (mode == base32::Mode::binary_lossy) { return; }
        else { encoded[3] = JAMTIS_ALPHABET[(binary[1] & 0b00000001) << 4]; return; }
    }
    encoded[3] = JAMTIS_ALPHABET[((binary[1] & 0b00000001) << 4) | ((binary[2] & 0b11110000) >> 4)];
    if (ALLOW_PARTIAL && 3 == binary_len)
    {
        if (mode == base32::Mode::binary_lossy) { return; }
        else { encoded[4] = JAMTIS_ALPHABET[(binary[2] & 0b00001111) << 1]; return; }
    }
    encoded[4] = JAMTIS_ALPHABET[((binary[2] & 0b00001111) << 1) | ((binary[3] & 0b10000000) >> 7)];
    encoded[5] = JAMTIS_ALPHABET[(binary[3] & 0b01111100) >> 2];
    if (ALLOW_PARTIAL && 4 == binary_len)
    {
        if (mode == base32::Mode::binary_lossy) { return; }
        else { encoded[6] = JAMTIS_ALPHABET[(binary[3] & 0b00000011) << 3]; return; }
    }
    encoded[6] = JAMTIS_ALPHABET[((binary[3] & 0b00000011) << 3) | ((binary[4] & 0b11100000) >> 5)];
    encoded[7] = JAMTIS_ALPHABET[(binary[4] & 0b00011111)];
}
//--------------------------------------------------------------------------------------------------
[[noreturn]] void throw_by_err_code(const base32::Error err)
{
    switch (err)
    {
    case base32::Error::invalid_char:
        throw std::runtime_error("invalid base32 character encountered in encoded string");
    case base32::Error::not_enough_space:
        throw std::runtime_error("not enough buffer space provided for base32 operation");
    default:
        throw std::logic_error("unexpected base32 error code");
    }
}
} // anonymous namespace
//--------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------
namespace base32
{
//--------------------------------------------------------------------------------------------------
const char JAMTIS_ALPHABET[32] =
{
    'x', 'm', 'r', 'b', 'a', 's', 'e', '3', '2', 'c', 'd', 'f', 'g', 'h', 'i', 'j',
    'k', 'n', 'p', 'q', 't', 'u', 'w', 'y', '0', '1', '4', '5', '6', '7', '8', '9'
};
//--------------------------------------------------------------------------------------------------
const unsigned char JAMTIS_INVERTED_ALPHABET[256] =
{
    BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC,
    BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC,
    BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, IGNC, BADC, BADC,
      24,   25,    8,    7,   26,   27,   28,   29,   30,   31, BADC, BADC, BADC, BADC, BADC, BADC,
    BADC,    4,    3,    9,   10,    6,   11,   12,   13,   14,   15,   16,   25,    1,   17,   24,
      18,   19,    2,    5,   20,   21,   21,   22,    0,   23,    8, BADC, BADC, BADC, BADC, BADC,
    BADC,    4,    3,    9,   10,    6,   11,   12,   13,   14,   15,   16,   25,    1,   17,   24,
      18,   19,    2,    5,   20,   21,   21,   22,    0,   23,    8, BADC, BADC, BADC, BADC, BADC,
    BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC,
    BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC,
    BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC,
    BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC,
    BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC,
    BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC,
    BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC,
    BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC, BADC
};
//--------------------------------------------------------------------------------------------------
ssize_t encoded_size(const size_t binary_len, const Mode mode) noexcept
{
    if (binary_len > RAW_MAX)
        return static_cast<ssize_t>(Error::not_enough_space);

    const ssize_t rem5 = binary_len % 5;
    const bool extra_tail = (mode == Mode::encoded_lossy) && rem5;
    return binary_len / 5 * 8 + rem5 * 8 / 5 + extra_tail;
}
//--------------------------------------------------------------------------------------------------
ssize_t decoded_size_max(const size_t encoded_len, const Mode mode) noexcept
{
    if (encoded_len > ENCODED_MAX)
        return static_cast<ssize_t>(Error::not_enough_space);

    const ssize_t rem8 = encoded_len % 8;
    const bool extra_tail = (mode == Mode::binary_lossy) && rem8;
    return encoded_len / 8 * 5 + rem8 * 5 / 8 + extra_tail;
}
//--------------------------------------------------------------------------------------------------
ssize_t encode(epee::span<const char> binary_buf,
    epee::span<char> encoded_str_out,
    const Mode mode)
{
    const ssize_t actual_encoded_len = encoded_size(binary_buf.size(), mode);
    if (actual_encoded_len < 0 || static_cast<size_t>(actual_encoded_len) > encoded_str_out.size())
        return static_cast<ssize_t>(Error::not_enough_space);

    while (binary_buf.size() >= 5)
    {
        // use encode_block<false> when we are encoding exactly 5 bytes
        encode_block<false>(binary_buf.data(), binary_buf.size(), encoded_str_out.data(), mode);
        binary_buf.remove_prefix(5);
        encoded_str_out.remove_prefix(8);
    }

    // use encode_block<true> when encoding a partial block on the tail
    encode_block<true>(binary_buf.data(), binary_buf.size(), encoded_str_out.data(), mode);

    return actual_encoded_len;
}
//--------------------------------------------------------------------------------------------------
std::string encode(const std::string &binary_buf, const Mode mode)
{
    ssize_t r = encoded_size(binary_buf.size(), mode);
    if (r < 0)
        throw_by_err_code(static_cast<Error>(r));
    std::string enc(r, '\0');
    if (0 > (r = encode(epee::to_span(binary_buf), {&enc[0], enc.size()}, mode)))
        throw_by_err_code(static_cast<Error>(r));
    if (r > (ssize_t) enc.size())
        throw std::logic_error("base32::encode buffer overflow occurred. this should never happen");
    enc.resize(r);
    return enc;
}
//--------------------------------------------------------------------------------------------------
ssize_t decode(const epee::span<const char> encoded_str,
    epee::span<char> decoded_buf_out,
    const Mode mode)
{
    size_t byte_offset = 0;
    unsigned char bit_offset = 0;

    if (encoded_str.size() > ENCODED_MAX)
        return static_cast<ssize_t>(Error::not_enough_space);

    // zero out resulting buffer since we only |= the buffer from here on out
    memset(decoded_buf_out.data(), 0, decoded_buf_out.size());

    for (size_t enc_i = 0; enc_i < encoded_str.size(); ++enc_i)
    {
        if (byte_offset >= decoded_buf_out.size())
            return static_cast<ssize_t>(Error::not_enough_space);

        // grab next alphabet index
        const unsigned char v = JAMTIS_INVERTED_ALPHABET[static_cast<size_t>(encoded_str[enc_i])];
        if (IGNC == v)
            continue;
        else if (v >= 32)
            return static_cast<ssize_t>(Error::invalid_char);

        // write symbol bits to current pointed-to byte
        decoded_buf_out[byte_offset] |= v << 3 >> bit_offset;

        // if we are in encoded lossy mode (default), then don't extend the binary buffer to write
        // only part of a symbol, we can just end here
        if (enc_i == encoded_str.size() - 1 && mode == Mode::encoded_lossy)
            return byte_offset + 1;

        // step byte & bit pointers, and determine if any symbol bits wrap to the next byte
        byte_offset += bit_offset >= 3;
        const bool write_next_byte = bit_offset > 3;
        bit_offset = (bit_offset + 5) & 7;

        if (!write_next_byte)
            continue;
        else if (byte_offset >= decoded_buf_out.size())
            return static_cast<ssize_t>(Error::not_enough_space);

        // write wrapped symbol bits to next byte
        decoded_buf_out[byte_offset] |= v << (8 - bit_offset);
    }

    return byte_offset + (bit_offset != 0);
}
//--------------------------------------------------------------------------------------------------
std::string decode(const std::string &encoded_buf, const Mode mode)
{
    ssize_t r = decoded_size_max(encoded_buf.size(), mode); 
    if (r < 0)
        throw_by_err_code(static_cast<Error>(r));
    std::string dec(r, '\0');
    if (0 > (r = decode(epee::to_span(encoded_buf), {&dec[0], dec.size()}, mode)))
        throw_by_err_code(static_cast<Error>(r));
    if(r > (ssize_t) dec.size())
        throw std::logic_error("base32::encode buffer overflow occurred. this should never happen");
    dec.resize(r);
    return dec;
}
//--------------------------------------------------------------------------------------------------
} // namespace base32
