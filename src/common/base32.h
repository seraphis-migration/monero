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

/**
 * @file Encode/Decode using Jamtis base32 encoding
 * 
 * We use the alphabet "xmrbase32cdfghijknpqtuwy01456789"
 * 
 * This alphabet was selected for the following reasons:
 *     1. To have a unique prefix that distinguishes the encoding from other variants of "base32"
 *     2. To contain all digits 0-9, allowing numeric values to be encoded in a human readable form
 *     3. To normalize the symbols o->0, l->1, v->u and z->2 for human transcription correction
 *
 * Hypens can be used to space base32 encoded strings, and are ignored during the decoding process.
*/

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "span.h"

namespace base32
{
enum class Error: ssize_t
{
    invalid_char = -1,    // encountered invalid character when decoding
    not_enough_space = -2 // not enough space in pre-allocated buffers
};

enum class Mode
{
    encoded_lossy, // when decoding, discard odd encoded LSB bits left at end of tail (default).
    binary_lossy   // when encoding, discard odd binary LSB bits left at end of tail.
};

// table of the base32 symbols, in Jamtis order
extern const char JAMTIS_ALPHABET[32];

// table that converts ascii character codes into base32 symbol indexes
extern const unsigned char JAMTIS_INVERTED_ALPHABET[256];

// constants in the inverted table that signal an ascii code is invalid or ignoreable, respectively
static constexpr const unsigned char BADC = 255;
static constexpr const unsigned char IGNC = 254;

/**
 * @brief calculate size of encoded string, returns not_enough_space if binary_len too big
*/
ssize_t encoded_size(const size_t binary_len, const Mode mode = Mode::encoded_lossy) noexcept;

/**
 * @brief calculate maximum size of decoded binary, returns not_enough_space if encoded_len too big
 *        ("maximum" size because hypens are skipped over)
*/
ssize_t decoded_size_max(const size_t encoded_len, const Mode mode = Mode::encoded_lossy) noexcept;

/**
 * @brief encode a binary buffer into a base32 string
 * @param binary_buf
 * @param[out] encoded_str_out null terminator is not included
 * @param mode
 * @return the size of the encoded string, if successful, otherwise a negative Error enum value
*/
ssize_t encode(epee::span<const char> binary_buf,
    epee::span<char> encoded_str_out,
    const Mode mode = Mode::encoded_lossy);

/**
 * @brief encode a binary buffer into a base32 string
 * @param binary_buf
 * @param mode
 * @return the encoded string
*/
std::string encode(const std::string &binary_buf, const Mode mode = Mode::encoded_lossy);

/**
 * @brief decode a base32 string into a binary buffer
 * @param encoded_str
 * @param[out] decoded_buf_out
 * @param mode
 * @return the size of the decoded buffer, if successful, otherwise a negative Error enum value
*/
ssize_t decode(epee::span<const char> encoded_str,
    epee::span<char> decoded_buf_out,
    const Mode mode = Mode::encoded_lossy);

/**
 * @brief decode a base32 string into a binary buffer
 * @param encoded_buf
 * @param mode
 * @return the decoded buffer
 * @throw if an invalid character is encountered
*/
std::string decode(const std::string &encoded_buf, const Mode mode = Mode::encoded_lossy);
} // namespace base32
