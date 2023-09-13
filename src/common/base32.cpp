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
 *  Copyright (C) 2015 Trustifier Inc.
 *  Copyright (C) 2015 Ahmed Masud
 *  Copyright (C) 2015 Topology LP
 *  Copyright (C) 2018 Jakob Petsovits
 *  All rights reserved.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to
 *  deal in the Software without restriction, including without limitation the
 *  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 *  sell copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 *  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 *  IN THE SOFTWARE.
 *
 *  Adapted from https://github.com/ahmed-masud/libbase32,
 *  commit 79761b2b79b0545697945efe0987a8d3004512f9.
 *  Quite different now.
 */

#include "base32.h"

#include <assert.h>

#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>

namespace tools
{
namespace base32
{

template <bool B>
using uint8_if = typename std::enable_if<B, uint8_t>::type;

static constexpr char base32_monero_alphabet[] = {'x',
    'm',
    'r',
    'b',
    'a',
    's',
    'e',
    '3',
    '2',
    'c',
    'd',
    'f',
    'g',
    'h',
    'i',
    'j',
    'k',
    'n',
    'p',
    'q',
    't',
    'u',
    'w',
    'y',
    '0',
    '1',
    '4',
    '5',
    '6',
    '7',
    '8',
    '9'};
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static constexpr uint8_t binary_block_size{5};
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static constexpr uint8_t encoded_block_size{8};
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static constexpr size_t alphabet_size()
{
    static_assert(sizeof(base32_monero_alphabet) == 32, "base32 alphabet must have 32 values");
    return sizeof(base32_monero_alphabet);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static constexpr char symbol(alphabet_index_t idx) { return base32_monero_alphabet[idx]; }
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static constexpr char normalized_symbol(char c)
{
    // Hex decoding is always case-insensitive (even in RFC 4648), the question
    // is only for encoding whether to use upper-case or lower-case letters.
    return c;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <uint8_t I>
static constexpr uint8_t index(const uint8_t* b /*binary block*/) noexcept
{
    static_assert(I >= 0 && I < encoded_block_size, "invalid encoding symbol index in a block");

    return (I == 0)   ? ((b[0] >> 3) & 0x1F)  // first 5 bits
           : (I == 1) ? (((b[0] << 2) & 0x1C) | ((b[1] >> 6) & 0x3))
           : (I == 2) ? ((b[1] >> 1) & 0x1F)
           : (I == 3) ? (((b[1] << 4) & 0x10) | ((b[2] >> 4) & 0xF))
           : (I == 4) ? (((b[2] << 1) & 0x1E) | ((b[3] >> 7) & 0x1))
           : (I == 5) ? ((b[3] >> 2) & 0x1F)
           : (I == 6) ? (((b[3] << 3) & 0x18) | ((b[4] >> 5) & 0x7))
                      : /*I == 7*/ (b[4] & 0x1F);  // last 5 bits;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <uint8_t I>
static constexpr uint8_if<I == 1 || I == 3 || I == 4 || I == 6> index_last(const uint8_t* b /*binary block*/) noexcept
{
    return (I == 1)   ? ((b[0] << 2) & 0x1C)              // abbreviated 2nd symbol
           : (I == 3) ? ((b[1] << 4) & 0x10)              // abbreviated 4th symbol
           : (I == 4) ? ((b[2] << 1) & 0x1E)              // abbreviated 5th symbol
                      : /*I == 6*/ ((b[3] << 3) & 0x18);  // abbreviated 7th symbol
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <uint8_t I>
static uint8_if<I != 1 && I != 3 && I != 4 && I != 6> index_last(const uint8_t* /*binary block*/)
{
    throw std::domain_error("invalid last encoding symbol index in a tail");
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static constexpr uint8_t num_encoded_tail_symbols(uint8_t num_bytes)
{
    return (num_bytes == 1)   ? 2  // 2 symbols, 6 padding characters
           : (num_bytes == 2) ? 4  // 4 symbols, 4 padding characters
           : (num_bytes == 3) ? 5  // 5 symbols, 3 padding characters
           : (num_bytes == 4) ? 7  // 7 symbols, 1 padding characters
                              : throw std::domain_error("invalid number of bytes in a tail block");
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static constexpr bool is_eof_symbol(char c) { return c == '\0'; }
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static constexpr bool should_ignore(char c)
{
    return c == '-';  // "Hyphens (-) can be inserted into strings [for readability]."
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <size_t I>
struct enc
{
    // Block encoding: Go from 0 to (block size - 1), append a symbol for each iteration unconditionally.
    static void block(std::string& encoded, const uint8_t* src)
    {
        using EncodedBlockSizeT                              = decltype(encoded_block_size);
        constexpr static const EncodedBlockSizeT SymbolIndex = static_cast<EncodedBlockSizeT>(I - 1);

        enc<I - 1>().block(encoded, src);
        encoded.push_back(symbol(index<SymbolIndex>(src)));
    }

    // Tail encoding: Go from 0 until (runtime) num_symbols, append a symbol for each iteration.
    template <typename EncodedBlockSizeT = decltype(encoded_block_size)>
    static void tail(std::string& encoded, const uint8_t* src, EncodedBlockSizeT num_symbols)
    {
        constexpr static const EncodedBlockSizeT SymbolIndex = encoded_block_size - I;
        constexpr static const EncodedBlockSizeT NumSymbols  = SymbolIndex + static_cast<EncodedBlockSizeT>(1);

        if (num_symbols == NumSymbols)
        {
            encoded.push_back(symbol(index_last<SymbolIndex>(src)));
            return;
        }
        encoded.push_back(symbol(index<SymbolIndex>(src)));
        enc<I - 1>().tail(encoded, src, num_symbols);
    }
};
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <>  // terminating specialization
struct enc<0>
{
    static void block(std::string&, const uint8_t*) {}

    template <typename EncodedBlockSizeT = decltype(encoded_block_size)>
    static void tail(std::string&, const uint8_t*, EncodedBlockSizeT)
    {
        // Not reached: block() should be called if num_symbols == block size, not tail().
        throw std::logic_error("base32/tail: this should not be called.");
    }
};
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template<unsigned... Is>
using seq = std::integer_sequence<unsigned, Is...>;

template<unsigned I>
using gen_seq = std::make_integer_sequence<unsigned, I>;

// template <unsigned... Is>
// struct seq
// {
// };
// //-------------------------------------------------------------------------------------------------------------------
// //-------------------------------------------------------------------------------------------------------------------
// template <unsigned N, unsigned... Is>
// struct gen_seq : gen_seq<N - 4, N - 4, N - 3, N - 2, N - 1, Is...>
// {
//     // Clang up to 3.6 has a limit of 256 for template recursion,
//     // so pass a few more symbols at once to make it work.
//     static_assert(N % 4 == 0, "I must be divisible by 4 to eventually end at 0");
// };
// template <unsigned... Is>
// struct gen_seq<0, Is...> : seq<Is...>
// {
// };
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <size_t N>
struct lookup_table_t
{
    alphabet_index_t lookup[N];
    static constexpr size_t size = N;
};
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename LambdaType, unsigned... Is>
constexpr lookup_table_t<sizeof...(Is)> make_lookup_table(seq<Is...>, LambdaType value_for_index)
{
    return {{value_for_index(Is)...}};
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <unsigned N, typename LambdaType>
constexpr lookup_table_t<N> make_lookup_table(LambdaType evalFunc)
{
    return make_lookup_table(gen_seq<N>(), evalFunc);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <alphabet_index_t InvalidIdx, size_t I>
struct index_if_in_alphabet
{
    static constexpr alphabet_index_t for_symbol(char symbol_char)
    {
        return (symbol(static_cast<alphabet_index_t>(alphabet_size() - I)) == symbol_char)
                   ? static_cast<alphabet_index_t>(alphabet_size() - I)
                   : index_if_in_alphabet<InvalidIdx, I - 1>::for_symbol(symbol_char);
    }
};
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <alphabet_index_t InvalidIdx>
struct index_if_in_alphabet<InvalidIdx, 0>
{  // terminating specialization
    static constexpr alphabet_index_t for_symbol(char) { return InvalidIdx; }
};
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
struct alphabet_index_info
{
    static constexpr const size_t num_possible_symbols          = 256;
    static constexpr const alphabet_index_t invalid_idx         = 1 << 9;
    static constexpr const alphabet_index_t eof_idx             = 1 << 10;
    static constexpr const alphabet_index_t stop_character_mask = static_cast<alphabet_index_t>(~0xFFu);

    static constexpr bool is_invalid(alphabet_index_t idx) { return idx == invalid_idx; }
    static constexpr bool is_eof(alphabet_index_t idx) { return idx == eof_idx; }
    static constexpr bool is_stop_character(alphabet_index_t idx) { return (idx & stop_character_mask) != 0; }

   private:
    static constexpr alphabet_index_t valid_index_or(alphabet_index_t a, alphabet_index_t b)
    {
        return a == invalid_idx ? b : a;
    }

    using idx_if_in_alphabet = index_if_in_alphabet<invalid_idx, alphabet_size()>;

    static constexpr alphabet_index_t index_of(char symbol_char)
    {
        return valid_index_or(
            idx_if_in_alphabet::for_symbol(symbol_char), is_eof_symbol(symbol_char) ? eof_idx : invalid_idx);
    }

    static constexpr alphabet_index_t index_at(size_t symbol_char)
    {
        return index_of(normalized_symbol(static_cast<char>(symbol_char)));
    }

   public:
    struct lookup
    {
        static alphabet_index_t for_symbol(char symbol_char)
        {
            static constexpr const auto t = make_lookup_table<num_possible_symbols>(&index_at);
            static_assert(t.size == num_possible_symbols, "lookup table must cover each possible (character) symbol");
            return t.lookup[static_cast<uint8_t>(symbol_char)];
        }
    };
};
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
size_t encoded_size(size_t binary_size) noexcept
{
    return (binary_size * encoded_block_size / binary_block_size) +
           (((binary_size * encoded_block_size) % binary_block_size) ? 1 : 0);
}
//-------------------------------------------------------------------------------------------------------------------
size_t decoded_max_size(size_t encoded_size) noexcept
{
    return (encoded_size / encoded_block_size * binary_block_size) +
           ((encoded_size % encoded_block_size) * binary_block_size / encoded_block_size);
}
//-------------------------------------------------------------------------------------------------------------------
void init(std::string& result, size_t capacity)
{
    result.clear();
    result.reserve(capacity);
}
//-------------------------------------------------------------------------------------------------------------------
void encode(std::string& encoded_result, const uint8_t* src, size_t src_size)
{
    using encoder = enc<encoded_block_size>;

    const uint8_t* src_end = src + src_size;

    if (src_size >= binary_block_size)
    {
        src_end -= binary_block_size;

        for (; src <= src_end; src += binary_block_size)
        {
            encoder::block(encoded_result, src);
        }
        src_end += binary_block_size;
    }

    if (src_end > src)
    {
        auto remaining_src_len = src_end - src;
        assert(!(!remaining_src_len || remaining_src_len >= binary_block_size));

        auto num_symbols = num_encoded_tail_symbols(static_cast<uint8_t>(remaining_src_len));

        encoder::tail(encoded_result, src, num_symbols);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void decode_block(std::string& decoded, const alphabet_index_t* idx)
{
    decoded.push_back(static_cast<uint8_t>(((idx[0] << 3) & 0xF8) | ((idx[1] >> 2) & 0x7)));
    decoded.push_back(static_cast<uint8_t>(((idx[1] << 6) & 0xC0) | ((idx[2] << 1) & 0x3E) | ((idx[3] >> 4) & 0x1)));
    decoded.push_back(static_cast<uint8_t>(((idx[3] << 4) & 0xF0) | ((idx[4] >> 1) & 0xF)));
    decoded.push_back(static_cast<uint8_t>(((idx[4] << 7) & 0x80) | ((idx[5] << 2) & 0x7C) | ((idx[6] >> 3) & 0x3)));
    decoded.push_back(static_cast<uint8_t>(((idx[6] << 5) & 0xE0) | (idx[7] & 0x1F)));
}
//-------------------------------------------------------------------------------------------------------------------
void decode_tail(std::string& decoded, const alphabet_index_t* idx, size_t idx_len)
{
    if (idx_len == 1)
    {
        throw std::invalid_argument("invalid number of symbols in last base32 block: found 1, expected 2, 4, 5 or 7");
    }
    if (idx_len == 3)
    {
        throw std::invalid_argument("invalid number of symbols in last base32 block: found 3, expected 2, 4, 5 or 7");
    }
    if (idx_len == 6)
    {
        throw std::invalid_argument("invalid number of symbols in last base32 block: found 6, expected 2, 4, 5 or 7");
    }

    // idx_len == 2: decoded size 1
    decoded.push_back(static_cast<uint8_t>(((idx[0] << 3) & 0xF8) | ((idx[1] >> 2) & 0x7)));
    if (idx_len == 2)
    {
        return;
    }
    // idx_len == 4: decoded size 2
    decoded.push_back(static_cast<uint8_t>(((idx[1] << 6) & 0xC0) | ((idx[2] << 1) & 0x3E) | ((idx[3] >> 4) & 0x1)));
    if (idx_len == 4)
    {
        return;
    }
    // idx_len == 5: decoded size 3
    decoded.push_back(static_cast<uint8_t>(((idx[3] << 4) & 0xF0) | ((idx[4] >> 1) & 0xF)));
    if (idx_len == 5)
    {
        return;
    }
    // idx_len == 7: decoded size 4
    decoded.push_back(static_cast<uint8_t>(((idx[4] << 7) & 0x80) | ((idx[5] << 2) & 0x7C) | ((idx[6] >> 3) & 0x3)));
}
//-------------------------------------------------------------------------------------------------------------------
void decode(std::string& binary_result, const char* src_encoded, size_t src_size)
{
    using alphabet_index_lookup = typename alphabet_index_info::lookup;

    const char* src     = src_encoded;
    const char* src_end = src + src_size;

    alphabet_index_t alphabet_indexes[encoded_block_size] = {};
    alphabet_indexes[0]                                   = alphabet_index_info::eof_idx;

    alphabet_index_t const* const alphabet_index_start = &alphabet_indexes[0];
    alphabet_index_t const* const alphabet_index_end   = &alphabet_indexes[encoded_block_size];
    alphabet_index_t* alphabet_index_ptr         = &alphabet_indexes[0];

    while (src < src_end)
    {
        if (should_ignore(*src))
        {
            ++src;
            continue;
        }
        *alphabet_index_ptr = alphabet_index_lookup::for_symbol(*src);
        if (alphabet_index_info::is_stop_character(*alphabet_index_ptr))
        {
            break;
        }
        ++src;
        ++alphabet_index_ptr;

        if (alphabet_index_ptr == alphabet_index_end)
        {
            decode_block(binary_result, alphabet_indexes);
            alphabet_index_ptr = const_cast<alphabet_index_t*>(alphabet_index_start);
            // alphabet_index_ptr = alphabet_index_start;
        }
    }

    if (alphabet_index_info::is_invalid(*alphabet_index_ptr))
    {
        throw std::invalid_argument("decode: Symbol error");
    }
    ++src;

    alphabet_index_t* last_index_ptr = alphabet_index_ptr;

    if (last_index_ptr != alphabet_index_start)
    {
        assert(!(alphabet_index_ptr >= alphabet_index_end));
        decode_tail(binary_result, alphabet_indexes, static_cast<size_t>(alphabet_index_ptr - alphabet_index_start));
    }
}
//-------------------------------------------------------------------------------------------------------------------
std::string encode(const std::string input)
{
    const uint8_t* binary = reinterpret_cast<const uint8_t*>(reinterpret_cast<const char*>(input.data()));
    size_t binary_size{input.size()};
    size_t encoded_buffer_size = encoded_size(binary_size);
    std::string encoded_out;
    init(encoded_out, encoded_buffer_size);
    encode(encoded_out, binary, binary_size);
    return encoded_out;
}
//-------------------------------------------------------------------------------------------------------------------
std::string decode(const std::string input)
{
    const char* binary = reinterpret_cast<const char*>(input.data());
    size_t binary_size{input.size()};
    size_t binary_buffer_size{decoded_max_size(binary_size)};
    std::string decoded_out;
    init(decoded_out, binary_buffer_size);
    decode(decoded_out, binary, binary_size);
    return decoded_out;
}

}  // namespace base32
}  // namespace tools
