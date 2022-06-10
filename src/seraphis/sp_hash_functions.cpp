// Copyright (c) 2021, The Monero Project
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

// NOT FOR PRODUCTION

//paired header
#include "sp_hash_functions.h"

//local headers
#include "crypto/blake2b.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "int-util.h"
#include "wipeable_string.h"

//third party headers

//standard headers
#include <string>


namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
// data_out = 'domain-sep' || [input]
//-------------------------------------------------------------------------------------------------------------------
static void hash_data(const std::string &domain_separator,
    const void *input,
    const std::size_t input_length,
    epee::wipeable_string &data_out)
{
    data_out.clear();
    data_out.reserve(domain_separator.size() + input_length);

    data_out += domain_separator;
    if (input && input_length > 0)
        data_out.append(reinterpret_cast<const char *>(input), input_length);
}
//-------------------------------------------------------------------------------------------------------------------
// H_32[k]('domain-sep' || [input])
// - if derivation_key == nullptr, then the hash is NOT keyed
//-------------------------------------------------------------------------------------------------------------------
static void hash_base(const std::string &domain_separator,
    const unsigned char *derivation_key,  //32 bytes
    const void *input,
    const std::size_t input_length,
    unsigned char *hash_out,
    const std::size_t out_length)
{
    epee::wipeable_string data;
    hash_data(domain_separator, input, input_length, data);

    blake2b(hash_out, out_length, data.data(), data.size(), derivation_key, derivation_key ? 32 : 0);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void sp_hash_to_1(const std::string &domain_separator,
    const void *input,
    const std::size_t input_length,
    unsigned char *hash_out)
{
    // H_1(x): 1-byte output
    hash_base(domain_separator, nullptr, input, input_length, hash_out, 1);
}
//-------------------------------------------------------------------------------------------------------------------
void sp_hash_to_8(const std::string &domain_separator,
    const void *input,
    const std::size_t input_length,
    unsigned char *hash_out)
{
    // H_8(x): 8-byte output
    hash_base(domain_separator, nullptr, input, input_length, hash_out, 8);
}
//-------------------------------------------------------------------------------------------------------------------
void sp_hash_to_16(const std::string &domain_separator,
    const void *input,
    const std::size_t input_length,
    unsigned char *hash_out)
{
    // H_16(x): 16-byte output
    hash_base(domain_separator, nullptr, input, input_length, hash_out, 16);
}
//-------------------------------------------------------------------------------------------------------------------
void sp_hash_to_32(const std::string &domain_separator,
    const void *input,
    const std::size_t input_length,
    unsigned char *hash_out)
{
    // H_32(x): 32-byte output
    hash_base(domain_separator, nullptr, input, input_length, hash_out, 32);
}
//-------------------------------------------------------------------------------------------------------------------
void sp_hash_to_scalar(const std::string &domain_separator,
    const void *input,
    const std::size_t input_length,
    unsigned char *hash_out)
{
    // H_n(x): Ed25519 group scalar output (32 bytes)
    // note: hash to 64 bytes then mod l
    unsigned char temp[64];
    hash_base(domain_separator, nullptr, input, input_length, temp, 64);
    sc_reduce(temp);  //mod l
    memcpy(hash_out, temp, 32);
}
//-------------------------------------------------------------------------------------------------------------------
void sp_derive_key(const std::string &domain_separator,
    const unsigned char *derivation_key,  //32 bytes
    const void *input,
    const std::size_t input_length,
    unsigned char *hash_out)
{
    // H_n[k](x): Ed25519 group scalar output (32 bytes)
    // note: hash to 64 bytes then mod l
    unsigned char temp[64];
    hash_base(domain_separator, derivation_key, input, input_length, temp, 64);
    sc_reduce(temp);  //mod l
    memcpy(hash_out, temp, 32);
}
//-------------------------------------------------------------------------------------------------------------------
void sp_derive_secret(const std::string &domain_separator,
    const unsigned char *derivation_key,  //32 bytes
    const void *input,
    const std::size_t input_length,
    unsigned char *hash_out)
{
    // H_32[k](x): 32-byte output
    hash_base(domain_separator, derivation_key, input, input_length, hash_out, 32);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
