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

//paired header
#include "sp_generator_factory.h"

//local headers
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "crypto/hash.h"
#include "cryptonote_config.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "sp_hash_functions.h"
#include "sp_transcript.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
namespace generator_factory
{

struct SpFactoryGenerator final
{
    crypto::public_key generator;
    ge_p3 generator_p3;
    ge_cached generator_cached;
};

// number of generators to generate (enough for to make a BPP2 proof with the max number of aggregated range proofs)
static constexpr std::size_t MAX_GENERATOR_COUNT{config::BULLETPROOF_PLUS2_MAX_COMMITMENTS*128};

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::vector<SpFactoryGenerator> prepare_generators()
{
    std::vector<SpFactoryGenerator> generators;

    // make generators
    generators.resize(MAX_GENERATOR_COUNT);

    rct::key intermediate_hash;

    for (std::size_t generator_index{0}; generator_index < MAX_GENERATOR_COUNT; ++generator_index)
    {
        SpKDFTranscript transcript{config::HASH_KEY_SERAPHIS_GENERATOR_FACTORY, 4};
        transcript.append("generator_index", generator_index);

        // G[generator_index] = keccak_to_pt(H_32("sp_generator_factory", generator_index))
        sp_hash_to_32(transcript.data(), transcript.size(), intermediate_hash.bytes);
        rct::hash_to_p3(generators[generator_index].generator_p3, intermediate_hash);

        // convert to other representations
        ge_p3_tobytes(to_bytes(generators[generator_index].generator), &generators[generator_index].generator_p3);
        ge_p3_to_cached(&generators[generator_index].generator_cached, &generators[generator_index].generator_p3);
    }

/*
// demo: print first generator public key to console
for (const unsigned char byte : generators[0].generator.data)
{
    printf("0x");
    if (byte < 16)
        printf("0");
    printf("%x ", byte);
}
printf("\n");
*/

    return generators;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static const SpFactoryGenerator& factory_generator_at_index(const std::size_t desired_index)
{
    static const std::vector<SpFactoryGenerator> s_factory_gens{prepare_generators()};

    CHECK_AND_ASSERT_THROW_MES(desired_index < MAX_GENERATOR_COUNT,
        "sp generator factory sanity check: requested generator index exceeds available generators.");

    return s_factory_gens[desired_index];
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
std::size_t max_generator_count()
{
    return MAX_GENERATOR_COUNT;
}
//-------------------------------------------------------------------------------------------------------------------
crypto::public_key get_generator_at_index(const std::size_t generator_index)
{
    return factory_generator_at_index(generator_index).generator;
}
//-------------------------------------------------------------------------------------------------------------------
ge_p3 get_generator_at_index_p3(const std::size_t generator_index)
{
    return factory_generator_at_index(generator_index).generator_p3;
}
//-------------------------------------------------------------------------------------------------------------------
ge_cached get_generator_at_index_cached(const std::size_t generator_index)
{
    return factory_generator_at_index(generator_index).generator_cached;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace generator_factory
} //namespace sp
