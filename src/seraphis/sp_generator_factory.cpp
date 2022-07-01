// Copyright (c) 2014-2020, The Monero Project
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
// 

//paired header
#include "sp_generator_factory.h"

//local headers
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "crypto/hash.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "seraphis_config_temp.h"
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

// minimum number of generators to generate
static const std::size_t DEFAULT_GENERATOR_COUNT{128};

// saved generators
static std::vector<crypto::public_key> factory_generators;
static std::vector<ge_p3> factory_generators_p3;
static std::vector<ge_cached> factory_generators_cached;

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void prepare_generators(const std::size_t min_generator_index)
{
    // leave early if we already have enough generators
    if (factory_generators.size() > min_generator_index)
        return;

    // prepare to extend the generators
    CHECK_AND_ASSERT_THROW_MES(min_generator_index < 10000,
        "sp generator factory sanity check: requested generator index is too high.");

    const std::size_t new_generator_count{
            min_generator_index + 1 > DEFAULT_GENERATOR_COUNT
            ? min_generator_index + 1
            : DEFAULT_GENERATOR_COUNT
        };

    const std::size_t old_generator_count{factory_generators.size()};
    factory_generators.resize(new_generator_count);
    factory_generators_p3.resize(new_generator_count);
    factory_generators_cached.resize(new_generator_count);

    // make generators
    rct::key intermediate_hash;

    for (std::size_t generator_index{old_generator_count}; generator_index < new_generator_count; ++generator_index)
    {
        SpKDFTranscript transcript{config::HASH_KEY_SERAPHIS_GENERATOR_FACTORY, 4};
        transcript.append("generator_index", generator_index);

        // G[generator_index] = keccak_to_pt(H_32("sp_generator_factory", generator_index))
        sp_hash_to_32(transcript, intermediate_hash.bytes);
        rct::hash_to_p3(factory_generators_p3[generator_index], intermediate_hash);

        // convert to other representations
        ge_p3_tobytes(to_bytes(factory_generators[generator_index]), &factory_generators_p3[generator_index]);
        ge_p3_to_cached(&factory_generators_cached[generator_index], &factory_generators_p3[generator_index]);
    }
}
//-------------------------------------------------------------------------------------------------------------------
crypto::public_key get_generator_at_index(const std::size_t generator_index)
{
    prepare_generators(generator_index);
    return factory_generators[generator_index];
}
//-------------------------------------------------------------------------------------------------------------------
ge_p3 get_generator_at_index_p3(const std::size_t generator_index)
{
    prepare_generators(generator_index);
    return factory_generators_p3[generator_index];
}
//-------------------------------------------------------------------------------------------------------------------
ge_cached get_generator_at_index_cached(const std::size_t generator_index)
{
    prepare_generators(generator_index);
    return factory_generators_cached[generator_index];
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace generator_factory
} //namespace sp
