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

#include "seraphis_impl/checkpoint_cache.h"

#include "ringct/rctOps.h"

#include <gtest/gtest.h>

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::vector<rct::key> create_dummy_blocks(const std::uint64_t num_blocks)
{
    return std::vector<rct::key>(num_blocks, rct::zero());
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void check_checkpoint_cache_state(const sp::CheckpointCache &cache,
    const std::uint64_t expected_top_index,
    const std::uint64_t expected_num_unpruned)
{
    ASSERT_GE(cache.bottom_block_index() + 1, (cache.min_checkpoint_index() - 1) + 1);
    ASSERT_LE(cache.bottom_block_index(), cache.top_block_index());
    ASSERT_EQ(cache.get_nearest_block_index(cache.bottom_block_index() - 1), cache.min_checkpoint_index() - 1);
    ASSERT_EQ(cache.get_nearest_block_index(-1), cache.min_checkpoint_index() - 1);
    if (cache.num_checkpoints() > 0)
    {
        ASSERT_NE(cache.bottom_block_index(), -1);
        ASSERT_EQ(cache.top_block_index(), expected_top_index);
        ASSERT_EQ(cache.get_next_block_index(cache.bottom_block_index() - 1), cache.bottom_block_index());
        ASSERT_EQ(cache.get_next_block_index(-1), cache.bottom_block_index());

        for (std::uint64_t i{
                    cache.top_block_index() - std::min(expected_num_unpruned, cache.num_checkpoints()) + 1
                };
            i <= cache.top_block_index();
            ++i)
        {
            ASSERT_EQ(cache.get_nearest_block_index(i), i);
        }
    }
    else
    {
        ASSERT_EQ(cache.get_next_block_index(cache.bottom_block_index() - 1), -1);
        ASSERT_EQ(cache.get_next_block_index(-1), -1);
    }
    for (std::uint64_t index_iterator{cache.bottom_block_index()};
        index_iterator != -1;
        index_iterator = cache.get_next_block_index(index_iterator))
    {
        ASSERT_EQ(cache.get_nearest_block_index(index_iterator), index_iterator);
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------

//-------------------------------------------------------------------------------------------------------------------
TEST(checkpoint_cache, unprunable_only)
{
    // prepare cache
    const sp::CheckpointCacheConfig config{
            .num_unprunable = 20,
            .max_separation = 1,
            .density_factor = 1
        };
    const std::uint64_t min_checkpoint_index{0};

    sp::CheckpointCache cache{config, min_checkpoint_index};
    ASSERT_TRUE(cache.min_checkpoint_index() == min_checkpoint_index);

    // add some blocks
    ASSERT_NO_THROW(cache.insert_new_block_ids(0, create_dummy_blocks(config.num_unprunable)));
    check_checkpoint_cache_state(cache, config.num_unprunable - 1, config.num_unprunable);

    // add some more blocks to the end
    // - this is past the prunable section, but using max separation 1
    ASSERT_NO_THROW(cache.insert_new_block_ids(cache.top_block_index() + 1, create_dummy_blocks(config.num_unprunable)));
    check_checkpoint_cache_state(cache, 2*config.num_unprunable - 1, 2*config.num_unprunable);

    // replace all the blocks
    ASSERT_NO_THROW(cache.insert_new_block_ids(0, create_dummy_blocks(config.num_unprunable)));
    check_checkpoint_cache_state(cache, config.num_unprunable - 1, config.num_unprunable);

    // replace half the blocks
    ASSERT_NO_THROW(cache.insert_new_block_ids(config.num_unprunable/2, create_dummy_blocks(config.num_unprunable)));
    check_checkpoint_cache_state(cache,
        config.num_unprunable - 1 + config.num_unprunable/2,
        config.num_unprunable + config.num_unprunable/2);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(checkpoint_cache, greater_refresh)
{
    const sp::CheckpointCacheConfig config{
            .num_unprunable = 10,
            .max_separation = 100,
            .density_factor = 5
        };
    const std::uint64_t min_checkpoint_index{20};

    // refresh index > latest_index - config.num_unprunable?
    sp::CheckpointCache cache{config, min_checkpoint_index};
    ASSERT_NO_THROW(cache.insert_new_block_ids(0, create_dummy_blocks(20)));
    check_checkpoint_cache_state(cache, 19, config.num_unprunable);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(checkpoint_cache, big_cache)
{
    const sp::CheckpointCacheConfig config{
            .num_unprunable = 30,
            .max_separation = 100000,
            .density_factor = 20
        };
    const std::uint64_t min_checkpoint_index{0};

    sp::CheckpointCache cache{config, min_checkpoint_index};
    cache.insert_new_block_ids(0, create_dummy_blocks(1000000));
    ASSERT_EQ(cache.num_checkpoints(), 173);
    check_checkpoint_cache_state(cache, 1000000 - 1, config.num_unprunable);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(checkpoint_cache, big_cache_incremental)
{
    const sp::CheckpointCacheConfig config{
            .num_unprunable = 30,
            .max_separation = 100000,
            .density_factor = 20
        };
    const std::uint64_t min_checkpoint_index{0};

    sp::CheckpointCache cache{config, min_checkpoint_index};

    for (std::size_t i{0}; i < 100; ++i)
    {
        cache.insert_new_block_ids(cache.top_block_index() + 1, create_dummy_blocks(10000));
        check_checkpoint_cache_state(cache, 10000*(i+1) - 1, config.num_unprunable);
    }
    ASSERT_EQ(cache.num_checkpoints(), 194);
}
//-------------------------------------------------------------------------------------------------------------------
