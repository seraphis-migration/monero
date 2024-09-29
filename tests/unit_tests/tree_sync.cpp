// Copyright (c) 2014, The Monero Project
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

#include "gtest/gtest.h"

#include "cryptonote_basic/cryptonote_format_utils.h"
#include "curve_trees.h"
#include "fcmp_pp/curve_trees.h"
#include "fcmp_pp/tree_sync.h"


//----------------------------------------------------------------------------------------------------------------------
TEST(tree_sync, register_output)
{
    // 1. Init
    auto curve_trees = fcmp_pp::curve_trees::curve_trees_v1();
    auto tree_sync = new fcmp_pp::curve_trees::TreeSync<Helios, Selene>(curve_trees);

    const std::size_t INIT_LEAVES = 10;
    auto outputs = test::generate_random_outputs(*curve_trees, 0, INIT_LEAVES);
    CHECK_AND_ASSERT_THROW_MES(outputs.size() == INIT_LEAVES, "unexpected size of outputs");

    // Mock values
    const uint64_t block_idx_included_in_chain = 0;
    const crypto::hash block_hash_included_in_chain = crypto::hash{};
    const uint64_t unlock_block_idx = 0;

    const auto output = outputs[0].output_pair;

    // 2. Register output - valid
    bool r = tree_sync->register_output(block_idx_included_in_chain,
        block_hash_included_in_chain,
        unlock_block_idx,
        output);

    ASSERT_TRUE(r);

    // 3. Register same output again - already registered
    r = tree_sync->register_output(block_idx_included_in_chain,
        block_hash_included_in_chain,
        unlock_block_idx,
        output);

    ASSERT_FALSE(r);

    // 4. Register another output with the same output pubkey as existing, different commitment - valid
    auto output_new_commitment = output;
    output_new_commitment.commitment = outputs[1].output_pair.commitment;

    ASSERT_EQ(output_new_commitment.output_pubkey, output.output_pubkey);
    ASSERT_NE(output_new_commitment.commitment, output.commitment);

    r = tree_sync->register_output(block_idx_included_in_chain,
        block_hash_included_in_chain,
        unlock_block_idx,
        output_new_commitment);

    ASSERT_TRUE(r);

    // 5. Sync the block of outputs
    tree_sync->sync_block(block_idx_included_in_chain,
        block_hash_included_in_chain,
        crypto::hash{}/*prev_block_hash*/,
        std::move(outputs));

    // 6. Register a new output where we already synced the block output unlocks in - expect throw
    const auto &new_output = test::generate_random_outputs(*curve_trees, INIT_LEAVES, 1).front().output_pair;
    EXPECT_ANY_THROW(tree_sync->register_output(block_idx_included_in_chain,
        block_hash_included_in_chain,
        unlock_block_idx,
        new_output));
}
//----------------------------------------------------------------------------------------------------------------------
TEST(tree_sync, sync_block_simple)
{
    // 1. Init
    static const std::size_t INIT_LEAVES = 10;

    auto curve_trees = fcmp_pp::curve_trees::curve_trees_v1();
    auto tree_sync = new fcmp_pp::curve_trees::TreeSync<Helios, Selene>(curve_trees);

    auto outputs = test::generate_random_outputs(*curve_trees, 0, INIT_LEAVES);
    CHECK_AND_ASSERT_THROW_MES(outputs.size() == INIT_LEAVES, "unexpected size of outputs");

    // Mock values
    const uint64_t block_idx_included_in_chain = 0;
    const crypto::hash block_hash_included_in_chain = crypto::hash{};
    const uint64_t unlock_block_idx = 0;

    const auto output = outputs[0].output_pair;

    // 2. Register output
    bool r = tree_sync->register_output(block_idx_included_in_chain,
        block_hash_included_in_chain,
        unlock_block_idx,
        output);

    ASSERT_TRUE(r);

    // 3. Sync the block of outputs
    tree_sync->sync_block(block_idx_included_in_chain,
        block_hash_included_in_chain,
        crypto::hash{}/*prev_block_hash*/,
        std::move(outputs));

    // 4. Get the output's path in the tree
    CurveTreesV1::Path output_path;
    ASSERT_TRUE(tree_sync->get_output_path(output, output_path));

    // If the c2 layer chunk width < INIT_LEAVES, the test won't use expected values below
    ASSERT_GE(curve_trees->m_c2_width, INIT_LEAVES);
    ASSERT_EQ(output_path.leaves.size(), INIT_LEAVES);
    ASSERT_TRUE(curve_trees->audit_path(output_path, output, INIT_LEAVES));
}
//----------------------------------------------------------------------------------------------------------------------
TEST(tree_sync, sync_n_blocks_register_n_outputs)
{
    // Init
    static const std::size_t LEAVES_PER_BLOCK = 10;
    static const std::size_t N_BLOCKS = 101;

    auto curve_trees = fcmp_pp::curve_trees::curve_trees_v1();
    auto tree_sync = new fcmp_pp::curve_trees::TreeSync<Helios, Selene>(curve_trees);

    crypto::hash prev_block_hash = crypto::hash{};

    // Keep track of all registered outputs so that we can make sure ALL output paths update correctly every block
    std::vector<fcmp_pp::curve_trees::OutputPair> registered_outputs;
    registered_outputs.reserve(N_BLOCKS);

    // Sync N_BLOCKS blocks, 1 block at a time
    for (std::size_t i = 0; i < N_BLOCKS; ++i)
    {
        LOG_PRINT_L1("Syncing block " << i+1);

        // Generate LEAVES_PER_BLOCK random outputs
        const auto n_total_leaves = i * LEAVES_PER_BLOCK;
        auto outputs = test::generate_random_outputs(*curve_trees, n_total_leaves, LEAVES_PER_BLOCK);
        CHECK_AND_ASSERT_THROW_MES(outputs.size() == LEAVES_PER_BLOCK, "unexpected size of outputs");

        // Pick an output to register
        auto output_to_register = i % LEAVES_PER_BLOCK;
        const auto output = outputs[output_to_register].output_pair;

        // Set output metadata
        const uint64_t block_idx_included_in_chain = i;
        crypto::hash block_hash_included_in_chain;
        crypto::cn_fast_hash(&i, sizeof(std::size_t), block_hash_included_in_chain);
        const uint64_t unlock_block_idx = i;

        // Register the output
        bool r = tree_sync->register_output(block_idx_included_in_chain,
            block_hash_included_in_chain,
            unlock_block_idx,
            output);
        ASSERT_TRUE(r);
        registered_outputs.push_back(output);

        // Sync the outputs generated above
        tree_sync->sync_block(block_idx_included_in_chain,
            block_hash_included_in_chain,
            prev_block_hash,
            std::move(outputs));

        // Audit all registered output paths
        for (const auto &o : registered_outputs)
        {
            CurveTreesV1::Path output_path;
            ASSERT_TRUE(tree_sync->get_output_path(o, output_path));
            ASSERT_TRUE(curve_trees->audit_path(output_path, o, (n_total_leaves+LEAVES_PER_BLOCK)));
        }

        // Update for next iteration
        prev_block_hash = block_hash_included_in_chain;
    }
}
//----------------------------------------------------------------------------------------------------------------------
TEST(tree_sync, sync_n_blocks_register_one_output)
{
    // Init
    static const std::size_t LEAVES_PER_BLOCK = 10;
    static const std::size_t N_BLOCKS = 101;
    static const std::size_t TOTAL_N_OUTPUTS = LEAVES_PER_BLOCK * N_BLOCKS;

    auto curve_trees = fcmp_pp::curve_trees::curve_trees_v1();

    // For every output, sync N_BLOCKS registering 1 output each separate sync, and audit its path
    for (std::size_t i = 0; i < TOTAL_N_OUTPUTS; ++i)
    {
        LOG_PRINT_L1("Test register output " << i << " / " << TOTAL_N_OUTPUTS);
        auto tree_sync = new fcmp_pp::curve_trees::TreeSync<Helios, Selene>(curve_trees);

        fcmp_pp::curve_trees::OutputPair registered_output;
        bool registered = false;

        crypto::hash prev_block_hash = crypto::hash{};

        // Sync N_BLOCKS blocks, 1 block at a time
        for (std::size_t j = 0; j < N_BLOCKS; ++j)
        {
            // Generate LEAVES_PER_BLOCK random outputs
            const auto n_total_leaves = j * LEAVES_PER_BLOCK;
            auto outputs = test::generate_random_outputs(*curve_trees, n_total_leaves, LEAVES_PER_BLOCK);
            CHECK_AND_ASSERT_THROW_MES(outputs.size() == LEAVES_PER_BLOCK, "unexpected size of outputs");

            // Block metadata
            const uint64_t block_idx_included_in_chain = j;
            crypto::hash block_hash_included_in_chain;
            crypto::cn_fast_hash(&j, sizeof(std::size_t), block_hash_included_in_chain);

            // Check if this chunk includes the output we're supposed to register
            if (n_total_leaves <= i && i < (n_total_leaves + LEAVES_PER_BLOCK))
            {
                ASSERT_FALSE(registered);

                auto output_to_register = i % LEAVES_PER_BLOCK;
                const auto output = outputs[output_to_register].output_pair;

                // Register the output
                bool r = tree_sync->register_output(block_idx_included_in_chain,
                    block_hash_included_in_chain,
                    block_idx_included_in_chain,
                    output);
                ASSERT_TRUE(r);

                registered = true;
                registered_output = output;
            }

            // Sync the outputs generated above
            tree_sync->sync_block(block_idx_included_in_chain,
                block_hash_included_in_chain,
                prev_block_hash,
                std::move(outputs));

            // Audit registered output path
            if (registered)
            {
                CurveTreesV1::Path output_path;
                ASSERT_TRUE(tree_sync->get_output_path(registered_output, output_path));
                ASSERT_TRUE(curve_trees->audit_path(output_path, registered_output, (n_total_leaves+LEAVES_PER_BLOCK)));
            }

            // Update for next iteration
            prev_block_hash = block_hash_included_in_chain;
        }

        ASSERT_TRUE(registered);
    }
}
//----------------------------------------------------------------------------------------------------------------------
// TODO: test sync deep tree with >=5 layers
// TODO: test edge cases: duplicate output when syncing, mismatched prev block hash in sync_block
// TODO: reorg handling
// TODO: clean up code
//----------------------------------------------------------------------------------------------------------------------
