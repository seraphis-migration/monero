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

// Checkpoint cache for storing a sequence of block ids whose density exponentially decays into the past.
// Note: A checkpoint cache is useful when you need to track block ids in order to identify and handle reorgs,
//       because typically reorgs only affect very recent blocks.

#pragma once

//local headers
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <deque>
#include <map>

//forward declarations


namespace sp
{

/// Configuration details for a checkpoint cache.
struct CheckpointCacheConfig final
{
    /// number of checkpoints that shouldn't be pruned
    /// - affects the upper end of the stored checkpoints
    std::uint64_t num_unprunable;
    /// maximum separation between checkpoints
    /// - affects the lower end of the stored checkpoints
    std::uint64_t max_separation;
    /// density factor for calibrating the decay rate of checkpoint density
    /// - higher factor means more checkpoints are retained
    std::uint64_t density_factor;
};

////
// CheckpointCache
// - stores a sequence of checkpoints in the range of block ids [refresh index, highest known block index]
// - the pruning strategy is as follows:
//   - range bottom: [refresh index, ..., (top index - num unprunable)]
//     - exponentially falling density from the top of the range to the bottom of the range,
//       with minimum density = 1/max_separation; pruning is achieved by sliding a window down
//       the range and removing the middle window element if the index range covered by the window is too small; simulated
//       elements are used for the top part of the range where the window would otherwise be hanging over 'empty space'
//   - range top (not pruned): ((top index - num unprunable), top index]
// - the bottom-most and top-most blocks that have been inserted will not be pruned (they can be removed/replaced by
//   subsequent inserts)
///
class CheckpointCache
{
public:
//constructors
    CheckpointCache(const CheckpointCacheConfig &config, const std::uint64_t min_checkpoint_index);

//member functions
    /// get minimum allowed index
    std::uint64_t min_checkpoint_index() const { return m_min_checkpoint_index; }
    /// get the number of stored checkpoints
    std::uint64_t num_checkpoints() const { return m_checkpoints.size(); }
    /// get the highest stored index or 'min index - 1' if cache is empty
    std::uint64_t top_block_index() const;
    /// get the lowest stored index or 'min index - 1' if cache is empty
    std::uint64_t bottom_block_index() const;
    /// get the block index of the nearest checkpoint > the test index, or -1 on failure
    /// note: it is allowed to test index -1
    std::uint64_t get_next_block_index(const std::uint64_t test_index) const;
    /// get the block index of the nearest checkpoint <= the test index, or 'min index - 1' on failure
    /// note: it is allowed to test index -1
    std::uint64_t get_nearest_block_index(const std::uint64_t test_index) const;
    /// try to get the block id with the given index (fails if index is unknown)
    bool try_get_block_id(const std::uint64_t block_index, rct::key &block_id_out) const;

    /// insert block ids starting at the specified index (all old blocks >= first_block_index will be removed)
    void insert_new_block_ids(const std::uint64_t first_block_index, const std::vector<rct::key> &new_block_ids);

private:
    /// get the window's prune candidate
    std::deque<std::uint64_t>::const_iterator get_window_prune_candidate(const std::deque<std::uint64_t> &window) const;
    /// get the expected checkpoint separation at a given distance from the highest prunable block
    std::uint64_t expected_checkpoint_separation(const std::uint64_t distance_from_highest_prunable) const;
    /// test if a window is prunable
    bool window_is_prunable(const std::deque<std::uint64_t> &window, const std::uint64_t max_candidate_index) const;
    /// remove prunable checkpoints
    void prune_checkpoints();

//member variables
    /// minimum checkpoint index
    const std::uint64_t m_min_checkpoint_index;

    /// config
    const CheckpointCacheConfig m_config;
    static const std::uint64_t m_window_size{3};

    /// stored checkpoints
    std::map<std::uint64_t, rct::key> m_checkpoints;
};

} //namespace sp
