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

#include "tree_sync.h"

#include "misc_log_ex.h"
#include "string_tools.h"


namespace fcmp_pp
{
namespace curve_trees
{
//----------------------------------------------------------------------------------------------------------------------
template<typename C>
static void cache_path_elem(const std::unique_ptr<C> &curve,
    const std::size_t child_width,
    const std::size_t parent_width,
    const std::vector<LayerExtension<C>> &layer_exts,
    const std::size_t layer_ext_idx,
    const LayerIdx layer_idx,
    const bool newly_registered_output,
    ChildChunkIdx &start_child_chunk_idx_inout,
    ChildChunkIdx &end_child_chunk_idx_inout,
    TreeElemCache &cached_tree_elems_inout)
{
    CHECK_AND_ASSERT_THROW_MES(layer_exts.size() > layer_ext_idx, "high layer_ext_idx");
    auto &layer_ext = layer_exts[layer_ext_idx];

    CHECK_AND_ASSERT_THROW_MES(!layer_ext.hashes.empty(), "empty layer ext");
    const uint64_t n_layer_elems = layer_ext.start_idx + layer_ext.hashes.size();

    // TODO: clean this up following cache_last_chunk approach
    end_child_chunk_idx_inout = std::min(end_child_chunk_idx_inout, n_layer_elems);

    MDEBUG("Caching path elems from start_child_chunk_idx: " << start_child_chunk_idx_inout << " to end_child_chunk_idx: " << end_child_chunk_idx_inout);

    // Collect the path elems in the tree extension
    for (ChildChunkIdx child_chunk_idx = start_child_chunk_idx_inout; child_chunk_idx < end_child_chunk_idx_inout; ++child_chunk_idx)
    {
        // TODO: separate function
        auto cached_layer_it = cached_tree_elems_inout.find(layer_idx);
        if (child_chunk_idx < layer_ext.start_idx)
        {
            // We expect we already have the tree elem cached, since it should be part of the last chunk
            CHECK_AND_ASSERT_THROW_MES(cached_layer_it != cached_tree_elems_inout.end(), "missing layer from last chunk");
            auto cached_tree_elem_it = cached_layer_it->second.find(child_chunk_idx);
            CHECK_AND_ASSERT_THROW_MES(cached_tree_elem_it != cached_layer_it->second.end(), "missing tree elem from last chunk");

            // We only bump the ref count for tree elems not in this tree extension if we're caching path elems for a
            // newly registered output. This tells the cache to keep the elem cached, don't prune it.
            if (newly_registered_output)
                cached_tree_elem_it->second.ref_count += 1;

            continue;
        }

        CHECK_AND_ASSERT_THROW_MES(child_chunk_idx >= layer_ext.start_idx, "low child_chunk_Idx");
        const ChildChunkIdx ext_hash_idx = child_chunk_idx - layer_ext.start_idx;

        // Check if the layer exists
        if (cached_layer_it == cached_tree_elems_inout.end())
        {
            cached_tree_elems_inout[layer_idx] = {{ child_chunk_idx, CachedTreeElem{
                    .tree_elem = curve->to_bytes(layer_ext.hashes[ext_hash_idx]),
                    .ref_count = 1,
                }}};
            continue;
        }

        // Check if we're keeping track of this tree elem already
        auto cached_tree_elem_it = cached_layer_it->second.find(child_chunk_idx);
        if (cached_tree_elem_it == cached_layer_it->second.end())
        {
            cached_tree_elems_inout[layer_idx][child_chunk_idx] = CachedTreeElem{
                    .tree_elem = curve->to_bytes(layer_ext.hashes[ext_hash_idx]),
                    .ref_count = 1,
                };
            continue;
        }

        // We only need to bump the ref count for *new* path elems in this tree extension, or for elems in the
        // path of a newly registered output. Otherwise we're duplicating refs to an output's path elems that won't get
        // purged.
        // TODO: when implementing reorg, see how this logic can be simplified
        const bool updating_existing_last_hash = ext_hash_idx == 0 && layer_ext.update_existing_last_hash;
        if (newly_registered_output || !updating_existing_last_hash)
            cached_tree_elem_it->second.ref_count += 1;

        // If the tree extension is updating an existing value, we need to update it in our cache too
        if (updating_existing_last_hash)
        {
            auto tree_elem = curve->to_bytes(layer_ext.hashes.front());
            cached_tree_elem_it->second.tree_elem = std::move(tree_elem);
        }
    }

    start_child_chunk_idx_inout /= parent_width;
    start_child_chunk_idx_inout = start_child_chunk_idx_inout - (start_child_chunk_idx_inout % child_width);
    end_child_chunk_idx_inout = start_child_chunk_idx_inout + child_width;
}
//----------------------------------------------------------------------------------------------------------------------
template<typename C>
static void cache_last_chunk(const std::unique_ptr<C> &curve,
    const std::vector<LayerExtension<C>> &layer_exts,
    const std::size_t layer_ext_idx,
    const LayerIdx layer_idx,
    const std::size_t parent_width,
    TreeElemCache &cached_tree_elems_inout,
    ChildChunkIdxSet &prunable_child_chunks_inout)
{
    CHECK_AND_ASSERT_THROW_MES(layer_exts.size() > layer_ext_idx, "unexpected high layer_ext_idx");

    const auto &layer_ext = layer_exts[layer_ext_idx];
    CHECK_AND_ASSERT_THROW_MES(!layer_ext.hashes.empty(), "unexpected empty layer ext");

    const ChildChunkIdx end_child_chunk_idx = layer_ext.start_idx + layer_ext.hashes.size();

    const ChildChunkIdx offset = end_child_chunk_idx % parent_width;
    const ChildChunkIdx end_offset = (offset > 0) ? offset : parent_width;
    CHECK_AND_ASSERT_THROW_MES(end_child_chunk_idx >= end_offset, "high end_offset");

    const ChildChunkIdx start_child_chunk_idx = end_child_chunk_idx - end_offset;

    MDEBUG("Caching start_child_chunk_idx " << start_child_chunk_idx << " to end_child_chunk_idx " << end_child_chunk_idx
        << " (layer start idx " << layer_ext.start_idx << " , parent_width " << parent_width << " , end_offset " << end_offset << ")");

    // TODO: this code is *mostly* duplicated above with subtle diffs
    for (ChildChunkIdx child_chunk_idx = start_child_chunk_idx; child_chunk_idx < end_child_chunk_idx; ++child_chunk_idx)
    {
        prunable_child_chunks_inout.insert(child_chunk_idx);

        auto cached_layer_it = cached_tree_elems_inout.find(layer_idx);
        if (child_chunk_idx < layer_ext.start_idx)
        {
            // We expect we already have the tree elem cached, since it should be part of the last chunk
            CHECK_AND_ASSERT_THROW_MES(cached_layer_it != cached_tree_elems_inout.end(), "missing layer from last chunk");
            auto cached_tree_elem_it = cached_layer_it->second.find(child_chunk_idx);
            CHECK_AND_ASSERT_THROW_MES(cached_tree_elem_it != cached_layer_it->second.end(), "missing tree elem from last chunk");

            cached_tree_elem_it->second.ref_count += 1;
            continue;
        }

        // TODO: separate function
        CHECK_AND_ASSERT_THROW_MES(child_chunk_idx >= layer_ext.start_idx, "low child_chunk_Idx");
        const ChildChunkIdx ext_hash_idx = child_chunk_idx - layer_ext.start_idx;

        if (cached_layer_it == cached_tree_elems_inout.end())
        {
            cached_tree_elems_inout[layer_idx] = {{ child_chunk_idx, CachedTreeElem {
                    .tree_elem = curve->to_bytes(layer_ext.hashes[ext_hash_idx]),
                    .ref_count = 1
                }}};
            continue;
        }

        auto cached_tree_elem_it = cached_layer_it->second.find(child_chunk_idx);
        if (cached_tree_elem_it == cached_layer_it->second.end())
        {
            cached_tree_elems_inout[layer_idx][child_chunk_idx] = CachedTreeElem{
                    .tree_elem = curve->to_bytes(layer_ext.hashes[ext_hash_idx]),
                    .ref_count = 1,
                };
            continue;
        }

        // We're already keeping track of this elem, so bump the ref count
        cached_tree_elem_it->second.ref_count += 1;

        // If the tree extension is updating an existing value, we need to update it in our cache too. Note that only the
        // first hash in the given layer extension can update (when update_existing_last_hash is true, the first hash is the
        // "existing last hash" before the tree extension is used to grow the tree).
        if (ext_hash_idx == 0 && layer_ext.update_existing_last_hash)
        {
            auto tree_elem = curve->to_bytes(layer_ext.hashes.front());
            cached_tree_elem_it->second.tree_elem = std::move(tree_elem);
        }
    }
}
//----------------------------------------------------------------------------------------------------------------------
template<typename C_CHILD, typename C_PARENT>
static std::vector<typename C_PARENT::Scalar> get_layer_last_chunk_children_to_trim(const std::unique_ptr<C_CHILD> &c_child,
    const ChildChunkCache &child_chunk_cache,
    const ChildChunkIdx start_trim_idx,
    const ChildChunkIdx end_trim_idx)
{
    std::vector<typename C_PARENT::Scalar> children_to_trim_out;
    if (end_trim_idx > start_trim_idx)
    {
        ChildChunkIdx idx = start_trim_idx;
        MDEBUG("Start trim from idx: " << idx << " , ending trim at: " << end_trim_idx);
        do
        {
            const auto cached_chunk_it = child_chunk_cache.find(idx);
            CHECK_AND_ASSERT_THROW_MES(cached_chunk_it != child_chunk_cache.end(), "missing child chunk for trim");

            auto child_point = c_child->from_bytes(cached_chunk_it->second.tree_elem);
            auto child_scalar = c_child->point_to_cycle_scalar(child_point);
            children_to_trim_out.push_back(std::move(child_scalar));

            ++idx;
        }
        while (idx < end_trim_idx);
    }

    return children_to_trim_out;
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
template<typename C1, typename C2>
bool TreeSync<C1, C2>::register_output(const OutputPair &output, const uint64_t unlock_block_idx)
{
    if (!m_cached_blocks.empty())
    {
        const auto &top_synced_block = m_cached_blocks.back();

        // If the output is already unlocked, we won't be able to tell the output's position in the tree
        CHECK_AND_ASSERT_THROW_MES(unlock_block_idx > top_synced_block.blk_idx,
            "already synced block in which output unlocked");
    }

    auto output_ref = get_output_ref(output);

    // Return false if already registered
    if (m_registered_outputs.find(output_ref) != m_registered_outputs.end())
        return false;

    // Add to registered outputs container
    m_registered_outputs.insert({ std::move(output_ref), AssignedLeafIdx{} });

    return true;
}

// Explicit instantiation
template bool TreeSync<Helios, Selene>::register_output(const OutputPair &output, const uint64_t unlock_block_idx);
//----------------------------------------------------------------------------------------------------------------------
// TODO: change all code to be more precise: I should know exactly which tree elems I need. Don't go by what's stored
template<typename C1, typename C2>
void TreeSync<C1, C2>::sync_block(const uint64_t block_idx,
    const crypto::hash &block_hash,
    const crypto::hash &prev_block_hash,
    std::vector<OutputContext> &&new_leaf_tuples)
{
    std::size_t n_leaf_tuples = 0;
    if (m_cached_blocks.empty())
    {
        // TODO: if block_idx > 0, we need the tree's last chunk elems and old_n_leaf_tuples
        CHECK_AND_ASSERT_THROW_MES(block_idx == 0, "syncing first block_idx > 0 not yet implemented");

        // Make sure all blockchain containers are empty
        CHECK_AND_ASSERT_THROW_MES(m_cached_blocks.empty(),     "expected empty cached blocks");
        CHECK_AND_ASSERT_THROW_MES(m_cached_leaves.empty(),     "expected empty cached leaves");
        CHECK_AND_ASSERT_THROW_MES(m_tree_elem_cache.empty(), "expected empty cached tree elems");
    }
    else
    {
        CHECK_AND_ASSERT_THROW_MES(block_idx > 0, "expected block_idx > 0");

        // Make sure provided block is contiguous to prior synced block
        const auto &prev_block = m_cached_blocks.back();
        CHECK_AND_ASSERT_THROW_MES(prev_block.blk_idx == (block_idx - 1), "failed contiguity idx check");
        CHECK_AND_ASSERT_THROW_MES(prev_block.blk_hash == prev_block_hash, "failed contiguity hash check");

        n_leaf_tuples = prev_block.n_leaf_tuples;
    }

    // Get the tree extension using existing tree data. We'll use the tree extension to update registered output paths
    // in the tree and cache the data necessary to build the next block's tree extension.
    const CurveTreesV1::LastHashes last_hashes = this->get_last_hashes(n_leaf_tuples);
    auto tree_extension = m_curve_trees->get_tree_extension(n_leaf_tuples,
        last_hashes,
        std::move(new_leaf_tuples));

    // Check if any registered outputs are present in the tree extension. If so, we assign the output its leaf idx and
    // start keeping track of the output's path elems
    // TODO: separate function
    std::unordered_set<LeafIdx> new_assigned_outputs;
    for (uint64_t i = 0; i < tree_extension.leaves.tuples.size(); ++i)
    {
        const auto &output_pair = tree_extension.leaves.tuples[i].output_pair;
        const auto output_ref = get_output_ref(output_pair);

        auto registered_output_it = m_registered_outputs.find(output_ref);
        if (registered_output_it == m_registered_outputs.end())
            continue;

        // If it's already assigned a leaf idx, then it must be a duplicate and we only care about the earliest one
        // TODO: test this circumstance
        if (registered_output_it->second.assigned_leaf_idx)
            continue;

        // Assign the leaf idx
        const LeafIdx leaf_idx = tree_extension.leaves.start_leaf_tuple_idx + i;
        registered_output_it->second.assign_leaf(leaf_idx);

        MDEBUG("Starting to keep track of leaf_idx: " << leaf_idx);
        new_assigned_outputs.insert(leaf_idx);
    }

    // Cache tree elems from the tree extension needed in order to keep track of registered output paths in the tree
    const auto &c1_layer_exts = tree_extension.c1_layer_extensions;
    const auto &c2_layer_exts = tree_extension.c2_layer_extensions;
    const std::size_t n_layers = c1_layer_exts.size() + c2_layer_exts.size();
    for (const auto &registered_o : m_registered_outputs)
    {
        // Skip all registered outputs which have not been included in the tree yet
        if (!registered_o.second.assigned_leaf_idx)
            continue;

        MDEBUG("Caching tree elems for leaf idx: " << registered_o.second.leaf_idx);

        // Cache leaves
        // TODO: separate function
        const LeafIdx leaf_idx = registered_o.second.leaf_idx;
        const LeafIdx start_leaf_idx = (leaf_idx / m_curve_trees->m_c2_width) * m_curve_trees->m_c2_width;
        const LeafIdx end_leaf_idx = std::min(start_leaf_idx + m_curve_trees->m_c2_width,
            tree_extension.leaves.start_leaf_tuple_idx + tree_extension.leaves.tuples.size());

        const bool newly_assigned_output = new_assigned_outputs.find(leaf_idx) != new_assigned_outputs.end();

        MERROR("Caching leaves for leaf_idx: " << leaf_idx << " , start_leaf_idx: " << start_leaf_idx << " , end_leaf_idx: " << end_leaf_idx << " , tree_extension.leaves.start_leaf_tuple_idx: " << tree_extension.leaves.start_leaf_tuple_idx);

        // If the registered output's chunk isn't present in this tree extension, we have no leaves to cache
        if (end_leaf_idx > tree_extension.leaves.start_leaf_tuple_idx)
        {
            MDEBUG("Caching leaves for leaf_idx: " << leaf_idx << " , start_leaf_idx: " << start_leaf_idx << " , end_leaf_idx: " << end_leaf_idx);

            CHECK_AND_ASSERT_THROW_MES(end_leaf_idx > start_leaf_idx, "unexpected end_leaf_idx > start_leaf_idx");

            // Cache the leaf elems from this leaf's chunk
            for (LeafIdx j = start_leaf_idx; j < end_leaf_idx; ++j)
            {
                auto leaf_it = m_cached_leaves.find(j);
                if (leaf_it != m_cached_leaves.end())
                {
                    // We only need to bump the ref count for new outputs included in this tree extension, or for
                    // outputs in the chunk of a newly registered output
                    const bool new_leaf = j >= tree_extension.leaves.start_leaf_tuple_idx;
                    if (newly_assigned_output || new_leaf)
                        leaf_it->second.ref_count += 1;

                    continue;
                }

                CHECK_AND_ASSERT_THROW_MES(j >= tree_extension.leaves.start_leaf_tuple_idx, "low j");
                const uint64_t tuple_idx = j - tree_extension.leaves.start_leaf_tuple_idx;

                CHECK_AND_ASSERT_THROW_MES(tree_extension.leaves.tuples.size() > tuple_idx, "high tuple_idx");
                auto tuple = std::move(tree_extension.leaves.tuples[tuple_idx]);

                m_cached_leaves[j] = CachedLeafTuple { .output = std::move(tuple.output_pair), .ref_count = 1 };
            }
        }
        // Done caching leaves

        // Now cache the rest of the path elems for each registered output
        // TODO: separate function
        const ChildChunkIdx child_chunk_idx = leaf_idx / m_curve_trees->m_c2_width;
        ChildChunkIdx start_child_chunk_idx = child_chunk_idx - (child_chunk_idx % m_curve_trees->m_c1_width);
        ChildChunkIdx end_child_chunk_idx = start_child_chunk_idx + m_curve_trees->m_c1_width;

        std::size_t c1_idx = 0, c2_idx = 0;
        bool parent_is_c1 = true;
        for (LayerIdx layer_idx = 0; layer_idx < n_layers; ++layer_idx)
        {
            MDEBUG("Caching tree elems from layer_idx " << layer_idx);
            if (parent_is_c1)
            {
                cache_path_elem(m_curve_trees->m_c2,
                        m_curve_trees->m_c2_width,
                        m_curve_trees->m_c1_width,
                        c2_layer_exts,
                        c2_idx,
                        layer_idx,
                        newly_assigned_output,
                        start_child_chunk_idx,
                        end_child_chunk_idx,
                        m_tree_elem_cache
                    );
                ++c2_idx;
            }
            else
            {
                cache_path_elem(m_curve_trees->m_c1,
                        m_curve_trees->m_c1_width,
                        m_curve_trees->m_c2_width,
                        c1_layer_exts,
                        c1_idx,
                        layer_idx,
                        newly_assigned_output,
                        start_child_chunk_idx,
                        end_child_chunk_idx,
                        m_tree_elem_cache
                    );
                ++c1_idx;
            }

            parent_is_c1 = !parent_is_c1;
        }
    }

    // Update cached blocks
    const uint64_t new_total_n_leaf_tuples = n_leaf_tuples + tree_extension.leaves.tuples.size();
    auto blk_meta = BlockMeta {
            .blk_idx = block_idx,
            .blk_hash = block_hash,
            .n_leaf_tuples = new_total_n_leaf_tuples,
        };
    m_cached_blocks.push_back(std::move(blk_meta));

    // Cache the last chunk of leaves, so if a registered output appears in the first chunk next block, we'll have all
    // prior leaves from that output's chunk
    // TODO: separate function
    LeavesSet prunable_leaves;

    const LeafIdx leaf_offset = new_total_n_leaf_tuples % m_curve_trees->m_c2_width;
    const LeafIdx end_leaf_offset = (leaf_offset > 0) ? leaf_offset : m_curve_trees->m_c2_width;
    CHECK_AND_ASSERT_THROW_MES(new_total_n_leaf_tuples >= end_leaf_offset, "high end_leaf_offset");

    const LeafIdx start_leaf_idx_last_chunk = new_total_n_leaf_tuples - end_leaf_offset;
    const LeafIdx end_leaf_idx_last_chunk = std::min(start_leaf_idx_last_chunk + m_curve_trees->m_c2_width, new_total_n_leaf_tuples);

    MERROR("Caching last leaves from leaf idx " << start_leaf_idx_last_chunk << " to " << end_leaf_idx_last_chunk);

    for (LeafIdx i = start_leaf_idx_last_chunk; i < end_leaf_idx_last_chunk; ++i)
    {
        // "Last chunk" leaves can be pruned once we exceed the max reorg depth and deque a block from the cache;
        // they aren't tied to registered outputs
        prunable_leaves.insert(i);

        // Bump the ref count if it's already cached
        auto leaf_it = m_cached_leaves.find(i);
        if (leaf_it != m_cached_leaves.end())
        {
            leaf_it->second.ref_count += 1;
            continue;
        }

        // The leaf is not cached, so cache it
        CHECK_AND_ASSERT_THROW_MES(i >= tree_extension.leaves.start_leaf_tuple_idx,
            "the leaf isn't in this tree extension, expected the leaf to be cached already");
        const auto ext_idx = i - tree_extension.leaves.start_leaf_tuple_idx;
        auto &output = tree_extension.leaves.tuples[ext_idx].output_pair;
        m_cached_leaves[i] = CachedLeafTuple {
                .output = std::move(output),
                .ref_count = 1,
            };
    }
    m_prunable_leaves_by_block[block_hash] = std::move(prunable_leaves);

    // Cache the last chunk of hashes from every layer. We need to do this to handle all of the following:
    //   1) So we can use the tree's last hashes to grow the tree from here next block.
    //   2) In case a registered output appears in the first chunk next block, we'll have all its path elems cached.
    //   3) To trim the tree on reorg using the last children from each chunk
    // TODO: separate function
    bool use_c2 = true;
    std::size_t c1_idx = 0, c2_idx = 0;
    std::unordered_map<LayerIdx, ChildChunkIdxSet> prunable_tree_elems;
    MDEBUG("Caching last chunks at block " << blk_meta.blk_idx);
    for (LayerIdx layer_idx = 0; layer_idx < n_layers; ++layer_idx)
    {
        MDEBUG("Caching the last chunk from layer " << layer_idx+1 << " / " << n_layers);
        ChildChunkIdxSet prunable_child_chunks;
        if (use_c2)
        {
            cache_last_chunk(m_curve_trees->m_c2, c2_layer_exts, c2_idx, layer_idx, m_curve_trees->m_c1_width, m_tree_elem_cache, prunable_child_chunks);
            ++c2_idx;
        }
        else
        {
            cache_last_chunk(m_curve_trees->m_c1, c1_layer_exts, c1_idx, layer_idx, m_curve_trees->m_c2_width, m_tree_elem_cache, prunable_child_chunks);
            ++c1_idx;
        }

        prunable_tree_elems[layer_idx] = std::move(prunable_child_chunks);
        use_c2 = !use_c2;
    }
    m_prunable_tree_elems_by_block[block_hash] = std::move(prunable_tree_elems);

    // Deque the oldest cached block
    // TODO: separate function
    if (m_cached_blocks.size() > m_max_reorg_depth)
    {
        CHECK_AND_ASSERT_THROW_MES(!m_cached_blocks.empty(), "empty cached blocks");
        const BlockMeta &oldest_block = m_cached_blocks.front();

        this->deque_block(oldest_block.blk_hash);

        // Prune the block
        m_cached_blocks.pop_front();

        // Keep in mind: the registered output path should remain untouched, chain state isn't changing. We're only
        // purging refs to last chunks from the cache.
    }

    CHECK_AND_ASSERT_THROW_MES(m_max_reorg_depth >= m_cached_blocks.size(), "cached blocks exceeded max reorg depth");
}

// Explicit instantiation
template void TreeSync<Helios, Selene>::sync_block(const uint64_t block_idx,
    const crypto::hash &block_hash,
    const crypto::hash &prev_block_hash,
    std::vector<OutputContext> &&new_leaf_tuples);
//----------------------------------------------------------------------------------------------------------------------
template<typename C1, typename C2>
bool TreeSync<C1, C2>::pop_block()
{
    if (m_cached_blocks.empty())
        return false;

    // Pop the top block off the back of the cache
    const uint64_t  old_n_leaf_tuples = m_cached_blocks.back().n_leaf_tuples;
    const BlockHash old_block_hash    = m_cached_blocks.back().blk_hash;
    this->deque_block(old_block_hash);
    m_cached_blocks.pop_back();

    // Determine how many leaves we need to trim
    uint64_t new_n_leaf_tuples = 0;
    if (!m_cached_blocks.empty())
    {
        // Trim to the new top block
        const BlockMeta &new_top_block = m_cached_blocks.back();
        new_n_leaf_tuples = new_top_block.n_leaf_tuples;
    }
    CHECK_AND_ASSERT_THROW_MES(old_n_leaf_tuples >= new_n_leaf_tuples, "expected old_n_leaf_tuples >= new_n_leaf_tuples");
    const uint64_t trim_n_leaf_tuples = old_n_leaf_tuples - new_n_leaf_tuples;

    // We're going to trim the tree as the node would to see exactly how the tree elems we know about need to change.
    // First get trim instructions
    const auto trim_instructions = m_curve_trees->get_trim_instructions(old_n_leaf_tuples, trim_n_leaf_tuples);
    MDEBUG("Acquired trim instructions for " << trim_instructions.size() << " layers");

    // Do initial tree reads using trim instructions
    const auto last_chunk_children_to_trim = this->get_last_chunk_children_to_trim(trim_instructions);
    const auto last_hashes_to_trim = this->get_last_hashes_to_trim(trim_instructions);

    // Get the new hashes, wrapped in a simple struct we can use to trim the tree
    const auto tree_reduction = m_curve_trees->get_tree_reduction(
        trim_instructions,
        last_chunk_children_to_trim,
        last_hashes_to_trim);

    const auto &c1_layer_reductions = tree_reduction.c1_layer_reductions;
    const auto &c2_layer_reductions = tree_reduction.c2_layer_reductions;
    const std::size_t new_n_layers = c2_layer_reductions.size() + c1_layer_reductions.size();

    // Use the tree reduction to update output paths
    for (auto &registered_o : m_registered_outputs)
    {
        // If the output isn't in the tree, it has no path elems we need to change in the cache 
        if (!registered_o.second.assigned_leaf_idx)
            continue;

        // TODO: below should all be a separate function
        // Get the output's cached path indexes in the tree
        const LeafIdx leaf_idx = registered_o.second.leaf_idx;
        MERROR("old_n_leaf_tuples: " << old_n_leaf_tuples << " leaf_idx: " << leaf_idx);
        const auto old_path_idxs = m_curve_trees->get_path_indexes(old_n_leaf_tuples, leaf_idx);

        // Use the tree reduction to update the cached leaves and path elems
        // First, remove any cached leaves if necessary
        if (old_path_idxs.leaf_range.second > tree_reduction.new_total_leaf_tuples)
        {
            // Remove leaves from the cache
            const LeafIdx start_leaf_idx = tree_reduction.new_total_leaf_tuples;
            const LeafIdx end_leaf_idx = old_path_idxs.leaf_range.second;

            // TODO: separate static function, duplicated above
            for (LeafIdx i = start_leaf_idx; i < end_leaf_idx; ++i)
            {
                auto leaf_it = m_cached_leaves.find(i);
                CHECK_AND_ASSERT_THROW_MES(leaf_it != m_cached_leaves.end(), "cache is missing leaf");
                CHECK_AND_ASSERT_THROW_MES(leaf_it->second.ref_count != 0, "leaf has 0 ref count");

                leaf_it->second.ref_count -= 1;

                // If the ref count is 0, garbage collect it
                if (leaf_it->second.ref_count == 0)
                    m_cached_leaves.erase(leaf_it);
            }
        }

        // Second, remove or update any cached path elems if necessary
        bool use_c2 = true;
        std::size_t c2_idx = 0;
        std::size_t c1_idx = 0;
        for (LayerIdx i = 0; i < new_n_layers; ++i)
        {
            auto cached_layer_it = m_tree_elem_cache.find(i);
            CHECK_AND_ASSERT_THROW_MES(cached_layer_it != m_tree_elem_cache.end(), "missing cached layer");

            uint64_t new_total_parents = 0;
            uint64_t old_chunk_end = 0;
            // TODO: templated function
            if (use_c2)
            {
                CHECK_AND_ASSERT_THROW_MES(c2_idx < c2_layer_reductions.size(), "unexpected c2 layer reduction");
                const auto &c2_reduction = c2_layer_reductions[c2_idx];

                new_total_parents = c2_reduction.new_total_parents;

                // We updated the last hash
                if (c2_reduction.update_existing_last_hash)
                {
                    CHECK_AND_ASSERT_THROW_MES(new_total_parents > 0, "unexpected 0 new_total_parents");
                    auto cached_tree_elem_it = cached_layer_it->second.find(new_total_parents - 1);
                    CHECK_AND_ASSERT_THROW_MES(cached_tree_elem_it != cached_layer_it->second.end(), "missing cached new last hash");

                    cached_tree_elem_it->second.tree_elem = m_curve_trees->m_c2->to_bytes(c2_reduction.new_last_hash);
                }

                CHECK_AND_ASSERT_THROW_MES(old_path_idxs.c2_layers.size() > c2_idx, "unexpected c2 path idxs");
                old_chunk_end = old_path_idxs.c2_layers[c2_idx].second;

                ++c2_idx;
            }
            else
            {
                CHECK_AND_ASSERT_THROW_MES(c1_idx < c1_layer_reductions.size(), "unexpected c1 layer reduction");
                const auto &c1_reduction = c1_layer_reductions[c1_idx];

                new_total_parents = c1_reduction.new_total_parents;

                // We updated the last hash
                if (c1_reduction.update_existing_last_hash)
                {
                    CHECK_AND_ASSERT_THROW_MES(new_total_parents > 0, "unexpected 0 new_total_parents");
                    auto cached_tree_elem_it = cached_layer_it->second.find(new_total_parents - 1);
                    CHECK_AND_ASSERT_THROW_MES(cached_tree_elem_it != cached_layer_it->second.end(), "missing cached new last hash");

                    cached_tree_elem_it->second.tree_elem = m_curve_trees->m_c1->to_bytes(c1_reduction.new_last_hash);
                }

                CHECK_AND_ASSERT_THROW_MES(old_path_idxs.c1_layers.size() > c1_idx, "unexpected c1 path idxs");
                old_chunk_end = old_path_idxs.c1_layers[c1_idx].second;

                ++c1_idx;
            }

            MERROR("old_chunk_end " << old_chunk_end << " , new_total_parents: " << new_total_parents);

            // Remove cached elems if necessary
            if (old_chunk_end > new_total_parents)
            {
                // Remove refs to stale path elems from the cache
                const ChildChunkIdx start_idx = new_total_parents;
                const ChildChunkIdx end_idx = old_chunk_end;

                MERROR("Removing in layer " << i << ": start_idx: " << start_idx << " , end_idx: " << end_idx);

                // TODO: separate static function, duplicated above
                for (ChildChunkIdx j = start_idx; j < end_idx; ++j)
                {
                    auto cached_tree_elem_it = cached_layer_it->second.find(j);
                    CHECK_AND_ASSERT_THROW_MES(cached_tree_elem_it != cached_layer_it->second.end(), "missing cached tree elem");
                    CHECK_AND_ASSERT_THROW_MES(cached_tree_elem_it->second.ref_count != 0, "cached elem has 0 ref count");

                    cached_tree_elem_it->second.ref_count -= 1;

                    // If the ref count is 0, garbage collect it
                    if (cached_tree_elem_it->second.ref_count == 0)
                        cached_layer_it->second.erase(cached_tree_elem_it);
                }

                if (cached_layer_it->second.empty())
                    m_tree_elem_cache.erase(cached_layer_it);
            }

            use_c2 = !use_c2;
        }

        const bool output_removed_from_tree = leaf_idx >= tree_reduction.new_total_leaf_tuples;
        if (output_removed_from_tree)
            registered_o.second.unassign_leaf();
    }

    // Check if there are any layers that need to be removed
    // TODO: de-dup this code
    LayerIdx layer_idx = new_n_layers;
    while (1)
    {
        auto cache_layer_it = m_tree_elem_cache.find(layer_idx);
        if (cache_layer_it == m_tree_elem_cache.end())
            break;

        MERROR("Removing cached layer " << layer_idx);
        m_tree_elem_cache.erase(cache_layer_it);
        ++layer_idx;
    }

    return true;
}

// Explicit instantiation
template bool TreeSync<Helios, Selene>::pop_block();
//----------------------------------------------------------------------------------------------------------------------
template<typename C1, typename C2>
bool TreeSync<C1, C2>::get_output_path(const OutputPair &output, typename CurveTrees<C1, C2>::Path &path_out) const
{
    // TODO: use n leaf tuples + leaf idx in tree to know exactly which elems from the tree we expect

    path_out.clear();

    // Return false if the output isn't registered
    auto registered_output_it = m_registered_outputs.find(get_output_ref(output));
    if (registered_output_it == m_registered_outputs.end())
        return false;

    // Return empty path if the output is registered but isn't in the tree
    if (!registered_output_it->second.assigned_leaf_idx)
        return true;

    const LeafIdx leaf_idx = registered_output_it->second.leaf_idx;
    ChildChunkIdx child_chunk_idx = leaf_idx / m_curve_trees->m_c2_width;
    const LeafIdx start_leaf_idx = child_chunk_idx * m_curve_trees->m_c2_width;
    const LeafIdx end_leaf_idx = start_leaf_idx + m_curve_trees->m_c2_width;

    MDEBUG("Getting output path at leaf_idx: " << leaf_idx << " , start_leaf_idx: " << start_leaf_idx << " , end_leaf_idx: " << end_leaf_idx);

    CHECK_AND_ASSERT_THROW_MES(start_leaf_idx <= leaf_idx && leaf_idx < end_leaf_idx, "unexpected leaf idx range");

    // Collect cached leaves from the leaf chunk this leaf is in
    for (LeafIdx i = start_leaf_idx; i < end_leaf_idx; ++i)
    {
        auto it = m_cached_leaves.find(i);
        if (it == m_cached_leaves.end())
            break;

        MDEBUG("Found leaf idx " << i);
        path_out.leaves.push_back(output_to_tuple(it->second.output));
    }

    CHECK_AND_ASSERT_THROW_MES((start_leaf_idx + path_out.leaves.size()) > leaf_idx, "leaves path missing leaf_idx");

    // Collect cached tree elems in the leaf's path
    LayerIdx layer_idx = 0;
    child_chunk_idx /= m_curve_trees->m_c1_width;
    ChildChunkIdx start_child_chunk_idx = child_chunk_idx * m_curve_trees->m_c1_width;
    ChildChunkIdx end_child_chunk_idx = start_child_chunk_idx + m_curve_trees->m_c1_width;
    bool parent_is_c1 = true;
    while (1)
    {
        auto cached_layer_it = m_tree_elem_cache.find(layer_idx);
        if (cached_layer_it == m_tree_elem_cache.end())
            break;

        MDEBUG("Getting output path at layer_idx " << layer_idx             << ", " <<
            "child_chunk_idx "                     << child_chunk_idx       << ", " <<
            "start_child_chunk_idx "               << start_child_chunk_idx << ", " <<
            "end_child_chunk_idx "                 << end_child_chunk_idx);

        if (parent_is_c1)
            path_out.c2_layers.emplace_back();
        else
            path_out.c1_layers.emplace_back();

        for (ChildChunkIdx i = start_child_chunk_idx; i < end_child_chunk_idx; ++i)
        {
            const auto cached_tree_elem_it = cached_layer_it->second.find(i);
            if (cached_tree_elem_it == cached_layer_it->second.end())
            {
                CHECK_AND_ASSERT_THROW_MES(i > start_child_chunk_idx, "missing cached tree elem");
                break;
            }

            auto &tree_elem = cached_tree_elem_it->second.tree_elem;
            MDEBUG("Found child chunk idx: " << i << " elem: " << epee::string_tools::pod_to_hex(tree_elem));
            if (parent_is_c1)
            {
                path_out.c2_layers.back().push_back(m_curve_trees->m_c2->from_bytes(tree_elem));
            }
            else
            {
                path_out.c1_layers.back().push_back(m_curve_trees->m_c1->from_bytes(tree_elem));
            }
        }

        parent_is_c1 = !parent_is_c1;
        const std::size_t width = parent_is_c1 ? m_curve_trees->m_c1_width : m_curve_trees->m_c2_width;

        child_chunk_idx /= width;
        start_child_chunk_idx = child_chunk_idx * width;
        end_child_chunk_idx = start_child_chunk_idx + width;

        ++layer_idx;
    }

    return true;
}

// Explicit instantiation
template bool TreeSync<Helios, Selene>::get_output_path(const OutputPair &output,
    CurveTrees<Helios, Selene>::Path &path_out) const;
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
template<typename C1, typename C2>
typename CurveTrees<C1, C2>::LastHashes TreeSync<C1, C2>::get_last_hashes(const std::size_t n_leaf_tuples) const
{
    MDEBUG("Getting last hashes on tree with " << n_leaf_tuples << " leaf tuples");

    typename CurveTrees<C1, C2>::LastHashes last_hashes;
    if (n_leaf_tuples == 0)
        return last_hashes;

    std::size_t n_children = n_leaf_tuples;
    bool use_c2 = true;
    LayerIdx layer_idx = 0;
    do
    {
        const std::size_t width = use_c2 ? m_curve_trees->m_c2_width : m_curve_trees->m_c1_width;
        const ChildChunkIdx last_child_chunk_idx = (n_children - 1) / width;

        MDEBUG("Getting last hash at layer_idx " << layer_idx << " and last_child_chunk_idx " << last_child_chunk_idx);

        auto cached_layer_it = m_tree_elem_cache.find(layer_idx);
        CHECK_AND_ASSERT_THROW_MES(cached_layer_it != m_tree_elem_cache.end(), "missing cached last hash layer");

        auto cached_tree_elem_it = cached_layer_it->second.find(last_child_chunk_idx);
        CHECK_AND_ASSERT_THROW_MES(cached_tree_elem_it != cached_layer_it->second.end(), "missing cached last hash");

        const auto &tree_elem = cached_tree_elem_it->second.tree_elem;
        if (use_c2)
            last_hashes.c2_last_hashes.push_back(m_curve_trees->m_c2->from_bytes(tree_elem));
        else
            last_hashes.c1_last_hashes.push_back(m_curve_trees->m_c1->from_bytes(tree_elem));

        ++layer_idx;
        n_children = last_child_chunk_idx + 1;
        use_c2 = !use_c2;
    }
    while (n_children > 1);

    return last_hashes;
}

// Explicit instantiation
template CurveTrees<Helios, Selene>::LastHashes TreeSync<Helios, Selene>::get_last_hashes(
    const std::size_t n_leaf_tuples) const;
//----------------------------------------------------------------------------------------------------------------------
template<>
CurveTrees<Helios, Selene>::LastChunkChildrenToTrim TreeSync<Helios, Selene>::get_last_chunk_children_to_trim(
    const std::vector<TrimLayerInstructions> &trim_instructions) const
{
    CurveTrees<Helios, Selene>::LastChunkChildrenToTrim all_children_to_trim;

    if (trim_instructions.empty())
        return all_children_to_trim;

    // Leaf layer
    const auto &trim_leaf_layer_instructions = trim_instructions[0];
    std::vector<Selene::Scalar> leaves_to_trim;
    const std::size_t LEAF_TUPLE_SIZE = CurveTrees<Helios, Selene>::LEAF_TUPLE_SIZE;
    // TODO: separate function
    if (trim_leaf_layer_instructions.end_trim_idx > trim_leaf_layer_instructions.start_trim_idx)
    {
        LeafIdx idx = trim_leaf_layer_instructions.start_trim_idx;
        MDEBUG("Start trim from idx: " << idx);
        do
        {
            CHECK_AND_ASSERT_THROW_MES(idx % LEAF_TUPLE_SIZE == 0, "expected divisble by leaf tuple size");
            const LeafIdx leaf_idx = idx / LEAF_TUPLE_SIZE;

            MERROR("Searching for leaf idx " << leaf_idx);
            const auto leaf_it = m_cached_leaves.find(leaf_idx);
            CHECK_AND_ASSERT_THROW_MES(leaf_it != m_cached_leaves.end(), "missing cached leaf");

            const auto leaf_tuple = m_curve_trees->leaf_tuple(leaf_it->second.output);

            leaves_to_trim.push_back(leaf_tuple.O_x);
            leaves_to_trim.push_back(leaf_tuple.I_x);
            leaves_to_trim.push_back(leaf_tuple.C_x);

            idx += LEAF_TUPLE_SIZE;
        }
        while (idx < trim_leaf_layer_instructions.end_trim_idx);
    }

    all_children_to_trim.c2_children.emplace_back(std::move(leaves_to_trim));

    bool parent_is_c2 = false;
    for (std::size_t i = 1; i < trim_instructions.size(); ++i)
    {
        MDEBUG("Getting trim instructions for layer " << i);

        const auto &trim_layer_instructions = trim_instructions[i];

        const ChildChunkIdx start_trim_idx = trim_layer_instructions.start_trim_idx;
        const ChildChunkIdx end_trim_idx   = trim_layer_instructions.end_trim_idx;

        const LayerIdx layer_idx = i - 1;
        const auto cached_layer_it = m_tree_elem_cache.find(layer_idx);
        CHECK_AND_ASSERT_THROW_MES(cached_layer_it != m_tree_elem_cache.end(), "missing layer for trim");

        if (parent_is_c2)
        {
            auto children_to_trim = get_layer_last_chunk_children_to_trim<Helios, Selene>(
                m_curve_trees->m_c1,
                cached_layer_it->second,
                start_trim_idx,
                end_trim_idx);

            all_children_to_trim.c2_children.emplace_back(std::move(children_to_trim));
        }
        else
        {
            auto children_to_trim = get_layer_last_chunk_children_to_trim<Selene, Helios>(
                m_curve_trees->m_c2,
                cached_layer_it->second,
                start_trim_idx,
                end_trim_idx);

            all_children_to_trim.c1_children.emplace_back(std::move(children_to_trim));
        }

        parent_is_c2 = !parent_is_c2;
    }

    return all_children_to_trim;
}
//----------------------------------------------------------------------------------------------------------------------
template<>
CurveTrees<Helios, Selene>::LastHashes TreeSync<Helios, Selene>::get_last_hashes_to_trim(
    const std::vector<TrimLayerInstructions> &trim_instructions) const
{
    CurveTrees<Helios, Selene>::LastHashes last_hashes;

    if (trim_instructions.empty())
        return last_hashes;

    bool parent_is_c2 = true;
    for (LayerIdx i = 0; i < trim_instructions.size(); ++i)
    {
        const auto &trim_layer_instructions = trim_instructions[i];

        const std::size_t new_total_parents = trim_layer_instructions.new_total_parents;
        CHECK_AND_ASSERT_THROW_MES(new_total_parents > 0, "no new parents");
        const ChildChunkIdx last_parent_idx = new_total_parents - 1;

        const auto cached_layer_it = m_tree_elem_cache.find(i);
        CHECK_AND_ASSERT_THROW_MES(cached_layer_it != m_tree_elem_cache.end(), "missing layer for trim");

        auto cached_chunk_it = cached_layer_it->second.find(last_parent_idx);
        CHECK_AND_ASSERT_THROW_MES(cached_chunk_it != cached_layer_it->second.end(), "missing cached chunk");

        if (parent_is_c2)
        {
            auto c2_point = m_curve_trees->m_c2->from_bytes(cached_chunk_it->second.tree_elem);
            last_hashes.c2_last_hashes.push_back(std::move(c2_point));
        }
        else
        {
            auto c1_point = m_curve_trees->m_c1->from_bytes(cached_chunk_it->second.tree_elem);
            last_hashes.c1_last_hashes.push_back(std::move(c1_point));
        }

        parent_is_c2 = !parent_is_c2;
    }

    return last_hashes;

}
//----------------------------------------------------------------------------------------------------------------------
template<typename C1, typename C2>
void TreeSync<C1, C2>::deque_block(const BlockHash &block_hash)
{
    // Remove refs to prunable leaves in the cache
    auto prunable_leaves_it = m_prunable_leaves_by_block.find(block_hash);
    CHECK_AND_ASSERT_THROW_MES(prunable_leaves_it != m_prunable_leaves_by_block.end(), "missing block of prunable leaves");
    for (const auto &prunable_leaf_idx : prunable_leaves_it->second)
    {
        auto leaf_it = m_cached_leaves.find(prunable_leaf_idx);
        CHECK_AND_ASSERT_THROW_MES(leaf_it != m_cached_leaves.end(), "cache is missing leaf");
        CHECK_AND_ASSERT_THROW_MES(leaf_it->second.ref_count != 0, "leaf has 0 ref count");

        leaf_it->second.ref_count -= 1;

        // If the ref count is 0, garbage collect it
        if (leaf_it->second.ref_count == 0)
            m_cached_leaves.erase(leaf_it);
    }
    m_prunable_leaves_by_block.erase(block_hash);

    // Remove refs to prunable tree elems in the cache
    auto prunable_tree_elems_it = m_prunable_tree_elems_by_block.find(block_hash);
    CHECK_AND_ASSERT_THROW_MES(prunable_tree_elems_it != m_prunable_tree_elems_by_block.end(), "missing block of prunable tree elems");
    for (const auto &tree_elem : prunable_tree_elems_it->second)
    {
        const LayerIdx layer_idx = tree_elem.first;
        const ChildChunkIdxSet &child_chunk_idx_set = tree_elem.second;
        if (child_chunk_idx_set.empty())
            continue;

        auto cached_layer_it = m_tree_elem_cache.find(layer_idx);
        CHECK_AND_ASSERT_THROW_MES(cached_layer_it != m_tree_elem_cache.end(), "missing cached layer");

        for (const auto &child_chunk_idx : child_chunk_idx_set)
        {
            auto cached_chunk_it = cached_layer_it->second.find(child_chunk_idx);
            CHECK_AND_ASSERT_THROW_MES(cached_chunk_it != cached_layer_it->second.end(), "missing cached chunk");
            CHECK_AND_ASSERT_THROW_MES(cached_chunk_it->second.ref_count != 0, "chunk has 0 ref count");

            cached_chunk_it->second.ref_count -= 1;

            // If the ref count is 0, garbage collect it
            if (cached_chunk_it->second.ref_count == 0)
                m_tree_elem_cache[layer_idx].erase(cached_chunk_it);
        }

        // If the layer is empty, garbage collect it
        if (m_tree_elem_cache[layer_idx].empty())
            m_tree_elem_cache.erase(layer_idx);
    }
    m_prunable_tree_elems_by_block.erase(block_hash);
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
}//namespace curve_trees
}//namespace fcmp_pp
