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
#include "misc_log_ex.h"
#include "unit_tests_utils.h"

//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
// CurveTreesGlobalTree helpers
//----------------------------------------------------------------------------------------------------------------------
template<typename C>
static fcmp::curve_trees::LastChunkData<C> get_last_child_layer_chunk(const bool update_last_parent,
    const std::size_t parent_layer_size,
    const typename C::Point &last_parent,
    const typename C::Scalar &last_child)
{
    if (update_last_parent)
        CHECK_AND_ASSERT_THROW_MES(parent_layer_size > 0, "empty parent layer");

    // If updating last parent, the next start will be the last parent's index, else we start at the tip
    const std::size_t next_start_child_chunk_index = update_last_parent
        ? (parent_layer_size - 1)
        : parent_layer_size;

    return fcmp::curve_trees::LastChunkData<C>{
        .next_start_child_chunk_index = next_start_child_chunk_index,
        .last_parent                  = last_parent,
        .update_last_parent           = update_last_parent,
        .last_child                   = last_child
    };
}
//----------------------------------------------------------------------------------------------------------------------
template<typename C>
static bool validate_layer(const C &curve,
    const CurveTreesGlobalTree::Layer<C> &parents,
    const std::vector<typename C::Scalar> &child_scalars,
    const std::size_t max_chunk_size)
{
    // Hash chunk of children scalars, then see if the hash matches up to respective parent
    std::size_t chunk_start_idx = 0;
    for (std::size_t i = 0; i < parents.size(); ++i)
    {
        CHECK_AND_ASSERT_MES(child_scalars.size() > chunk_start_idx, false, "chunk start too high");
        const std::size_t chunk_size = std::min(child_scalars.size() - chunk_start_idx, max_chunk_size);
        CHECK_AND_ASSERT_MES(child_scalars.size() >= (chunk_start_idx + chunk_size), false, "chunk size too large");

        const typename C::Point &parent = parents[i];

        const auto chunk_start = child_scalars.data() + chunk_start_idx;
        const typename C::Chunk chunk{chunk_start, chunk_size};

        for (std::size_t i = 0; i < chunk_size; ++i)
            MDEBUG("Hashing " << curve.to_string(chunk_start[i]));

        const typename C::Point chunk_hash = fcmp::curve_trees::get_new_parent(curve, chunk);

        MDEBUG("chunk_start_idx: " << chunk_start_idx << " , chunk_size: " << chunk_size << " , chunk_hash: " << curve.to_string(chunk_hash));

        const auto actual_bytes = curve.to_bytes(parent);
        const auto expected_bytes = curve.to_bytes(chunk_hash);
        CHECK_AND_ASSERT_MES(actual_bytes == expected_bytes, false, "unexpected hash");

        chunk_start_idx += chunk_size;
    }

    CHECK_AND_ASSERT_THROW_MES(chunk_start_idx == child_scalars.size(), "unexpected ending chunk start idx");

    return true;
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
// CurveTreesGlobalTree implementations
//----------------------------------------------------------------------------------------------------------------------
CurveTreesV1::LastChunks CurveTreesGlobalTree::get_last_chunks()
{
    const auto &leaves    = m_tree.leaves;
    const auto &c1_layers = m_tree.c1_layers;
    const auto &c2_layers = m_tree.c2_layers;

    // We started with c2 and then alternated, so c2 is the same size or 1 higher than c1
    CHECK_AND_ASSERT_THROW_MES(c2_layers.size() == c1_layers.size() || c2_layers.size() == (c1_layers.size() + 1),
        "unexpected number of curve layers");

    CurveTreesV1::LastChunks last_chunks;

    // Since leaf layer is append-only, we know the next start will be right after all existing leaf tuple
    const std::size_t num_leaf_tuples = leaves.size() * CurveTreesV1::LEAF_TUPLE_SIZE;
    last_chunks.next_start_leaf_index = num_leaf_tuples;

    if (c2_layers.empty())
        return last_chunks;

    auto &c1_last_chunks_out = last_chunks.c1_last_chunks;
    auto &c2_last_chunks_out = last_chunks.c2_last_chunks;

    c1_last_chunks_out.reserve(c1_layers.size());
    c2_last_chunks_out.reserve(c2_layers.size());

    // First push the last leaf chunk data into c2 chunks
    const bool update_last_parent = (num_leaf_tuples % m_curve_trees.m_leaf_layer_chunk_width) > 0;
    auto last_leaf_chunk = get_last_child_layer_chunk<Selene>(
        /*update_last_parent*/ update_last_parent,
        /*parent_layer_size */ c2_layers[0].size(),
        /*last_parent       */ c2_layers[0].back(),
        // Since the leaf layer is append-only, we'll never need access to the last child
        /*last_child        */ m_curve_trees.m_c2.zero_scalar());

    c2_last_chunks_out.push_back(std::move(last_leaf_chunk));

    // If there are no c1 layers, we're done
    if (c1_layers.empty())
        return last_chunks;

    // Next parents will be c1
    bool parent_is_c1 = true;

    // Then get last chunks up until the root
    std::size_t c1_idx = 0;
    std::size_t c2_idx = 0;
    while (c1_last_chunks_out.size() < c1_layers.size() || c2_last_chunks_out.size() < c2_layers.size())
    {
        CHECK_AND_ASSERT_THROW_MES(c1_layers.size() > c1_idx, "missing c1 layer");
        CHECK_AND_ASSERT_THROW_MES(c2_layers.size() > c2_idx, "missing c2 layer");

        // TODO: template the below if statement into another function
        if (parent_is_c1)
        {
            const Layer<Selene> &child_layer = c2_layers[c2_idx];
            CHECK_AND_ASSERT_THROW_MES(!child_layer.empty(), "child layer is empty");

            const Layer<Helios> &parent_layer = c1_layers[c1_idx];
            CHECK_AND_ASSERT_THROW_MES(!parent_layer.empty(), "parent layer is empty");

            const auto &last_child = m_curve_trees.m_c2.point_to_cycle_scalar(child_layer.back());

            auto last_parent_chunk = get_last_child_layer_chunk<Helios>(update_last_parent,
                parent_layer.size(),
                parent_layer.back(),
                last_child);

            c1_last_chunks_out.push_back(std::move(last_parent_chunk));

            ++c2_idx;
        }
        else
        {
            const Layer<Helios> &child_layer = c1_layers[c1_idx];
            CHECK_AND_ASSERT_THROW_MES(!child_layer.empty(), "child layer is empty");

            const Layer<Selene> &parent_layer = c2_layers[c2_idx];
            CHECK_AND_ASSERT_THROW_MES(!parent_layer.empty(), "parent layer is empty");

            const auto &last_child = m_curve_trees.m_c1.point_to_cycle_scalar(child_layer.back());

            auto last_parent_chunk = get_last_child_layer_chunk<Selene>(update_last_parent,
                parent_layer.size(),
                parent_layer.back(),
                last_child);

            c2_last_chunks_out.push_back(std::move(last_parent_chunk));

            ++c1_idx;
        }

        // Alternate curves every iteration
        parent_is_c1 = !parent_is_c1;
    }

    CHECK_AND_ASSERT_THROW_MES(c1_last_chunks_out.size() == c1_layers.size(), "unexpected c1 last chunks");
    CHECK_AND_ASSERT_THROW_MES(c2_last_chunks_out.size() == c2_layers.size(), "unexpected c2 last chunks");

    return last_chunks;
}
//----------------------------------------------------------------------------------------------------------------------
void CurveTreesGlobalTree::extend_tree(const CurveTreesV1::TreeExtension &tree_extension)
{
    // Add the leaves
    const std::size_t init_num_leaves = m_tree.leaves.size() * m_curve_trees.LEAF_TUPLE_SIZE;
    CHECK_AND_ASSERT_THROW_MES(init_num_leaves == tree_extension.leaves.start_idx,
        "unexpected leaf start idx");

    m_tree.leaves.reserve(m_tree.leaves.size() + tree_extension.leaves.tuples.size());
    for (const auto &leaf : tree_extension.leaves.tuples)
    {
        m_tree.leaves.emplace_back(CurveTreesV1::LeafTuple{
            .O_x = leaf.O_x,
            .I_x = leaf.I_x,
            .C_x = leaf.C_x
        });
    }

    // Add the layers
    const auto &c2_extensions = tree_extension.c2_layer_extensions;
    const auto &c1_extensions = tree_extension.c1_layer_extensions;
    CHECK_AND_ASSERT_THROW_MES(!c2_extensions.empty(), "empty c2 extensions");

    bool use_c2 = true;
    std::size_t c2_idx = 0;
    std::size_t c1_idx = 0;
    for (std::size_t i = 0; i < (c2_extensions.size() + c1_extensions.size()); ++i)
    {
        // TODO: template below if statement
        if (use_c2)
        {
            CHECK_AND_ASSERT_THROW_MES(c2_idx < c2_extensions.size(), "unexpected c2 layer extension");
            const fcmp::curve_trees::LayerExtension<Selene> &c2_ext = c2_extensions[c2_idx];

            CHECK_AND_ASSERT_THROW_MES(!c2_ext.hashes.empty(), "empty c2 layer extension");

            CHECK_AND_ASSERT_THROW_MES(c2_idx <= m_tree.c2_layers.size(), "missing c2 layer");
            if (m_tree.c2_layers.size() == c2_idx)
                m_tree.c2_layers.emplace_back(Layer<Selene>{});

            auto &c2_inout = m_tree.c2_layers[c2_idx];

            const bool started_after_tip = (c2_inout.size() == c2_ext.start_idx);
            const bool started_at_tip    = (c2_inout.size() == (c2_ext.start_idx + 1));
            CHECK_AND_ASSERT_THROW_MES(started_after_tip || started_at_tip, "unexpected c2 layer start");

            // We updated the last hash
            if (started_at_tip)
                c2_inout.back() = c2_ext.hashes.front();

            for (std::size_t i = started_at_tip ? 1 : 0; i < c2_ext.hashes.size(); ++i)
                c2_inout.emplace_back(c2_ext.hashes[i]);

            ++c2_idx;
        }
        else
        {
            CHECK_AND_ASSERT_THROW_MES(c1_idx < c1_extensions.size(), "unexpected c1 layer extension");
            const fcmp::curve_trees::LayerExtension<Helios> &c1_ext = c1_extensions[c1_idx];

            CHECK_AND_ASSERT_THROW_MES(!c1_ext.hashes.empty(), "empty c1 layer extension");

            CHECK_AND_ASSERT_THROW_MES(c1_idx <= m_tree.c1_layers.size(), "missing c1 layer");
            if (m_tree.c1_layers.size() == c1_idx)
                m_tree.c1_layers.emplace_back(Layer<Helios>{});

            auto &c1_inout = m_tree.c1_layers[c1_idx];

            const bool started_after_tip = (c1_inout.size() == c1_ext.start_idx);
            const bool started_at_tip    = (c1_inout.size() == (c1_ext.start_idx + 1));
            CHECK_AND_ASSERT_THROW_MES(started_after_tip || started_at_tip, "unexpected c1 layer start");

            // We updated the last hash
            if (started_at_tip)
                c1_inout.back() = c1_ext.hashes.front();

            for (std::size_t i = started_at_tip ? 1 : 0; i < c1_ext.hashes.size(); ++i)
                c1_inout.emplace_back(c1_ext.hashes[i]);

            ++c1_idx;
        }

        use_c2 = !use_c2;
    }
}
//----------------------------------------------------------------------------------------------------------------------
bool CurveTreesGlobalTree::audit_tree()
{
    const auto &leaves = m_tree.leaves;
    const auto &c1_layers = m_tree.c1_layers;
    const auto &c2_layers = m_tree.c2_layers;

    CHECK_AND_ASSERT_MES(!leaves.empty(), false, "must have at least 1 leaf in tree");
    CHECK_AND_ASSERT_MES(!c2_layers.empty(), false, "must have at least 1 c2 layer in tree");
    CHECK_AND_ASSERT_MES(c2_layers.size() == c1_layers.size() || c2_layers.size() == (c1_layers.size() + 1),
        false, "unexpected mismatch of c2 and c1 layers");

    // Verify root has 1 member in it
    const bool c2_is_root = c2_layers.size() > c1_layers.size();
    CHECK_AND_ASSERT_MES(c2_is_root ? c2_layers.back().size() == 1 : c1_layers.back().size() == 1, false,
        "root must have 1 member in it");

    // Iterate from root down to layer above leaves, and check hashes match up correctly
    bool parent_is_c2 = c2_is_root;
    std::size_t c2_idx = c2_layers.size() - 1;
    std::size_t c1_idx = c1_layers.empty() ? 0 : (c1_layers.size() - 1);
    for (std::size_t i = 1; i < (c2_layers.size() + c1_layers.size()); ++i)
    {
        // TODO: implement templated function for below if statement
        if (parent_is_c2)
        {
            MDEBUG("Validating parent c2 layer " << c2_idx << " , child c1 layer " << c1_idx);

            CHECK_AND_ASSERT_THROW_MES(c2_idx < c2_layers.size(), "unexpected c2_idx");
            CHECK_AND_ASSERT_THROW_MES(c1_idx < c1_layers.size(), "unexpected c1_idx");

            const Layer<Selene> &parents  = c2_layers[c2_idx];
            const Layer<Helios> &children = c1_layers[c1_idx];

            CHECK_AND_ASSERT_MES(!parents.empty(), false, "no parents at c2_idx " + std::to_string(c2_idx));
            CHECK_AND_ASSERT_MES(!children.empty(), false, "no children at c1_idx " + std::to_string(c1_idx));

            std::vector<Selene::Scalar> child_scalars;
            fcmp::tower_cycle::extend_scalars_from_cycle_points<Helios, Selene>(m_curve_trees.m_c1,
                children,
                child_scalars);

            const bool valid = validate_layer<Selene>(m_curve_trees.m_c2,
                parents,
                child_scalars,
                m_curve_trees.m_c2_width);

            CHECK_AND_ASSERT_MES(valid, false, "failed to validate c2_idx " + std::to_string(c2_idx));

            --c2_idx;
        }
        else
        {
            MDEBUG("Validating parent c1 layer " << c1_idx << " , child c2 layer " << c2_idx);

            CHECK_AND_ASSERT_THROW_MES(c1_idx < c1_layers.size(), "unexpected c1_idx");
            CHECK_AND_ASSERT_THROW_MES(c2_idx < c2_layers.size(), "unexpected c2_idx");

            const Layer<Helios> &parents  = c1_layers[c1_idx];
            const Layer<Selene> &children = c2_layers[c2_idx];

            CHECK_AND_ASSERT_MES(!parents.empty(), false, "no parents at c1_idx " + std::to_string(c1_idx));
            CHECK_AND_ASSERT_MES(!children.empty(), false, "no children at c2_idx " + std::to_string(c2_idx));

            std::vector<Helios::Scalar> child_scalars;
            fcmp::tower_cycle::extend_scalars_from_cycle_points<Selene, Helios>(m_curve_trees.m_c2,
                children,
                child_scalars);

            const bool valid = validate_layer<Helios>(
                m_curve_trees.m_c1,
                parents,
                child_scalars,
                m_curve_trees.m_c1_width);

            CHECK_AND_ASSERT_MES(valid, false, "failed to validate c1_idx " + std::to_string(c1_idx));

            --c1_idx;
        }

        parent_is_c2 = !parent_is_c2;
    }

    MDEBUG("Validating leaves");

    // Now validate leaves
    return validate_layer<Selene>(m_curve_trees.m_c2,
        c2_layers[0],
        m_curve_trees.flatten_leaves(leaves),
        m_curve_trees.m_leaf_layer_chunk_width);
}
//----------------------------------------------------------------------------------------------------------------------
// Logging helpers
//----------------------------------------------------------------------------------------------------------------------
void CurveTreesGlobalTree::log_last_chunks(const CurveTreesV1::LastChunks &last_chunks)
{
    const auto &c1_last_chunks = last_chunks.c1_last_chunks;
    const auto &c2_last_chunks = last_chunks.c2_last_chunks;

    MDEBUG("Total of " << c1_last_chunks.size() << " Helios last chunks and "
        << c2_last_chunks.size() << " Selene last chunks");

    bool use_c2 = true;
    std::size_t c1_idx = 0;
    std::size_t c2_idx = 0;
    for (std::size_t i = 0; i < (c1_last_chunks.size() + c2_last_chunks.size()); ++i)
    {
        if (use_c2)
        {
            CHECK_AND_ASSERT_THROW_MES(c2_idx < c2_last_chunks.size(), "unexpected c2 layer");

            const fcmp::curve_trees::LastChunkData<Selene> &last_chunk = c2_last_chunks[c2_idx];

            MDEBUG("next_start_child_chunk_index: " << last_chunk.next_start_child_chunk_index
                << " , last_parent: "               << m_curve_trees.m_c2.to_string(last_chunk.last_parent)
                << " , update_last_parent: "        << last_chunk.update_last_parent
                << " , last_child: "                << m_curve_trees.m_c2.to_string(last_chunk.last_child));

            ++c2_idx;
        }
        else
        {
            CHECK_AND_ASSERT_THROW_MES(c1_idx < c1_last_chunks.size(), "unexpected c1 layer");

            const fcmp::curve_trees::LastChunkData<Helios> &last_chunk = c1_last_chunks[c1_idx];

            MDEBUG("next_start_child_chunk_index: " << last_chunk.next_start_child_chunk_index
                << " , last_parent: "               << m_curve_trees.m_c1.to_string(last_chunk.last_parent)
                << " , update_last_parent: "        << last_chunk.update_last_parent
                << " , last_child: "                << m_curve_trees.m_c1.to_string(last_chunk.last_child));

            ++c1_idx;
        }

        use_c2 = !use_c2;
    }
}
//----------------------------------------------------------------------------------------------------------------------
void CurveTreesGlobalTree::log_tree_extension(const CurveTreesV1::TreeExtension &tree_extension)
{
    const auto &c1_extensions = tree_extension.c1_layer_extensions;
    const auto &c2_extensions = tree_extension.c2_layer_extensions;

    MDEBUG("Tree extension has " << tree_extension.leaves.tuples.size() << " leaves, "
        << c1_extensions.size() << " helios layers, " <<  c2_extensions.size() << " selene layers");

    MDEBUG("Leaf start idx: " << tree_extension.leaves.start_idx);
    for (std::size_t i = 0; i < tree_extension.leaves.tuples.size(); ++i)
    {
        const auto &leaf = tree_extension.leaves.tuples[i];

        const auto O_x = m_curve_trees.m_c2.to_string(leaf.O_x);
        const auto I_x = m_curve_trees.m_c2.to_string(leaf.I_x);
        const auto C_x = m_curve_trees.m_c2.to_string(leaf.C_x);

        MDEBUG("Leaf idx " << ((i*CurveTreesV1::LEAF_TUPLE_SIZE) + tree_extension.leaves.start_idx)
            << " : { O_x: " << O_x << " , I_x: " << I_x << " , C_x: " << C_x << " }");
    }

    bool use_c2 = true;
    std::size_t c1_idx = 0;
    std::size_t c2_idx = 0;
    for (std::size_t i = 0; i < (c1_extensions.size() + c2_extensions.size()); ++i)
    {
        if (use_c2)
        {
            CHECK_AND_ASSERT_THROW_MES(c2_idx < c2_extensions.size(), "unexpected c2 layer");

            const fcmp::curve_trees::LayerExtension<Selene> &c2_layer = c2_extensions[c2_idx];
            MDEBUG("Selene tree extension start idx: " << c2_layer.start_idx);

            for (std::size_t j = 0; j < c2_layer.hashes.size(); ++j)
                MDEBUG("Child chunk start idx: " << (j + c2_layer.start_idx) << " , hash: "
                    << m_curve_trees.m_c2.to_string(c2_layer.hashes[j]));

            ++c2_idx;
        }
        else
        {
            CHECK_AND_ASSERT_THROW_MES(c1_idx < c1_extensions.size(), "unexpected c1 layer");

            const fcmp::curve_trees::LayerExtension<Helios> &c1_layer = c1_extensions[c1_idx];
            MDEBUG("Helios tree extension start idx: " << c1_layer.start_idx);

            for (std::size_t j = 0; j < c1_layer.hashes.size(); ++j)
                MDEBUG("Child chunk start idx: " << (j + c1_layer.start_idx) << " , hash: "
                    << m_curve_trees.m_c1.to_string(c1_layer.hashes[j]));

            ++c1_idx;
        }

        use_c2 = !use_c2;
    }
}
//----------------------------------------------------------------------------------------------------------------------
void CurveTreesGlobalTree::log_tree()
{
    MDEBUG("Tree has " << m_tree.leaves.size() << " leaves, "
        << m_tree.c1_layers.size() << " helios layers, " <<  m_tree.c2_layers.size() << " selene layers");

    for (std::size_t i = 0; i < m_tree.leaves.size(); ++i)
    {
        const auto &leaf = m_tree.leaves[i];

        const auto O_x = m_curve_trees.m_c2.to_string(leaf.O_x);
        const auto I_x = m_curve_trees.m_c2.to_string(leaf.I_x);
        const auto C_x = m_curve_trees.m_c2.to_string(leaf.C_x);

        MDEBUG("Leaf idx " << i << " : { O_x: " << O_x << " , I_x: " << I_x << " , C_x: " << C_x << " }");
    }

    bool use_c2 = true;
    std::size_t c1_idx = 0;
    std::size_t c2_idx = 0;
    for (std::size_t i = 0; i < (m_tree.c1_layers.size() + m_tree.c2_layers.size()); ++i)
    {
        if (use_c2)
        {
            CHECK_AND_ASSERT_THROW_MES(c2_idx < m_tree.c2_layers.size(), "unexpected c2 layer");

            const CurveTreesGlobalTree::Layer<Selene> &c2_layer = m_tree.c2_layers[c2_idx];
            MDEBUG("Selene layer size: " << c2_layer.size() << " , tree layer: " << i);

            for (std::size_t j = 0; j < c2_layer.size(); ++j)
                MDEBUG("Child chunk start idx: " << j << " , hash: " << m_curve_trees.m_c2.to_string(c2_layer[j]));

            ++c2_idx;
        }
        else
        {
            CHECK_AND_ASSERT_THROW_MES(c1_idx < m_tree.c1_layers.size(), "unexpected c1 layer");

            const CurveTreesGlobalTree::Layer<Helios> &c1_layer = m_tree.c1_layers[c1_idx];
            MDEBUG("Helios layer size: " << c1_layer.size() << " , tree layer: " << i);

            for (std::size_t j = 0; j < c1_layer.size(); ++j)
                MDEBUG("Child chunk start idx: " << j << " , hash: " << m_curve_trees.m_c1.to_string(c1_layer[j]));

            ++c1_idx;
        }

        use_c2 = !use_c2;
    }
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
// Test helpers
//----------------------------------------------------------------------------------------------------------------------
const std::vector<CurveTreesV1::LeafTuple> generate_random_leaves(const CurveTreesV1 &curve_trees,
    const std::size_t num_leaves)
{
    std::vector<CurveTreesV1::LeafTuple> tuples;
    tuples.reserve(num_leaves);

    for (std::size_t i = 0; i < num_leaves; ++i)
    {
        // Generate random output tuple
        crypto::secret_key o,c;
        crypto::public_key O,C;
        crypto::generate_keys(O, o, o, false);
        crypto::generate_keys(C, c, c, false);

        auto leaf_tuple = curve_trees.output_to_leaf_tuple(O, C);

        tuples.emplace_back(std::move(leaf_tuple));
    }

    return tuples;
}
//----------------------------------------------------------------------------------------------------------------------
static bool grow_tree(CurveTreesV1 &curve_trees,
    CurveTreesGlobalTree &global_tree,
    const std::size_t num_leaves)
{
    // Get the last chunk from each layer in the tree; empty if tree is empty
    const auto last_chunks = global_tree.get_last_chunks();

    global_tree.log_last_chunks(last_chunks);

    // Get a tree extension object to the existing tree using randomly generated leaves
    // - The tree extension includes all elements we'll need to add to the existing tree when adding the new leaves
    const auto tree_extension = curve_trees.get_tree_extension(last_chunks,
        generate_random_leaves(curve_trees, num_leaves));

    global_tree.log_tree_extension(tree_extension);

    // Use the tree extension to extend the existing tree
    global_tree.extend_tree(tree_extension);

    global_tree.log_tree();

    // Validate tree structure and all hashes
    return global_tree.audit_tree();
}
//----------------------------------------------------------------------------------------------------------------------
static bool grow_tree_in_memory(const std::size_t init_leaves,
    const std::size_t ext_leaves,
    CurveTreesV1 &curve_trees)
{
    LOG_PRINT_L1("Adding " << init_leaves << " leaves to tree in memory, then extending by "
        << ext_leaves << " leaves");

    CurveTreesGlobalTree global_tree(curve_trees);

    // Initialize global tree with `init_leaves`
    MDEBUG("Adding " << init_leaves << " leaves to tree");

    bool res = grow_tree(curve_trees,
        global_tree,
        init_leaves);

    CHECK_AND_ASSERT_MES(res, false, "failed to add inital leaves to tree in memory");

    MDEBUG("Successfully added initial " << init_leaves << " leaves to tree in memory");

    // Then extend the global tree by `ext_leaves`
    MDEBUG("Extending tree by " << ext_leaves << " leaves");

    res = grow_tree(curve_trees,
        global_tree,
        ext_leaves);

    CHECK_AND_ASSERT_MES(res, false, "failed to extend tree in memory");

    MDEBUG("Successfully extended by " << ext_leaves << " leaves in memory");
    return true;
}
//----------------------------------------------------------------------------------------------------------------------
static bool grow_tree_db(const std::size_t init_leaves,
    const std::size_t ext_leaves,
    CurveTreesV1 &curve_trees,
    unit_test::BlockchainLMDBTest &test_db)
{
    INIT_BLOCKCHAIN_LMDB_TEST_DB();

    {
        cryptonote::db_wtxn_guard guard(test_db.m_db);

        LOG_PRINT_L1("Adding " << init_leaves << " leaves to db, then extending by " << ext_leaves << " leaves");

        test_db.m_db->grow_tree(curve_trees, generate_random_leaves(curve_trees, init_leaves));
        CHECK_AND_ASSERT_MES(test_db.m_db->audit_tree(curve_trees), false, "failed to add initial leaves to db");

        MDEBUG("Successfully added initial " << init_leaves << " leaves to db, extending by "
            << ext_leaves << " leaves");

        test_db.m_db->grow_tree(curve_trees, generate_random_leaves(curve_trees, ext_leaves));
        CHECK_AND_ASSERT_MES(test_db.m_db->audit_tree(curve_trees), false, "failed to extend tree in db");

        MDEBUG("Successfully extended tree in db by " << ext_leaves << " leaves");
    }

    return true;
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
// Test
//----------------------------------------------------------------------------------------------------------------------
TEST(curve_trees, grow_tree)
{
    Helios helios;
    Selene selene;

    LOG_PRINT_L1("Test grow tree with helios chunk width " << HELIOS_CHUNK_WIDTH
        << ", selene chunk width " << SELENE_CHUNK_WIDTH);

    auto curve_trees = CurveTreesV1(
        helios,
        selene,
        HELIOS_CHUNK_WIDTH,
        SELENE_CHUNK_WIDTH);

    unit_test::BlockchainLMDBTest test_db;

    CHECK_AND_ASSERT_THROW_MES(HELIOS_CHUNK_WIDTH > 1, "helios width must be > 1");
    CHECK_AND_ASSERT_THROW_MES(SELENE_CHUNK_WIDTH > 1, "selene width must be > 1");

    // Number of leaves for which x number of layers is required
    const std::size_t NEED_1_LAYER  = SELENE_CHUNK_WIDTH;
    const std::size_t NEED_2_LAYERS = NEED_1_LAYER  * HELIOS_CHUNK_WIDTH;
    const std::size_t NEED_3_LAYERS = NEED_2_LAYERS * SELENE_CHUNK_WIDTH;

    const std::vector<std::size_t> N_LEAVES{
        // Basic tests
        1,
        2,

        // Test with number of leaves {-1,0,+1} relative to chunk width boundaries
        NEED_1_LAYER-1,
        NEED_1_LAYER,
        NEED_1_LAYER+1,

        NEED_2_LAYERS-1,
        NEED_2_LAYERS,
        NEED_2_LAYERS+1,

        NEED_3_LAYERS,
    };

    for (const std::size_t init_leaves : N_LEAVES)
    {
        for (const std::size_t ext_leaves : N_LEAVES)
        {
            // Only test 3rd layer once because it's a huge test
            if (init_leaves > 1 && ext_leaves == NEED_3_LAYERS)
                continue;
            if (ext_leaves > 1 && init_leaves == NEED_3_LAYERS)
                continue;

            ASSERT_TRUE(grow_tree_in_memory(init_leaves, ext_leaves, curve_trees));
            ASSERT_TRUE(grow_tree_db(init_leaves, ext_leaves, curve_trees, test_db));
        }
    }
}
