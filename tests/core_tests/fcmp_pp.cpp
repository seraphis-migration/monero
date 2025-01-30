// Copyright (c) 2014-2024, The Monero Project
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
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "fcmp_pp.h"

#include "ringct/rctSigs.h"
#include "ringct/bulletproofs_plus.h"
#include "chaingen.h"
#include "blockchain_db/blockchain_db_utils.h"
#include "fcmp_pp/prove.h"
#include "fcmp_pp/tree_cache.h"
#include "device/device.hpp"

using namespace epee;
using namespace crypto;
using namespace cryptonote;

using Selene = fcmp_pp::curve_trees::Selene;
using Helios = fcmp_pp::curve_trees::Helios;
using TreeCacheV1 = fcmp_pp::curve_trees::TreeCache<Selene, Helios>;

//----------------------------------------------------------------------------------------------------------------------
// Tests

bool gen_fcmp_pp_tx_validation_base::generate_with(std::vector<test_event_entry>& events,
    size_t n_txes, const uint64_t *amounts_paid, bool valid, const rct::RCTConfig &rct_config, uint8_t hf_version,
    const std::function<bool(std::vector<tx_source_entry> &sources, std::vector<tx_destination_entry> &destinations, size_t tx_idx)> &pre_tx,
    const std::function<bool(transaction &tx, size_t tx_idx)> &post_tx) const
{
  uint64_t ts_start = 1338224400;

  GENERATE_ACCOUNT(miner_account);
  MAKE_GENESIS_BLOCK(events, blk_0, miner_account, ts_start);


  // create 12 miner accounts, and have them mine the next 12 blocks
  cryptonote::account_base miner_accounts[12];
  const cryptonote::block *prev_block = &blk_0;
  cryptonote::block blocks[12 + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW];
  for (size_t n = 0; n < 12; ++n) {
    miner_accounts[n].generate();
    CHECK_AND_ASSERT_MES(generator.construct_block_manually(blocks[n], *prev_block, miner_accounts[n],
        test_generator::bf_major_ver | test_generator::bf_minor_ver | test_generator::bf_timestamp | test_generator::bf_hf_version,
        2, 2, prev_block->timestamp + DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN * 2, // v2 has blocks twice as long
          crypto::hash(), 0, transaction(), std::vector<crypto::hash>(), 0, 0, 2),
        false, "Failed to generate block");
    events.push_back(blocks[n]);
    prev_block = blocks + n;
  }

  // mine CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW blocks so the above is spendable
  cryptonote::block blk_r, blk_last;
  {
    blk_last = blocks[11];
    for (size_t i = 0; i < CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW; ++i)
    {
      CHECK_AND_ASSERT_MES(generator.construct_block_manually(blocks[12+i], blk_last, miner_account,
          test_generator::bf_major_ver | test_generator::bf_minor_ver | test_generator::bf_timestamp | test_generator::bf_hf_version,
          2, 2, blk_last.timestamp + DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN * 2, // v2 has blocks twice as long
          crypto::hash(), 0, transaction(), std::vector<crypto::hash>(), 0, 0, 2),
          false, "Failed to generate block");
      events.push_back(blocks[12+i]);
      blk_last = blocks[12+i];
    }
    blk_r = blk_last;
  }

  // Build the FCMP++ curve tree
  TreeCacheV1 tree_cache(fcmp_pp::curve_trees::curve_trees_v1());
  std::vector<crypto::hash> new_block_hashes;
  std::vector<fcmp_pp::curve_trees::OutputsByLastLockedBlock> outs_by_last_locked_blocks;
  uint64_t first_output_id = 0;
  size_t blk_idx = 0;
  for (const auto &blk : blocks)
  {
    new_block_hashes.push_back(blk.hash);
    auto outs_meta = cryptonote::get_outs_by_last_locked_block(blk.miner_tx, {}, first_output_id, blk_idx);
    outs_by_last_locked_blocks.emplace_back(std::move(outs_meta.outs_by_last_locked_block));
    first_output_id = outs_meta.next_output_id;
    ++blk_idx;
  }

  // We're going to spend the first output in the first block
  const auto &spending_out = blocks[0].miner_tx.vout[0];

  // Register the output with the TreeCache to know its location in the tree
  const auto &output_pubkey = boost::get<txout_to_key>(spending_out.target).key;
  const rct::key C = rct::zeroCommitVartime(spending_out.amount);
  const fcmp_pp::curve_trees::OutputPair output_pair{.output_pubkey = output_pubkey, .commitment = C};
  tree_cache.register_output(output_pair, cryptonote::get_last_locked_block_index(blocks[0].miner_tx.unlock_time, 0));

  // Build the tree, keeping track of output's path in the tree
  fcmp_pp::curve_trees::CurveTreesV1::TreeExtension tree_extension;
  std::vector<uint64_t> n_new_leaf_tuples_per_block;
  tree_cache.sync_blocks(0, {}, new_block_hashes, outs_by_last_locked_blocks, tree_extension, n_new_leaf_tuples_per_block);
  tree_cache.process_synced_blocks(0, new_block_hashes, tree_extension, n_new_leaf_tuples_per_block);

  // create 1 tx in another block, spending from the first block
  std::vector<transaction> rct_txes;
  cryptonote::block blk_txes;
  std::vector<crypto::hash> starting_rct_tx_hashes;
  uint64_t fees = 0;
  std::vector<tx_source_entry> sources;
  fcmp_pp::ProofParams fcmp_pp_params;
  fcmp_pp_params.reference_block = new_block_hashes.back();

  sources.resize(1);
  tx_source_entry& src = sources.back();

  src.amount = spending_out.amount;
  size_t real_index_in_tx = 0;
  src.push_output(0, output_pubkey, src.amount);
  src.real_out_tx_key = cryptonote::get_tx_pub_key_from_extra(blocks[0].miner_tx);
  src.real_output = 0;
  src.real_output_in_tx_index = real_index_in_tx;
  src.mask = rct::identity();
  src.rct = false;

  //fill outputs entry
  tx_destination_entry td;
  td.addr = miner_accounts[0].get_keys().m_account_address;
  std::vector<tx_destination_entry> destinations;
  for (int o = 0; amounts_paid[o] != (uint64_t)-1; ++o)
  {
    td.amount = amounts_paid[o];
    destinations.push_back(td);
  }

  if (pre_tx && !pre_tx(sources, destinations, 0))
  {
    MDEBUG("pre_tx returned failure");
    return false;
  }

  // Set FCMP++ params
  fcmp_pp_params.proof_inputs.emplace_back();
  auto &proof_input = fcmp_pp_params.proof_inputs.back();

  // Get output's path in the tree
  fcmp_pp::curve_trees::CurveTreesV1::Path path;
  bool r = tree_cache.get_output_path(output_pair, path);
  CHECK_AND_ASSERT_MES(r, false, "failed to get output path");
  CHECK_AND_ASSERT_MES(!path.empty(), false, "path empty");

  // Get output's index in the path
  r = false;
  const auto output_tuple = fcmp_pp::curve_trees::output_to_tuple(output_pair);
  std::size_t output_idx_in_path = 0;
  for (const auto &leaf : path.leaves)
  {
    r = output_tuple.O == leaf.O && output_tuple.I == leaf.I && output_tuple.C == leaf.C;
    if (r)
      break;
    ++output_idx_in_path;
  }
  CHECK_AND_ASSERT_MES(r, false, "failed to find output in path");

  // Set up OutputBytes compatible with Rust FFI
  std::vector<fcmp_pp::OutputBytes> output_bytes;
  output_bytes.reserve(path.leaves.size());
  for (const auto &leaf : path.leaves)
  {
      output_bytes.push_back({
              .O_bytes = (uint8_t *)&leaf.O.bytes,
              .I_bytes = (uint8_t *)&leaf.I.bytes,
              .C_bytes = (uint8_t *)&leaf.C.bytes,
          });
  }
  const fcmp_pp::OutputChunk leaves{output_bytes.data(), output_bytes.size()};

  src.rerandomized_output = fcmp_pp::rerandomize_output(output_bytes[output_idx_in_path]);

  // Set the path
  {
    const auto curve_trees = fcmp_pp::curve_trees::curve_trees_v1();

    // selene scalars from helios points
    std::vector<std::vector<fcmp_pp::SeleneScalar>> selene_scalars;
    std::vector<Selene::Chunk> selene_chunks;
    for (const auto &helios_points : path.c2_layers)
    {
      // Exclude the root
      if (helios_points.size() == 1)
          break;
      selene_scalars.emplace_back();
      auto &selene_layer = selene_scalars.back();
      selene_layer.reserve(helios_points.size());
      for (const auto &c2_point : helios_points)
        selene_layer.emplace_back(curve_trees->m_c2->point_to_cycle_scalar(c2_point));
      // Padding with 0's
      for (std::size_t i = helios_points.size(); i < curve_trees->m_c1_width; ++i)
        selene_layer.emplace_back(curve_trees->m_c1->zero_scalar());
      selene_chunks.emplace_back(Selene::Chunk{selene_layer.data(), selene_layer.size()});
    }
    const Selene::ScalarChunks selene_scalar_chunks{selene_chunks.data(), selene_chunks.size()};

    // helios scalars from selene points
    std::vector<std::vector<fcmp_pp::HeliosScalar>> helios_scalars;
    std::vector<Helios::Chunk> helios_chunks;
    for (const auto &selene_points : path.c1_layers)
    {
      // Exclude the root
      if (selene_points.size() == 1)
        break;
      helios_scalars.emplace_back();
      auto &helios_layer = helios_scalars.back();
      helios_layer.reserve(selene_points.size());
      for (const auto &c1_point : selene_points)
        helios_layer.emplace_back(curve_trees->m_c1->point_to_cycle_scalar(c1_point));
      // Padding with 0's
      for (std::size_t i = selene_points.size(); i < curve_trees->m_c2_width; ++i)
        helios_layer.emplace_back(curve_trees->m_c2->zero_scalar());
      helios_chunks.emplace_back(Helios::Chunk{helios_layer.data(), helios_layer.size()});
    }
    const Helios::ScalarChunks helios_scalar_chunks{helios_chunks.data(), helios_chunks.size()};

    proof_input.path = fcmp_pp::path_new(leaves,
      output_idx_in_path,
      helios_scalar_chunks,
      selene_scalar_chunks);
  }

  // Collect blinds for rerandomized output
  {
    const auto o_blind = fcmp_pp::o_blind(src.rerandomized_output);
    const auto i_blind = fcmp_pp::i_blind(src.rerandomized_output);
    const auto i_blind_blind = fcmp_pp::i_blind_blind(src.rerandomized_output);
    const auto c_blind = fcmp_pp::c_blind(src.rerandomized_output);

    const auto blinded_o_blind = fcmp_pp::blind_o_blind(o_blind);
    const auto blinded_i_blind = fcmp_pp::blind_i_blind(i_blind);
    const auto blinded_i_blind_blind = fcmp_pp::blind_i_blind_blind(i_blind_blind);
    const auto blinded_c_blind = fcmp_pp::blind_c_blind(c_blind);

    proof_input.output_blinds = fcmp_pp::output_blinds_new(blinded_o_blind,
        blinded_i_blind,
        blinded_i_blind_blind,
        blinded_c_blind);
  }

  // Collect branch blinds
  {
    const std::size_t n_selene_layers = path.c1_layers.size();
    const std::size_t n_helios_layers = path.c2_layers.size();

    const bool is_selene_root = n_selene_layers > n_helios_layers;

    const std::size_t n_selene_layers_excl_root = n_selene_layers - (is_selene_root ? 1 : 0);
    const std::size_t n_helios_layers_excl_root = n_helios_layers - (is_selene_root ? 0 : 1);

    for (std::size_t i = 0; i < n_selene_layers_excl_root; ++i)
      proof_input.selene_branch_blinds.emplace_back(fcmp_pp::selene_branch_blind());
    for (std::size_t i = 0; i < n_helios_layers_excl_root; ++i)
      proof_input.helios_branch_blinds.emplace_back(fcmp_pp::helios_branch_blind());
}

  crypto::secret_key tx_key;
  std::vector<crypto::secret_key> additional_tx_keys;
  std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses;
  subaddresses[miner_accounts[0].get_keys().m_account_address.m_spend_public_key] = {0,0};
  rct_txes.resize(rct_txes.size() + 1);
  r = construct_tx_and_get_tx_key(miner_accounts[0].get_keys(), subaddresses, sources, destinations, cryptonote::account_public_address{}, std::vector<uint8_t>(), rct_txes.back(), tx_key, additional_tx_keys, fcmp_pp_params, true, rct_config, true);
  CHECK_AND_ASSERT_MES(r, false, "failed to construct transaction");

  if (post_tx && !post_tx(rct_txes.back(), 0))
  {
    MDEBUG("post_tx returned failure");
    return false;
  }

  //events.push_back(rct_txes.back());
  starting_rct_tx_hashes.push_back(get_transaction_hash(rct_txes.back()));
  LOG_PRINT_L0("Test tx: " << obj_to_json_str(rct_txes.back()));

  for (int o = 0; amounts_paid[o] != (uint64_t)-1; ++o)
  {
    crypto::key_derivation derivation;
    bool r = crypto::generate_key_derivation(destinations[o].addr.m_view_public_key, tx_key, derivation);
    CHECK_AND_ASSERT_MES(r, false, "Failed to generate key derivation");
    crypto::secret_key amount_key;
    crypto::derivation_to_scalar(derivation, o, amount_key);
    rct::key rct_tx_mask;
    const uint8_t type = rct_txes.back().rct_signatures.type;
    if (rct::is_rct_simple(type))
      rct::decodeRctSimple(rct_txes.back().rct_signatures, rct::sk2rct(amount_key), o, rct_tx_mask, hw::get_device("default"));
    else
      rct::decodeRct(rct_txes.back().rct_signatures, rct::sk2rct(amount_key), o, rct_tx_mask, hw::get_device("default"));
  }

  while (amounts_paid[0] != (size_t)-1)
    ++amounts_paid;
  ++amounts_paid;

  uint64_t fee = 0;
  get_tx_fee(rct_txes.back(), fee);
  fees += fee;

  if (!valid)
    DO_CALLBACK(events, "mark_invalid_tx");
  events.push_back(rct_txes);

  CHECK_AND_ASSERT_MES(generator.construct_block_manually(blk_txes, blk_last, miner_account,
      test_generator::bf_major_ver | test_generator::bf_minor_ver | test_generator::bf_timestamp | test_generator::bf_tx_hashes | test_generator::bf_hf_version | test_generator::bf_max_outs | test_generator::bf_tx_fees,
      hf_version, hf_version, blk_last.timestamp + DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN * 2, // v2 has blocks twice as long
      crypto::hash(), 0, transaction(), starting_rct_tx_hashes, 0, 6, hf_version, fees),
      false, "Failed to generate block");
  if (!valid)
    DO_CALLBACK(events, "mark_invalid_block");
  events.push_back(blk_txes);
  blk_last = blk_txes;

  return true;
}

bool gen_fcmp_pp_tx_valid_at_fork::generate(std::vector<test_event_entry>& events) const
{
  const uint64_t amounts_paid[] = {5000, 5000, (uint64_t)-1};
  const rct::RCTConfig rct_config = { rct::RangeProofPaddedBulletproof, 5 };
  return generate_with(events, 1, amounts_paid, true, rct_config, HF_VERSION_FCMP_PLUS_PLUS, NULL, NULL);
}

// TODO: verification
// TODO: spend from pre-RCT, post-RCT, and coinbase outputs
