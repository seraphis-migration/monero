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

#pragma once

#include <cstdint>
#include <vector>

#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "fcmp_pp_rust/fcmp++.h"
#include "fcmp_pp_types.h"

namespace fcmp_pp
{
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
struct ProofInput final
{
    uint8_t *rerandomized_output;
    uint8_t *path;
    uint8_t *output_blinds;
    std::vector<const uint8_t *> selene_branch_blinds;
    std::vector<const uint8_t *> helios_branch_blinds;
};

struct ProofParams final
{
    crypto::hash reference_block;
    std::vector<ProofInput> proof_inputs;
};
//----------------------------------------------------------------------------------------------------------------------
uint8_t *rerandomize_output(const OutputBytes output);

crypto::ec_point pseudo_out(const uint8_t *rerandomized_output);

uint8_t *o_blind(const uint8_t *rerandomized_output);
uint8_t *i_blind(const uint8_t *rerandomized_output);
uint8_t *i_blind_blind(const uint8_t *rerandomized_output);
uint8_t *c_blind(const uint8_t *rerandomized_output);

uint8_t *blind_o_blind(const uint8_t *o_blind);
uint8_t *blind_i_blind(const uint8_t *i_blind);
uint8_t *blind_i_blind_blind(const uint8_t *i_blind_blind);
uint8_t *blind_c_blind(const uint8_t *c_blind);

uint8_t *path_new(const OutputChunk &leaves,
    std::size_t output_idx,
    const HeliosT::ScalarChunks &helios_layer_chunks,
    const SeleneT::ScalarChunks &selene_layer_chunks);

uint8_t *output_blinds_new(const uint8_t *blinded_o_blind,
    const uint8_t *blinded_i_blind,
    const uint8_t *blinded_i_blind_blind,
    const uint8_t *blinded_c_blind);

uint8_t *selene_branch_blind();
uint8_t *helios_branch_blind();

uint8_t *fcmp_prove_input_new(const uint8_t *x,
    const uint8_t *y,
    const uint8_t *rerandomized_output,
    const uint8_t *path,
    const uint8_t *output_blinds,
    const std::vector<const uint8_t *> &selene_branch_blinds,
    const std::vector<const uint8_t *> &helios_branch_blinds);

FcmpPpProof prove(const crypto::hash &signable_tx_hash,
    const std::vector<const uint8_t *> &fcmp_prove_inputs,
    const std::size_t n_tree_layers);

bool verify(const crypto::hash &signable_tx_hash,
    const FcmpPpProof &fcmp_pp_proof,
    const std::size_t n_tree_layers,
    const uint8_t *tree_root,
    const std::vector<crypto::ec_point> &pseudo_outs,
    const std::vector<crypto::key_image> &key_images);

std::size_t proof_len(const std::size_t n_inputs, const uint8_t n_tree_layers);
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
}//namespace fcmp_pp
