// Copyright (c) 2025, The Monero Project
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

#include "stdbool.h"
#include "stdint.h"

#define FCMP_PP_SAL_PROOF_SIZE_V1 (12*32)


// ----- deps C bindings -----

/// A constant-time implementation of the Ed25519 field.
struct SeleneScalar {
  uintptr_t _0[32 / sizeof(uintptr_t)];
};

/// The field novel to Helios/Selene.
struct HeliosScalar {
  uintptr_t _0[32 / sizeof(uintptr_t)];
};

struct HeliosPoint {
  struct SeleneScalar x;
  struct SeleneScalar y;
  struct SeleneScalar z;
};

struct SelenePoint {
  struct HeliosScalar x;
  struct HeliosScalar y;
  struct HeliosScalar z;
};

// ----- End deps C bindings -----

typedef struct CResult {
  void* value;
  void* err;
} CResult;

struct OutputBytes {
  const uint8_t *O_bytes;
  const uint8_t *I_bytes;
  const uint8_t *C_bytes;
};

struct HeliosScalarSlice
{
  const struct HeliosScalar *buf;
  uintptr_t len;
};

struct SeleneScalarSlice
{
  const struct SeleneScalar *buf;
  uintptr_t len;
};

struct OutputSlice
{
  const struct OutputBytes *buf;
  uintptr_t len;
};

struct HeliosScalarChunks
{
  const struct HeliosScalarSlice *buf;
  uintptr_t len;
};

struct SeleneScalarChunks
{
  const struct SeleneScalarSlice *buf;
  uintptr_t len;
};

struct ObjectSlice
{
  const uint8_t * const *buf;
  uintptr_t len;
};

#ifdef __cplusplus
extern "C" {
#endif

struct HeliosPoint helios_hash_init_point();

struct SelenePoint selene_hash_init_point();

uint8_t *helios_scalar_to_bytes(struct HeliosScalar helios_scalar);

uint8_t *selene_scalar_to_bytes(struct SeleneScalar selene_scalar);

uint8_t *helios_point_to_bytes(struct HeliosPoint helios_point);

uint8_t *selene_point_to_bytes(struct SelenePoint selene_point);

struct HeliosPoint helios_point_from_bytes(const uint8_t *helios_point_bytes);

struct SelenePoint selene_point_from_bytes(const uint8_t *selene_point_bytes);

struct SeleneScalar selene_scalar_from_bytes(const uint8_t *selene_scalar_bytes);

struct HeliosScalar selene_point_to_helios_scalar(struct SelenePoint selene_point);

struct SeleneScalar helios_point_to_selene_scalar(struct HeliosPoint helios_point);

struct HeliosScalar helios_zero_scalar();

struct SeleneScalar selene_zero_scalar();

uint8_t *selene_tree_root(struct SelenePoint selene_point);

uint8_t *helios_tree_root(struct HeliosPoint helios_point);

CResult hash_grow_helios(struct HeliosPoint existing_hash,
                                             uintptr_t offset,
                                             struct HeliosScalar existing_child_at_offset,
                                             struct HeliosScalarSlice new_children);

CResult hash_trim_helios(struct HeliosPoint existing_hash,
                                             uintptr_t offset,
                                             struct HeliosScalarSlice children,
                                             struct HeliosScalar child_to_grow_back);

CResult hash_grow_selene(struct SelenePoint existing_hash,
                                             uintptr_t offset,
                                             struct SeleneScalar existing_child_at_offset,
                                             struct SeleneScalarSlice new_children);

CResult hash_trim_selene(struct SelenePoint existing_hash,
                                             uintptr_t offset,
                                             struct SeleneScalarSlice children,
                                             struct SeleneScalar child_to_grow_back);

CResult path_new(struct OutputSlice leaves,
                                             uintptr_t output_idx,
                                             struct HeliosScalarChunks helios_layer_chunks,
                                             struct SeleneScalarChunks selene_layer_chunks);

CResult rerandomize_output(struct OutputBytes output);

uint8_t *pseudo_out(const uint8_t *rerandomized_output);
void *fcmp_input_ref(const uint8_t* rerandomized_output);

CResult o_blind(const uint8_t *rerandomized_output);
CResult i_blind(const uint8_t *rerandomized_output);
CResult i_blind_blind(const uint8_t *rerandomized_output);
CResult c_blind(const uint8_t *rerandomized_output);

CResult blind_o_blind(const uint8_t *o_blind);
CResult blind_i_blind(const uint8_t *i_blind);
CResult blind_i_blind_blind(const uint8_t *i_blind_blind);
CResult blind_c_blind(const uint8_t *c_blind);

CResult output_blinds_new(const uint8_t *o_blind,
                                             const uint8_t *i_blind,
                                             const uint8_t *i_blind_blind,
                                             const uint8_t *c_blind);

CResult helios_branch_blind();
CResult selene_branch_blind();

CResult fcmp_prove_input_new(const uint8_t *x,
                                             const uint8_t *y,
                                             const uint8_t *rerandomized_output,
                                             const uint8_t *path,
                                             const uint8_t *output_blinds,
                                             struct ObjectSlice selene_branch_blinds,
                                             struct ObjectSlice helios_branch_blinds);

CResult prove(const uint8_t *signable_tx_hash,
                                             struct ObjectSlice fcmp_prove_inputs,
                                             uintptr_t n_tree_layers);

/**
 * brief: fcmp_pp_prove_sal - Make a FCMP++ spend auth & linkability proof
 * param: signable_tx_hash - message to sign
 * param: x - ed25519 scalar s.t. O~ = x G + y T
 * param: y - ed25519 scalar s.t. O~ = x G + y T
 * param: rerandomized_output - used for input tuple, r_i, and r_r_i
 * outparam: sal_proof_out - a buffer of size FCMP_PP_SAL_PROOF_SIZE_V1 where resultant SAL proof is stored
 * return: an error on failure, nothing otherwise
 * 
 * note: This call can technically be stripped down even more because `rerandomized_output` contains
 *       more information than we need: we can discard r_o and r_c. However, in practice, these
 *       values will always be known before a call to this function since O~ and C~ are added to the
 *       challenge transcript, so passing `rerandomized_output` is more ergonomic.
 */
CResult fcmp_pp_prove_sal(const uint8_t signable_tx_hash[32],
                                             const uint8_t x[32],
                                             const uint8_t y[32],
                                             const void *rerandomized_output,
                                             uint8_t sal_proof_out[FCMP_PP_SAL_PROOF_SIZE_V1]);

uintptr_t fcmp_pp_proof_size(uintptr_t n_inputs, uintptr_t n_tree_layers);

bool verify(const uint8_t *signable_tx_hash,
                                             const uint8_t *fcmp_pp_proof,
                                             uintptr_t fcmp_pp_proof_len,
                                             uintptr_t n_tree_layers,
                                             const uint8_t *tree_root,
                                             struct ObjectSlice pseudo_outs,
                                             struct ObjectSlice key_images);
/**
 * brief: fcmp_pp_verify_sal - Verify a FCMP++ spend auth & linkability proof
 * param: signable_tx_hash - message to verify
 * param: input - (O~, I~, C~, R) tuple
 * param: L - L = x Hp(O), AKA key image
 * param: sal_proof - SAL proof to verify
 * return: true on verification success, false otherwise
 */
bool fcmp_pp_verify_sal(const uint8_t signable_tx_hash[32],
                                             const void *input,
                                             const uint8_t L[32],
                                             const uint8_t sal_proof[FCMP_PP_SAL_PROOF_SIZE_V1]);

#ifdef __cplusplus
} //extern "C"
#endif
