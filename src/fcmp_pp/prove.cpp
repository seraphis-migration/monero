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

#include <string>

#include "prove.h"

namespace fcmp_pp
{
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static uint8_t *handle_res_ptr(const std::string func, const ::CResult &res)
{
    if (res.err != nullptr)
    {
        free(res.err);
        throw std::runtime_error("failed to " + func);
    }
    return (uint8_t *) res.value;
}

uint8_t *rerandomize_output(const OutputBytes output)
{
    auto res = ::rerandomize_output(output);
    return handle_res_ptr(__func__, res);
}

crypto::ec_point pseudo_out(const uint8_t *rerandomized_output)
{
    uint8_t * res_ptr = ::pseudo_out(rerandomized_output);
    crypto::ec_point res;
    static_assert(sizeof(crypto::ec_point) == 32, "unexpected size of crypto::ec_point");
    memcpy(&res, res_ptr, sizeof(crypto::ec_point));
    free(res_ptr);
    return res;
}

uint8_t *o_blind(const uint8_t *rerandomized_output)
{
    auto result = ::o_blind(rerandomized_output);
    return handle_res_ptr(__func__, result);
}

uint8_t *i_blind(const uint8_t *rerandomized_output)
{
    auto result = ::i_blind(rerandomized_output);
    return handle_res_ptr(__func__, result);
}

uint8_t *i_blind_blind(const uint8_t *rerandomized_output)
{
    auto result = ::i_blind_blind(rerandomized_output);
    return handle_res_ptr(__func__, result);
}

uint8_t *c_blind(const uint8_t *rerandomized_output)
{
    auto result = ::c_blind(rerandomized_output);
    return handle_res_ptr(__func__, result);
}

uint8_t *blind_o_blind(const uint8_t *o_blind)
{
    auto res = ::blind_o_blind(o_blind);
    return handle_res_ptr(__func__, res);
}

uint8_t *blind_i_blind(const uint8_t *i_blind)
{
    auto res = ::blind_i_blind(i_blind);
    return handle_res_ptr(__func__, res);
}

uint8_t *blind_i_blind_blind(const uint8_t *i_blind_blind)
{
    auto res = ::blind_i_blind_blind(i_blind_blind);
    return handle_res_ptr(__func__, res);
}

uint8_t *blind_c_blind(const uint8_t *c_blind)
{
    auto res = ::blind_c_blind(c_blind);
    return handle_res_ptr(__func__, res);
}

uint8_t *path_new(const OutputChunk &leaves,
    std::size_t output_idx,
    const HeliosT::ScalarChunks &helios_layer_chunks,
    const SeleneT::ScalarChunks &selene_layer_chunks)
{
    auto res = ::path_new(leaves, output_idx, helios_layer_chunks, selene_layer_chunks);
    return handle_res_ptr(__func__, res);
}

uint8_t *output_blinds_new(const uint8_t *blinded_o_blind,
    const uint8_t *blinded_i_blind,
    const uint8_t *blinded_i_blind_blind,
    const uint8_t *blinded_c_blind)
{
    auto res = ::output_blinds_new(blinded_o_blind, blinded_i_blind, blinded_i_blind_blind, blinded_c_blind);
    return handle_res_ptr(__func__, res);
}

uint8_t *selene_branch_blind()
{
    const auto res = ::selene_branch_blind();
    return handle_res_ptr(__func__, res);
}

uint8_t *helios_branch_blind()
{
    const auto res = ::helios_branch_blind();
    return handle_res_ptr(__func__, res);
}

uint8_t *fcmp_prove_input_new(const uint8_t *x,
    const uint8_t *y,
    const uint8_t *rerandomized_output,
    const uint8_t *path,
    const uint8_t *output_blinds,
    const std::vector<const uint8_t *> &selene_branch_blinds,
    const std::vector<const uint8_t *> &helios_branch_blinds)
{
    auto res = ::fcmp_prove_input_new(x,
        y,
        rerandomized_output,
        path,
        output_blinds,
        {selene_branch_blinds.data(), selene_branch_blinds.size()},
        {helios_branch_blinds.data(), helios_branch_blinds.size()});

    return handle_res_ptr(__func__, res);
}
//----------------------------------------------------------------------------------------------------------------------
FcmpPpProof prove(const crypto::hash &signable_tx_hash,
    const std::vector<const uint8_t *> &fcmp_prove_inputs,
    const std::size_t n_tree_layers)
{
    auto res = ::prove(reinterpret_cast<const uint8_t*>(&signable_tx_hash),
        {fcmp_prove_inputs.data(), fcmp_prove_inputs.size()},
        n_tree_layers);

    if (res.err != nullptr)
    {
        free(res.err);
        throw std::runtime_error("failed to construct FCMP++ proof");
    }

    // res.value is a void * pointing to a uint8_t *, so cast as a double pointer
    uint8_t **buf = (uint8_t**) res.value;

    const std::size_t proof_size = ::fcmp_pp_proof_size(fcmp_prove_inputs.size(), n_tree_layers);
    const FcmpPpProof proof{*buf, *buf + proof_size};

    // Free both pointers
    free(*buf);
    free(res.value);

    return proof;
}
//----------------------------------------------------------------------------------------------------------------------
FcmpPpSalProof prove_sal(const crypto::hash &signable_tx_hash,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const uint8_t *rerandomized_output)
{
    FcmpPpSalProof p;
    p.resize(FCMP_PP_SAL_PROOF_SIZE_V1);

    const ::CResult res = ::fcmp_pp_prove_sal(to_bytes(signable_tx_hash),
        to_bytes(x),
        to_bytes(y),
        rerandomized_output,
        &p[0]);

    handle_res_ptr(__func__, res);

    // No `free()` since result type `()` is zero-sized

    return p;
}
//----------------------------------------------------------------------------------------------------------------------
bool verify(const crypto::hash &signable_tx_hash,
    const FcmpPpProof &fcmp_pp_proof,
    const std::size_t n_tree_layers,
    const uint8_t *tree_root,
    const std::vector<crypto::ec_point> &pseudo_outs,
    const std::vector<crypto::key_image> &key_images)
{
    std::vector<const uint8_t *> pseudo_outs_ptrs;
    pseudo_outs_ptrs.reserve(pseudo_outs.size());
    for (const auto &po : pseudo_outs)
        pseudo_outs_ptrs.emplace_back((const uint8_t *)&po);

    std::vector<const uint8_t *> key_images_ptrs;
    key_images_ptrs.reserve(key_images.size());
    for (const auto &ki : key_images)
        key_images_ptrs.emplace_back((const uint8_t *)&ki.data);

    return ::verify(
            reinterpret_cast<const uint8_t*>(&signable_tx_hash),
            fcmp_pp_proof.data(),
            fcmp_pp_proof.size(),
            n_tree_layers,
            tree_root,
            {pseudo_outs_ptrs.data(), pseudo_outs_ptrs.size()},
            {key_images_ptrs.data(), key_images_ptrs.size()}
        );
}
//----------------------------------------------------------------------------------------------------------------------
bool verify_sal(const crypto::hash &signable_tx_hash,
    const void *input,
    crypto::key_image &key_image,
    const FcmpPpSalProof &sal_proof)
{
    if (sal_proof.size() != FCMP_PP_SAL_PROOF_SIZE_V1)
        return false;

    return ::fcmp_pp_verify_sal(to_bytes(signable_tx_hash),
        input,
        to_bytes(key_image),
        sal_proof.data());
}
//----------------------------------------------------------------------------------------------------------------------
std::size_t proof_len(const std::size_t n_inputs, const uint8_t n_tree_layers)
{
    static_assert(sizeof(std::size_t) >= sizeof(uint8_t), "unexpected size of size_t");
    return ::fcmp_pp_proof_size(n_inputs, (std::size_t) n_tree_layers);
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
}//namespace fcmp_pp
