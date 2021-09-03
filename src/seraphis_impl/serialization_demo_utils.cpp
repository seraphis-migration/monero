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

//paired header
#include "serialization_demo_utils.h"

//local headers
#include "common/container_helpers.h"
#include "crypto/crypto.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/binned_reference_set.h"
#include "seraphis_core/discretized_fee.h"
#include "seraphis_crypto/bulletproofs_plus2.h"
#include "seraphis_crypto/grootle.h"
#include "seraphis_crypto/sp_composition_proof.h"
#include "seraphis_impl/serialization_demo_types.h"
#include "seraphis_main/tx_builders_inputs.h"
#include "seraphis_main/tx_component_types.h"
#include "seraphis_main/tx_component_types_legacy.h"
#include "seraphis_main/txtype_coinbase_v1.h"
#include "seraphis_main/txtype_squashed_v1.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_impl"

namespace sp
{
namespace serialization
{
//-------------------------------------------------------------------------------------------------------------------
// array2 copies array1 by invoking copy_func() on each element
//-------------------------------------------------------------------------------------------------------------------
template <typename CopyFuncT, typename Type1, typename Type2>
static void copy_array(const CopyFuncT &copy_func, const std::vector<Type1> &array1, std::vector<Type2> &array2_out)
{
    array2_out.clear();
    array2_out.reserve(array1.size());
    for (const Type1 &obj : array1)
        copy_func(obj, tools::add_element(array2_out));
}
//-------------------------------------------------------------------------------------------------------------------
// array2 consumes array1 by invoking relay_func() on each element
//-------------------------------------------------------------------------------------------------------------------
template <typename RelayFuncT, typename Type1, typename Type2>
static void relay_array(const RelayFuncT &relay_func, std::vector<Type1> &array1_in, std::vector<Type2> &array2_out)
{
    array2_out.clear();
    array2_out.reserve(array1_in.size());
    for (Type1 &obj_in : array1_in)
        relay_func(obj_in, tools::add_element(array2_out));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void collect_sp_balance_proof_commitments_v1(const std::vector<SpEnoteImageV1> &seraphis_input_images,
    const std::vector<SpEnoteV1> &output_enotes,
    std::vector<rct::key> &commitments_out)
{
    commitments_out.clear();
    commitments_out.reserve(seraphis_input_images.size() + output_enotes.size());

    for (const SpEnoteImageV1 &input_image : seraphis_input_images)
        commitments_out.emplace_back(rct::scalarmultKey(masked_commitment_ref(input_image), rct::INV_EIGHT));

    for (const SpEnoteV1 &output_enote : output_enotes)
        commitments_out.emplace_back(rct::scalarmultKey(output_enote.core.amount_commitment, rct::INV_EIGHT));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void indices_to_offsets(std::vector<std::uint64_t> &indices_inout)
{
    if (indices_inout.size() == 0)
        return;

    for (std::size_t i{indices_inout.size() - 1}; i != 0; --i)
        indices_inout[i] -= indices_inout[i - 1];
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void indices_from_offsets(std::vector<std::uint64_t> &indices_inout)
{
    for (std::size_t i{1}; i < indices_inout.size(); ++i)
        indices_inout[i] += indices_inout[i - 1];
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void recover_legacy_ring_signatures_v4(
    std::vector<ser_LegacyRingSignatureV4_PARTIAL> &serializable_legacy_ring_signatures_in,
    const std::vector<LegacyEnoteImageV2> &legacy_enote_images,
    std::vector<LegacyRingSignatureV4> &legacy_ring_signatures_out)
{
    CHECK_AND_ASSERT_THROW_MES(legacy_enote_images.size() == serializable_legacy_ring_signatures_in.size(),
        "recovering legacy ring signature v4s: legacy input images don't line up with legacy ring signatures.");

    legacy_ring_signatures_out.clear();
    legacy_ring_signatures_out.reserve(serializable_legacy_ring_signatures_in.size());

    for (std::size_t legacy_input_index{0}; legacy_input_index < legacy_enote_images.size(); ++legacy_input_index)
    {
        recover_legacy_ring_signature_v4(serializable_legacy_ring_signatures_in[legacy_input_index],
            legacy_enote_images[legacy_input_index].key_image,
            tools::add_element(legacy_ring_signatures_out));
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void recover_sp_membership_proofs_v1(
    std::vector<ser_SpMembershipProofV1_PARTIAL> &serializable_membership_proofs_in,
    const std::vector<SpEnoteImageV1> &enote_images,
    const SpBinnedReferenceSetConfigV1 &sp_refset_bin_config,
    const std::size_t sp_ref_set_decomp_n,
    const std::size_t sp_ref_set_decomp_m,
    std::vector<SpMembershipProofV1> &membership_proofs_out)
{
    CHECK_AND_ASSERT_THROW_MES(enote_images.size() == serializable_membership_proofs_in.size(),
        "recovering seraphis membership proof v1s: seraphis input images don't line up with seraphis membership proofs.");

    membership_proofs_out.clear();
    membership_proofs_out.reserve(serializable_membership_proofs_in.size());
    rct::key generator_seed_temp;

    for (std::size_t sp_input_index{0}; sp_input_index < enote_images.size(); ++sp_input_index)
    {
        make_binned_ref_set_generator_seed_v1(masked_address_ref(enote_images[sp_input_index]),
            masked_commitment_ref(enote_images[sp_input_index]),
            generator_seed_temp);

        recover_sp_membership_proof_v1(serializable_membership_proofs_in[sp_input_index],
            sp_refset_bin_config,
            generator_seed_temp,
            sp_ref_set_decomp_n,
            sp_ref_set_decomp_m,
            tools::add_element(membership_proofs_out));
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_serializable_legacy_ring_signatures_v4(const std::vector<LegacyRingSignatureV4> &legacy_ring_signatures,
    std::vector<ser_LegacyRingSignatureV4_PARTIAL> &serializable_legacy_ring_signatures_out)
{
    serializable_legacy_ring_signatures_out.clear();
    serializable_legacy_ring_signatures_out.reserve(legacy_ring_signatures.size());

    for (const LegacyRingSignatureV4 &legacy_ring_signature : legacy_ring_signatures)
    {
        make_serializable_legacy_ring_signature_v4(legacy_ring_signature,
            tools::add_element(serializable_legacy_ring_signatures_out));
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_serializable_sp_membership_proofs_v1(const std::vector<SpMembershipProofV1> &membership_proofs,
    std::vector<ser_SpMembershipProofV1_PARTIAL> &serializable_membership_proofs_out)
{
    serializable_membership_proofs_out.clear();
    serializable_membership_proofs_out.reserve(membership_proofs.size());

    for (const SpMembershipProofV1 &membership_proof : membership_proofs)
    {
        make_serializable_sp_membership_proof_v1(membership_proof,
            tools::add_element(serializable_membership_proofs_out));
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void make_serializable_bpp2(const BulletproofPlus2 &bpp2, ser_BulletproofPlus2_PARTIAL &serializable_bpp2_out)
{
    serializable_bpp2_out.A  = bpp2.A;
    serializable_bpp2_out.A1 = bpp2.A1;
    serializable_bpp2_out.B  = bpp2.B;
    serializable_bpp2_out.r1 = bpp2.r1;
    serializable_bpp2_out.s1 = bpp2.s1;
    serializable_bpp2_out.d1 = bpp2.d1;
    serializable_bpp2_out.L  = bpp2.L;
    serializable_bpp2_out.R  = bpp2.R;
}
//-------------------------------------------------------------------------------------------------------------------
void make_serializable_clsag(const rct::clsag &clsag, ser_clsag_PARTIAL &serializable_clsag_out)
{
    serializable_clsag_out.s  = clsag.s;
    serializable_clsag_out.c1 = clsag.c1;
    serializable_clsag_out.D  = clsag.D;
}
//-------------------------------------------------------------------------------------------------------------------
void make_serializable_grootle_proof(const GrootleProof &grootle, ser_GrootleProof &serializable_grootle_out)
{
    serializable_grootle_out.A  = grootle.A;
    serializable_grootle_out.B  = grootle.B;
    serializable_grootle_out.f  = grootle.f;
    serializable_grootle_out.X  = grootle.X;
    serializable_grootle_out.zA = grootle.zA;
    serializable_grootle_out.z  = grootle.z;
}
//-------------------------------------------------------------------------------------------------------------------
void make_serializable_sp_composition_proof(const SpCompositionProof &proof,
    ser_SpCompositionProof &serializable_proof_out)
{
    serializable_proof_out.c    = proof.c;
    serializable_proof_out.r_t1 = proof.r_t1;
    serializable_proof_out.r_t2 = proof.r_t2;
    serializable_proof_out.r_ki = proof.r_ki;
    serializable_proof_out.K_t1 = proof.K_t1;
}
//-------------------------------------------------------------------------------------------------------------------
void make_serializable_sp_coinbase_enote_core(const SpCoinbaseEnoteCore &enote,
    ser_SpCoinbaseEnoteCore &serializable_enote_out)
{
    serializable_enote_out.onetime_address = enote.onetime_address;
    serializable_enote_out.amount          = enote.amount;
}
//-------------------------------------------------------------------------------------------------------------------
void make_serializable_sp_enote_core(const SpEnoteCore &enote, ser_SpEnoteCore &serializable_enote_out)
{
    serializable_enote_out.onetime_address   = enote.onetime_address;
    serializable_enote_out.amount_commitment = enote.amount_commitment;
}
//-------------------------------------------------------------------------------------------------------------------
void make_serializable_sp_enote_image_core(const SpEnoteImageCore &image, ser_SpEnoteImageCore &serializable_image_out)
{
    serializable_image_out.masked_address    = image.masked_address;
    serializable_image_out.masked_commitment = image.masked_commitment;
    serializable_image_out.key_image         = image.key_image;
}
//-------------------------------------------------------------------------------------------------------------------
void make_serializable_sp_binned_reference_set_v1(const SpBinnedReferenceSetV1 &refset,
    ser_SpBinnedReferenceSetV1_PARTIAL &serializable_refset_out)
{
    serializable_refset_out.bin_rotation_factor = refset.bin_rotation_factor;
    serializable_refset_out.bin_loci_COMPACT    = refset.bin_loci;
    indices_to_offsets(serializable_refset_out.bin_loci_COMPACT);
}
//-------------------------------------------------------------------------------------------------------------------
void make_serializable_legacy_enote_image_v2(const LegacyEnoteImageV2 &image,
    ser_LegacyEnoteImageV2 &serializable_image_out)
{
    serializable_image_out.masked_commitment = image.masked_commitment;
    serializable_image_out.key_image         = image.key_image;
}
//-------------------------------------------------------------------------------------------------------------------
void make_serializable_sp_coinbase_enote_v1(const SpCoinbaseEnoteV1 &enote, ser_SpCoinbaseEnoteV1 &serializable_enote_out)
{
    make_serializable_sp_coinbase_enote_core(enote.core, serializable_enote_out.core);
    memcpy(serializable_enote_out.addr_tag_enc.bytes,
        enote.addr_tag_enc.bytes,
        sizeof(enote.addr_tag_enc));
    serializable_enote_out.view_tag = enote.view_tag;
}
//-------------------------------------------------------------------------------------------------------------------
void make_serializable_sp_enote_v1(const SpEnoteV1 &enote, ser_SpEnoteV1 &serializable_enote_out)
{
    make_serializable_sp_enote_core(enote.core, serializable_enote_out.core);
    memcpy(serializable_enote_out.encoded_amount.bytes,
        enote.encoded_amount.bytes,
        sizeof(enote.encoded_amount));
    memcpy(serializable_enote_out.addr_tag_enc.bytes,
        enote.addr_tag_enc.bytes,
        sizeof(enote.addr_tag_enc));
    serializable_enote_out.view_tag = enote.view_tag;
}
//-------------------------------------------------------------------------------------------------------------------
void make_serializable_sp_enote_image_v1(const SpEnoteImageV1 &image, ser_SpEnoteImageV1 &serializable_image_out)
{
    make_serializable_sp_enote_image_core(image.core, serializable_image_out.core);
}
//-------------------------------------------------------------------------------------------------------------------
void make_serializable_sp_balance_proof_v1(const SpBalanceProofV1 &proof,
    ser_SpBalanceProofV1_PARTIAL &serializable_proof_out)
{
    make_serializable_bpp2(proof.bpp2_proof, serializable_proof_out.bpp2_proof_PARTIAL);
    serializable_proof_out.remainder_blinding_factor = proof.remainder_blinding_factor;
}
//-------------------------------------------------------------------------------------------------------------------
void make_serializable_legacy_ring_signature_v4(const LegacyRingSignatureV4 &signature,
    ser_LegacyRingSignatureV4_PARTIAL &serializable_signature_out)
{
    make_serializable_clsag(signature.clsag_proof, serializable_signature_out.clsag_proof_PARTIAL);
    serializable_signature_out.reference_set_COMPACT = signature.reference_set;
    indices_to_offsets(serializable_signature_out.reference_set_COMPACT);
}
//-------------------------------------------------------------------------------------------------------------------
void make_serializable_sp_membership_proof_v1(const SpMembershipProofV1 &proof,
    ser_SpMembershipProofV1_PARTIAL &serializable_proof_out)
{
    make_serializable_grootle_proof(proof.grootle_proof, serializable_proof_out.grootle_proof);
    make_serializable_sp_binned_reference_set_v1(proof.binned_reference_set,
        serializable_proof_out.binned_reference_set_PARTIAL);
}
//-------------------------------------------------------------------------------------------------------------------
void make_serializable_sp_image_proof_v1(const SpImageProofV1 &image_proof,
    ser_SpImageProofV1 &serializable_image_proof_out)
{
    make_serializable_sp_composition_proof(image_proof.composition_proof,
        serializable_image_proof_out.composition_proof);
}
//-------------------------------------------------------------------------------------------------------------------
void make_serializable_sp_tx_supplement_v1(const SpTxSupplementV1 &supplement,
    ser_SpTxSupplementV1 &serializable_supplement_out)
{
    serializable_supplement_out.output_enote_ephemeral_pubkeys = supplement.output_enote_ephemeral_pubkeys;
    serializable_supplement_out.tx_extra                       = supplement.tx_extra;
}
//-------------------------------------------------------------------------------------------------------------------
void make_serializable_discretized_fee(const DiscretizedFee discretized_fee,
    unsigned char &serializable_discretized_fee_out)
{
    serializable_discretized_fee_out = discretized_fee.fee_encoding;
}
//-------------------------------------------------------------------------------------------------------------------
void make_serializable_sp_tx_coinbase_v1(const SpTxCoinbaseV1 &tx, ser_SpTxCoinbaseV1 &serializable_tx_out)
{
    // semantic rules version
    serializable_tx_out.tx_semantic_rules_version = tx.tx_semantic_rules_version;

    // block height
    serializable_tx_out.block_height = tx.block_height;

    // block reward
    serializable_tx_out.block_reward = tx.block_reward;

    // tx outputs (new enotes)
    copy_array(&make_serializable_sp_coinbase_enote_v1, tx.outputs, serializable_tx_out.outputs);

    // supplemental data for tx
    make_serializable_sp_tx_supplement_v1(tx.tx_supplement, serializable_tx_out.tx_supplement);
}
//-------------------------------------------------------------------------------------------------------------------
void make_serializable_sp_tx_squashed_v1(const SpTxSquashedV1 &tx, ser_SpTxSquashedV1 &serializable_tx_out)
{
    // semantic rules version
    serializable_tx_out.tx_semantic_rules_version = tx.tx_semantic_rules_version;

    // legacy tx input images (spent legacy enotes)
    copy_array(&make_serializable_legacy_enote_image_v2, tx.legacy_input_images,
        serializable_tx_out.legacy_input_images);

    // seraphis tx input images (spent seraphis enotes)
    copy_array(&make_serializable_sp_enote_image_v1, tx.sp_input_images, serializable_tx_out.sp_input_images);

    // tx outputs (new enotes)
    copy_array(&make_serializable_sp_enote_v1, tx.outputs, serializable_tx_out.outputs);

    // balance proof (balance proof and range proofs)
    make_serializable_sp_balance_proof_v1(tx.balance_proof, serializable_tx_out.balance_proof);

    // ring signature proofs: membership and ownership/key-image-legitimacy for each legacy input
    make_serializable_legacy_ring_signatures_v4(tx.legacy_ring_signatures,
        serializable_tx_out.legacy_ring_signatures);

    // composition proofs: ownership/key-image-legitimacy for each seraphis input
    copy_array(&make_serializable_sp_image_proof_v1, tx.sp_image_proofs, serializable_tx_out.sp_image_proofs);

    // Grootle proofs on squashed enotes: membership for each seraphis input
    make_serializable_sp_membership_proofs_v1(tx.sp_membership_proofs, serializable_tx_out.sp_membership_proofs);

    // supplemental data for tx
    make_serializable_sp_tx_supplement_v1(tx.tx_supplement, serializable_tx_out.tx_supplement);

    // the transaction fee (discretized representation)
    make_serializable_discretized_fee(tx.tx_fee, serializable_tx_out.tx_fee);
}
//-------------------------------------------------------------------------------------------------------------------

//-------------------------------------------------------------------------------------------------------------------
void recover_bpp2(ser_BulletproofPlus2_PARTIAL &serializable_bpp2_in,
    std::vector<rct::key> balance_proof_commitments_mulinv8,
    BulletproofPlus2 &bpp2_out)
{
    bpp2_out.V  = std::move(balance_proof_commitments_mulinv8);
    bpp2_out.A  = serializable_bpp2_in.A;
    bpp2_out.A1 = serializable_bpp2_in.A1;
    bpp2_out.B  = serializable_bpp2_in.B;
    bpp2_out.r1 = serializable_bpp2_in.r1;
    bpp2_out.s1 = serializable_bpp2_in.s1;
    bpp2_out.d1 = serializable_bpp2_in.d1;
    bpp2_out.L  = std::move(serializable_bpp2_in.L);
    bpp2_out.R  = std::move(serializable_bpp2_in.R);
}
//-------------------------------------------------------------------------------------------------------------------
void recover_clsag(ser_clsag_PARTIAL &serializable_clsag_in, const crypto::key_image &key_image, rct::clsag &clsag_out)
{
    clsag_out.s  = std::move(serializable_clsag_in.s);
    clsag_out.c1 = serializable_clsag_in.c1;
    clsag_out.I  = rct::ki2rct(key_image);
    clsag_out.D  = serializable_clsag_in.D;
}
//-------------------------------------------------------------------------------------------------------------------
void recover_grootle_proof(ser_GrootleProof &serializable_grootle_in, GrootleProof &grootle_out)
{
    grootle_out.A  = serializable_grootle_in.A;
    grootle_out.B  = serializable_grootle_in.B;
    grootle_out.f  = std::move(serializable_grootle_in.f);
    grootle_out.X  = std::move(serializable_grootle_in.X);
    grootle_out.zA = serializable_grootle_in.zA;
    grootle_out.z  = serializable_grootle_in.z;
}
//-------------------------------------------------------------------------------------------------------------------
void recover_sp_composition_proof(const ser_SpCompositionProof &serializable_proof, SpCompositionProof &proof_out)
{
    proof_out.c    = serializable_proof.c;
    proof_out.r_t1 = serializable_proof.r_t1;
    proof_out.r_t2 = serializable_proof.r_t2;
    proof_out.r_ki = serializable_proof.r_ki;
    proof_out.K_t1 = serializable_proof.K_t1;
}
//-------------------------------------------------------------------------------------------------------------------
void recover_sp_coinbase_enote_core(const ser_SpCoinbaseEnoteCore &serializable_enote, SpCoinbaseEnoteCore &enote_out)
{
    enote_out.onetime_address = serializable_enote.onetime_address;
    enote_out.amount          = serializable_enote.amount;
}
//-------------------------------------------------------------------------------------------------------------------
void recover_sp_enote_core(const ser_SpEnoteCore &serializable_enote, SpEnoteCore &enote_out)
{
    enote_out.onetime_address   = serializable_enote.onetime_address;
    enote_out.amount_commitment = serializable_enote.amount_commitment;
}
//-------------------------------------------------------------------------------------------------------------------
void recover_sp_enote_image_core(const ser_SpEnoteImageCore &serializable_image, SpEnoteImageCore &image_out)
{
    image_out.masked_address    = serializable_image.masked_address;
    image_out.masked_commitment = serializable_image.masked_commitment;
    image_out.key_image         = serializable_image.key_image;
}
//-------------------------------------------------------------------------------------------------------------------
void recover_sp_binned_reference_set_v1(ser_SpBinnedReferenceSetV1_PARTIAL &serializable_refset_in,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    const rct::key &generator_seed,
    SpBinnedReferenceSetV1 &refset_out)
{
    // bin configuration details
    refset_out.bin_config = bin_config;

    // bin generator seed
    refset_out.bin_generator_seed = generator_seed;

    // rotation factor
    refset_out.bin_rotation_factor = serializable_refset_in.bin_rotation_factor;

    // bin loci
    refset_out.bin_loci = std::move(serializable_refset_in.bin_loci_COMPACT);
    indices_from_offsets(refset_out.bin_loci);
}
//-------------------------------------------------------------------------------------------------------------------
void recover_legacy_enote_image_v2(const ser_LegacyEnoteImageV2 &serializable_image, LegacyEnoteImageV2 &image_out)
{
    image_out.masked_commitment = serializable_image.masked_commitment;
    image_out.key_image         = serializable_image.key_image;
}
//-------------------------------------------------------------------------------------------------------------------
void recover_sp_coinbase_enote_v1(const ser_SpCoinbaseEnoteV1 &serializable_enote, SpCoinbaseEnoteV1 &enote_out)
{
    recover_sp_coinbase_enote_core(serializable_enote.core, enote_out.core);
    memcpy(enote_out.addr_tag_enc.bytes,
        serializable_enote.addr_tag_enc.bytes,
        sizeof(serializable_enote.addr_tag_enc));
    enote_out.view_tag = serializable_enote.view_tag;
}
//-------------------------------------------------------------------------------------------------------------------
void recover_sp_enote_v1(const ser_SpEnoteV1 &serializable_enote, SpEnoteV1 &enote_out)
{
    recover_sp_enote_core(serializable_enote.core, enote_out.core);
    memcpy(enote_out.encoded_amount.bytes,
        serializable_enote.encoded_amount.bytes,
        sizeof(serializable_enote.encoded_amount));
    memcpy(enote_out.addr_tag_enc.bytes,
        serializable_enote.addr_tag_enc.bytes,
        sizeof(serializable_enote.addr_tag_enc));
    enote_out.view_tag = serializable_enote.view_tag;
}
//-------------------------------------------------------------------------------------------------------------------
void recover_sp_enote_image_v1(const ser_SpEnoteImageV1 &serializable_image, SpEnoteImageV1 &image_out)
{
    recover_sp_enote_image_core(serializable_image.core, image_out.core);
}
//-------------------------------------------------------------------------------------------------------------------
void recover_sp_balance_proof_v1(ser_SpBalanceProofV1_PARTIAL &serializable_proof_in,
    std::vector<rct::key> commitments_inv8,
    SpBalanceProofV1 &proof_out)
{
    // bpp2
    recover_bpp2(serializable_proof_in.bpp2_proof_PARTIAL, std::move(commitments_inv8), proof_out.bpp2_proof);

    // remainder blinding factor
    proof_out.remainder_blinding_factor = serializable_proof_in.remainder_blinding_factor;
}
//-------------------------------------------------------------------------------------------------------------------
void recover_legacy_ring_signature_v4(ser_LegacyRingSignatureV4_PARTIAL &serializable_signature_in,
    const crypto::key_image &key_image,
    LegacyRingSignatureV4 &signature_out)
{
    // clsag
    recover_clsag(serializable_signature_in.clsag_proof_PARTIAL, key_image, signature_out.clsag_proof);

    // reference set
    signature_out.reference_set = std::move(serializable_signature_in.reference_set_COMPACT);
    indices_from_offsets(signature_out.reference_set);
}
//-------------------------------------------------------------------------------------------------------------------
void recover_sp_membership_proof_v1(ser_SpMembershipProofV1_PARTIAL &serializable_proof_in,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    const rct::key &generator_seed,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    SpMembershipProofV1 &proof_out)
{
    // grootle proof
    recover_grootle_proof(serializable_proof_in.grootle_proof, proof_out.grootle_proof);

    // binned reference set
    recover_sp_binned_reference_set_v1(serializable_proof_in.binned_reference_set_PARTIAL,
        bin_config,
        generator_seed,
        proof_out.binned_reference_set);

    // ref set size decomposition
    proof_out.ref_set_decomp_n = ref_set_decomp_n;
    proof_out.ref_set_decomp_m = ref_set_decomp_m;
}
//-------------------------------------------------------------------------------------------------------------------
void recover_sp_image_proof_v1(const ser_SpImageProofV1 &serializable_image_proof, SpImageProofV1 &image_proof_out)
{
    recover_sp_composition_proof(serializable_image_proof.composition_proof, image_proof_out.composition_proof);
}
//-------------------------------------------------------------------------------------------------------------------
void recover_sp_tx_supplement_v1(ser_SpTxSupplementV1 &serializable_supplement_in, SpTxSupplementV1 &supplement_out)
{
    supplement_out.output_enote_ephemeral_pubkeys =
        std::move(serializable_supplement_in.output_enote_ephemeral_pubkeys);
    supplement_out.tx_extra = std::move(serializable_supplement_in.tx_extra);
}
//-------------------------------------------------------------------------------------------------------------------
void recover_discretized_fee(const unsigned char serializable_discretized_fee, DiscretizedFee &discretized_fee_out)
{
    discretized_fee_out.fee_encoding = serializable_discretized_fee;
}
//-------------------------------------------------------------------------------------------------------------------
void recover_sp_tx_coinbase_v1(ser_SpTxCoinbaseV1 &serializable_tx_in, SpTxCoinbaseV1 &tx_out)
{
    // semantic rules version
    tx_out.tx_semantic_rules_version = serializable_tx_in.tx_semantic_rules_version;

    // block height
    tx_out.block_height = serializable_tx_in.block_height;

    // block reward
    tx_out.block_reward = serializable_tx_in.block_reward;

    // tx outputs (new enotes)
    relay_array(&recover_sp_coinbase_enote_v1, serializable_tx_in.outputs, tx_out.outputs);

    // supplemental data for tx
    recover_sp_tx_supplement_v1(serializable_tx_in.tx_supplement, tx_out.tx_supplement);
}
//-------------------------------------------------------------------------------------------------------------------
void recover_sp_tx_squashed_v1(ser_SpTxSquashedV1 &serializable_tx_in,
    const SpBinnedReferenceSetConfigV1 &sp_refset_bin_config,
    const std::size_t sp_ref_set_decomp_n,
    const std::size_t sp_ref_set_decomp_m,
    SpTxSquashedV1 &tx_out)
{
    // semantic rules version
    tx_out.tx_semantic_rules_version = serializable_tx_in.tx_semantic_rules_version;

    // legacy tx input images (spent legacy enotes)
    relay_array(&recover_legacy_enote_image_v2, serializable_tx_in.legacy_input_images, tx_out.legacy_input_images);

    // seraphis tx input images (spent seraphis enotes)
    relay_array(&recover_sp_enote_image_v1, serializable_tx_in.sp_input_images, tx_out.sp_input_images);

    // tx outputs (new enotes)
    relay_array(&recover_sp_enote_v1, serializable_tx_in.outputs, tx_out.outputs);

    // balance proof (balance proof and range proofs)
    std::vector<rct::key> balance_proof_commitments_mulinv8;
    collect_sp_balance_proof_commitments_v1(tx_out.sp_input_images,
        tx_out.outputs,
        balance_proof_commitments_mulinv8);
    recover_sp_balance_proof_v1(serializable_tx_in.balance_proof,
        std::move(balance_proof_commitments_mulinv8),
        tx_out.balance_proof);

    // ring signature proofs: membership and ownership/key-image-legitimacy for each legacy input
    recover_legacy_ring_signatures_v4(serializable_tx_in.legacy_ring_signatures,
        tx_out.legacy_input_images,
        tx_out.legacy_ring_signatures);

    // composition proofs: ownership/key-image-legitimacy for each seraphis input
    relay_array(&recover_sp_image_proof_v1, serializable_tx_in.sp_image_proofs, tx_out.sp_image_proofs);

    // Grootle proofs on squashed enotes: membership for each seraphis input
    recover_sp_membership_proofs_v1(serializable_tx_in.sp_membership_proofs,
        tx_out.sp_input_images,
        sp_refset_bin_config,
        sp_ref_set_decomp_n,
        sp_ref_set_decomp_m,
        tx_out.sp_membership_proofs);

    // supplemental data for tx
    recover_sp_tx_supplement_v1(serializable_tx_in.tx_supplement, tx_out.tx_supplement);

    // the transaction fee (discretized representation)
    recover_discretized_fee(serializable_tx_in.tx_fee, tx_out.tx_fee);
}
//-------------------------------------------------------------------------------------------------------------------
void recover_sp_tx_squashed_v1(ser_SpTxSquashedV1 &serializable_tx_in, SpTxSquashedV1 &tx_out)
{
    // get config for seraphis reference sets (assume the minimum values are needed; use raw API for other variations)
    const SemanticConfigSpRefSetV1 seraphis_ref_set_config{
            semantic_config_sp_ref_sets_v1(serializable_tx_in.tx_semantic_rules_version)
        };

    // finish recovering
    recover_sp_tx_squashed_v1(serializable_tx_in,
        SpBinnedReferenceSetConfigV1{
            .bin_radius = static_cast<ref_set_bin_dimension_v1_t>(seraphis_ref_set_config.bin_radius_min),
            .num_bin_members = static_cast<ref_set_bin_dimension_v1_t>(seraphis_ref_set_config.num_bin_members_min)
        },
        seraphis_ref_set_config.decomp_n_min,
        seraphis_ref_set_config.decomp_m_min,
        tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_recover_sp_tx_squashed_v1(ser_SpTxSquashedV1 &serializable_tx_in,
    const SpBinnedReferenceSetConfigV1 &sp_refset_bin_config,
    const std::size_t sp_ref_set_decomp_n,
    const std::size_t sp_ref_set_decomp_m,
    SpTxSquashedV1 &tx_out)
{
    try
    {
        recover_sp_tx_squashed_v1(serializable_tx_in,
            sp_refset_bin_config,
            sp_ref_set_decomp_n,
            sp_ref_set_decomp_m,
            tx_out);
    }
    catch (...) { return false; }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_recover_sp_tx_squashed_v1(ser_SpTxSquashedV1 &serializable_tx_in, SpTxSquashedV1 &tx_out)
{
    try
    {
        recover_sp_tx_squashed_v1(serializable_tx_in, tx_out);
    }
    catch (...) { return false; }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace serialization
} //namespace sp
