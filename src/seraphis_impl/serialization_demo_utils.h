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

// Serialization utilities for serializable seraphis types (a demonstration).
// WARNING: All of the deserialization functions are **destructive**, meaning the ser_ objects passed in will
//          often be left in an invalid state after a function call. Note that the serialization functions
//          are copy-only.

#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/binned_reference_set.h"
#include "seraphis_core/discretized_fee.h"
#include "seraphis_core/sp_core_types.h"
#include "seraphis_impl/serialization_demo_types.h"
#include "seraphis_main/tx_component_types.h"
#include "seraphis_main/tx_component_types_legacy.h"
#include "seraphis_main/txtype_squashed_v1.h"
#include "serialization/binary_archive.h"
#include "serialization/serialization.h"
#include "span.h"

//third party headers

//standard headers
#include <sstream>
#include <vector>

//forward declarations
namespace sp
{
    struct BulletproofPlus2;
    struct GrootleProof;
    struct SpCompositionProof;
}

namespace sp
{
namespace serialization
{

/**
* brief: try_append_serializable - try to serialize an object and append it to an input string
* type: SerializableT - type of the object to be serialized (the object must support serialization/deserialization)
* param: serializable -
* inoutparam: serialized_inout -
* return: true if serialization succeeded
*/
template <typename SerializableT>
bool try_append_serializable(SerializableT &serializable, std::string &serialized_inout)
{
    // serialize
    std::stringstream serializable_ss;
    binary_archive<true> b_archive(serializable_ss);
    if (!::serialization::serialize(b_archive, serializable))
        return false;

    // save to string
    serialized_inout.append(serializable_ss.str());

    return true;
}
/**
* brief: try_get_serializable - try to deserialize a string into an object
* type: SerializableT - type of the object to be deserialized into (the object must support serialization/deserialization)
* param: serialized -
* outparam: serializable_out -
* return: true if deserialization succeeded
*/
template <typename SerializableT>
bool try_get_serializable(epee::span<const std::uint8_t> serialized, SerializableT &serializable_out)
{
    // recover serializable
    binary_archive<false> archived{serialized};
    return ::serialization::serialize(archived, serializable_out);
}
/**
* brief: make_serializable_* - convert a normal object into one that is serializable
* param: object - normal object
* outparam: serializable_object_out - object to map the normal object into; this should be serializable/deserializable
*/
void make_serializable_bpp2(const BulletproofPlus2 &bpp2, ser_BulletproofPlus2_PARTIAL &serializable_bpp2_out);
void make_serializable_clsag(const rct::clsag &clsag, ser_clsag_PARTIAL &serializable_clsag_out);
void make_serializable_grootle_proof(const GrootleProof &grootle, ser_GrootleProof &serializable_grootle_out);
void make_serializable_sp_composition_proof(const SpCompositionProof &proof,
    ser_SpCompositionProof &serializable_proof_out);
void make_serializable_sp_coinbase_enote_core(const SpCoinbaseEnoteCore &enote,
    ser_SpCoinbaseEnoteCore &serializable_enote_out);
void make_serializable_sp_enote_core(const SpEnoteCore &enote, ser_SpEnoteCore &serializable_enote_out);
void make_serializable_sp_enote_image_core(const SpEnoteImageCore &image, ser_SpEnoteImageCore &serializable_image_out);
void make_serializable_sp_binned_reference_set_v1(const SpBinnedReferenceSetV1 &refset,
    ser_SpBinnedReferenceSetV1_PARTIAL &serializable_refset_out);
void make_serializable_legacy_enote_image_v2(const LegacyEnoteImageV2 &image,
    ser_LegacyEnoteImageV2 &serializable_image_out);
void make_serializable_sp_enote_v1(const SpEnoteV1 &enote, ser_SpEnoteV1 &serializable_enote_out);
void make_serializable_sp_enote_image_v1(const SpEnoteImageV1 &image, ser_SpEnoteImageV1 &serializable_image_out);
void make_serializable_sp_balance_proof_v1(const SpBalanceProofV1 &proof,
    ser_SpBalanceProofV1_PARTIAL &serializable_proof_out);
void make_serializable_legacy_ring_signature_v4(const LegacyRingSignatureV4 &signature,
    ser_LegacyRingSignatureV4_PARTIAL &serializable_signature_out);
void make_serializable_sp_membership_proof_v1(const SpMembershipProofV1 &proof,
    ser_SpMembershipProofV1_PARTIAL &serializable_proof_out);
void make_serializable_sp_image_proof_v1(const SpImageProofV1 &image_proof,
    ser_SpImageProofV1 &serializable_image_proof_out);
void make_serializable_sp_tx_supplement_v1(const SpTxSupplementV1 &supplement,
    ser_SpTxSupplementV1 &serializable_supplement_out);
void make_serializable_discretized_fee(const DiscretizedFee discretized_fee,
    unsigned char &serializable_discretized_fee_out);
void make_serializable_sp_tx_coinbase_v1(const SpTxCoinbaseV1 &tx, ser_SpTxCoinbaseV1 &serializable_tx_out);
void make_serializable_sp_tx_squashed_v1(const SpTxSquashedV1 &tx, ser_SpTxSquashedV1 &serializable_tx_out);
/**
* brief: recover_* - convert a serializable object back into its normal object parent
* param: serializable_object_in - serializable object to be consumed (destructive: may be left in an unusable state)
* param: ...params... - additional data not recorded in the serializable object to paste into the normal object
* outparam: object_out - object to map the serializable object and extra params into
*/
void recover_bpp2(ser_BulletproofPlus2_PARTIAL &serializable_bpp2_in,
    std::vector<rct::key> balance_proof_commitments_mulinv8,
    BulletproofPlus2 &bpp2_out);
void recover_clsag(ser_clsag_PARTIAL &serializable_clsag_in, const crypto::key_image &key_image, rct::clsag &clsag_out);
void recover_grootle_proof(ser_GrootleProof &serializable_grootle_in, GrootleProof &grootle_out);
void recover_sp_composition_proof(const ser_SpCompositionProof &serializable_proof, SpCompositionProof &proof_out);
void recover_sp_coinbase_enote_core(const ser_SpCoinbaseEnoteCore &serializable_enote, SpCoinbaseEnoteCore &enote_out);
void recover_sp_enote_core(const ser_SpEnoteCore &serializable_enote, SpEnoteCore &enote_out);
void recover_sp_enote_image_core(const ser_SpEnoteImageCore &serializable_image, SpEnoteImageCore &image_out);
void recover_sp_binned_reference_set_v1(ser_SpBinnedReferenceSetV1_PARTIAL &serializable_refset_in,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    const rct::key &generator_seed,
    SpBinnedReferenceSetV1 &refset_out);
void recover_legacy_enote_image_v2(const ser_LegacyEnoteImageV2 &serializable_image, LegacyEnoteImageV2 &image_out);
void recover_sp_coinbase_enote_v1(const ser_SpCoinbaseEnoteV1 &serializable_enote, SpCoinbaseEnoteV1 &enote_out);
void recover_sp_enote_v1(const ser_SpEnoteV1 &serializable_enote, SpEnoteV1 &enote_out);
void recover_sp_enote_image_v1(const ser_SpEnoteImageV1 &serializable_image, SpEnoteImageV1 &image_out);
void recover_sp_balance_proof_v1(ser_SpBalanceProofV1_PARTIAL &serializable_proof_in,
    std::vector<rct::key> commitments_inv8,
    SpBalanceProofV1 &proof_out);
void recover_legacy_ring_signature_v4(ser_LegacyRingSignatureV4_PARTIAL &serializable_signature_in,
    const crypto::key_image &key_image,
    LegacyRingSignatureV4 &signature_out);
void recover_sp_membership_proof_v1(ser_SpMembershipProofV1_PARTIAL &serializable_proof_in,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    const rct::key &generator_seed,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    SpMembershipProofV1 &proof_out);
void recover_sp_image_proof_v1(const ser_SpImageProofV1 &serializable_image_proof, SpImageProofV1 &image_proof_out);
void recover_sp_tx_supplement_v1(ser_SpTxSupplementV1 &serializable_supplement_in, SpTxSupplementV1 &supplement_out);
void recover_discretized_fee(const unsigned char serializable_discretized_fee, DiscretizedFee &discretized_fee_out);
void recover_sp_tx_coinbase_v1(ser_SpTxCoinbaseV1 &serializable_tx_in, SpTxCoinbaseV1 &tx_out);
void recover_sp_tx_squashed_v1(ser_SpTxSquashedV1 &serializable_tx_in,
    const SpBinnedReferenceSetConfigV1 &sp_refset_bin_config,
    const std::size_t sp_ref_set_decomp_n,
    const std::size_t sp_ref_set_decomp_m,
    SpTxSquashedV1 &tx_out);
void recover_sp_tx_squashed_v1(ser_SpTxSquashedV1 &serializable_tx_in, SpTxSquashedV1 &tx_out);
bool try_recover_sp_tx_squashed_v1(ser_SpTxSquashedV1 &serializable_tx_in,
    const SpBinnedReferenceSetConfigV1 &sp_refset_bin_config,
    const std::size_t sp_ref_set_decomp_n,
    const std::size_t sp_ref_set_decomp_m,
    SpTxSquashedV1 &tx_out);
bool try_recover_sp_tx_squashed_v1(ser_SpTxSquashedV1 &serializable_tx_in, SpTxSquashedV1 &tx_out);

} //namespace serialization
} //namespace sp
