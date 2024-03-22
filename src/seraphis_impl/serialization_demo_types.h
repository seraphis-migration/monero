// Copyright (c) 2023, The Monero Project
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

// Serializable types for seraphis transaction components and transactions (a demonstration).

#pragma once

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/binned_reference_set.h"
#include "seraphis_core/discretized_fee.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_core/jamtis_support_types.h"
#include "serialization/containers.h"
#include "serialization/crypto.h"
#include "serialization/serialization.h"
#include "seraphis_main/txtype_coinbase_v1.h"
#include "seraphis_main/txtype_squashed_v1.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace sp
{
namespace serialization
{
/// serializable jamtis::address_index_t
struct ser_address_index_t final
{
    unsigned char bytes[sizeof(jamtis::address_index_t)];
};

/// serializable jamtis::address_tag_t
struct ser_address_tag_t final
{
    unsigned char bytes[sizeof(jamtis::address_tag_t)];
};

/// serializable jamtis::encrypted_address_tag_t
struct ser_encrypted_address_tag_t final
{
    unsigned char bytes[sizeof(jamtis::encrypted_address_tag_t)];
};

/// serializable jamtis::encoded_amount_t
struct ser_encoded_amount_t final
{
    unsigned char bytes[sizeof(jamtis::encoded_amount_t)];
};

/// serializable SpCoinbaseEnoteCore
struct ser_SpCoinbaseEnoteCore final
{
    /// Ko
    rct::key onetime_address;
    /// a
    rct::xmr_amount amount;

    BEGIN_SERIALIZE()
        FIELD(onetime_address)
        VARINT_FIELD(amount)
    END_SERIALIZE()
};

/// serializable SpEnoteCore
struct ser_SpEnoteCore final
{
    /// Ko
    rct::key onetime_address;
    /// C
    rct::key amount_commitment;

    BEGIN_SERIALIZE()
        FIELD(onetime_address)
        FIELD(amount_commitment)
    END_SERIALIZE()
};

/// serializable SpEnoteImageCore
struct ser_SpEnoteImageCore final
{
    /// K"
    rct::key masked_address;
    /// C"
    rct::key masked_commitment;
    /// KI
    crypto::key_image key_image;

    BEGIN_SERIALIZE()
        FIELD(masked_address)
        FIELD(masked_commitment)
        FIELD(key_image)
    END_SERIALIZE()
};

/// partially serializable BulletproofPlus2
struct ser_BulletproofPlus2_PARTIAL final
{
    //rct::keyV V;  (not serializable here)
    rct::key A, A1, B;
    rct::key r1, s1, d1;
    rct::keyV L, R;

    BEGIN_SERIALIZE()
        FIELD(A)
        FIELD(A1)
        FIELD(B)
        FIELD(r1)
        FIELD(s1)
        FIELD(d1)
        FIELD(L)
        FIELD(R)
    END_SERIALIZE()
};

/// partially serializable rct::clsag
struct ser_clsag_PARTIAL final
{
    rct::keyV s; // scalars
    rct::key c1;

    //rct::key I; // signing key image   (not serializable here)
    rct::key D; // commitment key image

    BEGIN_SERIALIZE()
        FIELD(s)
        FIELD(c1)
        FIELD(D)
    END_SERIALIZE()
};

/// serializable SpCompositionProof
struct ser_SpCompositionProof final
{
    // challenge
    rct::key c;
    // responses
    rct::key r_t1;
    rct::key r_t2;
    rct::key r_ki;
    // intermediate proof key
    rct::key K_t1;

    BEGIN_SERIALIZE()
        FIELD(c)
        FIELD(r_t1)
        FIELD(r_t2)
        FIELD(r_ki)
        FIELD(K_t1)
    END_SERIALIZE()
};

/// serializable GrootleProof
struct ser_GrootleProof final
{
    rct::key A;
    rct::key B;
    rct::keyM f;
    rct::keyV X;
    rct::key zA;
    rct::key z;

    BEGIN_SERIALIZE()
        FIELD(A)
        FIELD(B)
        FIELD(f)
        FIELD(X)
        FIELD(zA)
        FIELD(z)
    END_SERIALIZE()
};

/// partially serializable SpBinnedReferenceSetV1
struct ser_SpBinnedReferenceSetV1_PARTIAL final
{
    /// bin configuration details (shared by all bins)
    //SpBinnedReferenceSetConfigV1 bin_config;  (not serializable here)
    /// bin generator seed (shared by all bins)
    //rct::key bin_generator_seed;              (not serializable here)
    /// rotation factor (shared by all bins)
    std::uint16_t bin_rotation_factor;
    /// bin loci (serializable as index offsets)
    std::vector<std::uint64_t> bin_loci_COMPACT;

    BEGIN_SERIALIZE()
        VARINT_FIELD(bin_rotation_factor)
            static_assert(sizeof(bin_rotation_factor) == sizeof(ref_set_bin_dimension_v1_t), "");
        FIELD(bin_loci_COMPACT)
    END_SERIALIZE()
};

/// serializable LegacyEnoteImageV2
struct ser_LegacyEnoteImageV2 final
{
    /// masked commitment (aka 'pseudo-output commitment')
    rct::key masked_commitment;
    /// legacy key image
    crypto::key_image key_image;

    BEGIN_SERIALIZE()
        FIELD(masked_commitment)
        FIELD(key_image)
    END_SERIALIZE()
};

/// serializable SpEnoteImageV1
struct ser_SpEnoteImageV1 final
{
    /// enote image core
    ser_SpEnoteImageCore core;

    BEGIN_SERIALIZE()
        FIELD(core)
    END_SERIALIZE()
};

/// serializable SpCoinbaseEnoteV1
struct ser_SpCoinbaseEnoteV1 final
{
    /// enote core (one-time address, amount commitment)
    ser_SpCoinbaseEnoteCore core;

    /// addr_tag_enc
    ser_encrypted_address_tag_t addr_tag_enc;
    /// view_tag
    unsigned char view_tag;

    BEGIN_SERIALIZE()
        FIELD(core)
        FIELD(addr_tag_enc)    static_assert(sizeof(addr_tag_enc) == sizeof(jamtis::encrypted_address_tag_t), "");
        VARINT_FIELD(view_tag) static_assert(sizeof(view_tag) == sizeof(jamtis::view_tag_t), "");
    END_SERIALIZE()
};

/// serializable SpEnoteV1
struct ser_SpEnoteV1 final
{
    /// enote core (one-time address, amount commitment)
    ser_SpEnoteCore core;

    /// enc(a)
    ser_encoded_amount_t encoded_amount;
    /// addr_tag_enc
    ser_encrypted_address_tag_t addr_tag_enc;
    /// view_tag
    unsigned char view_tag;

    BEGIN_SERIALIZE()
        FIELD(core)
        FIELD(encoded_amount)  static_assert(sizeof(encoded_amount) == sizeof(jamtis::encoded_amount_t), "");
        FIELD(addr_tag_enc)    static_assert(sizeof(addr_tag_enc) == sizeof(jamtis::encrypted_address_tag_t), "");
        VARINT_FIELD(view_tag) static_assert(sizeof(view_tag) == sizeof(jamtis::view_tag_t), "");
    END_SERIALIZE()
};

/// partially serializable SpBalanceProofV1
struct ser_SpBalanceProofV1_PARTIAL final
{
    /// an aggregate set of BP+ proofs (partial serialization)
    ser_BulletproofPlus2_PARTIAL bpp2_proof_PARTIAL;
    /// the remainder blinding factor
    rct::key remainder_blinding_factor;

    BEGIN_SERIALIZE()
        FIELD(bpp2_proof_PARTIAL)
        FIELD(remainder_blinding_factor)
    END_SERIALIZE()
};

/// partially serializable LegacyRingSignatureV4
struct ser_LegacyRingSignatureV4_PARTIAL final
{
    /// a clsag proof
    ser_clsag_PARTIAL clsag_proof_PARTIAL;
    /// on-chain indices of the proof's ring members (serializable as index offsets)
    std::vector<std::uint64_t> reference_set_COMPACT;

    BEGIN_SERIALIZE()
        FIELD(clsag_proof_PARTIAL)
        FIELD(reference_set_COMPACT)
    END_SERIALIZE()
};

/// serializable SpImageProofV1
struct ser_SpImageProofV1 final
{
    /// a seraphis composition proof
    ser_SpCompositionProof composition_proof;

    BEGIN_SERIALIZE()
        FIELD(composition_proof)
    END_SERIALIZE()
};

/// partially serializable SpMembershipProofV1 (does not include config info)
struct ser_SpMembershipProofV1_PARTIAL final
{
    /// a grootle proof
    ser_GrootleProof grootle_proof;
    /// binned representation of ledger indices of enotes referenced by the proof
    ser_SpBinnedReferenceSetV1_PARTIAL binned_reference_set_PARTIAL;
    /// ref set size = n^m
    //std::size_t ref_set_decomp_n;  (not serializable here)
    //std::size_t ref_set_decomp_m;  (not serializable here)

    BEGIN_SERIALIZE()
        FIELD(grootle_proof)
        FIELD(binned_reference_set_PARTIAL)
    END_SERIALIZE()
};

/// serializable SpTxSupplementV1
struct ser_SpTxSupplementV1 final
{
    /// xKe: enote ephemeral pubkeys for outputs
    std::vector<crypto::x25519_pubkey> output_enote_ephemeral_pubkeys;
    /// tx memo
    std::vector<unsigned char> tx_extra;

    BEGIN_SERIALIZE()
        FIELD(output_enote_ephemeral_pubkeys)
        FIELD(tx_extra)
    END_SERIALIZE()
};

/// serializable SpTxCoinbaseV1
struct ser_SpTxCoinbaseV1 final
{
    /// semantic rules version
    SpTxCoinbaseV1::SemanticRulesVersion tx_semantic_rules_version;

    /// height of the block whose block reward this coinbase tx disperses
    std::uint64_t block_height;
    /// tx outputs (new enotes)
    std::vector<ser_SpCoinbaseEnoteV1> outputs;
    /// supplemental data for tx
    ser_SpTxSupplementV1 tx_supplement;

    BEGIN_SERIALIZE()
        VARINT_FIELD(tx_semantic_rules_version)
        VARINT_FIELD(block_height)
        FIELD(outputs)
        FIELD(tx_supplement)
    END_SERIALIZE()
};

/// serializable SpTxSquashedV1
struct ser_SpTxSquashedV1 final
{
    /// semantic rules version
    SpTxSquashedV1::SemanticRulesVersion tx_semantic_rules_version;

    /// legacy tx input images (spent legacy enotes)
    std::vector<ser_LegacyEnoteImageV2> legacy_input_images;
    /// seraphis tx input images (spent seraphis enotes)
    std::vector<ser_SpEnoteImageV1> sp_input_images;
    /// tx outputs (new enotes)
    std::vector<ser_SpEnoteV1> outputs;
    /// balance proof (balance proof and range proofs)
    ser_SpBalanceProofV1_PARTIAL balance_proof;
    /// ring signature proofs: membership and ownership/key-image-legitimacy for each legacy input
    std::vector<ser_LegacyRingSignatureV4_PARTIAL> legacy_ring_signatures;
    /// composition proofs: ownership/key-image-legitimacy for each seraphis input
    std::vector<ser_SpImageProofV1> sp_image_proofs;
    /// Grootle proofs on squashed enotes: membership for each seraphis input
    std::vector<ser_SpMembershipProofV1_PARTIAL> sp_membership_proofs;
    /// supplemental data for tx
    ser_SpTxSupplementV1 tx_supplement;
    /// the transaction fee (discretized representation)
    unsigned char tx_fee;

    BEGIN_SERIALIZE()
        VARINT_FIELD(tx_semantic_rules_version)
        FIELD(legacy_input_images)
        FIELD(sp_input_images)
        FIELD(outputs)
        FIELD(balance_proof)
        FIELD(legacy_ring_signatures)
        FIELD(sp_image_proofs)
        FIELD(sp_membership_proofs)
        FIELD(tx_supplement)
        VARINT_FIELD(tx_fee) static_assert(sizeof(tx_fee) == sizeof(DiscretizedFee), "");
    END_SERIALIZE()
};

/// serializable JamtisDestinationV1
struct ser_JamtisDestinationV1 final
{
    /// K_1 (address spend key)
    rct::key addr_K1;
    /// xK_2 (address view key)
    crypto::x25519_pubkey addr_K2;
    /// xK_3 (DH base key)
    crypto::x25519_pubkey addr_K3;
    /// addr_tag
    ser_address_tag_t addr_tag;

    BEGIN_SERIALIZE()
        FIELD(addr_K1)
        FIELD(addr_K2)
        FIELD(addr_K3)
        FIELD(addr_tag)    static_assert(sizeof(addr_tag) == sizeof(jamtis::address_tag_t), "");
    END_SERIALIZE()
};

/// serializable JamtisPaymentProposalV1
struct ser_JamtisPaymentProposalV1 final
{
    /// destination address
    ser_JamtisDestinationV1 destination;
    /// amount
    rct::xmr_amount amount;
    /// enote ephemeral private key
    crypto::x25519_scalar enote_ephemeral_privkey;
    /// memo elements
    std::vector<unsigned char> partial_memo;

    BEGIN_SERIALIZE()
        FIELD(destination)
        FIELD(amount)
        FIELD(enote_ephemeral_privkey)
        FIELD(partial_memo)
    END_SERIALIZE()
};

/// serializable JamtisPaymentProposalV1
struct ser_JamtisPaymentProposalSelfSendV1 final
{
    /// destination address
    ser_JamtisDestinationV1 destination;
    /// amount
    rct::xmr_amount amount;
    /// selfspend type
    unsigned char type;
    /// enote ephemeral private key
    crypto::x25519_scalar enote_ephemeral_privkey;
    /// memo elements
    std::vector<unsigned char> partial_memo;

    BEGIN_SERIALIZE()
        FIELD(destination)
        FIELD(amount)
        FIELD(type)
        FIELD(enote_ephemeral_privkey)
        FIELD(partial_memo)
    END_SERIALIZE()
};

} //namespace serialization
} //namespace sp

BLOB_SERIALIZER(sp::serialization::ser_address_index_t);
BLOB_SERIALIZER(sp::serialization::ser_address_tag_t);
BLOB_SERIALIZER(sp::serialization::ser_encrypted_address_tag_t);
BLOB_SERIALIZER(sp::serialization::ser_encoded_amount_t);
