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
#include "tx_validators.h"

//local headers
#include "common/container_helpers.h"
#include "crypto/crypto.h"
#include "ringct/rctOps.h"
#include "ringct/rctSigs.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/binned_reference_set_utils.h"
#include "seraphis_core/discretized_fee.h"
#include "seraphis_core/tx_extra.h"
#include "seraphis_crypto/bulletproofs_plus2.h"
#include "seraphis_crypto/math_utils.h"
#include "seraphis_crypto/grootle.h"
#include "seraphis_crypto/sp_composition_proof.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "tx_builders_inputs.h"
#include "tx_builders_legacy_inputs.h"
#include "tx_component_types.h"
#include "tx_component_types_legacy.h"
#include "tx_validation_context.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <algorithm>
#include <memory>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
// helper for validating v1 balance proofs (balance equality check)
//-------------------------------------------------------------------------------------------------------------------
static bool validate_sp_amount_balance_equality_check_v1(const std::vector<LegacyEnoteImageV2> &legacy_input_images,
    const std::vector<SpEnoteImageV1> &sp_input_images,
    const std::vector<SpEnoteV1> &outputs,
    const rct::xmr_amount transaction_fee,
    const rct::key &remainder_blinding_factor)
{
    // the blinding factor should be a canonical scalar
    if (sc_check(remainder_blinding_factor.bytes) != 0)
        return false;

    // balance check
    rct::keyV input_image_amount_commitments;
    rct::keyV output_commitments;
    input_image_amount_commitments.reserve(legacy_input_images.size() + sp_input_images.size());
    output_commitments.reserve(outputs.size() + 2);

    for (const LegacyEnoteImageV2 &legacy_input_image : legacy_input_images)
        input_image_amount_commitments.emplace_back(legacy_input_image.masked_commitment);

    for (const SpEnoteImageV1 &sp_input_image : sp_input_images)
        input_image_amount_commitments.emplace_back(masked_commitment_ref(sp_input_image));

    for (const SpEnoteV1 &output : outputs)
        output_commitments.emplace_back(output.core.amount_commitment);

    output_commitments.emplace_back(rct::commit(transaction_fee, rct::zero()));

    if (!(remainder_blinding_factor == rct::zero()))
        output_commitments.emplace_back(rct::scalarmultBase(remainder_blinding_factor));

    // sum(input masked commitments) ?= sum(output commitments) + transaction_fee*H + remainder_blinding_factor*G
    return balance_check_equality(input_image_amount_commitments, output_commitments);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
bool validate_sp_semantics_coinbase_component_counts_v1(const SemanticConfigCoinbaseComponentCountsV1 &config,
    const std::size_t num_outputs,
    const std::size_t num_enote_pubkeys)
{
    // output count
    if (num_outputs < config.min_outputs ||
        num_outputs > config.max_outputs)
        return false;

    // outputs and enote pubkeys should be 1:1 (note: there are no 'shared' enote pubkeys in coinbase txs)
    if (num_outputs != num_enote_pubkeys)
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_sp_semantics_component_counts_v1(const SemanticConfigComponentCountsV1 &config,
    const std::size_t num_legacy_input_images,
    const std::size_t num_sp_input_images,
    const std::size_t num_legacy_ring_signatures,
    const std::size_t num_sp_membership_proofs,
    const std::size_t num_sp_image_proofs,
    const std::size_t num_outputs,
    const std::size_t num_enote_pubkeys,
    const std::size_t num_range_proofs)
{
    // input count
    if (num_legacy_input_images + num_sp_input_images < config.min_inputs ||
        num_legacy_input_images + num_sp_input_images > config.max_inputs)
        return false;

    // legacy input images and ring signatures should be 1:1
    if (num_legacy_input_images != num_legacy_ring_signatures)
        return false;

    // seraphis input images and image proofs should be 1:1
    if (num_sp_input_images != num_sp_image_proofs)
        return false;

    // seraphis input images and membership proofs should be 1:1
    if (num_sp_input_images != num_sp_membership_proofs)
        return false;

    // output count
    if (num_outputs < config.min_outputs ||
        num_outputs > config.max_outputs)
        return false;

    // range proofs should be 1:1 with seraphis input image amount commitments and outputs
    if (num_range_proofs != num_sp_input_images + num_outputs)
        return false;

    // outputs and enote pubkeys should be 1:1
    // - except for 2-out txs, which should have only one enote pubkey
    if (num_outputs == 2)
    {
        if (num_enote_pubkeys != 1)
            return false;
    }
    else if (num_outputs != num_enote_pubkeys)
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_sp_semantics_legacy_reference_sets_v1(const SemanticConfigLegacyRefSetV1 &config,
    const std::vector<LegacyRingSignatureV4> &legacy_ring_signatures)
{
    // assume valid if no signatures
    if (legacy_ring_signatures.size() == 0)
        return true;

    // check ring size in each ring signature
    for (const LegacyRingSignatureV4 &legacy_ring_signature : legacy_ring_signatures)
    {
        // reference set
        if (legacy_ring_signature.reference_set.size() < config.ring_size_min ||
            legacy_ring_signature.reference_set.size() > config.ring_size_max)
            return false;

        // CLSAG signature size
        if (legacy_ring_signature.reference_set.size() != legacy_ring_signature.clsag_proof.s.size())
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_sp_semantics_sp_reference_sets_v1(const SemanticConfigSpRefSetV1 &config,
    const std::vector<SpMembershipProofV1> &sp_membership_proofs)
{
    // assume valid if no proofs
    if (sp_membership_proofs.size() == 0)
        return true;

    // check ref set decomp
    const std::size_t ref_set_decomp_n{sp_membership_proofs[0].ref_set_decomp_n};
    const std::size_t ref_set_decomp_m{sp_membership_proofs[0].ref_set_decomp_m};

    if (ref_set_decomp_n < config.decomp_n_min ||
        ref_set_decomp_n > config.decomp_n_max)
        return false;

    if (ref_set_decomp_m < config.decomp_m_min ||
        ref_set_decomp_m > config.decomp_m_max)
        return false;

    // check binned reference set configuration
    const SpBinnedReferenceSetConfigV1 bin_config{sp_membership_proofs[0].binned_reference_set.bin_config};

    if (bin_config.bin_radius < config.bin_radius_min ||
        bin_config.bin_radius > config.bin_radius_max)
        return false;

    if (bin_config.num_bin_members < config.num_bin_members_min ||
        bin_config.num_bin_members > config.num_bin_members_max)
        return false;

    // check seraphis membership proofs
    for (const SpMembershipProofV1 &sp_proof : sp_membership_proofs)
    {
        // proof ref set decomposition (n^m) should match number of referenced enotes
        const std::size_t ref_set_size{math::uint_pow(sp_proof.ref_set_decomp_n, sp_proof.ref_set_decomp_m)};

        if (ref_set_size != reference_set_size(sp_proof.binned_reference_set))
            return false;

        // all proofs should have same ref set decomp (and implicitly: same ref set size)
        if (sp_proof.ref_set_decomp_n != ref_set_decomp_n)
            return false;
        if (sp_proof.ref_set_decomp_m != ref_set_decomp_m)
            return false;

        // all proofs should have the same bin config
        if (sp_proof.binned_reference_set.bin_config != bin_config)
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_sp_semantics_output_serialization_v1(const std::vector<SpCoinbaseEnoteV1> &output_enotes)
{
    ge_p3 temp_deserialized;

    // onetime addresses must be deserializable
    for (const SpCoinbaseEnoteV1 &output_enote : output_enotes)
    {
        if (ge_frombytes_vartime(&temp_deserialized, output_enote.core.onetime_address.bytes) != 0)
            return false;
    }

    // note: all possible serializations of x25519 public keys are valid, so we don't validate enote ephemeral pubkeys here

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_sp_semantics_output_serialization_v2(const std::vector<SpEnoteV1> &output_enotes)
{
    ge_p3 temp_deserialized;

    // onetime addresses must be deserializable
    for (const SpEnoteV1 &output_enote : output_enotes)
    {
        if (ge_frombytes_vartime(&temp_deserialized, output_enote.core.onetime_address.bytes) != 0)
            return false;
    }

    // note: all possible serializations of x25519 public keys are valid, so we don't validate enote ephemeral pubkeys here

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_sp_semantics_input_images_v1(const std::vector<LegacyEnoteImageV2> &legacy_input_images,
    const std::vector<SpEnoteImageV1> &sp_input_images)
{
    for (const LegacyEnoteImageV2 &legacy_image : legacy_input_images)
    {
        // input linking tags must be in the prime subgroup: l*KI = identity
        if (!sp::key_domain_is_prime_subgroup(rct::ki2rct(legacy_image.key_image)))
            return false;

        // image parts must not be identity
        if (legacy_image.masked_commitment == rct::identity())
            return false;
        if (rct::ki2rct(legacy_image.key_image) == rct::identity())
            return false;
    }

    for (const SpEnoteImageV1 &sp_image : sp_input_images)
    {
        // input linking tags must be in the prime subgroup: l*KI = identity
        if (!sp::key_domain_is_prime_subgroup(rct::ki2rct(key_image_ref(sp_image))))
            return false;

        // image parts must not be identity
        if (masked_address_ref(sp_image) == rct::identity())
            return false;
        if (masked_commitment_ref(sp_image) == rct::identity())
            return false;
        if (rct::ki2rct(key_image_ref(sp_image)) == rct::identity())
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_sp_semantics_coinbase_layout_v1(const std::vector<SpCoinbaseEnoteV1> &outputs,
    const std::vector<crypto::x25519_pubkey> &enote_ephemeral_pubkeys,
    const TxExtra &tx_extra)
{
    // output enotes should be sorted by onetime address with byte-wise comparisons (ascending), and unique
    if (!tools::is_sorted_and_unique(outputs, compare_Ko))
        return false;

    // enote ephemeral pubkeys should be unique (they don't need to be sorted)
    if (!keys_are_unique(enote_ephemeral_pubkeys))
        return false;

    // tx extra fields should be in sorted TLV (Type-Length-Value) format
    std::vector<ExtraFieldElement> extra_field_elements;
    if (!try_get_extra_field_elements(tx_extra, extra_field_elements))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_sp_semantics_layout_v1(const std::vector<LegacyRingSignatureV4> &legacy_ring_signatures,
    const std::vector<SpMembershipProofV1> &sp_membership_proofs,
    const std::vector<LegacyEnoteImageV2> &legacy_input_images,
    const std::vector<SpEnoteImageV1> &sp_input_images,
    const std::vector<SpEnoteV1> &outputs,
    const std::vector<crypto::x25519_pubkey> &enote_ephemeral_pubkeys,
    const TxExtra &tx_extra)
{
    // legacy reference sets should be sorted (ascending) without duplicates
    for (const LegacyRingSignatureV4 &legacy_ring_signature : legacy_ring_signatures)
    {
        if (!tools::is_sorted_and_unique(legacy_ring_signature.reference_set))
            return false;
    }

    // seraphis membership proof binned reference set bins should be sorted (ascending)
    // note: duplicate bin locations are allowed
    for (const SpMembershipProofV1 &sp_proof : sp_membership_proofs)
    {
        if (!std::is_sorted(sp_proof.binned_reference_set.bin_loci.begin(),
                sp_proof.binned_reference_set.bin_loci.end()))
            return false;
    }

    // legacy input images should be sorted by key image with byte-wise comparisons (ascending), and unique
    if (!tools::is_sorted_and_unique(legacy_input_images, compare_KI))
        return false;

    // seraphis input images should be sorted by key image with byte-wise comparisons (ascending), and unique
    if (!tools::is_sorted_and_unique(sp_input_images, compare_KI))
        return false;

    // legacy and seraphis input images should not have any matching key images
    // note: it is not necessary to check this because overlapping key images is impossible if the input proofs are valid

    // output enotes should be sorted by onetime address with byte-wise comparisons (ascending), and unique
    if (!tools::is_sorted_and_unique(outputs, compare_Ko))
        return false;

    // enote ephemeral pubkeys should be unique (they don't need to be sorted)
    if (!keys_are_unique(enote_ephemeral_pubkeys))
        return false;

    // tx extra fields should be in sorted TLV (Type-Length-Value) format
    std::vector<ExtraFieldElement> extra_field_elements;
    if (!try_get_extra_field_elements(tx_extra, extra_field_elements))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_sp_semantics_fee_v1(const DiscretizedFee discretized_transaction_fee)
{
    rct::xmr_amount raw_transaction_fee;
    if (!try_get_fee_value(discretized_transaction_fee, raw_transaction_fee))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_sp_key_images_v1(const std::vector<LegacyEnoteImageV2> &legacy_input_images,
    const std::vector<SpEnoteImageV1> &sp_input_images,
    const TxValidationContext &tx_validation_context)
{
    // check no legacy duplicates in ledger context
    for (const LegacyEnoteImageV2 &legacy_input_image : legacy_input_images)
    {
        if (tx_validation_context.cryptonote_key_image_exists(legacy_input_image.key_image))
            return false;
    }

    // check no seraphis duplicates in ledger context
    for (const SpEnoteImageV1 &sp_input_image : sp_input_images)
    {
        if (tx_validation_context.seraphis_key_image_exists(key_image_ref(sp_input_image)))
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_sp_coinbase_amount_overflow_v1(const std::vector<SpCoinbaseEnoteV1> &outputs)
{
    // expect the output sum doesn't overflow
    boost::multiprecision::uint128_t output_amount_sum{0};

    for (const SpCoinbaseEnoteV1 &output : outputs)
        output_amount_sum += output.core.amount;

    if (output_amount_sum > std::numeric_limits<rct::xmr_amount>::max())
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_sp_amount_balance_v1(const std::vector<LegacyEnoteImageV2> &legacy_input_images,
    const std::vector<SpEnoteImageV1> &sp_input_images,
    const std::vector<SpEnoteV1> &outputs,
    const DiscretizedFee discretized_transaction_fee,
    const SpBalanceProofV1 &balance_proof)
{
    const BulletproofPlus2 &range_proofs = balance_proof.bpp2_proof;

    // sanity check
    if (range_proofs.V.size() == 0)
        return false;

    // try to extract the fee
    rct::xmr_amount raw_transaction_fee;
    if (!try_get_fee_value(discretized_transaction_fee, raw_transaction_fee))
        return false;

    // check that amount commitments balance
    if (!validate_sp_amount_balance_equality_check_v1(legacy_input_images,
            sp_input_images,
            outputs,
            raw_transaction_fee,
            balance_proof.remainder_blinding_factor))
        return false;

    // check that commitments in range proofs line up with seraphis input image and output commitments
    if (sp_input_images.size() + outputs.size() != range_proofs.V.size())
        return false;

    for (std::size_t input_commitment_index{0}; input_commitment_index < sp_input_images.size(); ++input_commitment_index)
    {
        // the two stored copies of input image commitments must match
        if (!(masked_commitment_ref(sp_input_images[input_commitment_index]) ==
                rct::scalarmult8(range_proofs.V[input_commitment_index])))
            return false;
    }

    for (std::size_t output_commitment_index{0}; output_commitment_index < outputs.size(); ++output_commitment_index)
    {
        // the two stored copies of output commitments must match
        if (!(outputs[output_commitment_index].core.amount_commitment ==
                rct::scalarmult8(range_proofs.V[sp_input_images.size() + output_commitment_index])))
            return false;
    }

    // BP+: deferred for batch-verification

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_sp_legacy_input_proofs_v1(const std::vector<LegacyRingSignatureV4> &legacy_ring_signatures,
    const std::vector<LegacyEnoteImageV2> &legacy_input_images,
    const rct::key &tx_proposal_prefix,
    const TxValidationContext &tx_validation_context)
{
    // sanity check
    if (legacy_ring_signatures.size() != legacy_input_images.size())
        return false;

    // legacy ring signatures and input images should have the same main key images stored
    for (std::size_t legacy_input_index{0}; legacy_input_index < legacy_ring_signatures.size(); ++legacy_input_index)
    {
        if (rct::rct2ki(legacy_ring_signatures[legacy_input_index].clsag_proof.I) !=
                legacy_input_images[legacy_input_index].key_image)
            return false;
    }

    // validate each legacy ring signature
    rct::ctkeyV ring_members_temp;
    rct::key ring_signature_message_temp;

    for (std::size_t legacy_input_index{0}; legacy_input_index < legacy_ring_signatures.size(); ++legacy_input_index)
    {
        // collect CLSAG ring members
        ring_members_temp.clear();
        tx_validation_context.get_reference_set_proof_elements_v1(
            legacy_ring_signatures[legacy_input_index].reference_set,
            ring_members_temp);

        // make legacy proof message
        make_tx_legacy_ring_signature_message_v1(tx_proposal_prefix,
            legacy_ring_signatures[legacy_input_index].reference_set,
            ring_signature_message_temp);

        // verify CLSAG proof
        if (!rct::verRctCLSAGSimple(ring_signature_message_temp,
                legacy_ring_signatures[legacy_input_index].clsag_proof,
                ring_members_temp,
                legacy_input_images[legacy_input_index].masked_commitment))
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_sp_composition_proofs_v1(const std::vector<SpImageProofV1> &sp_image_proofs,
    const std::vector<SpEnoteImageV1> &sp_input_images,
    const rct::key &tx_proposal_prefix)
{
    // sanity check
    if (sp_image_proofs.size() != sp_input_images.size())
        return false;

    // validate each composition proof
    for (std::size_t input_index{0}; input_index < sp_input_images.size(); ++input_index)
    {
        if (!sp::verify_sp_composition_proof(sp_image_proofs[input_index].composition_proof,
                tx_proposal_prefix,
                masked_address_ref(sp_input_images[input_index]),
                key_image_ref(sp_input_images[input_index])))
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_sp_membership_proofs_v1_validation_data(const std::vector<const SpMembershipProofV1*> &sp_membership_proofs,
    const std::vector<const SpEnoteImageCore*> &sp_input_images,
    const TxValidationContext &tx_validation_context,
    std::list<SpMultiexpBuilder> &validation_data_out)
{
    const std::size_t num_proofs{sp_membership_proofs.size()};
    validation_data_out.clear();

    // sanity check
    if (num_proofs != sp_input_images.size())
        return false;

    // assume valid if no proofs
    if (num_proofs == 0)
        return true;

    // get batched validation data
    std::vector<const sp::GrootleProof*> proofs;
    std::vector<rct::keyV> membership_proof_keys;
    rct::keyV offsets;
    rct::keyV messages;
    proofs.reserve(num_proofs);
    membership_proof_keys.reserve(num_proofs);
    offsets.reserve(num_proofs);
    messages.reserve(num_proofs);

    rct::key generator_seed_reproduced;
    std::vector<std::uint64_t> reference_indices;

    for (std::size_t proof_index{0}; proof_index < num_proofs; ++proof_index)
    {
        // sanity check
        if (!sp_membership_proofs[proof_index] ||
            !sp_input_images[proof_index])
            return false;

        // the binned reference set's generator seed should be reproducible
        make_binned_ref_set_generator_seed_v1(sp_input_images[proof_index]->masked_address,
            sp_input_images[proof_index]->masked_commitment,
            generator_seed_reproduced);

        if (!(generator_seed_reproduced == sp_membership_proofs[proof_index]->binned_reference_set.bin_generator_seed))
            return false;

        // extract the references
        if(!try_get_reference_indices_from_binned_reference_set_v1(sp_membership_proofs[proof_index]->binned_reference_set,
                reference_indices))
            return false;

        // get proof keys from enotes stored in the ledger
        tx_validation_context.get_reference_set_proof_elements_v2(reference_indices,
            tools::add_element(membership_proof_keys));

        // offset (input image masked keys squashed: Q" = K" + C")
        rct::addKeys(tools::add_element(offsets),
            sp_input_images[proof_index]->masked_address,
            sp_input_images[proof_index]->masked_commitment);

        // proof message
        make_tx_membership_proof_message_v1(sp_membership_proofs[proof_index]->binned_reference_set,
            tools::add_element(messages));

        // save the proof
        proofs.emplace_back(&(sp_membership_proofs[proof_index]->grootle_proof));
    }

    // get verification data
    sp::get_grootle_verification_data(proofs,
        messages,
        membership_proof_keys,
        offsets,
        sp_membership_proofs[0]->ref_set_decomp_n,
        sp_membership_proofs[0]->ref_set_decomp_m,
        validation_data_out);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
