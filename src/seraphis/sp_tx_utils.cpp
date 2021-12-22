// Copyright (c) 2021, The Monero Project
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

// NOT FOR PRODUCTION

//paired header
#include "sp_tx_utils.h"

//local headers
#include "common/varint.h"
#include "concise_grootle.h"
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_config.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "mock_ledger_context.h"
#include "ringct/bulletproofs_plus.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_composition_proof.h"
#include "sp_core_utils.h"
#include "sp_crypto_utils.h"
#include "sp_tx_builder_types.h"
#include "sp_tx_component_types.h"
#include "sp_tx_misc_utils.h"

//third party headers

//standard headers
#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
// create t_k and t_c for an enote image
//-------------------------------------------------------------------------------------------------------------------
static void prepare_image_masks_sp_v1(crypto::secret_key &image_address_mask_out,
    crypto::secret_key &image_amount_mask_out)
{
    image_address_mask_out = rct::rct2sk(rct::zero());
    image_amount_mask_out = rct::rct2sk(rct::zero());

    // t_k
    while (image_address_mask_out == rct::rct2sk(rct::zero()))
        image_address_mask_out = rct::rct2sk(rct::skGen());

    // t_c
    while (image_amount_mask_out == rct::rct2sk(rct::zero()))
        image_amount_mask_out = rct::rct2sk(rct::skGen());
}
//-------------------------------------------------------------------------------------------------------------------
// create t_k and t_c for all enote images in a tx
//-------------------------------------------------------------------------------------------------------------------
static void prepare_image_masks_all_sp_v1(const std::vector<SpInputProposalV1> &input_proposals,
    std::vector<crypto::secret_key> &image_address_masks_out,
    std::vector<crypto::secret_key> &image_amount_masks_out)
{
    CHECK_AND_ASSERT_THROW_MES(input_proposals.size() > 0, "Tried to make tx input image set without any inputs.");

    image_address_masks_out.clear();
    image_amount_masks_out.clear();
    image_address_masks_out.resize(input_proposals.size());
    image_amount_masks_out.resize(input_proposals.size());

    // make all input images
    for (std::size_t input_index{0}; input_index < input_proposals.size(); ++input_index)
    {
        prepare_image_masks_sp_v1(image_address_masks_out[input_index],
            image_amount_masks_out[input_index]);
    }
}
//-------------------------------------------------------------------------------------------------------------------
// convert a crypto::secret_key vector to an rct::key vector, and obtain a memwiper for the rct::key vector
//-------------------------------------------------------------------------------------------------------------------
static auto convert_skv_to_rctv(const std::vector<crypto::secret_key> &skv, rct::keyV &rctv_out)
{
    auto a_wiper = epee::misc_utils::create_scope_leave_handler([&]{
        memwipe(rctv_out.data(), rctv_out.size()*sizeof(rct::key));
    });

    rctv_out.clear();
    rctv_out.reserve(skv.size());

    for (const auto &skey : skv)
        rctv_out.emplace_back(rct::sk2rct(skey));

    return a_wiper;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
rct::key get_tx_membership_proof_message_sp_v1(const std::vector<std::size_t> &enote_ledger_indices)
{
    rct::key hash_result;
    std::string hash;
    hash.reserve(sizeof(CRYPTONOTE_NAME) + enote_ledger_indices.size()*((sizeof(std::size_t) * 8 + 6) / 7));
    // project name
    hash = CRYPTONOTE_NAME;
    // all referenced enote ledger indices
    char converted_index[(sizeof(std::size_t) * 8 + 6) / 7];
    char* end;
    for (const std::size_t index : enote_ledger_indices)
    {
        // TODO: append real ledger references
        end = converted_index;
        tools::write_varint(end, index);
        assert(end <= converted_index + sizeof(converted_index));
        hash.append(converted_index, end - converted_index);
    }

    rct::hash_to_scalar(hash_result, hash.data(), hash.size());

    return hash_result;
}
//-------------------------------------------------------------------------------------------------------------------
rct::key get_tx_image_proof_message_sp_v1(const std::string &version_string,
    const std::vector<SpENoteV1> &output_enotes,
    const SpTxSupplementV1 &tx_supplement)
{
    rct::key hash_result;
    std::string hash;
    hash.reserve(sizeof(CRYPTONOTE_NAME) +
        version_string.size() +
        output_enotes.size()*SpENoteV1::get_size_bytes() +
        tx_supplement.m_output_enote_pubkeys.size());
    hash = CRYPTONOTE_NAME;
    hash += version_string;
    for (const auto &output_enote : output_enotes)
    {
        output_enote.append_to_string(hash);
    }
    for (const auto &enote_pubkey : tx_supplement.m_output_enote_pubkeys)
    {
        hash.append((const char*) enote_pubkey.bytes, sizeof(enote_pubkey));
    }

    rct::hash_to_scalar(hash_result, hash.data(), hash.size());

    return hash_result;
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<std::size_t> get_tx_input_sort_order_v1(const std::vector<SpTxPartialInputV1> &partial_inputs)
{
    std::vector<crypto::key_image> input_key_images;
    input_key_images.reserve(partial_inputs.size());

    for (const auto &partial_input : partial_inputs)
        input_key_images.emplace_back(partial_input.m_input_image.m_key_image);

    return get_tx_input_sort_order_v1(input_key_images);
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<std::size_t> get_tx_input_sort_order_v1(const std::vector<SpENoteImageV1> &input_images)
{
    std::vector<crypto::key_image> input_key_images;
    input_key_images.reserve(input_images.size());

    for (const auto &input_image : input_images)
        input_key_images.emplace_back(input_image.m_key_image);

    return get_tx_input_sort_order_v1(input_key_images);
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<std::size_t> get_tx_input_sort_order_v1(const std::vector<crypto::key_image> &input_key_images)
{
    std::vector<std::size_t> original_indices;
    original_indices.resize(input_key_images.size());

    for (std::size_t input_index{0}; input_index < input_key_images.size(); ++input_index)
        original_indices[input_index] = input_index;

    // sort: key images ascending with byte-wise comparisons
    std::sort(original_indices.begin(), original_indices.end(),
            [&input_key_images](const std::size_t input_index_1, const std::size_t input_index_2) -> bool
            {
                return memcmp(&(input_key_images[input_index_1]),
                    &(input_key_images[input_index_2]), sizeof(crypto::key_image)) < 0;
            }
        );

    return original_indices;
}
//-------------------------------------------------------------------------------------------------------------------
void align_v1_tx_membership_proofs_sp_v1(const std::vector<SpENoteImageV1> &input_images,
    std::vector<SpMembershipProofSortableV1> &tx_membership_proofs_sortable_in,
    std::vector<SpMembershipProofV1> &tx_membership_proofs_out)
{
    CHECK_AND_ASSERT_THROW_MES(tx_membership_proofs_sortable_in.size() == input_images.size(),
        "Mismatch between sortable membership proof count and partial tx input image count.");

    tx_membership_proofs_out.clear();
    tx_membership_proofs_out.reserve(tx_membership_proofs_sortable_in.size());

    for (std::size_t input_index{0}; input_index < input_images.size(); ++input_index)
    {
        // find the membership proof that matches with the input image at this index
        auto ordered_membership_proof = 
            std::find_if(tx_membership_proofs_sortable_in.begin(), tx_membership_proofs_sortable_in.end(),
                    [&](const SpMembershipProofSortableV1 &sortable_proof) -> bool
                    {
                        return input_images[input_index].m_masked_address == sortable_proof.m_masked_address;
                    }
                );

        CHECK_AND_ASSERT_THROW_MES(ordered_membership_proof != tx_membership_proofs_sortable_in.end(),
            "Could not find input image to match with a sortable membership proof.");

        tx_membership_proofs_out.emplace_back(std::move(ordered_membership_proof->m_membership_proof));
    }
}
//-------------------------------------------------------------------------------------------------------------------
void prepare_input_commitment_factors_for_balance_proof_v1(
    const std::vector<SpInputProposalV1> &input_proposals,
    const std::vector<crypto::secret_key> &image_address_masks,
    std::vector<rct::xmr_amount> &input_amounts_out,
    std::vector<crypto::secret_key> &input_image_amount_commitment_blinding_factors_out)
{
    CHECK_AND_ASSERT_THROW_MES(input_proposals.size() == image_address_masks.size(),
        "Mismatch between input proposals and image address masks.");

    input_amounts_out.clear();
    input_image_amount_commitment_blinding_factors_out.clear();
    input_amounts_out.resize(input_proposals.size());
    input_image_amount_commitment_blinding_factors_out.resize(input_proposals.size());

    for (std::size_t input_index{0}; input_index < input_proposals.size(); ++input_index)
    {
        input_amounts_out[input_index] = input_proposals[input_index].m_amount;

        // input image amount commitment blinding factor: t_c + x
        sc_add(&(input_image_amount_commitment_blinding_factors_out[input_index]),
            &(image_address_masks[input_index]),  // t_c
            &(input_proposals[input_index].m_amount_blinding_factor));  // x
    }
}
//-------------------------------------------------------------------------------------------------------------------
void prepare_input_commitment_factors_for_balance_proof_v1(
    const std::vector<SpTxPartialInputV1> &partial_inputs,
    std::vector<crypto::secret_key> &input_image_amount_commitment_blinding_factors_out)
{
    input_image_amount_commitment_blinding_factors_out.clear();
    input_image_amount_commitment_blinding_factors_out.resize(partial_inputs.size());

    for (std::size_t input_index{0}; input_index < partial_inputs.size(); ++input_index)
    {
        // input image amount commitment blinding factor: t_c + x
        sc_add(&(input_image_amount_commitment_blinding_factors_out[input_index]),
            &(partial_inputs[input_index].m_image_amount_mask),  // t_c
            &(partial_inputs[input_index].m_input_amount_blinding_factor));  // x
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_outputs_sp_v1(const std::vector<SpDestinationV1> &destinations,
    std::vector<SpENoteV1> &outputs_out,
    std::vector<rct::xmr_amount> &output_amounts_out,
    std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors_out,
    SpTxSupplementV1 &tx_supplement_inout)
{
    rct::keyV temp_enote_pubkeys;
    temp_enote_pubkeys.resize(destinations.size());
    outputs_out.clear();
    outputs_out.reserve(destinations.size());
    output_amounts_out.clear();
    output_amounts_out.reserve(destinations.size());
    output_amount_commitment_blinding_factors_out.clear();
    output_amount_commitment_blinding_factors_out.resize(destinations.size());

    for (std::size_t dest_index{0}; dest_index < destinations.size(); ++dest_index)
    {
        // build output set
        outputs_out.emplace_back(destinations[dest_index].to_enote_v1(dest_index, temp_enote_pubkeys[dest_index]));

        // prepare for range proofs
        output_amounts_out.emplace_back(destinations[dest_index].m_amount);
        destinations[dest_index].get_amount_blinding_factor(dest_index,
            output_amount_commitment_blinding_factors_out[dest_index]);
    }

    // copy non-duplicate enote pubkeys to tx supplement
    tx_supplement_inout.m_output_enote_pubkeys.clear();
    tx_supplement_inout.m_output_enote_pubkeys.reserve(destinations.size());

    for (const auto &enote_pubkey : temp_enote_pubkeys)
    {
        if (std::find(tx_supplement_inout.m_output_enote_pubkeys.begin(), tx_supplement_inout.m_output_enote_pubkeys.end(),
            enote_pubkey) == tx_supplement_inout.m_output_enote_pubkeys.end())
        {
            tx_supplement_inout.m_output_enote_pubkeys.emplace_back(enote_pubkey);
        }
    }

    // should be either 1 enote pubkey for entire destination set, or 1:1 per destination
    CHECK_AND_ASSERT_THROW_MES(tx_supplement_inout.m_output_enote_pubkeys.size() == 1 ||
        tx_supplement_inout.m_output_enote_pubkeys.size() == destinations.size(), "Invalid number of enote pubkeys in destination set.");
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_image_sp_v1(const SpInputProposalV1 &input_proposal,
    SpENoteImageV1 &input_image_out,
    crypto::secret_key &image_address_mask_out,
    crypto::secret_key &image_amount_mask_out)
{
    // for squashed enote model

    prepare_image_masks_sp_v1(image_address_mask_out, image_amount_mask_out);

    // enote image
    input_proposal.to_enote_image_squashed_base(image_address_mask_out, image_amount_mask_out, input_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_images_sp_v1(const std::vector<SpInputProposalV1> &input_proposals,
    std::vector<SpENoteImageV1> &input_images_out,
    std::vector<crypto::secret_key> &image_address_masks_out,
    std::vector<crypto::secret_key> &image_amount_masks_out)
{
    // for squashed enote model

    prepare_image_masks_all_sp_v1(input_proposals,
        image_address_masks_out,
        image_amount_masks_out);

    CHECK_AND_ASSERT_THROW_MES(image_address_masks_out.size() == input_proposals.size() &&
        image_amount_masks_out.size() == input_proposals.size(),
        "Vector size mismatch when preparing image masks.");

    input_images_out.clear();
    input_images_out.resize(input_proposals.size());

    // make input images
    for (std::size_t input_index{0}; input_index < input_proposals.size(); ++input_index)
    {
        input_proposals[input_index].to_enote_image_squashed_base(image_address_masks_out[input_index],
            image_amount_masks_out[input_index],
            input_images_out[input_index]);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_image_proof_sp_v1(const SpInputProposalV1 &input_proposal,
    const SpENoteImageV1 &input_image,
    const crypto::secret_key &image_address_mask,
    const rct::key &message,
    SpImageProofV1 &tx_image_proof_out)
{
    // prepare for proof (squashed enote model): y, z
    crypto::secret_key y, z;
    crypto::secret_key squash_prefix;
    make_seraphis_squash_prefix(input_proposal.m_enote.m_onetime_address,
        input_proposal.m_enote.m_amount_commitment,
        squash_prefix);

    sc_mul(&y, &squash_prefix, &(input_proposal.m_enote_view_privkey));  // H(Ko,C) (k_{a, recipient} + k_{a, sender})
    sc_mul(&z, &squash_prefix, &(input_proposal.m_spendbase_privkey));  // H(Ko,C) k_{b, recipient}

    // make seraphis composition proof
    tx_image_proof_out.m_composition_proof =
        sp_composition_prove(message, input_image.m_masked_address, image_address_mask, y, z);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_image_proofs_sp_v1(const std::vector<SpInputProposalV1> &input_proposals,
    const std::vector<SpENoteImageV1> &input_images,
    const std::vector<crypto::secret_key> &image_address_masks,
    const rct::key &message,
    std::vector<SpImageProofV1> &tx_image_proofs_out)
{
    // for squashed enote model

    CHECK_AND_ASSERT_THROW_MES(input_proposals.size() > 0, "Tried to make image proofs for 0 inputs.");
    CHECK_AND_ASSERT_THROW_MES(input_proposals.size() == input_images.size(), "Input components size mismatch");
    CHECK_AND_ASSERT_THROW_MES(input_proposals.size() == image_address_masks.size(), "Input components size mismatch");

    tx_image_proofs_out.clear();
    tx_image_proofs_out.resize(input_proposals.size());

    for (std::size_t input_index{0}; input_index < input_proposals.size(); ++input_index)
    {
        make_v1_tx_image_proof_sp_v1(input_proposals[input_index],
            input_images[input_index],
            image_address_masks[input_index],
            message,
            tx_image_proofs_out[input_index]);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_balance_proof_sp_v1(const std::vector<rct::xmr_amount> &input_amounts,
    const std::vector<rct::xmr_amount> &output_amounts,
    const std::vector<crypto::secret_key> &input_image_amount_commitment_blinding_factors,
    const std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors,
    std::shared_ptr<SpBalanceProofV1> &balance_proof_out)
{
    // for squashed enote model

    if (balance_proof_out.get() == nullptr)
        balance_proof_out = std::make_shared<SpBalanceProofV1>();

    // combine inputs and outputs
    std::vector<rct::xmr_amount> amounts;
    std::vector<crypto::secret_key> blinding_factors;
    amounts.reserve(input_amounts.size() + output_amounts.size());
    blinding_factors.reserve(input_amounts.size() + output_amounts.size());

    amounts = input_amounts;
    amounts.insert(amounts.end(),output_amounts.begin(), output_amounts.end());
    blinding_factors = input_image_amount_commitment_blinding_factors;
    blinding_factors.insert(blinding_factors.end(),
        output_amount_commitment_blinding_factors.begin(),
        output_amount_commitment_blinding_factors.end());

    // make range proofs
    rct::BulletproofPlus range_proofs;

    rct::keyV amount_commitment_blinding_factors;
    auto vec_wiper{convert_skv_to_rctv(blinding_factors, amount_commitment_blinding_factors)};
    make_bpp_rangeproofs(amounts,
        amount_commitment_blinding_factors,
        range_proofs);

    balance_proof_out->m_bpp_proof = std::move(range_proofs);

    // set the remainder blinding factor
    crypto::secret_key remainder_blinding_factor;
    subtract_secret_key_vectors(input_image_amount_commitment_blinding_factors,
        output_amount_commitment_blinding_factors,
        remainder_blinding_factor);

    balance_proof_out->m_remainder_blinding_factor = rct::sk2rct(remainder_blinding_factor);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_membership_proof_sp_v1(const SpMembershipReferenceSetV1 &membership_ref_set,
    const crypto::secret_key &image_address_mask,
    const crypto::secret_key &image_amount_mask,
    SpMembershipProofSortableV1 &tx_membership_proof_out)
{
    // for squashed enote model

    // make the membership proof
    make_v1_tx_membership_proof_sp_v1(membership_ref_set,
        image_address_mask,
        image_amount_mask,
        tx_membership_proof_out.m_membership_proof);

    // save the masked address for later matching the membership proof with its input image
    squash_seraphis_address(
        membership_ref_set.m_referenced_enotes[membership_ref_set.m_real_spend_index_in_set].m_onetime_address,
        membership_ref_set.m_referenced_enotes[membership_ref_set.m_real_spend_index_in_set].m_amount_commitment,
        tx_membership_proof_out.m_masked_address);

    mask_key(image_address_mask,
        tx_membership_proof_out.m_masked_address,
        tx_membership_proof_out.m_masked_address);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_membership_proof_sp_v1(const SpMembershipReferenceSetV1 &membership_ref_set,
    const crypto::secret_key &image_address_mask,
    const crypto::secret_key &image_amount_mask,
    SpMembershipProofV1 &tx_membership_proof_out)
{
    // for squashed enote model

    /// initial checks
    std::size_t ref_set_size{
            ref_set_size_from_decomp(membership_ref_set.m_ref_set_decomp_n, membership_ref_set.m_ref_set_decomp_m)
        };

    CHECK_AND_ASSERT_THROW_MES(membership_ref_set.m_referenced_enotes.size() == ref_set_size,
        "Ref set size doesn't match number of referenced enotes");
    CHECK_AND_ASSERT_THROW_MES(membership_ref_set.m_ledger_enote_indices.size() == ref_set_size,
        "Ref set size doesn't match number of referenced enotes' ledger indices");


    /// miscellaneous components
    tx_membership_proof_out.m_ledger_enote_indices = membership_ref_set.m_ledger_enote_indices;
    tx_membership_proof_out.m_ref_set_decomp_n = membership_ref_set.m_ref_set_decomp_n;
    tx_membership_proof_out.m_ref_set_decomp_m = membership_ref_set.m_ref_set_decomp_m;


    /// prepare to make proof

    // public keys referenced by proof
    rct::keyM referenced_enotes;
    referenced_enotes.resize(ref_set_size, rct::keyV(1));

    for (std::size_t ref_index{0}; ref_index < ref_set_size; ++ref_index)
    {
        // Q_i
        // computing this for every enote for every proof is expensive; TODO: copy Q_i from the node record
        seraphis_squashed_enote_Q(membership_ref_set.m_referenced_enotes[ref_index].m_onetime_address,
            membership_ref_set.m_referenced_enotes[ref_index].m_amount_commitment,
            referenced_enotes[ref_index][0]);
    }

    // proof offsets
    rct::keyV image_offsets;
    image_offsets.resize(1);

    // Q'
    crypto::secret_key q_prime;
    sc_add(&q_prime, &image_address_mask, &image_amount_mask);  // t_k + t_c
    mask_key(q_prime, referenced_enotes[membership_ref_set.m_real_spend_index_in_set][0], image_offsets[0]);  // Q'

    // secret key of (Q[l] - Q')
    std::vector<crypto::secret_key> image_masks;
    image_masks.emplace_back(q_prime);  // t_k + t_c
    sc_mul(&(image_masks[0]), &(image_masks[0]), MINUS_ONE.bytes);  // -(t_k + t_c)

    // proof message
    rct::key message{get_tx_membership_proof_message_sp_v1(membership_ref_set.m_ledger_enote_indices)};


    /// make concise grootle proof
    tx_membership_proof_out.m_concise_grootle_proof = concise_grootle_prove(referenced_enotes,
        membership_ref_set.m_real_spend_index_in_set,
        image_offsets,
        image_masks,
        membership_ref_set.m_ref_set_decomp_n,
        membership_ref_set.m_ref_set_decomp_m,
        message);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_membership_proofs_sp_v1(const std::vector<SpMembershipReferenceSetV1> &membership_ref_sets,
    const std::vector<crypto::secret_key> &image_address_masks,
    const std::vector<crypto::secret_key> &image_amount_masks,
    std::vector<SpMembershipProofSortableV1> &tx_membership_proofs_out)
{
    // for squashed enote model

    CHECK_AND_ASSERT_THROW_MES(membership_ref_sets.size() == image_address_masks.size(), "Input components size mismatch");
    CHECK_AND_ASSERT_THROW_MES(membership_ref_sets.size() == image_amount_masks.size(), "Input components size mismatch");

    tx_membership_proofs_out.clear();
    tx_membership_proofs_out.resize(membership_ref_sets.size());

    for (std::size_t input_index{0}; input_index < membership_ref_sets.size(); ++input_index)
    {
        make_v1_tx_membership_proof_sp_v1(membership_ref_sets[input_index],
            image_address_masks[input_index],
            image_amount_masks[input_index],
            tx_membership_proofs_out[input_index]);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_membership_proofs_sp_v1(const std::vector<SpMembershipReferenceSetV1> &membership_ref_sets,
    const std::vector<SpTxPartialInputV1> &partial_inputs,
    std::vector<SpMembershipProofSortableV1> &tx_membership_proofs_out)
{
    // for squashed enote model

    CHECK_AND_ASSERT_THROW_MES(membership_ref_sets.size() == partial_inputs.size(), "Input components size mismatch");

    tx_membership_proofs_out.clear();
    tx_membership_proofs_out.resize(membership_ref_sets.size());

    for (std::size_t input_index{0}; input_index < membership_ref_sets.size(); ++input_index)
    {
        CHECK_AND_ASSERT_THROW_MES(membership_ref_sets[input_index].
                m_referenced_enotes[membership_ref_sets[input_index].m_real_spend_index_in_set].m_onetime_address ==
            partial_inputs[input_index].m_input_enote.m_onetime_address, 
            "Membership ref set real spend doesn't match partial input's enote.");

        make_v1_tx_membership_proof_sp_v1(membership_ref_sets[input_index],
            partial_inputs[input_index].m_image_address_mask,
            partial_inputs[input_index].m_image_amount_mask,
            tx_membership_proofs_out[input_index]);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_membership_proofs_sp_v1(const std::vector<SpMembershipReferenceSetV1> &membership_ref_sets,
    const SpTxPartialV1 &partial_tx,
    std::vector<SpMembershipProofV1> &tx_membership_proofs_out)
{
    // for squashed enote model

    // note: ref sets are assumed to be pre-sorted, so sortable membership proofs are not needed
    CHECK_AND_ASSERT_THROW_MES(membership_ref_sets.size() == partial_tx.m_image_address_masks.size(),
        "Input components size mismatch");
    CHECK_AND_ASSERT_THROW_MES(membership_ref_sets.size() == partial_tx.m_image_amount_masks.size(),
        "Input components size mismatch");

    tx_membership_proofs_out.clear();
    tx_membership_proofs_out.resize(membership_ref_sets.size());

    for (std::size_t input_index{0}; input_index < membership_ref_sets.size(); ++input_index)
    {
        make_v1_tx_membership_proof_sp_v1(membership_ref_sets[input_index],
            partial_tx.m_image_address_masks[input_index],
            partial_tx.m_image_amount_masks[input_index],
            tx_membership_proofs_out[input_index]);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_partial_inputs_sp_v1(const std::vector<SpInputProposalV1> &input_proposals,
    const rct::key &proposal_prefix,
    const SpTxProposalV1 &tx_proposal,
    std::vector<SpTxPartialInputV1> &partial_inputs_out)
{
    CHECK_AND_ASSERT_THROW_MES(input_proposals.size() > 0, "Can't make partial tx inputs without any input proposals");

    partial_inputs_out.clear();
    partial_inputs_out.reserve(input_proposals.size());

    // make all inputs
    for (const auto &input_proposal : input_proposals)
        partial_inputs_out.emplace_back(input_proposal, proposal_prefix);
}
//-------------------------------------------------------------------------------------------------------------------
bool balance_check_in_out_amnts_sp_v1(const std::vector<SpInputProposalV1> &input_proposals,
    const std::vector<SpDestinationV1> &destinations,
    const rct::xmr_amount transaction_fee)
{
    std::vector<rct::xmr_amount> in_amounts;
    std::vector<rct::xmr_amount> out_amounts;
    in_amounts.reserve(input_proposals.size());
    out_amounts.reserve(destinations.size() + 1);

    for (const auto &input_proposal : input_proposals)
    {
        in_amounts.emplace_back(input_proposal.m_amount);
    }
    for (const auto &destination : destinations)
    {
        out_amounts.emplace_back(destination.m_amount);
    }

    out_amounts.emplace_back(transaction_fee);

    return balance_check_in_out_amnts(in_amounts, out_amounts);
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<SpInputProposalV1> gen_mock_sp_input_proposals_v1(const std::vector<rct::xmr_amount> in_amounts)
{
    // generate random inputs
    std::vector<SpInputProposalV1> input_proposals;
    input_proposals.resize(in_amounts.size());

    for (std::size_t input_index{0}; input_index < in_amounts.size(); ++input_index)
    {
        input_proposals[input_index].gen(in_amounts[input_index]);
    }

    return input_proposals;
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<SpMembershipReferenceSetV1> gen_mock_sp_membership_ref_sets_v1(
    const std::vector<SpInputProposalV1> &input_proposals,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    std::shared_ptr<MockLedgerContext> ledger_context_inout)
{
    // for squashed enote model

    std::vector<SpENoteV1> input_enotes;
    input_enotes.reserve(input_proposals.size());

    for (const auto &input_proposal : input_proposals)
    {
        input_enotes.emplace_back(input_proposal.m_enote);
    }

    return gen_mock_sp_membership_ref_sets_v1(input_enotes, ref_set_decomp_n, ref_set_decomp_m, ledger_context_inout);
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<SpMembershipReferenceSetV1> gen_mock_sp_membership_ref_sets_v1(
    const std::vector<SpENoteV1> &input_enotes,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    std::shared_ptr<MockLedgerContext> ledger_context_inout)
{
    // for squashed enote model

    std::vector<SpMembershipReferenceSetV1> reference_sets;
    reference_sets.resize(input_enotes.size());

    std::size_t ref_set_size{ref_set_size_from_decomp(ref_set_decomp_n, ref_set_decomp_m)};  // n^m

    for (std::size_t input_index{0}; input_index < input_enotes.size(); ++input_index)
    {
        reference_sets[input_index].m_ref_set_decomp_n = ref_set_decomp_n;
        reference_sets[input_index].m_ref_set_decomp_m = ref_set_decomp_m;
        reference_sets[input_index].m_real_spend_index_in_set = crypto::rand_idx(ref_set_size);  // pi

        reference_sets[input_index].m_ledger_enote_indices.resize(ref_set_size);
        reference_sets[input_index].m_referenced_enotes.resize(ref_set_size);

        for (std::size_t ref_index{0}; ref_index < ref_set_size; ++ref_index)
        {
            // add real input at pi
            if (ref_index == reference_sets[input_index].m_real_spend_index_in_set)
            {
                reference_sets[input_index].m_referenced_enotes[ref_index] = input_enotes[input_index];
            }
            // add dummy enote
            else
            {
                reference_sets[input_index].m_referenced_enotes[ref_index].gen();
            }

            // insert referenced enote into mock ledger (also, record squashed enote)
            // note: in a real context, you would instead 'get' the enote's index from the ledger, and error if not found
            reference_sets[input_index].m_ledger_enote_indices[ref_index] =
                ledger_context_inout->add_enote_sp_v1(reference_sets[input_index].m_referenced_enotes[ref_index]);
        }
    }

    return reference_sets;
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<SpDestinationV1> gen_mock_sp_destinations_v1(const std::vector<rct::xmr_amount> &out_amounts)
{
    // randomize destination order
    std::vector<rct::xmr_amount> randomized_out_amounts{out_amounts};
    std::shuffle(randomized_out_amounts.begin(), randomized_out_amounts.end(), crypto::random_device{});

    // generate random destinations
    std::vector<SpDestinationV1> destinations;
    destinations.resize(randomized_out_amounts.size());

    for (std::size_t dest_index{0}; dest_index < randomized_out_amounts.size(); ++dest_index)
    {
        destinations[dest_index].gen(randomized_out_amounts[dest_index]);
    }

    return destinations;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
