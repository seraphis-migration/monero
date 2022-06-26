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
#include "tx_builders_inputs.h"

//local headers
#include "common/varint.h"
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_config.h"
#include "grootle.h"
#include "jamtis_enote_utils.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "mock_ledger_context.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_config_temp.h"
#include "sp_composition_proof.h"
#include "sp_core_enote_utils.h"
#include "sp_crypto_utils.h"
#include "sp_hash_functions.h"
#include "sp_transcript.h"
#include "tx_binned_reference_set.h"
#include "tx_binned_reference_set_utils.h"
#include "tx_builder_types.h"
#include "tx_component_types.h"
#include "tx_misc_utils.h"
#include "tx_enote_record_types.h"
#include "tx_enote_record_utils.h"
#include "tx_ref_set_index_mapper_flat.h"

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
void make_binned_ref_set_generator_seed_v1(const rct::key &masked_address,
    const rct::key &masked_commitment,
    rct::key &generator_seed_out)
{
    // make binned reference set generator seed
    static const std::string domain_separator{config::HASH_KEY_BINNED_REF_SET_GENERATOR_SEED};

    // seed = H_32(K", C")
    SpTranscript transcript{domain_separator, 2*sizeof(rct::key)};
    transcript.append("K_masked", masked_address);
    transcript.append("C_masked", masked_commitment);

    // hash to the result
    sp_hash_to_32(transcript, generator_seed_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void make_binned_ref_set_generator_seed_v1(const rct::key &onetime_address,
    const rct::key &amount_commitment,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    rct::key &generator_seed_out)
{
    // make binned reference set generator seed from pieces

    // masked address and commitment
    rct::key masked_address;     //K" = t_k G + H_n(Ko,C) Ko
    rct::key masked_commitment;  //C" = t_c G + C
    make_seraphis_enote_image_masked_keys(onetime_address,
        amount_commitment,
        address_mask,
        commitment_mask,
        masked_address,
        masked_commitment);

    // finish making the seed
    make_binned_ref_set_generator_seed_v1(masked_address, masked_commitment, generator_seed_out);
}
//-------------------------------------------------------------------------------------------------------------------
void align_v1_membership_proofs_v1(const std::vector<SpEnoteImageV1> &input_images,
    std::vector<SpAlignableMembershipProofV1> alignable_membership_proofs,
    std::vector<SpMembershipProofV1> &membership_proofs_out)
{
    CHECK_AND_ASSERT_THROW_MES(alignable_membership_proofs.size() == input_images.size(),
        "Mismatch between alignable membership proof count and partial tx input image count.");

    membership_proofs_out.clear();
    membership_proofs_out.reserve(alignable_membership_proofs.size());

    for (const SpEnoteImageV1 &input_image : input_images)
    {
        // find the membership proof that matches with the input image at this index
        auto membership_proof_match =
            std::find(
                alignable_membership_proofs.begin(),
                alignable_membership_proofs.end(),
                input_image.m_core.m_masked_address
            );

        CHECK_AND_ASSERT_THROW_MES(membership_proof_match != alignable_membership_proofs.end(),
            "Could not find input image to match with an alignable membership proof.");

        membership_proofs_out.emplace_back(std::move(membership_proof_match->m_membership_proof));
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_tx_membership_proof_message_v1(const SpBinnedReferenceSetV1 &binned_reference_set, rct::key &message_out)
{
    static const std::string domain_separator{config::HASH_KEY_SERAPHIS_MEMBERSHIP_PROOF_MESSAGE};
    static const std::string project_name{CRYPTONOTE_NAME};

    // m = H_32('project name', {binned reference set})
    SpTranscript transcript{
            domain_separator,
            project_name.size() +
                binned_reference_set.get_size_bytes(true) +
                SpBinnedReferenceSetConfigV1::get_size_bytes()
        };
    transcript.append("project_name", project_name);  //i.e. referenced enotes are members of what project's ledger?
    transcript.append("binned_reference_set", binned_reference_set);

    sp_hash_to_32(transcript, message_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void prepare_input_commitment_factors_for_balance_proof_v1(
    const std::vector<SpInputProposalV1> &input_proposals,
    const std::vector<crypto::secret_key> &image_amount_masks,
    std::vector<rct::xmr_amount> &input_amounts_out,
    std::vector<crypto::secret_key> &blinding_factors_out)
{
    // use input proposals and image amount masks to get amounts/blinding factors
    CHECK_AND_ASSERT_THROW_MES(input_proposals.size() == image_amount_masks.size(),
        "Mismatch between input proposals and image address masks.");

    blinding_factors_out.clear();
    input_amounts_out.clear();
    blinding_factors_out.resize(input_proposals.size());
    input_amounts_out.reserve(input_proposals.size());

    for (std::size_t input_index{0}; input_index < input_proposals.size(); ++input_index)
    {
        // input image amount commitment blinding factor: t_c + x
        sc_add(to_bytes(blinding_factors_out[input_index]),
            to_bytes(image_amount_masks[input_index]),  // t_c
            to_bytes(input_proposals[input_index].m_core.m_amount_blinding_factor));  // x

        // input amount: a
        input_amounts_out.emplace_back(input_proposals[input_index].get_amount());
    }
}
//-------------------------------------------------------------------------------------------------------------------
void prepare_input_commitment_factors_for_balance_proof_v1(
    const std::vector<SpPartialInputV1> &partial_inputs,
    std::vector<rct::xmr_amount> &input_amounts_out,
    std::vector<crypto::secret_key> &blinding_factors_out)
{
    // use partial inputs to get amounts/blinding factors
    blinding_factors_out.clear();
    input_amounts_out.clear();
    blinding_factors_out.resize(partial_inputs.size());
    input_amounts_out.reserve(partial_inputs.size());

    for (std::size_t input_index{0}; input_index < partial_inputs.size(); ++input_index)
    {
        // input image amount commitment blinding factor: t_c + x
        sc_add(to_bytes(blinding_factors_out[input_index]),
            to_bytes(partial_inputs[input_index].m_commitment_mask),  // t_c
            to_bytes(partial_inputs[input_index].m_input_amount_blinding_factor));  // x

        // input amount: a
        input_amounts_out.emplace_back(partial_inputs[input_index].m_input_amount);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_input_images_prefix_v1(const std::vector<SpEnoteImageV1> &enote_images, rct::key &input_images_prefix_out)
{
    static const std::string domain_separator{config::HASH_KEY_SERAPHIS_INPUT_IMAGES_PREFIX_V1};

    // input images prefix = H_32({K", C", KI})
    SpTranscript transcript{domain_separator, enote_images.size()*SpEnoteImageV1::get_size_bytes()};
    transcript.append("enote_images", enote_images);

    sp_hash_to_32(transcript, input_images_prefix_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_input_proposal_semantics_v1(const SpInputProposalV1 &input_proposal,
    const rct::key &wallet_spend_pubkey_base)
{
    // 1. the onetime address must be reproducible
    rct::key onetime_address_reproduced{wallet_spend_pubkey_base};
    extend_seraphis_spendkey(input_proposal.m_core.m_enote_view_privkey, onetime_address_reproduced);

    CHECK_AND_ASSERT_THROW_MES(onetime_address_reproduced == input_proposal.m_core.m_enote_core.m_onetime_address,
        "input proposal v1 semantics check: could not reproduce the one-time address.");

    // 2. the key image must be reproducible and canonical
    crypto::key_image key_image_reproduced;
    make_seraphis_key_image(input_proposal.m_core.m_enote_view_privkey,
        rct::rct2pk(wallet_spend_pubkey_base),
        key_image_reproduced);

    CHECK_AND_ASSERT_THROW_MES(key_image_reproduced == input_proposal.m_core.m_key_image,
        "input proposal v1 semantics check: could not reproduce the key image.");
    CHECK_AND_ASSERT_THROW_MES(key_domain_is_prime_subgroup(rct::ki2rct(key_image_reproduced)),
        "input proposal v1 semantics check: the key image is not canonical.");

    // 3. the amount commitment must be reproducible
    const rct::key amount_commitment_reproduced{
            rct::commit(input_proposal.m_core.m_amount, rct::sk2rct(input_proposal.m_core.m_amount_blinding_factor))
        };

    CHECK_AND_ASSERT_THROW_MES(amount_commitment_reproduced == input_proposal.m_core.m_enote_core.m_amount_commitment,
        "input proposal v1 semantics check: could not reproduce the amount commitment.");
}
//-------------------------------------------------------------------------------------------------------------------
void make_input_proposal(const SpEnote &enote_core,
    const crypto::key_image &key_image,
    const crypto::secret_key &enote_view_privkey,
    const crypto::secret_key &input_amount_blinding_factor,
    const rct::xmr_amount &input_amount,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpInputProposal &proposal_out)
{
    // make an input proposal
    proposal_out.m_enote_core             = enote_core;
    proposal_out.m_key_image              = key_image;
    proposal_out.m_enote_view_privkey     = enote_view_privkey;
    proposal_out.m_amount_blinding_factor = input_amount_blinding_factor;
    proposal_out.m_amount                 = input_amount;
    proposal_out.m_address_mask           = address_mask;
    proposal_out.m_commitment_mask        = commitment_mask;
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_input_proposal_v1(const SpEnoteRecordV1 &enote_record,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpInputProposalV1 &proposal_out)
{
    // make input proposal from enote record
    make_input_proposal(enote_record.m_enote.m_core,
        enote_record.m_key_image,
        enote_record.m_enote_view_privkey,
        enote_record.m_amount_blinding_factor,
        enote_record.m_amount,
        address_mask,
        commitment_mask,
        proposal_out.m_core);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_make_v1_input_proposal_v1(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpInputProposalV1 &proposal_out)
{
    // try to extract info from enote then make an input proposal
    SpEnoteRecordV1 enote_record;
    if (!try_get_enote_record_v1(enote,
            enote_ephemeral_pubkey,
            input_context,
            wallet_spend_pubkey,
            k_view_balance,
            enote_record))
        return false;

    make_v1_input_proposal_v1(enote_record, address_mask, commitment_mask, proposal_out);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void make_standard_input_context_v1(const std::vector<SpInputProposalV1> &input_proposals, rct::key &input_context_out)
{
    // collect key images
    std::vector<crypto::key_image> key_images;

    for (const SpInputProposalV1 &input_proposal : input_proposals)
    {
        key_images.emplace_back();
        input_proposal.m_core.get_key_image(key_images.back());
    }

    // sort the key images
    std::sort(key_images.begin(), key_images.end());

    // make the input context
    jamtis::make_jamtis_input_context_standard(key_images, input_context_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_image_proof_v1(const SpInputProposal &input_proposal,
    const rct::key &message,
    const crypto::secret_key &spendbase_privkey,
    SpImageProofV1 &image_proof_out)
{
    // make image proof

    // the input enote
    SpEnote input_enote_core;
    input_proposal.get_enote_core(input_enote_core);

    // the input enote image
    SpEnoteImage input_enote_image_core;
    input_proposal.get_enote_image_core(input_enote_image_core);

    // prepare for proof (squashed enote model): y, z
    crypto::secret_key squash_prefix;
    make_seraphis_squash_prefix(input_enote_core.m_onetime_address,
        input_enote_core.m_amount_commitment,
        squash_prefix);  // H_n(Ko,C)

    // H_n(Ko,C) (k_{a, recipient} + k_{a, sender})
    crypto::secret_key y;
    sc_mul(to_bytes(y), to_bytes(squash_prefix), to_bytes(input_proposal.m_enote_view_privkey));
    // H_n(Ko,C) k_{b, recipient}
    crypto::secret_key z;
    sc_mul(to_bytes(z), to_bytes(squash_prefix), to_bytes(spendbase_privkey));

    // make seraphis composition proof
    image_proof_out.m_composition_proof =
        sp_composition_prove(message, input_enote_image_core.m_masked_address, input_proposal.m_address_mask, y, z);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_image_proofs_v1(const std::vector<SpInputProposalV1> &input_proposals,
    const rct::key &message,
    const crypto::secret_key &spendbase_privkey,
    std::vector<SpImageProofV1> &image_proofs_out)
{
    // make multiple image proofs
    CHECK_AND_ASSERT_THROW_MES(input_proposals.size() > 0, "Tried to make image proofs for 0 inputs.");

    image_proofs_out.clear();
    image_proofs_out.reserve(input_proposals.size());

    for (const SpInputProposalV1 &input_proposal : input_proposals)
    {
        image_proofs_out.emplace_back();
        make_v1_image_proof_v1(input_proposal.m_core, message, spendbase_privkey, image_proofs_out.back());
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_membership_proof_v1(const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    SpBinnedReferenceSetV1 binned_reference_set,
    const std::vector<rct::key> &referenced_enotes_squashed,
    const SpEnote &real_reference_enote,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpMembershipProofV1 &membership_proof_out)
{
    // make membership proof

    /// checks and initialization

    // misc
    const std::size_t ref_set_size{ref_set_size_from_decomp(ref_set_decomp_n, ref_set_decomp_m)};

    CHECK_AND_ASSERT_THROW_MES(referenced_enotes_squashed.size() == ref_set_size,
        "make membership proof: ref set size doesn't match number of referenced enotes.");
    CHECK_AND_ASSERT_THROW_MES(binned_reference_set.reference_set_size() == ref_set_size,
        "make membership proof: ref set size doesn't number of references in the binned reference set.");

    // make the real reference's squashed representation for later
    rct::key transformed_address;
    make_seraphis_squashed_address_key(real_reference_enote.m_onetime_address,
        real_reference_enote.m_amount_commitment,
        transformed_address);  //H_n(Ko,C) Ko

    rct::key real_Q;
    rct::addKeys(real_Q, transformed_address, real_reference_enote.m_amount_commitment);  //Hn(Ko, C) Ko + C

    // check binned reference set generator
    rct::key masked_address;
    mask_key(address_mask, transformed_address, masked_address);  //K" = t_k G + H_n(Ko,C) Ko

    rct::key masked_commitment;
    mask_key(commitment_mask, real_reference_enote.m_amount_commitment, masked_commitment);  //C" = t_c G + C

    rct::key generator_seed_reproduced;
    make_binned_ref_set_generator_seed_v1(masked_address, masked_commitment, generator_seed_reproduced);

    CHECK_AND_ASSERT_THROW_MES(generator_seed_reproduced == binned_reference_set.m_bin_generator_seed,
        "make membership proof: unable to reproduce binned reference set generator seed.");


    /// prepare to make proof

    // find the real referenced enote
    std::size_t real_spend_index_in_set{};  //l
    bool found_real{false};

    for (std::size_t ref_index{0}; ref_index < ref_set_size; ++ref_index)
    {
        if (real_Q == referenced_enotes_squashed[ref_index])  //Q[l]
        {
            real_spend_index_in_set = ref_index;
            found_real = true;
            break;
        }
    }
    CHECK_AND_ASSERT_THROW_MES(found_real,
        "make membership proof: could not find enote for membership proof in reference set.");

    // proof offset (only one in the squashed enote model)
    const rct::key image_offset{rct::addKeys(masked_address, masked_commitment)};  //Q" = K" + C"

    // secret key of: Q[l] - Q" = -(t_k + t_c) G
    crypto::secret_key image_mask;
    sc_add(to_bytes(image_mask), to_bytes(address_mask), to_bytes(commitment_mask));  // t_k + t_c
    sc_mul(to_bytes(image_mask), to_bytes(image_mask), MINUS_ONE.bytes);  // -(t_k + t_c)

    // proof message
    rct::key message;
    make_tx_membership_proof_message_v1(binned_reference_set, message);


    /// make grootle proof
    membership_proof_out.m_grootle_proof = grootle_prove(referenced_enotes_squashed,
        real_spend_index_in_set,
        image_offset,
        image_mask,
        ref_set_decomp_n,
        ref_set_decomp_m,
        message);


    /// copy miscellaneous components
    membership_proof_out.m_binned_reference_set = std::move(binned_reference_set);
    membership_proof_out.m_ref_set_decomp_n     = ref_set_decomp_n;
    membership_proof_out.m_ref_set_decomp_m     = ref_set_decomp_m;
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_membership_proof_v1(SpMembershipProofPrepV1 membership_proof_prep, SpMembershipProofV1 &membership_proof_out)
{
    make_v1_membership_proof_v1(membership_proof_prep.m_ref_set_decomp_n,
        membership_proof_prep.m_ref_set_decomp_m,
        std::move(membership_proof_prep.m_binned_reference_set),
        membership_proof_prep.m_referenced_enotes_squashed,
        membership_proof_prep.m_real_reference_enote,
        membership_proof_prep.m_address_mask,
        membership_proof_prep.m_commitment_mask,
        membership_proof_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_membership_proof_v1(SpMembershipProofPrepV1 membership_proof_prep,
    SpAlignableMembershipProofV1 &alignable_membership_proof_out)
{
    // make alignable membership proof

    // save the masked address to later match the membership proof with its input image
    make_seraphis_squashed_address_key(
        membership_proof_prep.m_real_reference_enote.m_onetime_address,
        membership_proof_prep.m_real_reference_enote.m_amount_commitment,
        alignable_membership_proof_out.m_masked_address);  //H_n(Ko,C) Ko

    mask_key(membership_proof_prep.m_address_mask,
        alignable_membership_proof_out.m_masked_address,
        alignable_membership_proof_out.m_masked_address);  //t_k G + H_n(Ko,C) Ko

    // make the membership proof
    make_v1_membership_proof_v1(std::move(membership_proof_prep), alignable_membership_proof_out.m_membership_proof);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_membership_proofs_v1(std::vector<SpMembershipProofPrepV1> membership_proof_preps,
    std::vector<SpMembershipProofV1> &membership_proofs_out)
{
    // make multiple membership proofs
    // note: proof preps are assumed to be pre-sorted, so alignable membership proofs are not needed
    membership_proofs_out.clear();
    membership_proofs_out.reserve(membership_proof_preps.size());

    for (SpMembershipProofPrepV1 &proof_prep : membership_proof_preps)
    {
        membership_proofs_out.emplace_back();
        make_v1_membership_proof_v1(std::move(proof_prep), membership_proofs_out.back());
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_membership_proofs_v1(std::vector<SpMembershipProofPrepV1> membership_proof_preps,
    std::vector<SpAlignableMembershipProofV1> &alignable_membership_proofs_out)
{
    // make multiple alignable membership proofs
    alignable_membership_proofs_out.clear();
    alignable_membership_proofs_out.reserve(membership_proof_preps.size());

    for (SpMembershipProofPrepV1 &proof_prep : membership_proof_preps)
    {
        alignable_membership_proofs_out.emplace_back();
        make_v1_membership_proof_v1(std::move(proof_prep), alignable_membership_proofs_out.back());
    }
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_partial_input_semantics_v1(const SpPartialInputV1 &partial_input)
{
    // input amount commitment can be reconstructed
    const rct::key reconstructed_amount_commitment{
            rct::commit(partial_input.m_input_amount, rct::sk2rct(partial_input.m_input_amount_blinding_factor))
        };

    CHECK_AND_ASSERT_THROW_MES(reconstructed_amount_commitment == partial_input.m_input_enote_core.m_amount_commitment,
        "partial input semantics (v1): could not reconstruct amount commitment.");

    // input image masked address and commitment can be reconstructed
    rct::key reconstructed_masked_address;
    rct::key reconstructed_masked_commitment;
    make_seraphis_enote_image_masked_keys(partial_input.m_input_enote_core.m_onetime_address,
        partial_input.m_input_enote_core.m_amount_commitment,
        partial_input.m_address_mask,
        partial_input.m_commitment_mask,
        reconstructed_masked_address,
        reconstructed_masked_commitment);

    CHECK_AND_ASSERT_THROW_MES(reconstructed_masked_address == partial_input.m_input_image.m_core.m_masked_address,
        "partial input semantics (v1): could not reconstruct masked address.");
    CHECK_AND_ASSERT_THROW_MES(reconstructed_masked_commitment == partial_input.m_input_image.m_core.m_masked_commitment,
        "partial input semantics (v1): could not reconstruct masked address.");

    // image proof is valid
    CHECK_AND_ASSERT_THROW_MES(sp_composition_verify(partial_input.m_image_proof.m_composition_proof,
            partial_input.m_proposal_prefix,
            reconstructed_masked_address,
            partial_input.m_input_image.m_core.m_key_image),
        "partial input semantics (v1): image proof is invalid.");
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_partial_input_v1(const SpInputProposalV1 &input_proposal,
    const rct::key &proposal_prefix,
    const crypto::secret_key &spendbase_privkey,
    SpPartialInputV1 &partial_input_out)
{
    // check input proposal semantics
    rct::key wallet_spend_pubkey_base;
    make_seraphis_spendbase(spendbase_privkey, wallet_spend_pubkey_base);

    check_v1_input_proposal_semantics_v1(input_proposal, wallet_spend_pubkey_base);

    // prepare input image
    input_proposal.get_enote_image_v1(partial_input_out.m_input_image);

    // copy misc. proposal info
    partial_input_out.m_address_mask                 = input_proposal.m_core.m_address_mask;
    partial_input_out.m_commitment_mask              = input_proposal.m_core.m_commitment_mask;
    partial_input_out.m_proposal_prefix              = proposal_prefix;
    partial_input_out.m_input_amount                 = input_proposal.get_amount();
    partial_input_out.m_input_amount_blinding_factor = input_proposal.m_core.m_amount_blinding_factor;
    input_proposal.m_core.get_enote_core(partial_input_out.m_input_enote_core);

    // construct image proof
    make_v1_image_proof_v1(input_proposal.m_core,
        partial_input_out.m_proposal_prefix,
        spendbase_privkey,
        partial_input_out.m_image_proof);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_partial_inputs_v1(const std::vector<SpInputProposalV1> &input_proposals,
    const rct::key &proposal_prefix,
    const crypto::secret_key &spendbase_privkey,
    std::vector<SpPartialInputV1> &partial_inputs_out)
{
    CHECK_AND_ASSERT_THROW_MES(input_proposals.size() > 0, "Can't make partial tx inputs without any input proposals.");

    partial_inputs_out.clear();
    partial_inputs_out.reserve(input_proposals.size());

    // make all inputs
    for (const SpInputProposalV1 &input_proposal : input_proposals)
    {
        partial_inputs_out.emplace_back();
        make_v1_partial_input_v1(input_proposal, proposal_prefix, spendbase_privkey, partial_inputs_out.back());
    }
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<SpInputProposalV1> gen_mock_sp_input_proposals_v1(const crypto::secret_key &spendbase_privkey,
    const std::vector<rct::xmr_amount> in_amounts)
{
    // generate random inputs
    std::vector<SpInputProposalV1> input_proposals;
    input_proposals.reserve(in_amounts.size());

    for (const rct::xmr_amount in_amount : in_amounts)
    {
        input_proposals.emplace_back();
        input_proposals.back().gen(spendbase_privkey, in_amount);
    }

    return input_proposals;
}
//-------------------------------------------------------------------------------------------------------------------
SpMembershipProofPrepV1 gen_mock_sp_membership_proof_prep_for_enote_at_pos_v1(const SpEnote &real_reference_enote,
    const std::uint64_t &real_reference_index_in_ledger,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    const MockLedgerContext &ledger_context)
{
    // generate a mock membership proof prep

    /// checks and initialization
    const std::size_t ref_set_size{ref_set_size_from_decomp(ref_set_decomp_n, ref_set_decomp_m)};  // n^m

    CHECK_AND_ASSERT_THROW_MES(check_bin_config_v1(ref_set_size, bin_config),
        "gen mock membership proof prep: invalid binned reference set config.");


    /// make binned reference set
    SpMembershipProofPrepV1 proof_prep;

    // 1) flat index mapper for mock-up
    const SpRefSetIndexMapperFlat flat_index_mapper{
            ledger_context.min_enote_index(),
            ledger_context.max_enote_index()
        };

    // 2) generator seed
    rct::key generator_seed;
    make_binned_ref_set_generator_seed_v1(real_reference_enote.m_onetime_address,
        real_reference_enote.m_amount_commitment,
        address_mask,
        commitment_mask,
        generator_seed);

    // 3) binned reference set
    make_binned_reference_set_v1(flat_index_mapper,
        bin_config,
        generator_seed,
        ref_set_size,
        real_reference_index_in_ledger,
        proof_prep.m_binned_reference_set);


    /// copy all referenced enotes from the ledger (in squashed enote representation)
    std::vector<std::uint64_t> reference_indices;
    CHECK_AND_ASSERT_THROW_MES(try_get_reference_indices_from_binned_reference_set_v1(proof_prep.m_binned_reference_set,
            reference_indices),
        "gen mock membership proof prep: could not extract reference indices from binned representation (bug).");

    ledger_context.get_reference_set_proof_elements_v1(reference_indices, proof_prep.m_referenced_enotes_squashed);


    /// copy misc pieces
    proof_prep.m_ref_set_decomp_n = ref_set_decomp_n;
    proof_prep.m_ref_set_decomp_m = ref_set_decomp_m;
    proof_prep.m_real_reference_enote = real_reference_enote;
    proof_prep.m_address_mask = address_mask;
    proof_prep.m_commitment_mask = commitment_mask;

    return proof_prep;
}
//-------------------------------------------------------------------------------------------------------------------
SpMembershipProofPrepV1 gen_mock_sp_membership_proof_prep_v1(
    const SpEnote &real_reference_enote,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    MockLedgerContext &ledger_context_inout)
{
    // generate a mock membership proof prep

    /// add fake enotes to the ledger (2x the ref set size), with the real one at a random location

    // 1. make fake enotes
    const std::size_t ref_set_size{ref_set_size_from_decomp(ref_set_decomp_n, ref_set_decomp_m)};  // n^m
    const std::size_t num_enotes_to_add{ref_set_size * 2};
    const std::size_t add_real_at_pos{crypto::rand_idx(num_enotes_to_add)};
    std::vector<SpEnoteV1> mock_enotes;
    mock_enotes.reserve(num_enotes_to_add);

    for (std::size_t enote_to_add{0}; enote_to_add < num_enotes_to_add; ++enote_to_add)
    {
        mock_enotes.emplace_back();

        if (enote_to_add == add_real_at_pos)
            mock_enotes.back().m_core = real_reference_enote;
        else
            mock_enotes.back().gen();
    }

    // 2. clear any txs lingering unconfirmed
    ledger_context_inout.commit_unconfirmed_txs_v1(rct::pkGen(), SpTxSupplementV1{}, std::vector<SpEnoteV1>{});

    // 3. add mock enotes as the outputs of a mock coinbase tx
    const std::uint64_t real_reference_index_in_ledger{ledger_context_inout.max_enote_index() + add_real_at_pos + 1};
    ledger_context_inout.commit_unconfirmed_txs_v1(rct::pkGen(), SpTxSupplementV1{}, std::move(mock_enotes));


    /// finish making the proof prep
    return gen_mock_sp_membership_proof_prep_for_enote_at_pos_v1(real_reference_enote,
        real_reference_index_in_ledger,
        address_mask,
        commitment_mask,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context_inout);
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<SpMembershipProofPrepV1> gen_mock_sp_membership_proof_preps_v1(
    const std::vector<SpEnote> &real_referenced_enotes,
    const std::vector<crypto::secret_key> &address_masks,
    const std::vector<crypto::secret_key> &commitment_masks,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    MockLedgerContext &ledger_context_inout)
{
    // make mock membership ref sets from input enotes
    CHECK_AND_ASSERT_THROW_MES(real_referenced_enotes.size() == address_masks.size(),
        "gen mock membership proof preps: input enotes don't line up with address masks.");
    CHECK_AND_ASSERT_THROW_MES(real_referenced_enotes.size() == commitment_masks.size(),
        "gen mock membership proof preps: input enotes don't line up with commitment masks.");

    std::vector<SpMembershipProofPrepV1> proof_preps;
    proof_preps.reserve(real_referenced_enotes.size());

    for (std::size_t input_index{0}; input_index < real_referenced_enotes.size(); ++input_index)
    {
        proof_preps.emplace_back(
                gen_mock_sp_membership_proof_prep_v1(real_referenced_enotes[input_index],
                    address_masks[input_index],
                    commitment_masks[input_index],
                    ref_set_decomp_n,
                    ref_set_decomp_m,
                    bin_config,
                    ledger_context_inout)
            );
    }

    return proof_preps;
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<SpMembershipProofPrepV1> gen_mock_sp_membership_proof_preps_v1(
    const std::vector<SpInputProposalV1> &input_proposals,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    MockLedgerContext &ledger_context_inout)
{
    // make mock membership ref sets from input proposals
    std::vector<SpEnote> input_enotes;
    std::vector<crypto::secret_key> address_masks;
    std::vector<crypto::secret_key> commitment_masks;
    input_enotes.reserve(input_proposals.size());

    for (const SpInputProposalV1 &input_proposal : input_proposals)
    {
        input_enotes.emplace_back();
        input_proposal.m_core.get_enote_core(input_enotes.back());

        address_masks.emplace_back(input_proposal.m_core.m_address_mask);
        commitment_masks.emplace_back(input_proposal.m_core.m_commitment_mask);
    }

    return gen_mock_sp_membership_proof_preps_v1(input_enotes,
        address_masks,
        commitment_masks,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context_inout);
}
//-------------------------------------------------------------------------------------------------------------------
void make_mock_sp_membership_proof_preps_for_inputs_v1(
    const std::unordered_map<crypto::key_image, std::uint64_t> &input_ledger_mappings,
    const std::vector<SpInputProposalV1> &input_proposals,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    const MockLedgerContext &ledger_context,
    std::vector<SpMembershipProofPrepV1> &membership_proof_preps_out)
{
    CHECK_AND_ASSERT_THROW_MES(input_ledger_mappings.size() == input_proposals.size(),
        "make mock membership proof preps: input proposals don't line up with their enotes' ledger indices.");

    membership_proof_preps_out.clear();
    membership_proof_preps_out.reserve(input_proposals.size());

    for (const SpInputProposalV1 &input_proposal : input_proposals)
    {
        CHECK_AND_ASSERT_THROW_MES(
                input_ledger_mappings.find(input_proposal.m_core.m_key_image) != input_ledger_mappings.end(),
            "make mock membership proof preps: the enote ledger indices map is missing an expected key image.");

        membership_proof_preps_out.emplace_back(
                gen_mock_sp_membership_proof_prep_for_enote_at_pos_v1(input_proposal.m_core.m_enote_core,
                        input_ledger_mappings.at(input_proposal.m_core.m_key_image),
                        input_proposal.m_core.m_address_mask,
                        input_proposal.m_core.m_commitment_mask,
                        ref_set_decomp_n,
                        ref_set_decomp_m,
                        bin_config,
                        ledger_context)
            );
    }
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
