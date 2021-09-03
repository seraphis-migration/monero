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
#include "tx_builders_multisig.h"

//local headers
#include "common/container_helpers.h"
#include "contextual_enote_record_utils.h"
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "crypto/generators.h"
#include "cryptonote_basic/subaddress_index.h"
#include "cryptonote_config.h"
#include "device/device.hpp"
#include "enote_record_types.h"
#include "enote_record_utils.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "multisig/multisig_clsag.h"
#include "multisig/multisig_nonce_cache.h"
#include "multisig/multisig_partial_sig_makers.h"
#include "multisig/multisig_signer_set_filter.h"
#include "multisig/multisig_signing_helper_types.h"
#include "multisig/multisig_signing_helper_utils.h"
#include "multisig/multisig_sp_composition_proof.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/discretized_fee.h"
#include "seraphis_core/jamtis_address_utils.h"
#include "seraphis_core/jamtis_core_utils.h"
#include "seraphis_core/jamtis_enote_utils.h"
#include "seraphis_core/legacy_core_utils.h"
#include "seraphis_core/sp_core_enote_utils.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "tx_builder_types.h"
#include "tx_builder_types_legacy.h"
#include "tx_builder_types_multisig.h"
#include "tx_builders_inputs.h"
#include "tx_builders_legacy_inputs.h"
#include "tx_builders_mixed.h"
#include "tx_builders_outputs.h"
#include "tx_component_types.h"
#include "txtype_base.h"

//third party headers

//standard headers
#include <list>
#include <unordered_map>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
// legacy proof contexts: [ legacy Ko : legacy input message ]
//-------------------------------------------------------------------------------------------------------------------
static void get_legacy_proof_contexts_v1(const rct::key &tx_proposal_prefix,
    const std::vector<LegacyMultisigInputProposalV1> &legacy_multisig_input_proposals,
    std::unordered_map<rct::key, rct::key> &proof_contexts_out)  //[ proof key : proof message ]
{
    proof_contexts_out.clear();
    proof_contexts_out.reserve(legacy_multisig_input_proposals.size());

    for (const LegacyMultisigInputProposalV1 &input_proposal : legacy_multisig_input_proposals)
    {
        make_tx_legacy_ring_signature_message_v1(tx_proposal_prefix,
            input_proposal.reference_set,
            proof_contexts_out[onetime_address_ref(input_proposal.enote)]);
    }
}
//-------------------------------------------------------------------------------------------------------------------
// seraphis proof contexts: [ seraphis K" : tx proposal prefix ]
//-------------------------------------------------------------------------------------------------------------------
static void get_seraphis_proof_contexts_v1(const rct::key &tx_proposal_prefix,
    const std::vector<SpInputProposalV1> &sp_input_proposals,
    std::unordered_map<rct::key, rct::key> &proof_contexts_out)  //[ proof key : proof message ]
{
    proof_contexts_out.clear();
    proof_contexts_out.reserve(sp_input_proposals.size());
    SpEnoteImageV1 enote_image_temp;

    for (const SpInputProposalV1 &input_proposal : sp_input_proposals)
    {
        get_enote_image_v1(input_proposal, enote_image_temp);
        proof_contexts_out[masked_address_ref(enote_image_temp)] = tx_proposal_prefix;
    }
}
//-------------------------------------------------------------------------------------------------------------------
// legacy proof base points: [ legacy Ko : {G, Hp(legacy Ko)} ]
//-------------------------------------------------------------------------------------------------------------------
static void get_legacy_proof_base_keys_v1(const std::vector<LegacyInputProposalV1> &legacy_input_proposals,
    std::unordered_map<rct::key, rct::keyV> &legacy_proof_key_base_points_out)
{
    legacy_proof_key_base_points_out.clear();
    legacy_proof_key_base_points_out.reserve(legacy_input_proposals.size());
    crypto::key_image KI_base_temp;

    for (const LegacyInputProposalV1 &input_proposal : legacy_input_proposals)
    {
        // Hp(Ko)
        crypto::generate_key_image(rct::rct2pk(input_proposal.onetime_address), rct::rct2sk(rct::I), KI_base_temp);

        // [ Ko : {G, Hp(Ko)} ]
        legacy_proof_key_base_points_out[input_proposal.onetime_address] =
            {
                rct::G,
                rct::ki2rct(KI_base_temp)
            };
    }
}
//-------------------------------------------------------------------------------------------------------------------
// seraphis proof keys: [ seraphis K" : {U} ]
//-------------------------------------------------------------------------------------------------------------------
static void get_sp_proof_base_keys_v1(const std::vector<SpInputProposalV1> &sp_input_proposals,
    std::unordered_map<rct::key, rct::keyV> &sp_proof_key_base_points_out)
{
    sp_proof_key_base_points_out.clear();
    sp_proof_key_base_points_out.reserve(sp_input_proposals.size());
    SpEnoteImageV1 enote_image_temp;

    for (const SpInputProposalV1 &input_proposal : sp_input_proposals)
    {
        get_enote_image_v1(input_proposal, enote_image_temp);
        sp_proof_key_base_points_out[masked_address_ref(enote_image_temp)] = {rct::pk2rct(crypto::get_U())};
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void check_semantics_legacy_multisig_input_material_v1(const rct::key &tx_proposal_prefix,
    const LegacyMultisigInputProposalV1 &multisig_input_proposal,
    const multisig::CLSAGMultisigProposal &input_proof_proposal)
{
    // 1. get legacy ring signature message
    rct::key message;
    make_tx_legacy_ring_signature_message_v1(tx_proposal_prefix, multisig_input_proposal.reference_set, message);

    // 2. input proof proposal message should equal the expected message
    CHECK_AND_ASSERT_THROW_MES(input_proof_proposal.message == message,
        "semantics check legacy multisig input material v1: legacy input proof proposal does not match the tx proposal "
        "(unknown proof message).");

    // 3. input proof proposal should match with the multisig input proposal
    CHECK_AND_ASSERT_THROW_MES(matches_with(multisig_input_proposal, input_proof_proposal),
        "semantics check legacy multisig input material v1: legacy multisig input proposal does not match input proof "
        "proposal.");

    // 4. input proof proposal should be well formed
    CHECK_AND_ASSERT_THROW_MES(input_proof_proposal.ring_members.size() ==
            input_proof_proposal.decoy_responses.size(),
        "semantics check legacy multisig input material v1: legacy input proof proposal has invalid number of decoy "
        "responses.");
    CHECK_AND_ASSERT_THROW_MES(input_proof_proposal.l < input_proof_proposal.ring_members.size(),
        "semantics check legacy multisig input material v1: legacy input proof proposal has out-of-range real index.");
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void check_semantics_sp_multisig_input_material_v1(const rct::key &tx_proposal_prefix,
    const SpInputProposalV1 &input_proposal,
    const multisig::SpCompositionProofMultisigProposal &input_proof_proposal)
{
    // 1. input proof proposal messages should all equal the specified tx proposal prefix
    CHECK_AND_ASSERT_THROW_MES(input_proof_proposal.message == tx_proposal_prefix,
        "semantics check seraphis multisig input material v1: sp input proof proposal does not match the tx proposal "
        "(different proposal prefix).");

    // 2. input proof proposal proof key should match with the input proposal
    SpEnoteImageV1 sp_enote_image;
    get_enote_image_v1(input_proposal, sp_enote_image);

    CHECK_AND_ASSERT_THROW_MES(input_proof_proposal.K == masked_address_ref(sp_enote_image),
        "semantics check seraphis multisig input material v1: sp input proof proposal does not match input proposal "
        "(different proof keys).");

    // 3. input proof proposal key image should match with the input proposal
    CHECK_AND_ASSERT_THROW_MES(input_proof_proposal.KI == key_image_ref(sp_enote_image),
        "semantics check seraphis multisig input material v1: sp input proof proposal does not match input proposal "
        "(different key images).");
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void replace_legacy_input_proposal_destination_for_tx_simulation_v1(
    const LegacyMultisigInputProposalV1 &multisig_input_proposal,
    const multisig::CLSAGMultisigProposal &input_proof_proposal,
    const crypto::secret_key &legacy_spend_privkey_mock,
    LegacyInputProposalV1 &input_proposal_inout,
    LegacyRingSignaturePrepV1 &legacy_ring_signature_prep_out)
{
    // 1. new onetime address privkey: k_view_stuff + k^s_mock
    crypto::secret_key legacy_onetime_address_privkey;
    sc_add(to_bytes(legacy_onetime_address_privkey),
        to_bytes(input_proposal_inout.enote_view_extension),
        to_bytes(legacy_spend_privkey_mock));

    // 2. replace the onetime address
    input_proposal_inout.onetime_address = rct::scalarmultBase(rct::sk2rct(legacy_onetime_address_privkey));

    // 3. update the key image for the new onetime address
    make_legacy_key_image(input_proposal_inout.enote_view_extension,
        legacy_spend_privkey_mock,
        input_proposal_inout.onetime_address,
        hw::get_device("default"),
        input_proposal_inout.key_image);

    // 4. make a legacy ring signature prep for this input
    legacy_ring_signature_prep_out =
        LegacyRingSignaturePrepV1{
                .tx_proposal_prefix        = rct::I, //set this later
                .reference_set             = multisig_input_proposal.reference_set,
                .referenced_enotes         = input_proof_proposal.ring_members,
                .real_reference_index      = input_proof_proposal.l,
                .reference_image           =
                    LegacyEnoteImageV2{
                            .masked_commitment = input_proof_proposal.masked_C,
                            .key_image         = input_proposal_inout.key_image
                        },
                .reference_view_privkey    = input_proposal_inout.enote_view_extension,
                .reference_commitment_mask = input_proposal_inout.commitment_mask
            };

    // 4. replace the real-spend enote's onetime address in the reference set
    legacy_ring_signature_prep_out
        .referenced_enotes.at(legacy_ring_signature_prep_out.real_reference_index)
        .dest = input_proposal_inout.onetime_address;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void replace_legacy_input_proposal_destinations_for_tx_simulation_v1(
    const std::vector<LegacyMultisigInputProposalV1> &multisig_input_proposals,
    const std::vector<multisig::CLSAGMultisigProposal> &input_proof_proposals,
    const crypto::secret_key &legacy_spend_privkey_mock,
    std::vector<LegacyInputProposalV1> &input_proposals_inout,
    std::vector<LegacyRingSignaturePrepV1> &legacy_ring_signature_preps_out)
{
    const std::size_t num_inputs{multisig_input_proposals.size()};
    CHECK_AND_ASSERT_THROW_MES(input_proof_proposals.size() == num_inputs,
        "replace legacy input proposal destinations for tx sim v1: proof proposals size mismatch.");
    CHECK_AND_ASSERT_THROW_MES(input_proposals_inout.size() == num_inputs,
        "replace legacy input proposal destinations for tx sim v1: initial proposals size mismatch.");

    // 1. update the input proposals and make ring signature preps from the updated context
    legacy_ring_signature_preps_out.clear();
    legacy_ring_signature_preps_out.reserve(num_inputs);

    for (std::size_t legacy_input_index{0}; legacy_input_index < num_inputs; ++legacy_input_index)
    {
        replace_legacy_input_proposal_destination_for_tx_simulation_v1(multisig_input_proposals[legacy_input_index],
            input_proof_proposals[legacy_input_index],
            legacy_spend_privkey_mock,
            input_proposals_inout[legacy_input_index],
            tools::add_element(legacy_ring_signature_preps_out));
    }

    // 2. repair legacy ring signature preps that may reference other preps' real enotes
    // note: assume reference sets contain unique references and are all the same size
    for (const LegacyRingSignaturePrepV1 &reference_prep : legacy_ring_signature_preps_out)
    {
        for (LegacyRingSignaturePrepV1 &prep_to_repair : legacy_ring_signature_preps_out)
        {
            // a. see if the reference prep's real reference is a decoy in this prep's reference set
            auto ref_set_it =
                std::find(prep_to_repair.reference_set.begin(),
                    prep_to_repair.reference_set.end(),
                    reference_prep.reference_set.at(reference_prep.real_reference_index));

            // b. if not, skip it
            if (ref_set_it == prep_to_repair.reference_set.end())
                continue;

            // c. otherwise, update the decoy's onetime address
            prep_to_repair
                .referenced_enotes
                .at(std::distance(prep_to_repair.reference_set.begin(), ref_set_it))
                .dest = 
                    reference_prep
                        .referenced_enotes
                        .at(reference_prep.real_reference_index)
                        .dest;
        }
    }

    // 3. make sure the updated input proposals are sorted
    std::sort(input_proposals_inout.begin(),
        input_proposals_inout.end(),
        tools::compare_func<LegacyInputProposalV1>(compare_KI));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void replace_sp_input_proposal_destination_for_tx_simulation_v1(const rct::key &sp_core_spend_pubkey_mock,
    const crypto::secret_key &k_view_balance,
    SpInputProposalCore &sp_input_proposal_inout)
{
    // 1. save the amount commitment in a new temporary enote core shuttle variable
    SpEnoteCore temp_enote_core;
    temp_enote_core.amount_commitment = amount_commitment_ref(sp_input_proposal_inout.enote_core);

    // 2. extended spendkey
    rct::key seraphis_extended_spendkey_temp{sp_core_spend_pubkey_mock};  //k_m U
    extend_seraphis_spendkey_u(sp_input_proposal_inout.enote_view_extension_u,
        seraphis_extended_spendkey_temp);  //(k_u + k_m) U

    // 3. new onetime address
    rct::key seraphis_onetime_address_temp{seraphis_extended_spendkey_temp};  //(k_u + k_m) U
    extend_seraphis_spendkey_x(k_view_balance, seraphis_onetime_address_temp);  //k_vb X + (k_u + k_m) U
    extend_seraphis_spendkey_x(sp_input_proposal_inout.enote_view_extension_x,
        seraphis_onetime_address_temp);  //(k_x + k_vb) X + (k_u + k_m) U
    mask_key(sp_input_proposal_inout.enote_view_extension_g,
        seraphis_onetime_address_temp,
        temp_enote_core.onetime_address);  //k_g G + (k_x + k_vb) X + (k_u + k_m) U

    // 4. reset the proposal's enote core
    sp_input_proposal_inout.enote_core = temp_enote_core;

    // 5. update key image for new onetime address
    make_seraphis_key_image(add_secrets(sp_input_proposal_inout.enote_view_extension_x, k_view_balance),
        rct::rct2pk(seraphis_extended_spendkey_temp),
        sp_input_proposal_inout.key_image);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void replace_sp_input_proposal_destinations_for_tx_simulation_v1(const rct::key &sp_core_spend_pubkey_mock,
    const crypto::secret_key &k_view_balance,
    std::vector<SpInputProposalV1> &sp_input_proposals_inout)
{
    // 1. update the input proposals
    for (SpInputProposalV1 &sp_input_proposal : sp_input_proposals_inout)
    {
        replace_sp_input_proposal_destination_for_tx_simulation_v1(sp_core_spend_pubkey_mock,
            k_view_balance,
            sp_input_proposal.core);
    }

    // 2. make sure the updated proposals are sorted
    std::sort(sp_input_proposals_inout.begin(),
        sp_input_proposals_inout.end(),
        tools::compare_func<SpInputProposalV1>(compare_KI));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void prepare_legacy_input_proof_proposal_v1(const rct::key &tx_proposal_prefix,
    const LegacyInputProposalV1 &legacy_input_proposal,
    LegacyMultisigRingSignaturePrepV1 multisig_proof_prep,
    multisig::CLSAGMultisigProposal &multisig_proposal_out)
{
    // 1. message to sign
    rct::key legacy_ring_signature_message;
    make_tx_legacy_ring_signature_message_v1(tx_proposal_prefix,
        multisig_proof_prep.reference_set,
        legacy_ring_signature_message);

    // 2. legacy enote image
    LegacyEnoteImageV2 legacy_enote_image;
    get_enote_image_v2(legacy_input_proposal, legacy_enote_image);

    // 3. legacy auxilliary key image: D
    crypto::key_image auxilliary_key_image;
    make_legacy_auxilliary_key_image_v1(legacy_input_proposal.commitment_mask,
        legacy_input_proposal.onetime_address,
        hw::get_device("default"),
        auxilliary_key_image);

    // 4. legacy multisig proof proposal
    multisig::make_clsag_multisig_proposal(legacy_ring_signature_message,
        std::move(multisig_proof_prep.referenced_enotes),
        legacy_enote_image.masked_commitment,
        legacy_enote_image.key_image,
        auxilliary_key_image,
        multisig_proof_prep.real_reference_index,
        multisig_proposal_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void prepare_legacy_clsag_privkeys_for_multisig(const crypto::secret_key &enote_view_extension,
    const crypto::secret_key &commitment_mask,
    crypto::secret_key &k_offset_out,
    crypto::secret_key &z_out)
{
    // prepare k_offset: legacy enote view privkey
    k_offset_out = enote_view_extension;

    // prepare z: - mask
    // note: legacy commitments to zero are
    //  C_z = C[l] - C"
    //      = C[l] - (mask G + C[l])
    //      = (- mask) G
    sc_0(to_bytes(z_out));
    sc_sub(to_bytes(z_out), to_bytes(z_out), to_bytes(commitment_mask));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void collect_legacy_clsag_privkeys_for_multisig(const std::vector<LegacyInputProposalV1> &legacy_input_proposals,
    std::vector<crypto::secret_key> &proof_privkeys_k_offset_out,
    std::vector<crypto::secret_key> &proof_privkeys_z_out)
{
    CHECK_AND_ASSERT_THROW_MES(tools::is_sorted_and_unique(legacy_input_proposals, compare_KI),
        "collect legacy clsag privkeys for multisig: legacy input proposals aren't sorted and unique.");

    proof_privkeys_k_offset_out.clear();
    proof_privkeys_k_offset_out.reserve(legacy_input_proposals.size());
    proof_privkeys_z_out.clear();
    proof_privkeys_z_out.reserve(legacy_input_proposals.size());

    for (const LegacyInputProposalV1 &legacy_input_proposal : legacy_input_proposals)
    {
        prepare_legacy_clsag_privkeys_for_multisig(legacy_input_proposal.enote_view_extension,
            legacy_input_proposal.commitment_mask,
            tools::add_element(proof_privkeys_k_offset_out),
            tools::add_element(proof_privkeys_z_out));
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void prepare_sp_composition_proof_privkeys_for_multisig(const crypto::secret_key &k_view_balance,
    const crypto::secret_key &enote_view_extension_g,
    const crypto::secret_key &enote_view_extension_x,
    const crypto::secret_key &enote_view_extension_u,
    const crypto::secret_key &address_mask,
    const rct::key &squash_prefix,
    crypto::secret_key &x_out,
    crypto::secret_key &y_out,
    crypto::secret_key &z_offset_out,
    crypto::secret_key &z_multiplier_out)
{
    // prepare x: t_k + Hn(Ko,C) * k_g
    sc_mul(to_bytes(x_out), squash_prefix.bytes, to_bytes(enote_view_extension_g));
    sc_add(to_bytes(x_out), to_bytes(address_mask), to_bytes(x_out));

    // prepare y: Hn(Ko,C) * (k_x + k_vb)
    sc_add(to_bytes(y_out), to_bytes(enote_view_extension_x), to_bytes(k_view_balance));
    sc_mul(to_bytes(y_out), squash_prefix.bytes, to_bytes(y_out));

    // prepare z_offset: k_u
    z_offset_out = enote_view_extension_u;

    // prepare z_multiplier: Hn(Ko,C)
    z_multiplier_out = rct::rct2sk(squash_prefix);

    // note: z = z_multiplier * (z_offset + sum_e(z_e))
    //         = Hn(Ko,C)     * (k_u      + k_m       )
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void collect_sp_composition_proof_privkeys_for_multisig(const std::vector<SpInputProposalV1> &sp_input_proposals,
    const crypto::secret_key &k_view_balance,
    std::vector<crypto::secret_key> &proof_privkeys_x_out,
    std::vector<crypto::secret_key> &proof_privkeys_y_out,
    std::vector<crypto::secret_key> &proof_privkeys_z_offset_out,
    std::vector<crypto::secret_key> &proof_privkeys_z_multiplier_out)
{
    CHECK_AND_ASSERT_THROW_MES(tools::is_sorted_and_unique(sp_input_proposals, compare_KI),
        "collect sp composition proof privkeys for multisig: sp input proposals aren't sorted and unique.");

    proof_privkeys_x_out.clear();
    proof_privkeys_x_out.reserve(sp_input_proposals.size());
    proof_privkeys_y_out.clear();
    proof_privkeys_y_out.reserve(sp_input_proposals.size());
    proof_privkeys_z_offset_out.clear();
    proof_privkeys_z_offset_out.reserve(sp_input_proposals.size());
    proof_privkeys_z_multiplier_out.clear();
    proof_privkeys_z_multiplier_out.reserve(sp_input_proposals.size());
    rct::key squash_prefix_temp;

    for (const SpInputProposalV1 &sp_input_proposal : sp_input_proposals)
    {
        // Hn(Ko,C)
        get_squash_prefix(sp_input_proposal, squash_prefix_temp);

        // x, y, z_offset, z_multiplier
        prepare_sp_composition_proof_privkeys_for_multisig(k_view_balance,
            sp_input_proposal.core.enote_view_extension_g,
            sp_input_proposal.core.enote_view_extension_x,
            sp_input_proposal.core.enote_view_extension_u,
            sp_input_proposal.core.address_mask,
            squash_prefix_temp,
            tools::add_element(proof_privkeys_x_out),
            tools::add_element(proof_privkeys_y_out),
            tools::add_element(proof_privkeys_z_offset_out),
            tools::add_element(proof_privkeys_z_multiplier_out));
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_make_v1_legacy_input_v1(const rct::key &tx_proposal_prefix,
    const LegacyInputProposalV1 &input_proposal,
    std::vector<std::uint64_t> reference_set,
    rct::ctkeyV referenced_enotes,
    const rct::key &masked_commitment,
    const std::vector<multisig::CLSAGMultisigPartial> &input_proof_partial_sigs,
    const rct::key &legacy_spend_pubkey,
    LegacyInputV1 &input_out)
{
    try
    {
        // 1. make legacy ring signature message
        rct::key ring_signature_message;
        make_tx_legacy_ring_signature_message_v1(tx_proposal_prefix, reference_set, ring_signature_message);

        // 2. all partial sigs must sign the expected message
        for (const multisig::CLSAGMultisigPartial &partial_sig : input_proof_partial_sigs)
        {
            CHECK_AND_ASSERT_THROW_MES(partial_sig.message == ring_signature_message,
                "multisig make partial legacy input v1: a partial signature's message does not match the expected "
                "message.");
        }

        // 3. assemble proof (will throw if partial sig assembly doesn't produce a valid proof)
        LegacyRingSignatureV4 ring_signature;
        multisig::finalize_clsag_multisig_proof(input_proof_partial_sigs,
            referenced_enotes,
            masked_commitment,
            ring_signature.clsag_proof);

        ring_signature.reference_set = std::move(reference_set);

        // 4. make legacy input
        make_v1_legacy_input_v1(tx_proposal_prefix,
            input_proposal,
            std::move(ring_signature),
            std::move(referenced_enotes),
            legacy_spend_pubkey,
            input_out);

        // 5. validate semantics to minimize failure modes
        check_v1_legacy_input_semantics_v1(input_out);
    }
    catch (...) { return false; }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_make_v1_sp_partial_input_v1(const rct::key &tx_proposal_prefix,
    const SpInputProposalV1 &input_proposal,
    const std::vector<multisig::SpCompositionProofMultisigPartial> &input_proof_partial_sigs,
    const rct::key &sp_core_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpPartialInputV1 &partial_input_out)
{
    try
    {
        // 1. all partial sigs must sign the expected message
        for (const multisig::SpCompositionProofMultisigPartial &partial_sig : input_proof_partial_sigs)
        {
            CHECK_AND_ASSERT_THROW_MES(partial_sig.message == tx_proposal_prefix,
                "multisig make partial seraphis input v1: a partial signature's message does not match the expected "
                "message.");
        }

        // 2. assemble proof (will throw if partial sig assembly doesn't produce a valid proof)
        SpImageProofV1 sp_image_proof;
        multisig::finalize_sp_composition_multisig_proof(input_proof_partial_sigs, sp_image_proof.composition_proof);

        // 3. make the partial input
        make_v1_partial_input_v1(input_proposal,
            tx_proposal_prefix,
            std::move(sp_image_proof),
            sp_core_spend_pubkey,
            k_view_balance,
            partial_input_out);

        // 4. validate semantics to minimize failure modes
        check_v1_partial_input_semantics_v1(partial_input_out);
    }
    catch (...) { return false; }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_make_legacy_inputs_for_multisig_v1(const rct::key &tx_proposal_prefix,
    const std::vector<LegacyInputProposalV1> &legacy_input_proposals,
    const std::vector<LegacyMultisigInputProposalV1> &legacy_multisig_input_proposals,
    const std::vector<multisig::CLSAGMultisigProposal> &legacy_input_proof_proposals,
    const std::vector<crypto::public_key> &multisig_signers,
    const std::unordered_map<crypto::public_key, std::vector<multisig::MultisigPartialSigSetV1>>
        &legacy_input_partial_sigs_per_signer,
    const rct::key &legacy_spend_pubkey,
    std::list<multisig::MultisigSigningErrorVariant> &multisig_errors_inout,
    std::vector<LegacyInputV1> &legacy_inputs_out)
{
    // 1. process legacy input proposals
    // - map legacy input proposals to their onetime addresses
    // - map masked commitments to the corresponding onetime addresses
    std::unordered_map<rct::key, LegacyInputProposalV1> mapped_legacy_input_proposals;
    std::unordered_map<rct::key, rct::key> mapped_masked_commitments;

    for (const LegacyInputProposalV1 &legacy_input_proposal : legacy_input_proposals)
    {
        mapped_legacy_input_proposals[legacy_input_proposal.onetime_address] = legacy_input_proposal;
        mask_key(legacy_input_proposal.commitment_mask,
            legacy_input_proposal.amount_commitment,
            mapped_masked_commitments[legacy_input_proposal.onetime_address]);
    }

    // 2. process multisig legacy input proposals
    // - map ring signature messages to onetime addresses
    // - map legacy reference sets to onetime addresses
    std::unordered_map<rct::key, rct::key> legacy_proof_contexts;  //[ proof key : proof message ]
    std::unordered_map<rct::key, std::vector<std::uint64_t>> mapped_reference_sets;
    rct::key message_temp;

    for (const LegacyMultisigInputProposalV1 &legacy_multisig_input_proposal : legacy_multisig_input_proposals)
    {
        // [ proof key : proof message ]
        make_tx_legacy_ring_signature_message_v1(tx_proposal_prefix,
            legacy_multisig_input_proposal.reference_set,
            message_temp);
        legacy_proof_contexts[onetime_address_ref(legacy_multisig_input_proposal.enote)] = message_temp;

        // [ proof key : reference set ]
        mapped_reference_sets[onetime_address_ref(legacy_multisig_input_proposal.enote)] =
            legacy_multisig_input_proposal.reference_set;
    }

    // 3. map legacy ring members to onetime addresses
    std::unordered_map<rct::key, rct::ctkeyV> mapped_ring_members;

    for (const multisig::CLSAGMultisigProposal &legacy_input_proof_proposal : legacy_input_proof_proposals)
        mapped_ring_members[main_proof_key_ref(legacy_input_proof_proposal)] = legacy_input_proof_proposal.ring_members;

    // 4. filter the legacy partial signatures into a map
    std::unordered_map<multisig::signer_set_filter,  //signing group
        std::unordered_map<rct::key,                 //proof key (onetime address)
            std::vector<multisig::MultisigPartialSigVariant>>> collected_sigs_per_key_per_filter;

    multisig::filter_multisig_partial_signatures_for_combining_v1(multisig_signers,
        legacy_proof_contexts,
        multisig::MultisigPartialSigVariant::type_index_of<multisig::CLSAGMultisigPartial>(),
        legacy_input_partial_sigs_per_signer,
        multisig_errors_inout,
        collected_sigs_per_key_per_filter);

    // 5. try to make one legacy input per input proposal (fails if can't make proofs for all inputs)
    if (!multisig::try_assemble_multisig_partial_sigs_signer_group_attempts<
                multisig::CLSAGMultisigPartial,
                LegacyInputV1
            >(
                legacy_input_proposals.size(),
                collected_sigs_per_key_per_filter,
                [&](const rct::key &proof_key,
                    const std::vector<multisig::CLSAGMultisigPartial> &partial_sigs,
                    LegacyInputV1 &legacy_input_out) -> bool
                {
                    // sanity check
                    if (legacy_proof_contexts.find(proof_key) == legacy_proof_contexts.end())
                        return false;

                    // try to make the input
                    return try_make_v1_legacy_input_v1(tx_proposal_prefix,
                        mapped_legacy_input_proposals.at(proof_key),
                        mapped_reference_sets.at(proof_key),
                        mapped_ring_members.at(proof_key),
                        mapped_masked_commitments.at(proof_key),
                        partial_sigs,
                        legacy_spend_pubkey,
                        legacy_input_out);
                },
                multisig_errors_inout,
                legacy_inputs_out
            ))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_make_sp_partial_inputs_for_multisig_v1(const rct::key &tx_proposal_prefix,
    const std::vector<SpInputProposalV1> &sp_input_proposals,
    const std::vector<crypto::public_key> &multisig_signers,
    const std::unordered_map<crypto::public_key, std::vector<multisig::MultisigPartialSigSetV1>>
        &sp_input_partial_sigs_per_signer,
    const rct::key &sp_core_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    std::list<multisig::MultisigSigningErrorVariant> &multisig_errors_inout,
    std::vector<SpPartialInputV1> &sp_partial_inputs_out)
{
    // 1. process seraphis input proposals
    // - collect seraphis masked addresses of input images
    // - map seraphis input proposals to their masked addresses
    std::unordered_map<rct::key, rct::key> sp_proof_contexts;  //[ proof key : proof message ]
    std::unordered_map<rct::key, SpInputProposalV1> mapped_sp_input_proposals;
    SpEnoteImageV1 enote_image_temp;

    for (const SpInputProposalV1 &sp_input_proposal : sp_input_proposals)
    {
        get_enote_image_v1(sp_input_proposal, enote_image_temp);
        sp_proof_contexts[masked_address_ref(enote_image_temp)] = tx_proposal_prefix;
        mapped_sp_input_proposals[masked_address_ref(enote_image_temp)] = sp_input_proposal;
    }

    // 2. filter the seraphis partial signatures into a map
    std::unordered_map<multisig::signer_set_filter,  //signing group
        std::unordered_map<rct::key,                 //proof key (masked address)
            std::vector<multisig::MultisigPartialSigVariant>>> collected_sigs_per_key_per_filter;

    multisig::filter_multisig_partial_signatures_for_combining_v1(multisig_signers,
        sp_proof_contexts,
        multisig::MultisigPartialSigVariant::type_index_of<multisig::SpCompositionProofMultisigPartial>(),
        sp_input_partial_sigs_per_signer,
        multisig_errors_inout,
        collected_sigs_per_key_per_filter);

    // 3. try to make one seraphis partial input per input proposal (fails if can't make proofs for all inputs)
    if (!multisig::try_assemble_multisig_partial_sigs_signer_group_attempts<
                multisig::SpCompositionProofMultisigPartial,
                SpPartialInputV1
            >(
                sp_input_proposals.size(),
                collected_sigs_per_key_per_filter,
                [&](const rct::key &proof_key,
                    const std::vector<multisig::SpCompositionProofMultisigPartial> &partial_sigs,
                    SpPartialInputV1 &sp_partial_input_out) -> bool
                {
                    // sanity check
                    if (sp_proof_contexts.find(proof_key) == sp_proof_contexts.end())
                        return false;

                    // try to make the partial input
                    return try_make_v1_sp_partial_input_v1(tx_proposal_prefix,
                        mapped_sp_input_proposals.at(proof_key),
                        partial_sigs,
                        sp_core_spend_pubkey,
                        k_view_balance,
                        sp_partial_input_out);
                },
                multisig_errors_inout,
                sp_partial_inputs_out
            ))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void check_v1_legacy_multisig_input_proposal_semantics_v1(const LegacyMultisigInputProposalV1 &multisig_input_proposal)
{
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(multisig_input_proposal.commitment_mask)),
        "semantics check legacy multisig input proposal v1: bad address mask (zero).");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(multisig_input_proposal.commitment_mask)) == 0,
        "semantics check legacy multisig input proposal v1: bad address mask (not canonical).");
    CHECK_AND_ASSERT_THROW_MES(std::find(multisig_input_proposal.reference_set.begin(),
                multisig_input_proposal.reference_set.end(),
                multisig_input_proposal.tx_output_index) !=
            multisig_input_proposal.reference_set.end(),
        "semantics check legacy multisig input proposal v1: referenced enote index is not in the reference set.");
    CHECK_AND_ASSERT_THROW_MES(tools::is_sorted_and_unique(multisig_input_proposal.reference_set),
        "semantics check legacy multisig input proposal v1: reference set indices are not sorted and unique.");
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_legacy_multisig_input_proposal_v1(const LegacyEnoteVariant &enote,
    const crypto::key_image &key_image,
    const rct::key &enote_ephemeral_pubkey,
    const std::uint64_t tx_output_index,
    const std::uint64_t unlock_time,
    const crypto::secret_key &commitment_mask,
    std::vector<std::uint64_t> reference_set,
    LegacyMultisigInputProposalV1 &proposal_out)
{
    // add components
    proposal_out.enote                  = enote;
    proposal_out.key_image              = key_image;
    proposal_out.enote_ephemeral_pubkey = enote_ephemeral_pubkey;
    proposal_out.tx_output_index        = tx_output_index;
    proposal_out.unlock_time            = unlock_time;
    proposal_out.commitment_mask        = commitment_mask;
    proposal_out.reference_set          = std::move(reference_set);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_legacy_multisig_input_proposal_v1(const LegacyEnoteRecord &enote_record,
    const crypto::secret_key &commitment_mask,
    std::vector<std::uint64_t> reference_set,
    LegacyMultisigInputProposalV1 &proposal_out)
{
    make_v1_legacy_multisig_input_proposal_v1(enote_record.enote,
        enote_record.key_image,
        enote_record.enote_ephemeral_pubkey,
        enote_record.tx_output_index,
        enote_record.unlock_time,
        commitment_mask,
        std::move(reference_set),
        proposal_out);
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_sp_multisig_input_proposal_semantics_v1(const SpMultisigInputProposalV1 &multisig_input_proposal)
{
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(multisig_input_proposal.address_mask)),
        "semantics check sp multisig input proposal v1: bad address mask (zero).");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(multisig_input_proposal.address_mask)) == 0,
        "semantics check sp multisig input proposal v1: bad address mask (not canonical).");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(multisig_input_proposal.commitment_mask)),
        "semantics check sp multisig input proposal v1: bad commitment mask (zero).");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(multisig_input_proposal.commitment_mask)) == 0,
        "semantics check sp multisig input proposal v1: bad commitment mask (not canonical).");
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_sp_multisig_input_proposal_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpMultisigInputProposalV1 &proposal_out)
{
    // add components
    proposal_out.enote                  = enote;
    proposal_out.enote_ephemeral_pubkey = enote_ephemeral_pubkey;
    proposal_out.input_context          = input_context;
    proposal_out.address_mask           = address_mask;
    proposal_out.commitment_mask        = commitment_mask;
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_sp_multisig_input_proposal_v1(const SpEnoteRecordV1 &enote_record,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpMultisigInputProposalV1 &proposal_out)
{
    make_v1_sp_multisig_input_proposal_v1(enote_record.enote,
        enote_record.enote_ephemeral_pubkey,
        enote_record.input_context,
        address_mask,
        commitment_mask,
        proposal_out);
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_multisig_tx_proposal_semantics_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const tx_version_t &expected_tx_version,
    const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance)
{
    /// multisig signing config checks

    // 1. proposal should contain expected tx version encoding
    CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.tx_version == expected_tx_version,
        "semantics check multisig tx proposal v1: intended tx version encoding is invalid.");

    // 2. signer set filter must be valid (at least 'threshold' signers allowed, format is valid)
    CHECK_AND_ASSERT_THROW_MES(multisig::validate_aggregate_multisig_signer_set_filter(threshold,
            num_signers,
            multisig_tx_proposal.aggregate_signer_set_filter),
        "semantics check multisig tx proposal v1: invalid aggregate signer set filter.");


    /// input/output checks

    // 1. check the multisig input proposal semantics
    // a. legacy
    CHECK_AND_ASSERT_THROW_MES(tools::is_sorted_and_unique(multisig_tx_proposal.legacy_multisig_input_proposals,
            compare_KI),
        "semantics check multisig tx proposal v1: legacy multisig input proposals are not sorted and unique.");

    for (const LegacyMultisigInputProposalV1 &legacy_multisig_input_proposal :
            multisig_tx_proposal.legacy_multisig_input_proposals)
        check_v1_legacy_multisig_input_proposal_semantics_v1(legacy_multisig_input_proposal);

    // b. seraphis (these are NOT sorted)
    for (const SpMultisigInputProposalV1 &sp_multisig_input_proposal :
            multisig_tx_proposal.sp_multisig_input_proposals)
        check_v1_sp_multisig_input_proposal_semantics_v1(sp_multisig_input_proposal);

    // 2. convert the proposal to a plain tx proposal and check its semantics (a comprehensive set of tests)
    SpTxProposalV1 tx_proposal;
    get_v1_tx_proposal_v1(multisig_tx_proposal,
        legacy_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        jamtis_spend_pubkey,
        k_view_balance,
        tx_proposal);

    check_v1_tx_proposal_semantics_v1(tx_proposal, legacy_spend_pubkey, jamtis_spend_pubkey, k_view_balance);

    // 3. get tx proposal prefix
    rct::key tx_proposal_prefix;
    get_tx_proposal_prefix_v1(tx_proposal, multisig_tx_proposal.tx_version, k_view_balance, tx_proposal_prefix);


    /// multisig-related input checks

    // 1. input proposals line up 1:1 with multisig input proof proposals
    CHECK_AND_ASSERT_THROW_MES(tx_proposal.legacy_input_proposals.size() ==
            multisig_tx_proposal.legacy_input_proof_proposals.size(),
        "semantics check multisig tx proposal v1: legacy input proposals don't line up with input proposal proofs.");

    CHECK_AND_ASSERT_THROW_MES(tx_proposal.sp_input_proposals.size() ==
            multisig_tx_proposal.sp_input_proof_proposals.size(),
        "semantics check multisig tx proposal v1: sp input proposals don't line up with input proposal proofs.");

    // 2. assess each legacy input proof proposal
    for (std::size_t legacy_input_index{0};
        legacy_input_index < multisig_tx_proposal.legacy_input_proof_proposals.size();
        ++legacy_input_index)
    {
        check_semantics_legacy_multisig_input_material_v1(tx_proposal_prefix,
            multisig_tx_proposal.legacy_multisig_input_proposals[legacy_input_index],
            multisig_tx_proposal.legacy_input_proof_proposals[legacy_input_index]);
    }

    // 3. assess each seraphis input proof proposal (iterate through sorted input vectors; note that multisig
    //    input proposals are NOT sorted, but input proof proposals and input proposals obtained from
    //    a normal tx proposal ARE sorted)
    for (std::size_t sp_input_index{0};
        sp_input_index < multisig_tx_proposal.sp_input_proof_proposals.size();
        ++sp_input_index)
    {
        check_semantics_sp_multisig_input_material_v1(tx_proposal_prefix,
            tx_proposal.sp_input_proposals[sp_input_index],
            multisig_tx_proposal.sp_input_proof_proposals[sp_input_index]);
    }
}
//-------------------------------------------------------------------------------------------------------------------
bool try_simulate_tx_from_multisig_tx_proposal_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    hw::device &hwdev)
{
    try
    {
        // 1. get versioning of the proposed tx
        const tx_version_t tx_version{tx_version_from(semantic_rules_version)};

        // 2. validate the multisig tx proposal
        check_v1_multisig_tx_proposal_semantics_v1(multisig_tx_proposal,
            tx_version,
            threshold,
            num_signers,
            legacy_spend_pubkey,
            legacy_subaddress_map,
            legacy_view_privkey,
            jamtis_spend_pubkey,
            k_view_balance);

        // 3. convert to a regular tx proposal
        SpTxProposalV1 tx_proposal;
        get_v1_tx_proposal_v1(multisig_tx_proposal,
            legacy_spend_pubkey,
            legacy_subaddress_map,
            legacy_view_privkey,
            jamtis_spend_pubkey,
            k_view_balance,
            tx_proposal);

        // 4. make mock legacy and jamtis spend private keys
        const crypto::secret_key legacy_spend_privkey_mock{rct::rct2sk(rct::skGen())};  //k^s (legacy)
        const crypto::secret_key sp_spend_privkey_mock{rct::rct2sk(rct::skGen())};  //k_m (seraphis)
        const rct::key sp_core_spend_pubkey_mock{
                rct::scalarmultKey(rct::pk2rct(crypto::get_U()), rct::sk2rct(sp_spend_privkey_mock))
            };  //k_m U

        // 5. make simulated input proposals for the tx using the mock spend keys
        // a. legacy input proposals + legacy input proof preps
        // note: after this, the legacy input proof preps are unsorted and missing the message the proofs should sign
        std::vector<LegacyRingSignaturePrepV1> legacy_ring_signature_preps;
        replace_legacy_input_proposal_destinations_for_tx_simulation_v1(
            multisig_tx_proposal.legacy_multisig_input_proposals,
            multisig_tx_proposal.legacy_input_proof_proposals,
            legacy_spend_privkey_mock,
            tx_proposal.legacy_input_proposals,
            legacy_ring_signature_preps);

        // b. seraphis input proposals
        replace_sp_input_proposal_destinations_for_tx_simulation_v1(sp_core_spend_pubkey_mock,
            k_view_balance,
            tx_proposal.sp_input_proposals);

        // note: at this point calling check_v1_tx_proposal_semantics_v1() would not work because the check assumes
        //       inputs will be signed by the same keys as selfsend outputs in the tx, but that is no longer the case
        //       for our simulation

        // 6. tx proposal prefix of modified tx proposal
        rct::key tx_proposal_prefix;
        get_tx_proposal_prefix_v1(tx_proposal, tx_version, k_view_balance, tx_proposal_prefix);

        // 7. finish preparing the legacy ring signature preps
        for (LegacyRingSignaturePrepV1 &ring_signature_prep : legacy_ring_signature_preps)
            ring_signature_prep.tx_proposal_prefix = tx_proposal_prefix;  //now we can set this

        std::sort(legacy_ring_signature_preps.begin(),
            legacy_ring_signature_preps.end(),
            tools::compare_func<LegacyRingSignaturePrepV1>(compare_KI));

        // 8. convert the input proposals to inputs/partial inputs
        // a. legacy inputs
        std::vector<LegacyInputV1> legacy_inputs;
        make_v1_legacy_inputs_v1(tx_proposal_prefix,
            tx_proposal.legacy_input_proposals,
            std::move(legacy_ring_signature_preps),  //must be sorted
            legacy_spend_privkey_mock,
            hwdev,
            legacy_inputs);

        // b. seraphis partial inputs
        std::vector<SpPartialInputV1> sp_partial_inputs;
        make_v1_partial_inputs_v1(tx_proposal.sp_input_proposals,
            tx_proposal_prefix,
            sp_spend_privkey_mock,
            k_view_balance,
            sp_partial_inputs);

        // 9. convert the tx proposal payment proposals to output proposals
        // note: we can't use the tx proposal directly to make a partial tx because doing so would invoke
        //       check_v1_tx_proposal_semantics_v1(), which won't work here
        std::vector<SpOutputProposalV1> output_proposals;
        get_output_proposals_v1(tx_proposal, k_view_balance, output_proposals);

        // 10. construct a partial tx
        SpPartialTxV1 partial_tx;
        make_v1_partial_tx_v1(std::move(legacy_inputs),
            std::move(sp_partial_inputs),
            std::move(output_proposals),
            tx_proposal.tx_fee,
            tx_proposal.partial_memo,
            tx_version,
            partial_tx);

        // 11. validate the partial tx (this internally simulates a full transaction)
        check_v1_partial_tx_semantics_v1(partial_tx, semantic_rules_version);
    }
    catch (...) { return false; }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_tx_proposal_v1(std::vector<LegacyMultisigInputProposalV1> legacy_multisig_input_proposals,
    std::vector<SpMultisigInputProposalV1> sp_multisig_input_proposals,
    std::unordered_map<crypto::key_image, LegacyMultisigRingSignaturePrepV1> legacy_multisig_ring_signature_preps,
    const multisig::signer_set_filter aggregate_signer_set_filter,
    std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals,
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals,
    const DiscretizedFee discretized_transaction_fee,
    std::vector<ExtraFieldElement> additional_memo_elements,
    const tx_version_t &tx_version,
    const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpMultisigTxProposalV1 &proposal_out)
{
    CHECK_AND_ASSERT_THROW_MES(tools::keys_match_internal_values(legacy_multisig_ring_signature_preps,
            [](const crypto::key_image &key, const LegacyMultisigRingSignaturePrepV1 &prep) -> bool
            {
                return key == prep.key_image;
            }),
        "make v1 multisig tx proposal (v1): a legacy ring signature prep is mapped to the incorrect key image.");

    // 1. pre-sort legacy multisig input proposals
    // note: they need to be sorted in the multisig tx proposal, and the tx proposal also calls sort on legacy input
    //       proposals so pre-sorting here means less work there
    std::sort(legacy_multisig_input_proposals.begin(),
        legacy_multisig_input_proposals.end(),
        tools::compare_func<LegacyMultisigInputProposalV1>(compare_KI));

    // 2. convert legacy multisig input proposals to legacy input proposals
    std::vector<LegacyInputProposalV1> legacy_input_proposals;
    legacy_input_proposals.reserve(legacy_multisig_input_proposals.size());

    for (const LegacyMultisigInputProposalV1 &legacy_multisig_input_proposal : legacy_multisig_input_proposals)
    {
        get_legacy_input_proposal_v1(legacy_multisig_input_proposal,
            legacy_spend_pubkey,
            legacy_subaddress_map,
            legacy_view_privkey,
            tools::add_element(legacy_input_proposals));
    }

    // 3. convert seraphis multisig input proposals to seraphis input proposals
    std::vector<SpInputProposalV1> sp_input_proposals;
    sp_input_proposals.reserve(sp_multisig_input_proposals.size());

    for (const SpMultisigInputProposalV1 &sp_multisig_input_proposal : sp_multisig_input_proposals)
    {
        get_sp_input_proposal_v1(sp_multisig_input_proposal,
            jamtis_spend_pubkey,
            k_view_balance,
            tools::add_element(sp_input_proposals));
    }

    // 4. make a temporary normal tx proposal
    SpTxProposalV1 tx_proposal;
    make_v1_tx_proposal_v1(std::move(legacy_input_proposals),
        std::move(sp_input_proposals),
        normal_payment_proposals,
        selfsend_payment_proposals,
        discretized_transaction_fee,
        additional_memo_elements,
        tx_proposal);

    // 5. sanity check the normal tx proposal
    check_v1_tx_proposal_semantics_v1(tx_proposal, legacy_spend_pubkey, jamtis_spend_pubkey, k_view_balance);

    // 6. get proposal prefix
    rct::key tx_proposal_prefix;
    get_tx_proposal_prefix_v1(tx_proposal, tx_version, k_view_balance, tx_proposal_prefix);

    // 7. make sure the legacy proof preps align with legacy input proposals
    // note: if the legacy input proposals contain duplicates, then the call to check_v1_tx_proposal_semantics_v1()
    //       will catch it
    CHECK_AND_ASSERT_THROW_MES(legacy_multisig_ring_signature_preps.size() ==
            tx_proposal.legacy_input_proposals.size(),
        "make v1 multisig tx proposal (v1): legacy ring signature preps don't line up with input proposals.");

    // 8. prepare legacy proof proposals
    // note: using the tx proposal ensures proof proposals are sorted
    proposal_out.legacy_input_proof_proposals.clear();
    proposal_out.legacy_input_proof_proposals.reserve(tx_proposal.legacy_input_proposals.size());

    for (const LegacyInputProposalV1 &legacy_input_proposal : tx_proposal.legacy_input_proposals)
    {
        CHECK_AND_ASSERT_THROW_MES(legacy_multisig_ring_signature_preps.find(legacy_input_proposal.key_image) !=
                legacy_multisig_ring_signature_preps.end(),
            "make v1 multisig tx proposal (v1): a legacy ring signature prep doesn't line up with an input proposal.");

        // a. prepare the proof proposal
        prepare_legacy_input_proof_proposal_v1(tx_proposal_prefix,
            legacy_input_proposal,
            std::move(legacy_multisig_ring_signature_preps[legacy_input_proposal.key_image]),
            tools::add_element(proposal_out.legacy_input_proof_proposals));

        // b. clear this input's entry in the map so duplicate key images are handled better
        legacy_multisig_ring_signature_preps.erase(legacy_input_proposal.key_image);
    }

    // 9. prepare composition proof proposals for each seraphis input
    // note: using the tx proposal ensures proof proposals are sorted
    proposal_out.sp_input_proof_proposals.clear();
    proposal_out.sp_input_proof_proposals.reserve(tx_proposal.sp_input_proposals.size());
    SpEnoteImageV1 sp_enote_image_temp;

    for (const SpInputProposalV1 &sp_input_proposal : tx_proposal.sp_input_proposals)
    {
        get_enote_image_v1(sp_input_proposal, sp_enote_image_temp);

        multisig::make_sp_composition_multisig_proposal(tx_proposal_prefix,
            masked_address_ref(sp_enote_image_temp),
            key_image_ref(sp_enote_image_temp),
            tools::add_element(proposal_out.sp_input_proof_proposals));
    }

    // 10. add miscellaneous components
    proposal_out.legacy_multisig_input_proposals = std::move(legacy_multisig_input_proposals);
    proposal_out.sp_multisig_input_proposals     = std::move(sp_multisig_input_proposals);
    proposal_out.aggregate_signer_set_filter     = aggregate_signer_set_filter;
    proposal_out.normal_payment_proposals        = std::move(normal_payment_proposals);
    proposal_out.selfsend_payment_proposals      = std::move(selfsend_payment_proposals);
    proposal_out.tx_fee                          = discretized_transaction_fee;
    make_tx_extra(std::move(additional_memo_elements), proposal_out.partial_memo);
    proposal_out.tx_version                      = tx_version;
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_tx_proposal_v1(const std::vector<LegacyContextualEnoteRecordV1> &legacy_contextual_inputs,
    const std::vector<SpContextualEnoteRecordV1> &sp_contextual_inputs,
    std::unordered_map<crypto::key_image, LegacyMultisigRingSignaturePrepV1> legacy_multisig_ring_signature_preps,
    const multisig::signer_set_filter aggregate_signer_set_filter,
    std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals,
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals,
    const DiscretizedFee discretized_transaction_fee,
    TxExtra partial_memo_for_tx,
    const tx_version_t &tx_version,
    const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpMultisigTxProposalV1 &multisig_tx_proposal_out)
{
    CHECK_AND_ASSERT_THROW_MES(tools::keys_match_internal_values(legacy_multisig_ring_signature_preps,
            [](const crypto::key_image &key, const LegacyMultisigRingSignaturePrepV1 &prep) -> bool
            {
                return key == prep.key_image;
            }),
        "make v1 multisig tx proposal (v1): a legacy ring signature prep is mapped to the incorrect key image.");

    // 1. convert legacy inputs to legacy multisig input proposals (inputs to spend)
    CHECK_AND_ASSERT_THROW_MES(legacy_contextual_inputs.size() == legacy_multisig_ring_signature_preps.size(),
        "make v1 multisig tx proposal (v1): legacy contextual inputs don't line up with ring signature preps.");

    std::vector<LegacyMultisigInputProposalV1> legacy_multisig_input_proposals;
    legacy_multisig_input_proposals.reserve(legacy_contextual_inputs.size());

    for (const LegacyContextualEnoteRecordV1 &legacy_contextual_input : legacy_contextual_inputs)
    {
        CHECK_AND_ASSERT_THROW_MES(legacy_multisig_ring_signature_preps.find(key_image_ref(legacy_contextual_input)) !=
                legacy_multisig_ring_signature_preps.end(),
            "make v1 multisig tx proposal (v1): a legacy contextual input doesn't have a corresponding multisig prep.");

        // convert inputs to multisig input proposals
        make_v1_legacy_multisig_input_proposal_v1(legacy_contextual_input.record,
            rct::rct2sk(rct::skGen()),
            legacy_multisig_ring_signature_preps
                    .at(key_image_ref(legacy_contextual_input))
                    .reference_set,  //don't consume, the full prep needs to be consumed later
            tools::add_element(legacy_multisig_input_proposals));
    }

    // 2. convert seraphis inputs to seraphis multisig input proposals (inputs to spend)
    std::vector<SpMultisigInputProposalV1> sp_multisig_input_proposals;
    sp_multisig_input_proposals.reserve(sp_contextual_inputs.size());

    for (const SpContextualEnoteRecordV1 &contextual_input : sp_contextual_inputs)
    {
        // convert inputs to multisig input proposals
        make_v1_sp_multisig_input_proposal_v1(contextual_input.record,
            rct::rct2sk(rct::skGen()),
            rct::rct2sk(rct::skGen()),
            tools::add_element(sp_multisig_input_proposals));
    }

    // 3. get memo elements
    std::vector<ExtraFieldElement> extra_field_elements;
    CHECK_AND_ASSERT_THROW_MES(try_get_extra_field_elements(partial_memo_for_tx, extra_field_elements),
        "make tx proposal for transfer (v1): unable to extract memo field elements for tx proposal.");

    // 4. finalize multisig tx proposal
    make_v1_multisig_tx_proposal_v1(std::move(legacy_multisig_input_proposals),
        std::move(sp_multisig_input_proposals),
        std::move(legacy_multisig_ring_signature_preps),
        aggregate_signer_set_filter,
        std::move(normal_payment_proposals),
        std::move(selfsend_payment_proposals),
        discretized_transaction_fee,
        std::move(extra_field_elements),
        tx_version,
        legacy_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        jamtis_spend_pubkey,
        k_view_balance,
        multisig_tx_proposal_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_init_sets_for_inputs_v1(const crypto::public_key &signer_id,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const tx_version_t &expected_tx_version,
    const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    multisig::MultisigNonceCache &nonce_record_inout,
    //[ proof key : init set ]
    std::unordered_map<rct::key, multisig::MultisigProofInitSetV1> &legacy_input_init_set_collection_out,
    //[ proof key : init set ]
    std::unordered_map<rct::key, multisig::MultisigProofInitSetV1> &sp_input_init_set_collection_out)
{
    // 1. validate multisig tx proposal
    check_v1_multisig_tx_proposal_semantics_v1(multisig_tx_proposal,
        expected_tx_version,
        threshold,
        multisig_signers.size(),
        legacy_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        jamtis_spend_pubkey,
        k_view_balance);

    CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.legacy_multisig_input_proposals.size() +
            multisig_tx_proposal.sp_multisig_input_proposals.size() > 0,
        "make multisig input init sets v1: no inputs to initialize.");

    // 2. make tx proposal (to get sorted inputs and the tx proposal prefix)
    SpTxProposalV1 tx_proposal;
    get_v1_tx_proposal_v1(multisig_tx_proposal,
        legacy_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        jamtis_spend_pubkey,
        k_view_balance,
        tx_proposal);

    // 3. tx proposal prefix
    rct::key tx_proposal_prefix;
    get_tx_proposal_prefix_v1(tx_proposal, multisig_tx_proposal.tx_version, k_view_balance, tx_proposal_prefix);

    // 4. prepare proof contexts and multisig proof base points
    // a. legacy proof context     [ legacy Ko : legacy input message ]
    // b. legacy proof base points [ legacy Ko : {G, Hp(legacy Ko)}   ]
    std::unordered_map<rct::key, rct::key> legacy_input_proof_contexts;
    std::unordered_map<rct::key, rct::keyV> legacy_proof_key_base_points;
    get_legacy_proof_contexts_v1(tx_proposal_prefix,
        multisig_tx_proposal.legacy_multisig_input_proposals,
        legacy_input_proof_contexts);
    get_legacy_proof_base_keys_v1(tx_proposal.legacy_input_proposals, legacy_proof_key_base_points);

    // c. seraphis proof context     [ seraphis K" : tx proposal prefix ]
    // d. seraphis proof base points [ seraphis K" : {U}                ]
    std::unordered_map<rct::key, rct::key> sp_input_proof_contexts;
    std::unordered_map<rct::key, rct::keyV> sp_proof_key_base_points;
    get_seraphis_proof_contexts_v1(tx_proposal_prefix, tx_proposal.sp_input_proposals, sp_input_proof_contexts);
    get_sp_proof_base_keys_v1(tx_proposal.sp_input_proposals, sp_proof_key_base_points);

    // 5. finish making multisig input init sets
    // a. legacy input init set
    multisig::make_v1_multisig_init_set_collection_v1(threshold,
        multisig_signers,
        multisig_tx_proposal.aggregate_signer_set_filter,
        signer_id,
        legacy_input_proof_contexts,
        legacy_proof_key_base_points,
        nonce_record_inout,
        legacy_input_init_set_collection_out);

    // b. seraphis input init set
    multisig::make_v1_multisig_init_set_collection_v1(threshold,
        multisig_signers,
        multisig_tx_proposal.aggregate_signer_set_filter,
        signer_id,
        sp_input_proof_contexts,
        sp_proof_key_base_points,
        nonce_record_inout,
        sp_input_init_set_collection_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_make_v1_multisig_partial_sig_sets_for_legacy_inputs_v1(const multisig::multisig_account &signer_account,
    const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const tx_version_t &expected_tx_version,
    //[ proof key : init set ]
    std::unordered_map<rct::key, multisig::MultisigProofInitSetV1> local_input_init_set_collection,
    //[ signer id : [ proof key : init set ] ]
    std::unordered_map<crypto::public_key, std::unordered_map<rct::key, multisig::MultisigProofInitSetV1>>
        other_input_init_set_collections,
    std::list<multisig::MultisigSigningErrorVariant> &multisig_errors_inout,
    multisig::MultisigNonceCache &nonce_record_inout,
    std::vector<multisig::MultisigPartialSigSetV1> &legacy_input_partial_sig_sets_out)
{
    legacy_input_partial_sig_sets_out.clear();

    CHECK_AND_ASSERT_THROW_MES(signer_account.multisig_is_ready(),
        "multisig legacy input partial sigs v1: signer account is not complete, so it can't make partial signatures.");
    CHECK_AND_ASSERT_THROW_MES(signer_account.get_era() == cryptonote::account_generator_era::cryptonote,
        "multisig legacy input partial sigs v1: signer account is not a cryptonote account, so it can't make legacy "
        "partial signatures.");

    // early return if there are no legacy inputs in the multisig tx proposal
    if (multisig_tx_proposal.legacy_multisig_input_proposals.size() == 0)
        return true;


    /// prepare pieces to use below

    // 1. misc. from account
    const crypto::secret_key &legacy_view_privkey{signer_account.get_common_privkey()};
    const std::uint32_t threshold{signer_account.get_threshold()};
    const rct::key legacy_spend_pubkey{rct::pk2rct(signer_account.get_multisig_pubkey())};

    // 2. make sure the multisig tx proposal is valid
    check_v1_multisig_tx_proposal_semantics_v1(multisig_tx_proposal,
        expected_tx_version,
        threshold,
        signer_account.get_signers().size(),
        legacy_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        jamtis_spend_pubkey,
        k_view_balance);

    // 3. normal tx proposal (to get tx proposal prefix and sorted inputs)
    SpTxProposalV1 tx_proposal;
    get_v1_tx_proposal_v1(multisig_tx_proposal,
        legacy_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        jamtis_spend_pubkey,
        k_view_balance,
        tx_proposal);

    // 4. tx proposal prefix
    rct::key tx_proposal_prefix;
    get_tx_proposal_prefix_v1(tx_proposal, multisig_tx_proposal.tx_version, k_view_balance, tx_proposal_prefix);

    // 5. legacy proof contexts: [ onetime address : legacy input message ]
    std::unordered_map<rct::key, rct::key> input_proof_contexts;  //[ proof key : proof message ]
    get_legacy_proof_contexts_v1(tx_proposal_prefix,
        multisig_tx_proposal.legacy_multisig_input_proposals,
        input_proof_contexts);

    // 6. prepare legacy proof privkeys (non-multisig components)
    std::vector<crypto::secret_key> proof_privkeys_k_offset;
    std::vector<crypto::secret_key> proof_privkeys_z;

    collect_legacy_clsag_privkeys_for_multisig(tx_proposal.legacy_input_proposals,
        proof_privkeys_k_offset,
        proof_privkeys_z);

    // 7. signature maker for legacy CLSAG proofs
    const multisig::MultisigPartialSigMakerCLSAG partial_sig_maker{
            threshold,
            multisig_tx_proposal.legacy_input_proof_proposals,
            proof_privkeys_k_offset,
            proof_privkeys_z
        };


    /// make the partial signatures
    if (!multisig::try_make_v1_multisig_partial_sig_sets_v1(signer_account,
            cryptonote::account_generator_era::cryptonote,
            multisig_tx_proposal.aggregate_signer_set_filter,
            input_proof_contexts,
            2,  //legacy multisig: sign on G and Hp(Ko)
            partial_sig_maker,
            std::move(local_input_init_set_collection),
            std::move(other_input_init_set_collections),
            multisig_errors_inout,
            nonce_record_inout,
            legacy_input_partial_sig_sets_out))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_make_v1_multisig_partial_sig_sets_for_sp_inputs_v1(const multisig::multisig_account &signer_account,
    const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const tx_version_t &expected_tx_version,
    //[ proof key : init set ]
    std::unordered_map<rct::key, multisig::MultisigProofInitSetV1> local_input_init_set_collection,
    //[ signer id : [ proof key : init set ] ]
    std::unordered_map<crypto::public_key, std::unordered_map<rct::key, multisig::MultisigProofInitSetV1>>
        other_input_init_set_collections,
    std::list<multisig::MultisigSigningErrorVariant> &multisig_errors_inout,
    multisig::MultisigNonceCache &nonce_record_inout,
    std::vector<multisig::MultisigPartialSigSetV1> &sp_input_partial_sig_sets_out)
{
    sp_input_partial_sig_sets_out.clear();

    CHECK_AND_ASSERT_THROW_MES(signer_account.multisig_is_ready(),
        "multisig input partial sigs: signer account is not complete, so it can't make partial signatures.");
    CHECK_AND_ASSERT_THROW_MES(signer_account.get_era() == cryptonote::account_generator_era::seraphis,
        "multisig input partial sigs: signer account is not a seraphis account, so it can't make seraphis partial "
        "signatures.");

    // early return if there are no seraphis inputs in the multisig tx proposal
    if (multisig_tx_proposal.sp_multisig_input_proposals.size() == 0)
        return true;


    /// prepare pieces to use below

    // 1. misc. from account
    const crypto::secret_key &k_view_balance{signer_account.get_common_privkey()};
    const std::uint32_t threshold{signer_account.get_threshold()};

    // 2. jamtis spend pubkey: k_vb X + k_m U
    rct::key jamtis_spend_pubkey{rct::pk2rct(signer_account.get_multisig_pubkey())};
    extend_seraphis_spendkey_x(k_view_balance, jamtis_spend_pubkey);

    // 3. make sure the multisig tx proposal is valid
    check_v1_multisig_tx_proposal_semantics_v1(multisig_tx_proposal,
        expected_tx_version,
        threshold,
        signer_account.get_signers().size(),
        legacy_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        jamtis_spend_pubkey,
        k_view_balance);

    // 4. normal tx proposal (to get tx proposal prefix and sorted inputs)
    SpTxProposalV1 tx_proposal;
    get_v1_tx_proposal_v1(multisig_tx_proposal,
        legacy_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        jamtis_spend_pubkey,
        k_view_balance,
        tx_proposal);

    // 5. tx proposal prefix
    rct::key tx_proposal_prefix;
    get_tx_proposal_prefix_v1(tx_proposal, multisig_tx_proposal.tx_version, k_view_balance, tx_proposal_prefix);

    // 6. seraphis proof contexts: [ masked address : tx proposal prefix ]
    // note: all seraphis input image proofs sign the same message
    std::unordered_map<rct::key, rct::key> input_proof_contexts;  //[ proof key : proof message ]
    get_seraphis_proof_contexts_v1(tx_proposal_prefix, tx_proposal.sp_input_proposals, input_proof_contexts);

    // 7. prepare seraphis proof privkeys (non-multisig components)
    std::vector<crypto::secret_key> proof_privkeys_x;
    std::vector<crypto::secret_key> proof_privkeys_y;
    std::vector<crypto::secret_key> proof_privkeys_z_offset;
    std::vector<crypto::secret_key> proof_privkeys_z_multiplier;

    collect_sp_composition_proof_privkeys_for_multisig(tx_proposal.sp_input_proposals,
        k_view_balance,
        proof_privkeys_x,
        proof_privkeys_y,
        proof_privkeys_z_offset,
        proof_privkeys_z_multiplier);

    // 8. signature maker for seraphis composition proofs
    const multisig::MultisigPartialSigMakerSpCompositionProof partial_sig_maker{
            threshold,
            multisig_tx_proposal.sp_input_proof_proposals,
            proof_privkeys_x,
            proof_privkeys_y,
            proof_privkeys_z_offset,
            proof_privkeys_z_multiplier
        };


    /// make the partial signatures
    if (!multisig::try_make_v1_multisig_partial_sig_sets_v1(signer_account,
            cryptonote::account_generator_era::seraphis,
            multisig_tx_proposal.aggregate_signer_set_filter,
            input_proof_contexts,
            1,  //sp multisig: sign on U
            partial_sig_maker,
            std::move(local_input_init_set_collection),
            std::move(other_input_init_set_collections),
            multisig_errors_inout,
            nonce_record_inout,
            sp_input_partial_sig_sets_out))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_make_inputs_for_multisig_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const std::vector<crypto::public_key> &multisig_signers,
    const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const std::unordered_map<crypto::public_key, std::vector<multisig::MultisigPartialSigSetV1>>
        &legacy_input_partial_sigs_per_signer,
    const std::unordered_map<crypto::public_key, std::vector<multisig::MultisigPartialSigSetV1>>
        &sp_input_partial_sigs_per_signer,
    std::list<multisig::MultisigSigningErrorVariant> &multisig_errors_inout,
    std::vector<LegacyInputV1> &legacy_inputs_out,
    std::vector<SpPartialInputV1> &sp_partial_inputs_out)
{
    // note: we do not validate semantics of anything here, because this function is just optimistically attempting to
    //       combine partial sig sets into partial inputs if possible

    // 1. get tx proposal
    SpTxProposalV1 tx_proposal;
    get_v1_tx_proposal_v1(multisig_tx_proposal,
        legacy_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        jamtis_spend_pubkey,
        k_view_balance,
        tx_proposal);

    // 2. the proof message is the tx's proposal prefix
    rct::key tx_proposal_prefix;
    get_tx_proposal_prefix_v1(tx_proposal, multisig_tx_proposal.tx_version, k_view_balance, tx_proposal_prefix);

    // 3. try to make legacy inputs
    if (!try_make_legacy_inputs_for_multisig_v1(tx_proposal_prefix,
            tx_proposal.legacy_input_proposals,
            multisig_tx_proposal.legacy_multisig_input_proposals,
            multisig_tx_proposal.legacy_input_proof_proposals,
            multisig_signers,
            legacy_input_partial_sigs_per_signer,
            legacy_spend_pubkey,
            multisig_errors_inout,
            legacy_inputs_out))
        return false;

    // 4. try to make seraphis partial inputs
    rct::key sp_core_spend_pubkey{jamtis_spend_pubkey};
    reduce_seraphis_spendkey_x(k_view_balance, sp_core_spend_pubkey);

    if (!try_make_sp_partial_inputs_for_multisig_v1(tx_proposal_prefix,
            tx_proposal.sp_input_proposals,
            multisig_signers,
            sp_input_partial_sigs_per_signer,
            sp_core_spend_pubkey,
            k_view_balance,
            multisig_errors_inout,
            sp_partial_inputs_out))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
