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
#include "tx_builders_mixed.h"

//local headers
#include "common/container_helpers.h"
#include "contextual_enote_record_utils.h"
#include "crypto/crypto.h"
#include "cryptonote_config.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/binned_reference_set_utils.h"
#include "seraphis_core/jamtis_core_utils.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_core/sp_core_enote_utils.h"
#include "seraphis_core/sp_ref_set_index_mapper_flat.h"
#include "seraphis_crypto/bulletproofs_plus2.h"
#include "seraphis_crypto/math_utils.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_crypto/sp_hash_functions.h"
#include "seraphis_crypto/sp_legacy_proof_helpers.h"
#include "seraphis_crypto/sp_transcript.h"
#include "tx_builder_types.h"
#include "tx_builders_inputs.h"
#include "tx_builders_legacy_inputs.h"
#include "tx_builders_outputs.h"
#include "tx_component_types.h"
#include "tx_component_types_legacy.h"
#include "tx_validators.h"
#include "txtype_base.h"
#include "txtype_squashed_v1.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
////
// TxValidationContextSimple
// - assumes key images are not double-spent
// - stores manually-specified reference set elements (useful for validating partial txs)
///
class TxValidationContextSimple final : public TxValidationContext
{
public:
//constructors
    TxValidationContextSimple(const std::unordered_map<std::uint64_t, rct::ctkey> &legacy_reference_set_proof_elements,
        const std::unordered_map<std::uint64_t, rct::key> &sp_reference_set_proof_elements) :
        m_legacy_reference_set_proof_elements{legacy_reference_set_proof_elements},
        m_sp_reference_set_proof_elements{sp_reference_set_proof_elements}
    {}

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    TxValidationContextSimple& operator=(TxValidationContextSimple&&) = delete;

//member functions
    /**
    * brief: *_key_image_exists - check if a key image exists (always false here)
    * ...
    */
    bool cryptonote_key_image_exists(const crypto::key_image &key_image) const override
    {
        return false;
    }
    bool seraphis_key_image_exists(const crypto::key_image &key_image) const override
    {
        return false;
    }
    /**
    * brief: get_reference_set_proof_elements_v1 - gets legacy {KI, C} pairs stored in the validation context
    * param: indices -
    * outparam: proof_elements_out - {KI, C}
    */
    void get_reference_set_proof_elements_v1(const std::vector<std::uint64_t> &indices,
        rct::ctkeyV &proof_elements_out) const override
    {
        proof_elements_out.clear();
        proof_elements_out.reserve(indices.size());

        for (const std::uint64_t index : indices)
        {
            if (m_legacy_reference_set_proof_elements.find(index) != m_legacy_reference_set_proof_elements.end())
                proof_elements_out.emplace_back(m_legacy_reference_set_proof_elements.at(index));
            else
                proof_elements_out.emplace_back(rct::ctkey{});
        }
    }
    /**
    * brief: get_reference_set_proof_elements_v2 - gets seraphis squashed enotes stored in the validation context
    * param: indices -
    * outparam: proof_elements_out - {squashed enote}
    */
    void get_reference_set_proof_elements_v2(const std::vector<std::uint64_t> &indices,
        rct::keyV &proof_elements_out) const override
    {
        proof_elements_out.clear();
        proof_elements_out.reserve(indices.size());

        for (const std::uint64_t index : indices)
        {
            if (m_sp_reference_set_proof_elements.find(index) != m_sp_reference_set_proof_elements.end())
                proof_elements_out.emplace_back(m_sp_reference_set_proof_elements.at(index));
            else
                proof_elements_out.emplace_back(rct::key{});
        }
    }

//member variables
private:
    const std::unordered_map<std::uint64_t, rct::ctkey> &m_legacy_reference_set_proof_elements;
    const std::unordered_map<std::uint64_t, rct::key> &m_sp_reference_set_proof_elements;
};

//-------------------------------------------------------------------------------------------------------------------
// convert a crypto::secret_key vector to an rct::key vector, and obtain a memwiper for the rct::key vector
//-------------------------------------------------------------------------------------------------------------------
static auto convert_skv_to_rctv(const std::vector<crypto::secret_key> &skv, rct::keyV &rctv_out)
{
    auto a_wiper = epee::misc_utils::create_scope_leave_handler(
            [&rctv_out]()
            {
                memwipe(rctv_out.data(), rctv_out.size()*sizeof(rct::key));
            }
        );

    rctv_out.clear();
    rctv_out.reserve(skv.size());

    for (const crypto::secret_key &skey : skv)
        rctv_out.emplace_back(rct::sk2rct(skey));

    return a_wiper;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool same_key_image(const LegacyInputV1 &input, const LegacyInputProposalV1 &input_proposal)
{
    return input.input_image.key_image == input_proposal.key_image;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool same_key_image(const SpPartialInputV1 &partial_input, const SpInputProposalV1 &input_proposal)
{
    return key_image_ref(partial_input.input_image) == key_image_ref(input_proposal);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void legacy_enote_records_to_input_proposals(
    const std::vector<LegacyContextualEnoteRecordV1> &legacy_contextual_records,
    std::vector<LegacyInputProposalV1> &legacy_input_proposals_out)
{
    legacy_input_proposals_out.clear();
    legacy_input_proposals_out.reserve(legacy_contextual_records.size());

    for (const LegacyContextualEnoteRecordV1 &legacy_contextual_input : legacy_contextual_records)
    {
        // convert legacy inputs to input proposals
        make_v1_legacy_input_proposal_v1(legacy_contextual_input.record,
            rct::rct2sk(rct::skGen()),
            tools::add_element(legacy_input_proposals_out));
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void sp_enote_records_to_input_proposals(const std::vector<SpContextualEnoteRecordV1> &sp_contextual_records,
    std::vector<SpInputProposalV1> &sp_input_proposals_out)
{
    sp_input_proposals_out.clear();
    sp_input_proposals_out.reserve(sp_contextual_records.size());

    for (const SpContextualEnoteRecordV1 &sp_contextual_input : sp_contextual_records)
    {
        // convert seraphis inputs to input proposals
        make_v1_input_proposal_v1(sp_contextual_input.record,
            rct::rct2sk(rct::skGen()),
            rct::rct2sk(rct::skGen()),
            tools::add_element(sp_input_proposals_out));
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void prepare_sp_membership_proof_prep_for_tx_simulation_v1(const rct::keyV &simulated_ledger_squashed_enotes,
    const std::size_t real_reference_index,
    const SpEnoteCoreVariant &real_reference_enote,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    SpMembershipProofPrepV1 &prep_out)
{
    /// checks and initialization
    const std::size_t ref_set_size{math::uint_pow(ref_set_decomp_n, ref_set_decomp_m)};  //n^m

    CHECK_AND_ASSERT_THROW_MES(simulated_ledger_squashed_enotes.size() > 0,
        "prepare sp membership proof prep v1 (tx simulation): insufficient reference elements.");
    CHECK_AND_ASSERT_THROW_MES(simulated_ledger_squashed_enotes.size() >= compute_bin_width(bin_config.bin_radius),
        "prepare sp membership proof prep v1 (tx simulation): insufficient reference elements.");
    CHECK_AND_ASSERT_THROW_MES(real_reference_index < simulated_ledger_squashed_enotes.size(),
        "prepare sp membership proof prep v1 (tx simulation): real reference is out of bounds.");
    CHECK_AND_ASSERT_THROW_MES(validate_bin_config_v1(ref_set_size, bin_config),
        "prepare sp membership proof prep v1 (tx simulation): invalid binned reference set config.");


    /// make binned reference set

    // 1. flat index mapper for mock-up
    const SpRefSetIndexMapperFlat flat_index_mapper{0, simulated_ledger_squashed_enotes.size() - 1};

    // 2. generator seed
    rct::key generator_seed;
    make_binned_ref_set_generator_seed_v1(onetime_address_ref(real_reference_enote),
        amount_commitment_ref(real_reference_enote),
        address_mask,
        commitment_mask,
        generator_seed);

    // 3. binned reference set
    make_binned_reference_set_v1(flat_index_mapper,
        bin_config,
        generator_seed,
        ref_set_size,
        real_reference_index,
        prep_out.binned_reference_set);


    /// copy all referenced enotes from the simulated ledger (in squashed enote representation)
    std::vector<std::uint64_t> reference_indices;
    CHECK_AND_ASSERT_THROW_MES(try_get_reference_indices_from_binned_reference_set_v1(prep_out.binned_reference_set,
            reference_indices),
        "prepare sp membership proof prep v1 (tx simulation): could not extract reference indices from binned "
        "representation (bug).");

    prep_out.referenced_enotes_squashed.clear();
    prep_out.referenced_enotes_squashed.reserve(reference_indices.size());

    for (const std::uint64_t reference_index : reference_indices)
    {
        CHECK_AND_ASSERT_THROW_MES(reference_index < simulated_ledger_squashed_enotes.size(),
            "prepare sp membership proof prep v1 (tx simulation): invalid index recovered from binned representation "
            "(bug).");
        prep_out.referenced_enotes_squashed.emplace_back(simulated_ledger_squashed_enotes.at(reference_index));
    }


    /// copy misc pieces
    prep_out.ref_set_decomp_n = ref_set_decomp_n;
    prep_out.ref_set_decomp_m = ref_set_decomp_m;
    prep_out.real_reference_enote = real_reference_enote;
    prep_out.address_mask = address_mask;
    prep_out.commitment_mask = commitment_mask;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void prepare_sp_membership_proof_preps_for_tx_simulation_v1(
    const std::vector<SpEnoteCoreVariant> &real_reference_enotes,
    const std::vector<crypto::secret_key> &address_masks,
    const std::vector<crypto::secret_key> &commitment_masks,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    std::vector<SpMembershipProofPrepV1> &preps_out,
    std::unordered_map<std::uint64_t, rct::key> &sp_reference_set_proof_elements_out)
{
    preps_out.clear();
    sp_reference_set_proof_elements_out.clear();

    /// checks
    CHECK_AND_ASSERT_THROW_MES(real_reference_enotes.size() == address_masks.size(),
        "prepare sp membership proof preps v1 (tx simulation): invalid number of address masks.");
    CHECK_AND_ASSERT_THROW_MES(real_reference_enotes.size() == commitment_masks.size(),
        "prepare sp membership proof preps v1 (tx simulation): invalid number of commitment masks.");


    /// make preps

    // 1. convert real reference enotes to squashed representations
    // - the enotes' indices in the input vectors will be treated as their indices in the simulated ledger
    rct::keyV simulated_ledger_squashed_enotes;
    simulated_ledger_squashed_enotes.reserve(
            std::max(static_cast<std::uint64_t>(real_reference_enotes.size()), compute_bin_width(bin_config.bin_radius))
        );

    for (std::size_t proof_index{0}; proof_index < real_reference_enotes.size(); ++proof_index)
    {
        make_seraphis_squashed_enote_Q(onetime_address_ref(real_reference_enotes[proof_index]),
            amount_commitment_ref(real_reference_enotes[proof_index]),
            tools::add_element(simulated_ledger_squashed_enotes));

        // save the [ index : squashed enote ] mapping
        sp_reference_set_proof_elements_out[proof_index] = simulated_ledger_squashed_enotes.back();
    }

    // 2. pad the simulated ledger's squashed enotes so there are enough to satisfy the binning config
    for (std::size_t ref_set_index{simulated_ledger_squashed_enotes.size()};
        ref_set_index < compute_bin_width(bin_config.bin_radius);
        ++ref_set_index)
    {
        simulated_ledger_squashed_enotes.emplace_back(rct::pkGen());

        // save the [ index : squashed enote ] mapping
        sp_reference_set_proof_elements_out[ref_set_index] = simulated_ledger_squashed_enotes.back();
    }

    // 3. make each membership proof prep
    for (std::size_t proof_index{0}; proof_index < real_reference_enotes.size(); ++proof_index)
    {
        // make the proof prep
        prepare_sp_membership_proof_prep_for_tx_simulation_v1(simulated_ledger_squashed_enotes,
            proof_index,
            real_reference_enotes[proof_index],
            address_masks[proof_index],
            commitment_masks[proof_index],
            ref_set_decomp_n,
            ref_set_decomp_m,
            bin_config,
            tools::add_element(preps_out));
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void check_tx_proposal_semantics_inputs_v1(const std::vector<LegacyInputProposalV1> &legacy_input_proposals,
    const std::vector<SpInputProposalV1> &sp_input_proposals,
    const rct::key &legacy_spend_pubkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    std::vector<rct::xmr_amount> &in_amounts_out)
{
    // 1. there should be at least one input
    CHECK_AND_ASSERT_THROW_MES(legacy_input_proposals.size() + sp_input_proposals.size() >= 1,
        "Semantics check tx proposal inputs v1: there are no inputs.");

    // 2. input proposals should be sorted and unique
    CHECK_AND_ASSERT_THROW_MES(tools::is_sorted_and_unique(legacy_input_proposals, compare_KI),
        "Semantics check tx proposal inputs v1: legacy input proposals are not sorted and unique.");
    CHECK_AND_ASSERT_THROW_MES(tools::is_sorted_and_unique(sp_input_proposals, compare_KI),
        "Semantics check tx proposal inputs v1: seraphis input proposals are not sorted and unique.");

    // 3. legacy input proposal semantics should be valid
    for (const LegacyInputProposalV1 &legacy_input_proposal : legacy_input_proposals)
        check_v1_legacy_input_proposal_semantics_v1(legacy_input_proposal, legacy_spend_pubkey);

    // 4. seraphis input proposal semantics should be valid
    rct::key sp_core_spend_pubkey{jamtis_spend_pubkey};
    reduce_seraphis_spendkey_x(k_view_balance, sp_core_spend_pubkey);

    for (const SpInputProposalV1 &sp_input_proposal : sp_input_proposals)
        check_v1_input_proposal_semantics_v1(sp_input_proposal, sp_core_spend_pubkey, k_view_balance);

    // 5. collect input amounts
    in_amounts_out.reserve(legacy_input_proposals.size() + sp_input_proposals.size());

    for (const LegacyInputProposalV1 &legacy_input_proposal : legacy_input_proposals)
        in_amounts_out.emplace_back(amount_ref(legacy_input_proposal));

    for (const SpInputProposalV1 &sp_input_proposal : sp_input_proposals)
        in_amounts_out.emplace_back(amount_ref(sp_input_proposal));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void check_tx_proposal_semantics_selfsend_outputs_v1(const std::size_t num_normal_payment_proposals,
    const std::vector<jamtis::JamtisPaymentProposalSelfSendV1> &selfsend_payment_proposals,
    const rct::key &input_context,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance)
{
    // 1. there must be at least one self-send output
    CHECK_AND_ASSERT_THROW_MES(selfsend_payment_proposals.size() > 0,
        "Semantics check tx proposal selfsends v1: there are no self-send outputs (at least one is expected).");

    // 2. there cannot be two self-send outputs of the same type and no other outputs
    // note: violations of this rule will cause both outputs to have the same sender-receiver shared secret, which
    //       can cause privacy issues for the tx author
    if (num_normal_payment_proposals == 0 &&
        selfsend_payment_proposals.size() == 2)
    {
        CHECK_AND_ASSERT_THROW_MES(selfsend_payment_proposals[0].type != selfsend_payment_proposals[1].type,
            "Semantics check tx proposal selfsends v1: there are two self-send outputs of the same type but no other "
            "outputs (not allowed).");
    }

    // 3. all self-send destinations must be owned by the wallet
    for (const jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_payment_proposal : selfsend_payment_proposals)
    {
        check_jamtis_payment_proposal_selfsend_semantics_v1(selfsend_payment_proposal,
            input_context,
            jamtis_spend_pubkey,
            k_view_balance);
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void check_tx_proposal_semantics_output_proposals_v1(const std::vector<SpOutputProposalV1> &output_proposals,
    const TxExtra &partial_memo,
    std::vector<rct::xmr_amount> &output_amounts_out)
{
    // 1. check output proposal semantics
    check_v1_output_proposal_set_semantics_v1(output_proposals);

    // 2. extract outputs from the output proposals
    std::vector<SpEnoteV1> output_enotes;
    std::vector<crypto::secret_key> output_amount_commitment_blinding_factors;
    SpTxSupplementV1 tx_supplement;

    make_v1_outputs_v1(output_proposals,
        output_enotes,
        output_amounts_out,
        output_amount_commitment_blinding_factors,
        tx_supplement.output_enote_ephemeral_pubkeys);

    finalize_tx_extra_v1(partial_memo, output_proposals, tx_supplement.tx_extra);

    // 3. at least two outputs are expected
    // note: this rule exists because the vast majority of txs normally have at least 2 outputs (i.e. 1+ outputs and
    //       change), so preventing 1-output txs improves tx uniformity
    CHECK_AND_ASSERT_THROW_MES(output_enotes.size() >= 2,
        "Semantics check tx proposal outputs v1: there are fewer than 2 outputs.");

    // 4. outputs should be sorted and unique
    CHECK_AND_ASSERT_THROW_MES(tools::is_sorted_and_unique(output_enotes, compare_Ko),
        "Semantics check tx proposal outputs v1: output onetime addresses are not sorted and unique.");

    // 5. onetime addresses should be canonical (sanity check so our tx outputs don't end up with duplicate key images)
    for (const SpEnoteV1 &output_enote : output_enotes)
    {
        CHECK_AND_ASSERT_THROW_MES(onetime_address_is_canonical(output_enote.core),
            "Semantics check tx proposal outputs v1: an output onetime address is not in the prime subgroup.");
    }

    // 6. check that output amount commitments can be reproduced
    CHECK_AND_ASSERT_THROW_MES(output_enotes.size() == output_amounts_out.size(),
        "Semantics check tx proposal outputs v1: outputs don't line up with output amounts.");
    CHECK_AND_ASSERT_THROW_MES(output_enotes.size() == output_amount_commitment_blinding_factors.size(),
        "Semantics check tx proposal outputs v1: outputs don't line up with output amount commitment blinding factors.");

    for (std::size_t output_index{0}; output_index < output_enotes.size(); ++output_index)
    {
        CHECK_AND_ASSERT_THROW_MES(output_enotes[output_index].core.amount_commitment ==
                rct::commit(output_amounts_out[output_index],
                    rct::sk2rct(output_amount_commitment_blinding_factors[output_index])),
            "Semantics check tx proposal outputs v1: could not reproduce an output's amount commitment.");
    }

    // 7. check tx supplement (especially enote ephemeral pubkeys)
    // note: require ephemeral pubkey optimization for normal txs
    check_v1_tx_supplement_semantics_v2(tx_supplement, output_enotes.size());
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void collect_legacy_ring_signature_ring_members(const std::vector<LegacyRingSignatureV4> &legacy_ring_signatures,
    const std::vector<rct::ctkeyV> &legacy_ring_signature_rings,
    std::unordered_map<std::uint64_t, rct::ctkey> &legacy_reference_set_proof_elements_out)
{
    // map legacy ring members onto their on-chain legacy enote indices
    CHECK_AND_ASSERT_THROW_MES(legacy_ring_signatures.size() == legacy_ring_signature_rings.size(),
        "collect legacy ring signature ring members: legacy ring signatures don't line up with legacy ring signature "
        "rings.");

    for (std::size_t legacy_input_index{0}; legacy_input_index < legacy_ring_signatures.size(); ++legacy_input_index)
    {
        CHECK_AND_ASSERT_THROW_MES(legacy_ring_signatures[legacy_input_index].reference_set.size() ==
                legacy_ring_signature_rings[legacy_input_index].size(),
            "collect legacy ring signature ring members: a reference set doesn't line up with the corresponding ring.");

        for (std::size_t ring_index{0}; ring_index < legacy_ring_signature_rings[legacy_input_index].size(); ++ring_index)
        {
            legacy_reference_set_proof_elements_out[
                    legacy_ring_signatures[legacy_input_index].reference_set[ring_index]
                ] = legacy_ring_signature_rings[legacy_input_index][ring_index];
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void make_tx_proposal_prefix_v1(const tx_version_t &tx_version,
    const std::vector<crypto::key_image> &legacy_input_key_images,
    const std::vector<crypto::key_image> &sp_input_key_images,
    const std::vector<SpEnoteV1> &output_enotes,
    const rct::xmr_amount transaction_fee,
    const SpTxSupplementV1 &tx_supplement,
    rct::key &tx_proposal_prefix_out)
{
    // note: these were added due to hard-to-diagnose sorting bugs, however they do incur some cost for tx verification
    CHECK_AND_ASSERT_THROW_MES(std::is_sorted(legacy_input_key_images.begin(), legacy_input_key_images.end()),
        "tx proposal prefix (v1): legacy input key images are not sorted.");
    CHECK_AND_ASSERT_THROW_MES(std::is_sorted(sp_input_key_images.begin(), sp_input_key_images.end()),
        "tx proposal prefix (v1): seraphis input key images are not sorted.");
    CHECK_AND_ASSERT_THROW_MES(std::is_sorted(output_enotes.begin(),
            output_enotes.end(),
            tools::compare_func<SpEnoteV1>(compare_Ko)),
        "tx proposal prefix (v1): output enotes are not sorted.");

    // H_32(tx version, legacy input key images, seraphis input key images, output enotes, fee, tx supplement)
    SpFSTranscript transcript{
            config::HASH_KEY_SERAPHIS_TX_PROPOSAL_MESSAGE_V1,
            sizeof(tx_version) +
                (legacy_input_key_images.size() + sp_input_key_images.size())*sizeof(crypto::key_image) +
                output_enotes.size()*sp_enote_v1_size_bytes() +
                sizeof(transaction_fee) +
                sp_tx_supplement_v1_size_bytes(tx_supplement)
        };
    transcript.append("tx_version", tx_version.bytes);
    transcript.append("legacy_input_key_images", legacy_input_key_images);
    transcript.append("sp_input_key_images", sp_input_key_images);
    transcript.append("output_enotes", output_enotes);
    transcript.append("transaction_fee", transaction_fee);
    transcript.append("tx_supplement", tx_supplement);

    sp_hash_to_32(transcript.data(), transcript.size(), tx_proposal_prefix_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void make_tx_proposal_prefix_v1(const tx_version_t &tx_version,
    const std::vector<crypto::key_image> &legacy_input_key_images,
    const std::vector<crypto::key_image> &sp_input_key_images,
    const std::vector<SpEnoteV1> &output_enotes,
    const DiscretizedFee transaction_fee,
    const SpTxSupplementV1 &tx_supplement,
    rct::key &tx_proposal_prefix_out)
{
    // get raw fee value
    rct::xmr_amount raw_transaction_fee;
    CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(transaction_fee, raw_transaction_fee),
        "make image proposal prefix (v1): could not extract raw fee from discretized fee.");

    // get proposal prefix
    make_tx_proposal_prefix_v1(tx_version,
        legacy_input_key_images,
        sp_input_key_images,
        output_enotes,
        raw_transaction_fee,
        tx_supplement,
        tx_proposal_prefix_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_tx_proposal_prefix_v1(const tx_version_t &tx_version,
    const std::vector<LegacyEnoteImageV2> &input_legacy_enote_images,
    const std::vector<SpEnoteImageV1> &input_sp_enote_images,
    const std::vector<SpEnoteV1> &output_enotes,
    const DiscretizedFee transaction_fee,
    const SpTxSupplementV1 &tx_supplement,
    rct::key &tx_proposal_prefix_out)
{
    // get key images from enote images
    std::vector<crypto::key_image> legacy_input_key_images;
    std::vector<crypto::key_image> sp_input_key_images;
    legacy_input_key_images.reserve(input_legacy_enote_images.size());
    sp_input_key_images.reserve(input_sp_enote_images.size());

    for (const LegacyEnoteImageV2 &legacy_enote_image : input_legacy_enote_images)
        legacy_input_key_images.emplace_back(legacy_enote_image.key_image);

    for (const SpEnoteImageV1 &sp_enote_image : input_sp_enote_images)
        sp_input_key_images.emplace_back(key_image_ref(sp_enote_image));

    // get proposal prefix
    make_tx_proposal_prefix_v1(tx_version,
        legacy_input_key_images,
        sp_input_key_images,
        output_enotes,
        transaction_fee,
        tx_supplement,
        tx_proposal_prefix_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_tx_proposal_prefix_v1(const tx_version_t &tx_version,
    const std::vector<crypto::key_image> &legacy_input_key_images,
    const std::vector<crypto::key_image> &sp_input_key_images,
    const std::vector<SpOutputProposalV1> &output_proposals,
    const DiscretizedFee transaction_fee,
    const TxExtra &partial_memo,
    rct::key &tx_proposal_prefix_out)
{
    // extract info from output proposals
    std::vector<SpEnoteV1> output_enotes;
    std::vector<rct::xmr_amount> output_amounts;
    std::vector<crypto::secret_key> output_amount_commitment_blinding_factors;
    SpTxSupplementV1 tx_supplement;

    make_v1_outputs_v1(output_proposals,
        output_enotes,
        output_amounts,
        output_amount_commitment_blinding_factors,
        tx_supplement.output_enote_ephemeral_pubkeys);

    // collect full memo
    finalize_tx_extra_v1(partial_memo, output_proposals, tx_supplement.tx_extra);

    // get proposal prefix
    make_tx_proposal_prefix_v1(tx_version,
        legacy_input_key_images,
        sp_input_key_images,
        output_enotes,
        transaction_fee,
        tx_supplement,
        tx_proposal_prefix_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_tx_proposal_prefix_v1(const tx_version_t &tx_version,
    const std::vector<LegacyInputV1> &legacy_inputs,
    const std::vector<SpPartialInputV1> &sp_partial_inputs,
    const std::vector<SpOutputProposalV1> &output_proposals,
    const DiscretizedFee transaction_fee,
    const TxExtra &partial_memo,
    rct::key &tx_proposal_prefix_out)
{
    // get key images from partial inputs
    std::vector<crypto::key_image> legacy_input_key_images;
    std::vector<crypto::key_image> sp_input_key_images;
    legacy_input_key_images.reserve(legacy_inputs.size());
    sp_input_key_images.reserve(sp_partial_inputs.size());

    for (const LegacyInputV1 &legacy_input : legacy_inputs)
        legacy_input_key_images.emplace_back(legacy_input.input_image.key_image);

    for (const SpPartialInputV1 &sp_partial_input : sp_partial_inputs)
        sp_input_key_images.emplace_back(key_image_ref(sp_partial_input.input_image));

    // get proposal prefix
    make_tx_proposal_prefix_v1(tx_version,
        legacy_input_key_images,
        sp_input_key_images,
        output_proposals,
        transaction_fee,
        partial_memo,
        tx_proposal_prefix_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_tx_proposal_prefix_v1(const tx_version_t &tx_version,
    const std::vector<LegacyInputProposalV1> &legacy_input_proposals,
    const std::vector<SpInputProposalV1> &sp_input_proposals,
    const std::vector<SpOutputProposalV1> &output_proposals,
    const DiscretizedFee transaction_fee,
    const TxExtra &partial_memo,
    rct::key &tx_proposal_prefix_out)
{
    // get key images from input proposals
    std::vector<crypto::key_image> legacy_input_key_images;
    std::vector<crypto::key_image> sp_input_key_images;
    legacy_input_key_images.reserve(legacy_input_proposals.size());
    sp_input_key_images.reserve(sp_input_proposals.size());

    for (const LegacyInputProposalV1 &legacy_input_proposal : legacy_input_proposals)
        legacy_input_key_images.emplace_back(legacy_input_proposal.key_image);

    for (const SpInputProposalV1 &sp_input_proposal : sp_input_proposals)
        sp_input_key_images.emplace_back(key_image_ref(sp_input_proposal));

    // get proposal prefix
    make_tx_proposal_prefix_v1(tx_version,
        legacy_input_key_images,
        sp_input_key_images,
        output_proposals,
        transaction_fee,
        partial_memo,
        tx_proposal_prefix_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_tx_proposal_prefix_v1(const SpTxSquashedV1 &tx, rct::key &tx_proposal_prefix_out)
{
    // get proposal prefix
    make_tx_proposal_prefix_v1(tx_version_from(tx.tx_semantic_rules_version),
        tx.legacy_input_images,
        tx.sp_input_images,
        tx.outputs,
        tx.tx_fee,
        tx.tx_supplement,
        tx_proposal_prefix_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_tx_proofs_prefix_v1(const SpBalanceProofV1 &balance_proof,
    const std::vector<LegacyRingSignatureV4> &legacy_ring_signatures,
    const std::vector<SpImageProofV1> &sp_image_proofs,
    const std::vector<SpMembershipProofV1> &sp_membership_proofs,
    rct::key &tx_proofs_prefix_out)
{
    // H_32(balance proof, legacy ring signatures, seraphis image proofs, seraphis membership proofs)
    SpFSTranscript transcript{
            config::HASH_KEY_SERAPHIS_TX_PROOFS_PREFIX_V1,
            sp_balance_proof_v1_size_bytes(balance_proof) +
                (legacy_ring_signatures.size()
                    ? legacy_ring_signatures.size() * legacy_ring_signature_v4_size_bytes(legacy_ring_signatures[0])
                    : 0) +
                sp_image_proofs.size() * sp_image_proof_v1_size_bytes() +
                (sp_membership_proofs.size()
                    ? sp_membership_proofs.size() * sp_membership_proof_v1_size_bytes(sp_membership_proofs[0])
                    : 0)
        };
    transcript.append("balance_proof", balance_proof);
    transcript.append("legacy_ring_signatures", legacy_ring_signatures);
    transcript.append("sp_image_proofs", sp_image_proofs);
    transcript.append("sp_membership_proofs", sp_membership_proofs);

    sp_hash_to_32(transcript.data(), transcript.size(), tx_proofs_prefix_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void make_tx_artifacts_merkle_root_v1(const rct::key &input_images_prefix,
    const rct::key &tx_proofs_prefix,
    rct::key &tx_artifacts_merkle_root_out)
{
    // H_32(input images prefix, tx proofs prefix)
    SpFSTranscript transcript{
            config::HASH_KEY_SERAPHIS_TX_ARTIFACTS_MERKLE_ROOT_V1,
            2*sizeof(rct::key)
        };
    transcript.append("input_images_prefix", input_images_prefix);
    transcript.append("tx_proofs_prefix", tx_proofs_prefix);

    sp_hash_to_32(transcript.data(), transcript.size(), tx_artifacts_merkle_root_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_coinbase_tx_proposal_semantics_v1(const SpCoinbaseTxProposalV1 &tx_proposal)
{
    // 1. extract output proposals from tx proposal (and check their semantics)
    std::vector<SpCoinbaseOutputProposalV1> output_proposals;
    get_coinbase_output_proposals_v1(tx_proposal, output_proposals);

    check_v1_coinbase_output_proposal_set_semantics_v1(output_proposals);

    // 2. extract outputs from the output proposals
    std::vector<SpCoinbaseEnoteV1> output_enotes;
    SpTxSupplementV1 tx_supplement;

    make_v1_coinbase_outputs_v1(output_proposals, output_enotes, tx_supplement.output_enote_ephemeral_pubkeys);
    finalize_tx_extra_v1(tx_proposal.partial_memo, output_proposals, tx_supplement.tx_extra);

    // 3. outputs should be sorted and unique
    CHECK_AND_ASSERT_THROW_MES(tools::is_sorted_and_unique(output_enotes, compare_Ko),
        "Semantics check coinbase tx proposal v1: output onetime addresses are not sorted and unique.");

    // 4. onetime addresses should be canonical (sanity check so our tx outputs don't end up with duplicate key images)
    for (const SpCoinbaseEnoteV1 &output_enote : output_enotes)
    {
        CHECK_AND_ASSERT_THROW_MES(onetime_address_is_canonical(output_enote.core),
            "Semantics check coinbase tx proposal v1: an output onetime address is not in the prime subgroup.");
    }

    // 5. check tx supplement (especially enote ephemeral pubkeys)
    // note: there is no ephemeral pubkey optimization for coinbase txs
    check_v1_tx_supplement_semantics_v1(tx_supplement, output_enotes.size());

    // 6. check balance
    CHECK_AND_ASSERT_THROW_MES(validate_sp_coinbase_amount_balance_v1(tx_proposal.block_reward, output_enotes),
        "Semantics check coinbase tx proposal v1: outputs do not balance the block reward.");
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_tx_proposal_semantics_v1(const SpTxProposalV1 &tx_proposal,
    const rct::key &legacy_spend_pubkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance)
{
    // 1. check inputs
    std::vector<rct::xmr_amount> in_amounts;
    check_tx_proposal_semantics_inputs_v1(tx_proposal.legacy_input_proposals,
        tx_proposal.sp_input_proposals,
        legacy_spend_pubkey,
        jamtis_spend_pubkey,
        k_view_balance,
        in_amounts);

    // 2. check self-send payment proposals
    rct::key input_context;
    make_standard_input_context_v1(tx_proposal.legacy_input_proposals, tx_proposal.sp_input_proposals, input_context);

    check_tx_proposal_semantics_selfsend_outputs_v1(tx_proposal.normal_payment_proposals.size(),
        tx_proposal.selfsend_payment_proposals,
        input_context,
        jamtis_spend_pubkey,
        k_view_balance);

    // 3. check output proposals
    std::vector<SpOutputProposalV1> output_proposals;
    get_output_proposals_v1(tx_proposal, k_view_balance, output_proposals);

    std::vector<rct::xmr_amount> output_amounts;
    check_tx_proposal_semantics_output_proposals_v1(output_proposals, tx_proposal.partial_memo, output_amounts);

    // 4. try to extract the fee value
    rct::xmr_amount raw_transaction_fee;
    CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(tx_proposal.tx_fee, raw_transaction_fee),
        "Semantics check tx proposal v1: could not extract fee value from discretized fee.");

    // 5. check balance: sum(input amnts) == sum(output amnts) + fee
    CHECK_AND_ASSERT_THROW_MES(balance_check_in_out_amnts(in_amounts, output_amounts, raw_transaction_fee),
        "Semantics check tx proposal v1: input/output amounts did not balance with desired fee.");
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_coinbase_tx_proposal_v1(const std::uint64_t block_height,
    const rct::xmr_amount block_reward,
    std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals,
    std::vector<ExtraFieldElement> additional_memo_elements,
    SpCoinbaseTxProposalV1 &tx_proposal_out)
{
    // set fields
    tx_proposal_out.block_height             = block_height;
    tx_proposal_out.block_reward             = block_reward;
    tx_proposal_out.normal_payment_proposals = std::move(normal_payment_proposals);
    make_tx_extra(std::move(additional_memo_elements), tx_proposal_out.partial_memo);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_proposal_v1(std::vector<LegacyInputProposalV1> legacy_input_proposals,
    std::vector<SpInputProposalV1> sp_input_proposals,
    std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals,
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals,
    const DiscretizedFee discretized_transaction_fee,
    std::vector<ExtraFieldElement> additional_memo_elements,
    SpTxProposalV1 &tx_proposal_out)
{
    // inputs should be sorted by key image
    std::sort(legacy_input_proposals.begin(),
        legacy_input_proposals.end(),
        tools::compare_func<LegacyInputProposalV1>(compare_KI));
    std::sort(sp_input_proposals.begin(), sp_input_proposals.end(), tools::compare_func<SpInputProposalV1>(compare_KI));

    // set fields
    tx_proposal_out.legacy_input_proposals     = std::move(legacy_input_proposals);
    tx_proposal_out.sp_input_proposals         = std::move(sp_input_proposals);
    tx_proposal_out.normal_payment_proposals   = std::move(normal_payment_proposals);
    tx_proposal_out.selfsend_payment_proposals = std::move(selfsend_payment_proposals);
    tx_proposal_out.tx_fee                     = discretized_transaction_fee;
    make_tx_extra(std::move(additional_memo_elements), tx_proposal_out.partial_memo);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_proposal_v1(const std::vector<LegacyContextualEnoteRecordV1> &legacy_contextual_inputs,
    const std::vector<SpContextualEnoteRecordV1> &sp_contextual_inputs,
    std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals,
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals,
    const DiscretizedFee discretized_transaction_fee,
    const TxExtra &partial_memo_for_tx,
    SpTxProposalV1 &tx_proposal_out)
{
    // 1. legacy input proposals
    std::vector<LegacyInputProposalV1> legacy_input_proposals;
    legacy_enote_records_to_input_proposals(legacy_contextual_inputs, legacy_input_proposals);

    // 2. seraphis input proposals
    std::vector<SpInputProposalV1> sp_input_proposals;
    sp_enote_records_to_input_proposals(sp_contextual_inputs, sp_input_proposals);

    // 3. get memo elements
    std::vector<ExtraFieldElement> extra_field_elements;
    CHECK_AND_ASSERT_THROW_MES(try_get_extra_field_elements(partial_memo_for_tx, extra_field_elements),
        "make tx proposal for transfer (v1): unable to extract memo field elements for tx proposal.");

    // 4. assemble into tx proposal
    make_v1_tx_proposal_v1(std::move(legacy_input_proposals),
        std::move(sp_input_proposals),
        std::move(normal_payment_proposals),
        std::move(selfsend_payment_proposals),
        discretized_transaction_fee,
        std::move(extra_field_elements),
        tx_proposal_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool balance_check_in_out_amnts_v1(const rct::xmr_amount block_reward,
    const std::vector<SpCoinbaseOutputProposalV1> &output_proposals)
{
    // output amounts
    std::vector<rct::xmr_amount> out_amounts;
    out_amounts.reserve(output_proposals.size());

    for (const SpCoinbaseOutputProposalV1 &output_proposal : output_proposals)
        out_amounts.emplace_back(amount_ref(output_proposal));

    // balance check
    return balance_check_in_out_amnts({block_reward}, out_amounts, 0);
}
//-------------------------------------------------------------------------------------------------------------------
bool balance_check_in_out_amnts_v2(const std::vector<LegacyInputProposalV1> &legacy_input_proposals,
    const std::vector<SpInputProposalV1> &sp_input_proposals,
    const std::vector<SpOutputProposalV1> &output_proposals,
    const DiscretizedFee discretized_transaction_fee)
{
    // input amounts
    std::vector<rct::xmr_amount> in_amounts;
    in_amounts.reserve(legacy_input_proposals.size() + sp_input_proposals.size());

    for (const LegacyInputProposalV1 &legacy_input_proposal : legacy_input_proposals)
        in_amounts.emplace_back(amount_ref(legacy_input_proposal));

    for (const SpInputProposalV1 &sp_input_proposal : sp_input_proposals)
        in_amounts.emplace_back(amount_ref(sp_input_proposal));

    // output amounts
    std::vector<rct::xmr_amount> out_amounts;
    out_amounts.reserve(output_proposals.size());

    for (const SpOutputProposalV1 &output_proposal : output_proposals)
        out_amounts.emplace_back(amount_ref(output_proposal));

    // fee
    rct::xmr_amount raw_transaction_fee;
    CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(discretized_transaction_fee, raw_transaction_fee),
        "balance check in out amnts v1: unable to extract transaction fee from discretized fee representation.");

    // balance check
    return balance_check_in_out_amnts(in_amounts, out_amounts, raw_transaction_fee);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_balance_proof_v1(const std::vector<rct::xmr_amount> &legacy_input_amounts,
    const std::vector<rct::xmr_amount> &sp_input_amounts,
    const std::vector<rct::xmr_amount> &output_amounts,
    const rct::xmr_amount transaction_fee,
    const std::vector<crypto::secret_key> &legacy_input_image_amount_commitment_blinding_factors,
    const std::vector<crypto::secret_key> &sp_input_image_amount_commitment_blinding_factors,
    const std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors,
    SpBalanceProofV1 &balance_proof_out)
{
    // for squashed enote model

    // 1. check balance
    std::vector<rct::xmr_amount> all_in_amounts{legacy_input_amounts};
    all_in_amounts.insert(all_in_amounts.end(), sp_input_amounts.begin(), sp_input_amounts.end());

    CHECK_AND_ASSERT_THROW_MES(balance_check_in_out_amnts(all_in_amounts, output_amounts, transaction_fee),
        "make v1 balance proof (v1): amounts don't balance.");

    // 2. combine seraphis inputs and outputs for range proof (legacy input masked commitments are not range proofed)
    std::vector<rct::xmr_amount> range_proof_amounts{sp_input_amounts};
    range_proof_amounts.insert(range_proof_amounts.end(), output_amounts.begin(), output_amounts.end());

    std::vector<crypto::secret_key> range_proof_blinding_factors{sp_input_image_amount_commitment_blinding_factors};
    range_proof_blinding_factors.insert(range_proof_blinding_factors.end(),
        output_amount_commitment_blinding_factors.begin(),
        output_amount_commitment_blinding_factors.end());

    // 3. make range proofs
    BulletproofPlus2 range_proofs;

    rct::keyV range_proof_amount_commitment_blinding_factors;
    auto vec_wiper = convert_skv_to_rctv(range_proof_blinding_factors, range_proof_amount_commitment_blinding_factors);
    make_bpp2_rangeproofs(range_proof_amounts, range_proof_amount_commitment_blinding_factors, range_proofs);

    balance_proof_out.bpp2_proof = std::move(range_proofs);

    // 4. set the remainder blinding factor
    // blinding_factor = sum(legacy input blinding factors) + sum(sp input blinding factors) - sum(output blinding factors)
    std::vector<crypto::secret_key> collected_input_blinding_factors{sp_input_image_amount_commitment_blinding_factors};
    collected_input_blinding_factors.insert(collected_input_blinding_factors.end(),
        legacy_input_image_amount_commitment_blinding_factors.begin(),
        legacy_input_image_amount_commitment_blinding_factors.end());

    crypto::secret_key remainder_blinding_factor;
    subtract_secret_key_vectors(collected_input_blinding_factors,
        output_amount_commitment_blinding_factors,
        remainder_blinding_factor);

    balance_proof_out.remainder_blinding_factor = rct::sk2rct(remainder_blinding_factor);
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_partial_tx_semantics_v1(const SpPartialTxV1 &partial_tx,
    const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version)
{
    // 1. get parameters for making mock seraphis ref sets (use minimum parameters for efficiency when possible)
    const SemanticConfigSpRefSetV1 ref_set_config{semantic_config_sp_ref_sets_v1(semantic_rules_version)};
    const SpBinnedReferenceSetConfigV1 bin_config{
            .bin_radius = static_cast<ref_set_bin_dimension_v1_t>(ref_set_config.bin_radius_min),
            .num_bin_members = static_cast<ref_set_bin_dimension_v1_t>(ref_set_config.num_bin_members_min),
        };

    // 2. make mock membership proof ref sets
    std::vector<SpMembershipProofPrepV1> sp_membership_proof_preps;
    std::unordered_map<std::uint64_t, rct::key> sp_reference_set_proof_elements;

    prepare_sp_membership_proof_preps_for_tx_simulation_v1(partial_tx.sp_input_enotes,
        partial_tx.sp_address_masks,
        partial_tx.sp_commitment_masks,
        ref_set_config.decomp_n_min,
        ref_set_config.decomp_m_min,
        bin_config,
        sp_membership_proof_preps,
        sp_reference_set_proof_elements);

    // 3. make the mock seraphis membership proofs
    std::vector<SpMembershipProofV1> sp_membership_proofs;
    make_v1_membership_proofs_v1(std::move(sp_membership_proof_preps), sp_membership_proofs);

    // 4. collect legacy ring signature ring members for mock validation context
    std::unordered_map<std::uint64_t, rct::ctkey> legacy_reference_set_proof_elements;

    collect_legacy_ring_signature_ring_members(partial_tx.legacy_ring_signatures,
        partial_tx.legacy_ring_signature_rings,
        legacy_reference_set_proof_elements);

    // 5. make tx (use raw constructor instead of partial tx constructor which would call this function in an infinite
    //    recursion)
    SpTxSquashedV1 test_tx;
    make_seraphis_tx_squashed_v1(semantic_rules_version,
        partial_tx.legacy_input_images,
        partial_tx.sp_input_images,
        partial_tx.outputs,
        partial_tx.balance_proof,
        partial_tx.legacy_ring_signatures,
        partial_tx.sp_image_proofs,
        std::move(sp_membership_proofs),
        partial_tx.tx_supplement,
        partial_tx.tx_fee,
        test_tx);

    // 6. validate tx
    const TxValidationContextSimple tx_validation_context{
            legacy_reference_set_proof_elements,
            sp_reference_set_proof_elements
        };

    CHECK_AND_ASSERT_THROW_MES(validate_tx(test_tx, tx_validation_context),
        "v1 partial tx semantics check (v1): test transaction was invalid using requested semantics rules version!");
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_partial_tx_v1(std::vector<LegacyInputV1> legacy_inputs,
    std::vector<SpPartialInputV1> sp_partial_inputs,
    std::vector<SpOutputProposalV1> output_proposals,
    const DiscretizedFee discretized_transaction_fee,
    const TxExtra &partial_memo,
    const tx_version_t &tx_version,
    SpPartialTxV1 &partial_tx_out)
{
    /// preparation and checks
    partial_tx_out = SpPartialTxV1{};

    // 1. sort the inputs by key image
    std::sort(legacy_inputs.begin(), legacy_inputs.end(), tools::compare_func<LegacyInputV1>(compare_KI));
    std::sort(sp_partial_inputs.begin(), sp_partial_inputs.end(), tools::compare_func<SpPartialInputV1>(compare_KI));

    // 2. sort the outputs by onetime address
    std::sort(output_proposals.begin(), output_proposals.end(), tools::compare_func<SpOutputProposalV1>(compare_Ko));

    // 3. semantics checks for inputs and outputs
    for (const LegacyInputV1 &legacy_input : legacy_inputs)
        check_v1_legacy_input_semantics_v1(legacy_input);

    for (const SpPartialInputV1 &partial_input : sp_partial_inputs)
        check_v1_partial_input_semantics_v1(partial_input);

    check_v1_output_proposal_set_semantics_v1(output_proposals);  //do this after sorting the proposals

    // 4. extract info from output proposals
    std::vector<SpEnoteV1> output_enotes;
    std::vector<rct::xmr_amount> output_amounts;
    std::vector<crypto::secret_key> output_amount_commitment_blinding_factors;
    SpTxSupplementV1 tx_supplement;

    make_v1_outputs_v1(output_proposals,
        output_enotes,
        output_amounts,
        output_amount_commitment_blinding_factors,
        tx_supplement.output_enote_ephemeral_pubkeys);

    // 5. collect full memo
    finalize_tx_extra_v1(partial_memo, output_proposals, tx_supplement.tx_extra);

    // 6. check: inputs and proposal must have consistent proposal prefixes
    rct::key tx_proposal_prefix;
    make_tx_proposal_prefix_v1(tx_version,
        legacy_inputs,
        sp_partial_inputs,
        output_proposals,
        discretized_transaction_fee,
        partial_memo,
        tx_proposal_prefix);

    for (const LegacyInputV1 &legacy_input : legacy_inputs)
    {
        CHECK_AND_ASSERT_THROW_MES(legacy_input.tx_proposal_prefix == tx_proposal_prefix,
            "making partial tx v1: a legacy input's proposal prefix is invalid/inconsistent.");
    }

    for (const SpPartialInputV1 &partial_input : sp_partial_inputs)
    {
        CHECK_AND_ASSERT_THROW_MES(partial_input.tx_proposal_prefix == tx_proposal_prefix,
            "making partial tx v1: a seraphis partial input's proposal prefix is invalid/inconsistent.");
    }


    /// balance proof

    // 1. get input amounts and image amount commitment blinding factors
    std::vector<rct::xmr_amount> legacy_input_amounts;
    std::vector<crypto::secret_key> legacy_input_image_amount_commitment_blinding_factors;
    get_legacy_input_commitment_factors_v1(legacy_inputs,
        legacy_input_amounts,
        legacy_input_image_amount_commitment_blinding_factors);

    std::vector<rct::xmr_amount> sp_input_amounts;
    std::vector<crypto::secret_key> sp_input_image_amount_commitment_blinding_factors;
    get_input_commitment_factors_v1(sp_partial_inputs,
        sp_input_amounts,
        sp_input_image_amount_commitment_blinding_factors);

    // 2. extract the fee
    rct::xmr_amount raw_transaction_fee;
    CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(discretized_transaction_fee, raw_transaction_fee),
        "making partial tx v1: could not extract a fee value from the discretized fee.");

    // 3. make balance proof
    make_v1_balance_proof_v1(legacy_input_amounts,
        sp_input_amounts,
        output_amounts,
        raw_transaction_fee,
        legacy_input_image_amount_commitment_blinding_factors,
        sp_input_image_amount_commitment_blinding_factors,
        output_amount_commitment_blinding_factors,
        partial_tx_out.balance_proof);


    /// copy misc tx pieces

    // 1. gather legacy tx input parts
    partial_tx_out.legacy_input_images.reserve(legacy_inputs.size());
    partial_tx_out.legacy_ring_signatures.reserve(legacy_inputs.size());
    partial_tx_out.legacy_ring_signature_rings.reserve(legacy_inputs.size());

    for (LegacyInputV1 &legacy_input : legacy_inputs)
    {
        partial_tx_out.legacy_input_images.emplace_back(legacy_input.input_image);
        partial_tx_out.legacy_ring_signatures.emplace_back(std::move(legacy_input.ring_signature));
        partial_tx_out.legacy_ring_signature_rings.emplace_back(std::move(legacy_input.ring_members));
    }

    // 2. gather seraphis tx input parts
    partial_tx_out.sp_input_images.reserve(sp_partial_inputs.size());
    partial_tx_out.sp_image_proofs.reserve(sp_partial_inputs.size());
    partial_tx_out.sp_input_enotes.reserve(sp_partial_inputs.size());
    partial_tx_out.sp_address_masks.reserve(sp_partial_inputs.size());
    partial_tx_out.sp_commitment_masks.reserve(sp_partial_inputs.size());

    for (SpPartialInputV1 &partial_input : sp_partial_inputs)
    {
        partial_tx_out.sp_input_images.emplace_back(partial_input.input_image);
        partial_tx_out.sp_image_proofs.emplace_back(std::move(partial_input.image_proof));
        partial_tx_out.sp_input_enotes.emplace_back(partial_input.input_enote_core);
        partial_tx_out.sp_address_masks.emplace_back(partial_input.address_mask);
        partial_tx_out.sp_commitment_masks.emplace_back(partial_input.commitment_mask);
    }

    // 3. gather tx output parts
    partial_tx_out.outputs       = std::move(output_enotes);
    partial_tx_out.tx_fee        = discretized_transaction_fee;
    partial_tx_out.tx_supplement = std::move(tx_supplement);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_partial_tx_v1(const SpTxProposalV1 &tx_proposal,
    std::vector<LegacyInputV1> legacy_inputs,
    std::vector<SpPartialInputV1> sp_partial_inputs,
    const tx_version_t &tx_version,
    const rct::key &legacy_spend_pubkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpPartialTxV1 &partial_tx_out)
{
    // 1. validate tx proposal
    check_v1_tx_proposal_semantics_v1(tx_proposal, legacy_spend_pubkey, jamtis_spend_pubkey, k_view_balance);

    // 2. sort the inputs by key image
    std::sort(legacy_inputs.begin(), legacy_inputs.end(), tools::compare_func<LegacyInputV1>(compare_KI));
    std::sort(sp_partial_inputs.begin(), sp_partial_inputs.end(), tools::compare_func<SpPartialInputV1>(compare_KI));

    // 3. legacy inputs must line up with legacy input proposals in the tx proposal
    CHECK_AND_ASSERT_THROW_MES(legacy_inputs.size() == tx_proposal.legacy_input_proposals.size(),
        "making partial tx v1: number of legacy inputs doesn't match number of legacy input proposals.");

    for (std::size_t input_index{0}; input_index < legacy_inputs.size(); ++input_index)
    {
        CHECK_AND_ASSERT_THROW_MES(same_key_image(legacy_inputs[input_index],
                tx_proposal.legacy_input_proposals[input_index]),
            "making partial tx v1: legacy inputs and input proposals don't line up (inconsistent key images).");
    }

    // 4. seraphis partial inputs must line up with seraphis input proposals in the tx proposal
    CHECK_AND_ASSERT_THROW_MES(sp_partial_inputs.size() == tx_proposal.sp_input_proposals.size(),
        "making partial tx v1: number of seraphis partial inputs doesn't match number of seraphis input proposals.");

    for (std::size_t input_index{0}; input_index < sp_partial_inputs.size(); ++input_index)
    {
        CHECK_AND_ASSERT_THROW_MES(same_key_image(sp_partial_inputs[input_index],
                tx_proposal.sp_input_proposals[input_index]),
            "making partial tx v1: seraphis partial inputs and input proposals don't line up (inconsistent key "
            "images).");
    }

    // 5. extract output proposals from tx proposal
    std::vector<SpOutputProposalV1> output_proposals;
    get_output_proposals_v1(tx_proposal, k_view_balance, output_proposals);

    // 6. construct partial tx
    make_v1_partial_tx_v1(std::move(legacy_inputs),
        std::move(sp_partial_inputs),
        std::move(output_proposals),
        tx_proposal.tx_fee,
        tx_proposal.partial_memo,
        tx_version,
        partial_tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
