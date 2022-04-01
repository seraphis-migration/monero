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
#include "tx_builders_multisig.h"

//local headers
#include "crypto/crypto.h"
#include "misc_log_ex.h"
#include "multisig/multisig_signer_set_filter.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_core_enote_utils.h"
#include "tx_builder_types.h"
#include "tx_builder_types_multisig.h"
#include "tx_builders_mixed.h"
#include "tx_builders_outputs.h"
#include "tx_component_types.h"
#include "tx_misc_utils.h"
#include "tx_record_types.h"
#include "tx_record_utils.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <unordered_map>
#include <unordered_set>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//----------------------------------------------------------------------------------------------------------------------
// TODO: move to a 'math' library, with unit tests
//----------------------------------------------------------------------------------------------------------------------
static std::uint32_t n_choose_k(const std::uint32_t n, const std::uint32_t k)
{
    static_assert(std::numeric_limits<std::int32_t>::digits <= std::numeric_limits<double>::digits,
        "n_choose_k requires no rounding issues when converting between int32 <-> double.");

    if (n < k)
        return 0;

    double fp_result = boost::math::binomial_coefficient<double>(n, k);

    if (fp_result < 0)
        return 0;

    if (fp_result > std::numeric_limits<std::int32_t>::max())  // note: std::round() returns std::int32_t
        return 0;

    return static_cast<std::uint32_t>(std::round(fp_result));
}
//-------------------------------------------------------------------------------------------------------------------
// finalize checking multisig tx proposal semantics
// - doesn't validate onetime addresses and enote ephemeral pubkeys (these require the expensive get_v1_tx_proposal_v1())
// - assumes 'converted_input_proposals' are converted versions of the public input proposals stored in the tx proposal
//-------------------------------------------------------------------------------------------------------------------
static void check_v1_multisig_tx_proposal_semantics_v1_final(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const std::vector<SpMultisigInputProposalV1> &converted_input_proposals,
    const rct::key &proposal_prefix)
{
    // should be at least 1 input and 1 output
    CHECK_AND_ASSERT_THROW_MES(converted_input_proposals.size() > 0, "multisig tx proposal: no inputs.");
    CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_explicit_payments.size() +
            multisig_tx_proposal.m_opaque_payments.size() > 0,
        "multisig tx proposal: no outputs.");

    // input proposals line up 1:1 with input proof proposals, each input has a unique key image
    CHECK_AND_ASSERT_THROW_MES(converted_input_proposals.size() ==
        multisig_tx_proposal.m_input_proof_proposals.size(),
        "multisig tx proposal: input proposals don't line up with input proposal proofs.");

    SpEnote enote_core_temp;
    std::vector<crypto::key_image> key_images;
    key_images.reserve(converted_input_proposals.size());

    for (std::size_t input_index{0}; input_index < converted_input_proposals.size(); ++input_index)
    {
        // input proof proposal messages all equal proposal prefix of core tx proposal
        CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_input_proof_proposals[input_index].message == proposal_prefix,
            "multisig tx proposal: input proof proposal does not match the tx proposal (different proposal prefix).");

        // input proof proposal keys and key images all line up 1:1 and match with input proposals
        converted_input_proposals[input_index].get_enote_core(enote_core_temp);
        key_images.emplace_back();
        converted_input_proposals[input_index].get_key_image(key_images.back());
        CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_input_proof_proposals[input_index].K ==
                enote_core_temp.m_onetime_address,
            "multisig tx proposal: input proof proposal does not match input proposal (different onetime addresses).");
        CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_input_proof_proposals[input_index].KI ==
                key_images.back(),
            "multisig tx proposal: input proof proposal does not match input proposal (different key images).");

        // check that the key image obtained is canonical
        CHECK_AND_ASSERT_THROW_MES(key_domain_is_prime_subgroup(rct::ki2rct(key_images.back())),
            "multisig tx proposal: an input's key image is not in the prime subgroup.");
    }

    std::sort(key_images.begin(), key_images.end());
    CHECK_AND_ASSERT_THROW_MES(std::adjacent_find(key_images.begin(), key_images.end()) == key_images.end(),
        "multisig tx proposal: inputs are not unique (found duplicate key image).");

    // signer set filter must be valid (at least 'threshold' signers allowed, format is valid)
    CHECK_AND_ASSERT_THROW_MES(multisig::validate_aggregate_multisig_signer_set_filter(threshold,
            num_signers,
            multisig_tx_proposal.m_aggregate_signer_set_filter),
        "multisig tx proposal: invalid aggregate signer set filter.");
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
bool validate_v1_multisig_input_init_set_for_partial_sig_set_v1(const SpMultisigInputInitSetV1 &input_init_set,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const rct::key &expected_proposal_prefix,
    const multisig::signer_set_filter expected_aggregate_signer_set_filter,
    const std::vector<rct::key> &expected_masked_addresses)
{
    // signer in signer list
    if (std::find(multisig_signers.begin(), multisig_signers.end(), input_init_set.m_signer_id) == multisig_signers.end())
        return false;

    // proposal prefix matches expected prefix
    if (!(input_init_set.m_proposal_prefix == expected_proposal_prefix))
        return false;

    // aggregate filter matches expected aggregate filter
    if (input_init_set.m_aggregate_signer_set_filter != expected_aggregate_signer_set_filter)
        return false;

    // signer is in aggregate filter
    if (!multisig::signer_is_in_filter(input_init_set.m_signer_id, multisig_signers, expected_aggregate_signer_set_filter))
        return false;

    // masked addresses in init set line up 1:1 with expected masked addresses
    if (input_init_set.m_input_inits.size() != expected_masked_addresses.size())
        return false;

    for (const rct::key &masked_address : expected_masked_addresses)
    {
        if (input_init_set.m_input_inits.find(masked_address) == input_init_set.m_input_inits.end())
            return false;
    }

    // init set semantics must be valid
    try { check_v1_multisig_input_init_set_semantics_v1(input_init_set, threshold, multisig_signers); }
    catch (...) { return false; }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void get_masked_addresses(const std::vector<SpMultisigPublicInputProposalV1> &public_input_proposals,
    rct::keyV &masked_addresses_out)
{
    masked_addresses_out.clear();
    masked_addresses_out.reserve(public_input_proposals.size());

    for (const SpMultisigPublicInputProposalV1 &input_proposal : public_input_proposals)
    {
        masked_addresses_out.emplace_back();
        input_proposal.get_masked_address(masked_addresses_out.back());
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_public_input_proposal_v1(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpMultisigPublicInputProposalV1 &proposal_out)
{
    // add components
    proposal_out.m_enote = enote;
    proposal_out.m_enote_ephemeral_pubkey = enote_ephemeral_pubkey;
    proposal_out.m_address_mask = address_mask;
    proposal_out.m_commitment_mask = commitment_mask;
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_multisig_input_proposal_semantics_v1(const SpMultisigInputProposalV1 &input_proposal)
{
    // input amount components should be able to reproduce the amount commitment
    rct::key reconstructed_amount_commitment{
            rct::commit(input_proposal.m_input_amount, rct::sk2rct(input_proposal.m_input_amount_blinding_factor))
        };
    CHECK_AND_ASSERT_THROW_MES(reconstructed_amount_commitment == input_proposal.m_core.m_enote.m_core.m_amount_commitment,
        "multisig input proposal: could not reconstruct the amount commitment.");
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_input_proposal_v1(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const crypto::secret_key &enote_view_privkey,
    const rct::xmr_amount &input_amount,
    const crypto::secret_key &input_amount_blinding_factor,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpMultisigInputProposalV1 &proposal_out)
{
    // make multisig input proposal

    // set core
    make_v1_multisig_public_input_proposal_v1(enote,
        enote_ephemeral_pubkey,
        address_mask,
        commitment_mask,
        proposal_out.m_core);

    // add components
    proposal_out.m_enote_view_privkey = enote_view_privkey;
    proposal_out.m_input_amount = input_amount;
    proposal_out.m_input_amount_blinding_factor = input_amount_blinding_factor;

    // make sure it is well-formed
    check_v1_multisig_input_proposal_semantics_v1(proposal_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_input_proposal_v1(const SpEnoteRecordV1 &enote_record,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpMultisigInputProposalV1 &proposal_out)
{
    // make multisig input proposal from enote record
    make_v1_multisig_input_proposal_v1(enote_record.m_enote,
        enote_record.m_enote_ephemeral_pubkey,
        enote_record.m_enote_view_privkey,
        enote_record.m_amount,
        enote_record.m_amount_blinding_factor,
        address_mask,
        commitment_mask,
        proposal_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_v1_multisig_input_proposal_v1(const SpMultisigPublicInputProposalV1 &public_input_proposal,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpMultisigInputProposalV1 &proposal_out)
{
    // try to extract info from enote then make multisig input proposal
    SpEnoteRecordV1 enote_record;
    if (!try_get_enote_record_v1(public_input_proposal.m_enote,
            public_input_proposal.m_enote_ephemeral_pubkey,
            wallet_spend_pubkey,
            k_view_balance,
            enote_record))
        return false;

    make_v1_multisig_input_proposal_v1(enote_record,
        public_input_proposal.m_address_mask,
        public_input_proposal.m_commitment_mask,
        proposal_out);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_v1_multisig_input_proposals_v1(const std::vector<SpMultisigPublicInputProposalV1> &public_input_proposals,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    std::vector<SpMultisigInputProposalV1> &converted_input_proposals_out)
{
    // convert the public input proposals
    converted_input_proposals_out.reserve(public_input_proposals.size());

    for (const SpMultisigPublicInputProposalV1 &input_proposal : public_input_proposals)
    {
        converted_input_proposals_out.emplace_back();
        if (!try_get_v1_multisig_input_proposal_v1(input_proposal,
                wallet_spend_pubkey,
                k_view_balance,
                converted_input_proposals_out.back()))
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void finalize_multisig_output_proposals_v1(const std::vector<SpMultisigInputProposalV1> &full_input_proposals,
    const rct::xmr_amount transaction_fee,
    const jamtis::JamtisDestinationV1 &change_destination,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const std::vector<jamtis::JamtisPaymentProposalV1> &explicit_payments,
    std::vector<SpOutputProposalV1> &opaque_payments_inout)
{
    // collect total input amount
    boost::multiprecision::uint128_t total_input_amount{0};

    for (const SpMultisigInputProposalV1 &input_proposal : full_input_proposals)
        total_input_amount += input_proposal.m_input_amount;

    // copy existing output proposals
    std::vector<SpOutputProposalV1> output_proposals_temp;
    output_proposals_temp.reserve(opaque_payments_inout.size() + explicit_payments.size() + 2);  //finalize adds 2 at most
    output_proposals_temp = opaque_payments_inout;

    // add explicit payments to output proposal set
    for (const jamtis::JamtisPaymentProposalV1 &jamtis_payment_proposal : explicit_payments)
    {
        output_proposals_temp.emplace_back();
        jamtis_payment_proposal.get_output_proposal_v1(output_proposals_temp.back());
    }

    // save number of output proposals so we know how many get added
    const std::size_t num_original_payments{output_proposals_temp.size()};

    // finalize the output proposal set
    finalize_v1_output_proposal_set_v1(total_input_amount,
        transaction_fee,
        change_destination,
        wallet_spend_pubkey,
        k_view_balance,
        output_proposals_temp);

    CHECK_AND_ASSERT_THROW_MES(output_proposals_temp.size() >= num_original_payments,
        "finalize multisig output proposals: finalizing output proposals reduced number of proposals (bug).");

    // add new output proposals to the original opaque output set
    opaque_payments_inout.reserve(opaque_payments_inout.size() + output_proposals_temp.size() - num_original_payments);

    for (std::size_t output_proposal_index{num_original_payments};
            output_proposal_index < output_proposals_temp.size();
            ++output_proposal_index)
        opaque_payments_inout.emplace_back(output_proposals_temp[output_proposal_index]);
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_multisig_tx_proposal_full_balance_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const rct::xmr_amount desired_fee)
{
    // get input amounts
    std::vector<rct::xmr_amount> in_amounts;
    in_amounts.reserve(multisig_tx_proposal.m_input_proposals.size());

    std::vector<SpMultisigInputProposalV1> converted_input_proposals;
    CHECK_AND_ASSERT_THROW_MES(try_get_v1_multisig_input_proposals_v1(multisig_tx_proposal.m_input_proposals,
            wallet_spend_pubkey,
            k_view_balance,
            converted_input_proposals),
        "multisig tx proposal balance check: could not extract data from an input proposal (maybe input not owned by user).");

    for (const SpMultisigInputProposalV1 &input_proposal : converted_input_proposals)
        in_amounts.emplace_back(input_proposal.m_input_amount);

    // get output amounts
    SpTxProposalV1 tx_proposal;
    multisig_tx_proposal.get_v1_tx_proposal_v1(tx_proposal);

    CHECK_AND_ASSERT_THROW_MES(balance_check_in_out_amnts(in_amounts, tx_proposal.m_output_amounts, desired_fee),
        "multisig tx proposal: input/output amounts did not balance with desired fee.");
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_multisig_tx_proposal_semantics_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const std::string &expected_version_string,
    const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance)
{
    // proposal should contain expected tx version encoding
    CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_version_string == expected_version_string,
        "multisig tx proposal: intended tx version encoding is invalid.");

    // convert to a plain tx proposal to check the following
    // - unique onetime addresses
    // - if only 2 outputs, should be 1 unique enote ephemeral pubkey, otherwise 1:1 with outputs and all unique
    const rct::key proposal_prefix{multisig_tx_proposal.get_proposal_prefix_v1()};

    // convert the public input proposals
    std::vector<SpMultisigInputProposalV1> converted_input_proposals;
    CHECK_AND_ASSERT_THROW_MES(try_get_v1_multisig_input_proposals_v1(multisig_tx_proposal.m_input_proposals,
            wallet_spend_pubkey,
            k_view_balance,
            converted_input_proposals),
        "multisig tx proposal: could not extract data from an input proposal (maybe input not owned by user).");

    // finish the checks
    check_v1_multisig_tx_proposal_semantics_v1_final(multisig_tx_proposal,
        threshold,
        num_signers,
        converted_input_proposals,
        proposal_prefix);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_tx_proposal_v1(const std::uint32_t threshold,
    const std::uint32_t num_signers,
    std::vector<jamtis::JamtisPaymentProposalV1> explicit_payments,
    std::vector<SpOutputProposalV1> opaque_payments,
    TxExtra partial_memo,
    std::string version_string,
    const std::vector<SpMultisigInputProposalV1> &full_input_proposals,
    const multisig::signer_set_filter aggregate_signer_set_filter,
    SpMultisigTxProposalV1 &proposal_out)
{
    // add miscellaneous components
    proposal_out.m_explicit_payments = std::move(explicit_payments);
    proposal_out.m_opaque_payments = std::move(opaque_payments);
    proposal_out.m_partial_memo = std::move(partial_memo);
    proposal_out.m_aggregate_signer_set_filter = aggregate_signer_set_filter;
    proposal_out.m_version_string = std::move(version_string);

    // get proposal prefix (it is safe to do this as soon as the outputs, memo, and version are set)
    const rct::key proposal_prefix{proposal_out.get_proposal_prefix_v1()};

    // prepare composition proofs for each input
    proposal_out.m_input_proof_proposals.clear();
    proposal_out.m_input_proof_proposals.reserve(full_input_proposals.size());
    rct::key masked_address_temp;
    SpEnoteImage enote_image_temp;

    for (const SpMultisigInputProposalV1 &full_input_proposal : full_input_proposals)
    {
        full_input_proposal.m_core.get_masked_address(masked_address_temp);
        full_input_proposal.get_enote_image(enote_image_temp);
        proposal_out.m_input_proof_proposals.emplace_back(
                sp_composition_multisig_proposal(proposal_prefix,
                    masked_address_temp,
                    enote_image_temp.m_key_image)
            );
    }

    // set public input proposals
    proposal_out.m_input_proposals.reserve(full_input_proposals.size());
    for (const SpMultisigInputProposalV1 &full_input_proposal : full_input_proposals)
        proposal_out.m_input_proposals.emplace_back(full_input_proposal.m_core);

    // sanity check the proposal contents
    check_v1_multisig_tx_proposal_semantics_v1_final(proposal_out,
        threshold,
        num_signers,
        full_input_proposals,
        proposal_prefix);
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_multisig_input_init_set_semantics_v1(const SpMultisigInputInitSetV1 &input_init_set,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers)
{
    // input init's signer must be known and permitted by the aggregate filter
    CHECK_AND_ASSERT_THROW_MES(std::find(multisig_signers.begin(), multisig_signers.end(), input_init_set.m_signer_id) !=
        multisig_signers.end(), "multisig input initializer: initializer from unknown signer.");
    CHECK_AND_ASSERT_THROW_MES(multisig::signer_is_in_filter(input_init_set.m_signer_id,
            multisig_signers,
            input_init_set.m_aggregate_signer_set_filter),
        "multisig input initializer: signer is not eligible unexpectedly.");

    // signer set filter must be valid (at least 'threshold' signers allowed, format is valid)
    CHECK_AND_ASSERT_THROW_MES(multisig::validate_aggregate_multisig_signer_set_filter(threshold,
            multisig_signers.size(),
            input_init_set.m_aggregate_signer_set_filter),
        "multisig tx proposal: invalid aggregate signer set filter.");

    // for each enote image to sign, there should be one nonce set (signing attemp) per signer set that contains the signer
    // - there are 'num signers requested' choose 'threshold' total signer sets per enote image
    // - remove our signer, then choose 'threshold - 1' signers from the remaining 'num signers requested - 1'
    const std::uint32_t num_sets_with_signer_expected(
            n_choose_k(multisig::get_num_flags_set(input_init_set.m_aggregate_signer_set_filter) - 1, threshold - 1)
        );

    for (const auto &init : input_init_set.m_input_inits)
    {
        CHECK_AND_ASSERT_THROW_MES(init.second.size() == num_sets_with_signer_expected,
            "multisig input initializer: don't have expected number of nonce sets (one per signer set with signer).");
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_input_init_set_v1(const crypto::public_key &signer_id,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const rct::key &proposal_prefix,
    const rct::keyV &masked_addresses,
    const multisig::signer_set_filter aggregate_signer_set_filter,
    SpCompositionProofMultisigNonceRecord &nonce_record_inout,
    SpMultisigInputInitSetV1 &input_init_set_out)
{
    // set components
    input_init_set_out.m_signer_id = signer_id;
    input_init_set_out.m_proposal_prefix = proposal_prefix;
    input_init_set_out.m_aggregate_signer_set_filter = aggregate_signer_set_filter;

    // prepare input init nonce map
    const std::uint32_t num_sets_with_signer_expected{
            n_choose_k(multisig::get_num_flags_set(aggregate_signer_set_filter) - 1, threshold - 1)
        };

    input_init_set_out.m_input_inits.clear();
    for (const rct::key &masked_address : masked_addresses)
    {
        // enforce canonical proof keys
        // NOTE: This is only a sanity check, as the underlying onetime addresses could contain duplicates (just with
        //       different masks).
        CHECK_AND_ASSERT_THROW_MES(key_domain_is_prime_subgroup(masked_address),
            "multisig input initializer: found enote image address with non-canonical representation!");

        input_init_set_out.m_input_inits[masked_address].reserve(num_sets_with_signer_expected);
    }

    CHECK_AND_ASSERT_THROW_MES(input_init_set_out.m_input_inits.size() == masked_addresses.size(),
        "multisig input initializer: found duplicate masked address (only unique enote images allowed).");

    // add nonces for every possible signer set that includes the signer
    std::vector<multisig::signer_set_filter> filter_permutations;
    multisig::aggregate_multisig_signer_set_filter_to_permutations(threshold,
        multisig_signers.size(),
        aggregate_signer_set_filter,
        filter_permutations);

    for (const multisig::signer_set_filter filter : filter_permutations)
    {
        // ignore filters that don't include the signer
        if (!multisig::signer_is_in_filter(input_init_set_out.m_signer_id, multisig_signers, filter))
            continue;

        // add nonces for each enote image we want to attempt to sign with this signer set
        for (const rct::key &masked_address : masked_addresses)
        {
            // note: ignore failures to add nonces (using existing nonces is allowed)
            nonce_record_inout.try_add_nonces(proposal_prefix, masked_address, filter, sp_composition_multisig_init());

            // record the nonce pubkeys (should not fail)
            input_init_set_out.m_input_inits[masked_address].emplace_back();
            CHECK_AND_ASSERT_THROW_MES(nonce_record_inout.try_get_recorded_nonce_pubkeys(proposal_prefix,
                    masked_address,
                    filter,
                    input_init_set_out.m_input_inits[masked_address].back()),
                "multisig input init: could not get nonce pubkeys from nonce record (bug).");
        }
    }

    // check that the input initializer is well formed
    check_v1_multisig_input_init_set_semantics_v1(input_init_set_out, threshold, multisig_signers);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_input_init_set_v1(const crypto::public_key &signer_id,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const SpMultisigTxProposalV1 &multisig_tx_proposal,
    SpCompositionProofMultisigNonceRecord &nonce_record_inout,
    SpMultisigInputInitSetV1 &input_init_set_out)
{
    // make multisig input inits from a tx proposal
    CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_input_proposals.size() > 0,
        "multisig input initializer: no inputs to initialize.");

    // make proposal prefix
    const rct::key proposal_prefix{multisig_tx_proposal.get_proposal_prefix_v1()};

    // prepare masked addresses
    rct::keyV masked_addresses;
    get_masked_addresses(multisig_tx_proposal.m_input_proposals, masked_addresses);

    make_v1_multisig_input_init_set_v1(signer_id,
        threshold,
        multisig_signers,
        proposal_prefix,
        masked_addresses,
        multisig_tx_proposal.m_aggregate_signer_set_filter,
        nonce_record_inout,
        input_init_set_out);
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_multisig_input_partial_sig_semantics_v1(const SpMultisigInputPartialSigSetV1 &input_partial_sig_set,
    const std::vector<crypto::public_key> &multisig_signers)
{
    // signer is in filter
    CHECK_AND_ASSERT_THROW_MES(multisig::signer_is_in_filter(input_partial_sig_set.m_signer_id,
            multisig_signers,
            input_partial_sig_set.m_signer_set_filter),
        "multisig input partial sig set: the signer is not a member of the signer group.");

    // all inputs sign the same message
    for (const SpCompositionProofMultisigPartial &partial_sig : input_partial_sig_set.m_partial_signatures)
    {
        CHECK_AND_ASSERT_THROW_MES(partial_sig.message == input_partial_sig_set.m_proposal_prefix,
            "multisig input partial sig set: a partial signature's message does not match the set's proposal prefix.");
    }
}
//-------------------------------------------------------------------------------------------------------------------
bool try_make_v1_multisig_input_partial_sig_sets_v1(const multisig::multisig_account &signer_account,
    const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const SpMultisigInputInitSetV1 &local_input_init_set,
    std::vector<SpMultisigInputInitSetV1> other_input_init_sets,
    SpCompositionProofMultisigNonceRecord &nonce_record_inout,
    std::vector<SpMultisigInputPartialSigSetV1> &input_partial_sig_sets_out)
{
    //TODO: break this function into pieces somehow
    CHECK_AND_ASSERT_THROW_MES(signer_account.multisig_is_ready(),
        "multisig input partial sigs: signer account is not complete, so it can't make partial signatures.");

    /// prepare pieces to use below

    const rct::key proposal_prefix{multisig_tx_proposal.get_proposal_prefix_v1()};
    const std::vector<crypto::public_key> &multisig_signers = signer_account.get_signers();
    rct::keyV input_masked_addresses;
    get_masked_addresses(multisig_tx_proposal.m_input_proposals, input_masked_addresses);

    std::vector<multisig::signer_set_filter> filter_permutations;
    multisig::aggregate_multisig_signer_set_filter_to_permutations(signer_account.get_threshold(),
        multisig_signers.size(),
        multisig_tx_proposal.m_aggregate_signer_set_filter,
        filter_permutations);


    /// validate and filter input inits

    // 1) local input init set must be valid
    CHECK_AND_ASSERT_THROW_MES(local_input_init_set.m_signer_id == signer_account.get_base_pubkey(),
        "multisig input partial sigs: local input init set is not from local signer.");
    CHECK_AND_ASSERT_THROW_MES(validate_v1_multisig_input_init_set_for_partial_sig_set_v1(
            local_input_init_set,
            signer_account.get_threshold(),
            multisig_signers,
            proposal_prefix,
            multisig_tx_proposal.m_aggregate_signer_set_filter,
            input_masked_addresses),
        "multisig input partial sigs: the local signer's input initializer doesn't match the multisig tx proposal.");

    // 2) weed out invalid other input init sets
    (void) std::remove_if(other_input_init_sets.begin(), other_input_init_sets.end(),
            [&](const SpMultisigInputInitSetV1 &other_input_init_set) -> bool
            {
                return !validate_v1_multisig_input_init_set_for_partial_sig_set_v1(
                    other_input_init_set,
                    signer_account.get_threshold(),
                    multisig_signers,
                    proposal_prefix,
                    multisig_tx_proposal.m_aggregate_signer_set_filter,
                    input_masked_addresses);
            }
        );

    // 3) add local signer to init sets
    other_input_init_sets.emplace_back(local_input_init_set);

    // 4) remove inits from duplicate signers (including duplicate local signer inits)
    std::sort(other_input_init_sets.begin(), other_input_init_sets.end(),
            [](const SpMultisigInputInitSetV1 &set1, const SpMultisigInputInitSetV1 &set2) -> bool
            {
                return set1.m_signer_id < set2.m_signer_id;
            }
        );
    (void) std::unique(other_input_init_sets.begin(), other_input_init_sets.end(),
            [&](const SpMultisigInputInitSetV1 &set1, const SpMultisigInputInitSetV1 &set2) -> bool
            {
                return set1.m_signer_id == set2.m_signer_id;
            }
        );


    /// prepare for signing

    // 1) save local signer as filter
    multisig::signer_set_filter local_signer_filter;
    multisig::multisig_signer_to_filter(signer_account.get_base_pubkey(), multisig_signers, local_signer_filter);

    // 2) collect available signers
    std::vector<crypto::public_key> available_signers;
    available_signers.reserve(other_input_init_sets.size());

    for (const SpMultisigInputInitSetV1 &other_input_init_set : other_input_init_sets)
        available_signers.emplace_back(other_input_init_set.m_signer_id);

    // give up if not enough signers
    if (available_signers.size() < signer_account.get_threshold())
        return false;

    // 3) available signers as a filter
    multisig::signer_set_filter available_signers_filter;
    multisig::multisig_signers_to_filter(available_signers, multisig_signers, available_signers_filter);

    // 4) available signers as individual filters
    std::vector<multisig::signer_set_filter> available_signers_as_filters;
    available_signers_as_filters.reserve(available_signers.size());

    for (const crypto::public_key &available_signer : available_signers)
    {
        available_signers_as_filters.emplace_back();
        multisig::multisig_signer_to_filter(available_signer, multisig_signers, available_signers_as_filters.back());
    }

    // 5) record input enote view privkeys with squash prefix
    std::vector<crypto::secret_key> squash_prefixes;
    squash_prefixes.reserve(multisig_tx_proposal.m_input_proposals.size());

    for (const SpMultisigPublicInputProposalV1 &input_proposal : multisig_tx_proposal.m_input_proposals)
    {
        squash_prefixes.emplace_back();
        input_proposal.get_squash_prefix(squash_prefixes.back());
    }

    // 6) extract data from input proposals so input enote view privkeys are available
    std::vector<SpMultisigInputProposalV1> converted_input_proposals;

    if (!try_get_v1_multisig_input_proposals_v1(multisig_tx_proposal.m_input_proposals,
            rct::pk2rct(signer_account.get_multisig_pubkey()),
            signer_account.get_common_privkey(),
            converted_input_proposals))
        return false;


    /// make partial signatures for every available group of signers of size threshold that includes the local signer

    CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_input_proposals.size() == 
            multisig_tx_proposal.m_input_proof_proposals.size(),
        "multisig input partial sigs: input proposals don't line up with input proof proposals (bug).");
    CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_input_proposals.size() == 
            converted_input_proposals.size(),
        "multisig input partial sigs: input proposals don't line up with converted input proposals (bug).");
    CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_input_proposals.size() == 
            squash_prefixes.size(),
        "multisig input partial sigs: input proposals don't line up with prepared enote squash prefixes (bug).");
    CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_input_proposals.size() == 
            input_masked_addresses.size(),
        "multisig input partial sigs: input proposals don't line up with masked addresses (bug).");

    // signer nonce trackers are pointers into the nonce vectors in each signer's init set
    // - a signer's nonce vectors line up 1:1 with the filters in 'filter_permutations' of which the signer is a member
    // - we want to track through each signers' vectors as we go through the full set of 'filter_permutations'
    std::vector<std::size_t> signer_nonce_trackers(available_signers.size(), 0);

    std::vector<SpCompositionProofMultisigPubNonces> signer_pub_nonces_temp;
    signer_pub_nonces_temp.reserve(signer_account.get_threshold());

    crypto::secret_key enote_view_privkey_with_squash_prefix, z_temp, z_temp_with_squash_prefix;

    const std::uint32_t expected_partial_sig_sets{
            n_choose_k(available_signers.size() - 1, signer_account.get_threshold() - 1)
        };
    input_partial_sig_sets_out.clear();
    input_partial_sig_sets_out.reserve(expected_partial_sig_sets);
    std::uint32_t aborted_partial_sig_sets{0};

    for (const multisig::signer_set_filter filter : filter_permutations)
    {
        // for filters that contain only available signers (and include the local signer), make a partial signature set
        // - throw on failure so the partial sig set can be rolled back
        if ((filter & available_signers_filter) == filter &&
            (filter & local_signer_filter))
        {
            // if this throws, then the signer's nonces for this filter/proposal/input_set combo that were used before
            //   the throw will be completely lost; however, if it does throw then this signing attempt was futile to
            //   begin with
            // - note: one scenario where this design could be undesirable is if the signer wants 'at least one' input's
            //   partial signature to succeed; the design implemened here relies on the stronger precondition of 'all or
            //   nothing' because the basic multisig model assumes honest players are 100% honest, and anything less should
            //   be ignored
            input_partial_sig_sets_out.emplace_back();
            try
            {
                // copy miscellanea
                input_partial_sig_sets_out.back().m_signer_id = signer_account.get_base_pubkey();
                input_partial_sig_sets_out.back().m_proposal_prefix = proposal_prefix;
                input_partial_sig_sets_out.back().m_signer_set_filter = filter;

                // local signer's signing key for this group
                if (!signer_account.try_get_aggregate_signing_key(filter, z_temp))
                    throw;

                // make a partial signature for each input
                input_partial_sig_sets_out.back().m_partial_signatures.reserve(input_masked_addresses.size());

                for (std::size_t input_index{0}; input_index < multisig_tx_proposal.m_input_proposals.size(); ++input_index)
                {
                    // collect nonces from all signers in this signing group
                    signer_pub_nonces_temp.clear();
                    for (std::size_t signer_index{0}; signer_index < other_input_init_sets.size(); ++signer_index)
                    {
                        if ((available_signers_as_filters[signer_index] & filter) == 0)
                            continue;

                        // indexing:
                        // - this signer's init set
                        // - select the input we are working on (via this input's masked address)
                        // - select the nonces that line up with the signer's nonce tracker
                        signer_pub_nonces_temp.emplace_back();
                        if (!other_input_init_sets[signer_index].try_get_nonces(input_masked_addresses[input_index],
                                signer_nonce_trackers[signer_index],
                                signer_pub_nonces_temp.back()))
                            throw;
                    }

                    // sanity check
                    CHECK_AND_ASSERT_THROW_MES(signer_pub_nonces_temp.size() == signer_account.get_threshold(), "");

                    // apply squash prefix to signing keys y and z_e
                    sc_mul(to_bytes(enote_view_privkey_with_squash_prefix),
                        to_bytes(squash_prefixes[input_index]),
                        to_bytes(converted_input_proposals[input_index].m_enote_view_privkey));
                    sc_mul(to_bytes(z_temp_with_squash_prefix),
                        to_bytes(squash_prefixes[input_index]),
                        to_bytes(z_temp));

                    // local signer's partial sig for this input
                    input_partial_sig_sets_out.back().m_partial_signatures.emplace_back();

                    if (!try_get_sp_composition_multisig_partial_sig(
                            multisig_tx_proposal.m_input_proof_proposals[input_index],
                            multisig_tx_proposal.m_input_proposals[input_index].m_address_mask,  //x
                            enote_view_privkey_with_squash_prefix,                               //y
                            z_temp_with_squash_prefix,                                           //z_e
                            signer_pub_nonces_temp,
                            filter,
                            nonce_record_inout,
                            input_partial_sig_sets_out.back().m_partial_signatures.back()))
                        throw;
                }

                // final sanity check
                check_v1_multisig_input_partial_sig_semantics_v1(input_partial_sig_sets_out.back(), multisig_signers);
            }
            catch (...)
            {
                input_partial_sig_sets_out.pop_back();
                ++aborted_partial_sig_sets;
            }
        }

        // increment nonce trackers for all signers in this filter
        for (std::size_t signer_index{0}; signer_index < available_signers.size(); ++signer_index)
        {
            if (available_signers_as_filters[signer_index] & filter)
                ++signer_nonce_trackers[signer_index];
        }
    }

    // sanity check
    CHECK_AND_ASSERT_THROW_MES(expected_partial_sig_sets - aborted_partial_sig_sets == input_partial_sig_sets_out.size(),
        "multisig input partial sigs: did not produce expected number of partial sig sets (bug).");

    if (input_partial_sig_sets_out.size() == 0)
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_make_v1_partial_input_v1(const SpMultisigInputProposalV1 &input_proposal,
    const rct::key &expected_proposal_prefix,
    const std::vector<SpCompositionProofMultisigPartial> &input_proof_partial_sigs,
    SpPartialInputV1 &partial_input_out)
{
    try
    {
        // all partial sigs must sign the same message
        for (const SpCompositionProofMultisigPartial &partial_sig : input_proof_partial_sigs)
        {
            CHECK_AND_ASSERT_THROW_MES(partial_sig.message == expected_proposal_prefix,
                "multisig make partial input: a partial signature's message does not match the expected proposal prefix.");
        }

        // assemble proof
        partial_input_out.m_image_proof.m_composition_proof = sp_composition_prove_multisig_final(input_proof_partial_sigs);

        // copy miscellaneous pieces
        input_proposal.get_enote_image(partial_input_out.m_input_image.m_core);
        partial_input_out.m_image_address_mask = input_proposal.m_core.m_address_mask;
        partial_input_out.m_image_commitment_mask = input_proposal.m_core.m_commitment_mask;
        partial_input_out.m_proposal_prefix = expected_proposal_prefix;
        input_proposal.get_enote_core(partial_input_out.m_input_enote_core);
        partial_input_out.m_input_amount = input_proposal.m_input_amount;
        partial_input_out.m_input_amount_blinding_factor = input_proposal.m_input_amount_blinding_factor;
    }
    catch (...)
    {
        return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_partial_inputs_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const std::vector<crypto::public_key> &multisig_signers,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    std::vector<SpMultisigInputPartialSigSetV1> input_partial_sigs,
    std::vector<SpPartialInputV1> &partial_inputs_out)
{
    // convert to full input proposals so key images are available
    std::vector<SpMultisigInputProposalV1> converted_input_proposals;
    CHECK_AND_ASSERT_THROW_MES(try_get_v1_multisig_input_proposals_v1(multisig_tx_proposal.m_input_proposals,
            wallet_spend_pubkey,
            k_view_balance,
            converted_input_proposals),
        "multisig make partial inputs: failed to extract data from input proposals (maybe user doesn't own an input).");

    // collect masked addresses of input images
    // map input proposals to their masked addresses for ease of use later
    std::unordered_set<rct::key> expected_masked_addresses;
    std::unordered_map<rct::key, SpMultisigInputProposalV1> mapped_converted_input_proposals;
    rct::key temp_masked_address;

    for (const SpMultisigInputProposalV1 &input_proposal : converted_input_proposals)
    {
        input_proposal.m_core.get_masked_address(temp_masked_address);
        expected_masked_addresses.insert(temp_masked_address);
        mapped_converted_input_proposals[temp_masked_address] = input_proposal;
    }

    // get expected proposal prefix
    const rct::key expected_proposal_prefix{multisig_tx_proposal.get_proposal_prefix_v1()};

    // filter the partial signatures into maps
    std::unordered_map<multisig::signer_set_filter, std::unordered_set<crypto::public_key>> collected_signers_per_filter;
    std::unordered_map<multisig::signer_set_filter,  //signing group
        std::unordered_map<rct::key,                 //masked address
            std::vector<SpCompositionProofMultisigPartial>>> collected_sigs_per_key_per_filter;

    for (SpMultisigInputPartialSigSetV1 &input_partial_sig : input_partial_sigs)
    {
        // skip sig sets with unknown proposal prefixes
        if (!(input_partial_sig.m_proposal_prefix == expected_proposal_prefix))
            continue;

        // skip sig sets that are invalid
        try { check_v1_multisig_input_partial_sig_semantics_v1(input_partial_sig, multisig_signers); }
        catch (...) { continue; }

        // skip sig sets that look like duplicates (same signer group and signer)
        // - do this after checking sig set validity to avoid inserting invalid filters into the collected signers map
        if (collected_signers_per_filter[input_partial_sig.m_signer_set_filter].find(input_partial_sig.m_signer_id) !=
                collected_signers_per_filter[input_partial_sig.m_signer_set_filter].end())
            continue;

        // record that this signer/filter combo has been used
        collected_signers_per_filter[input_partial_sig.m_signer_set_filter].insert(input_partial_sig.m_signer_id);

        // record the partial sigs
        for (SpCompositionProofMultisigPartial &partial_sig : input_partial_sig.m_partial_signatures)
        {
            // skip partial sigs with unknown masked addresses
            if (expected_masked_addresses.find(partial_sig.K) == expected_masked_addresses.end())
                continue;

            collected_sigs_per_key_per_filter[input_partial_sig.m_signer_set_filter][partial_sig.K].emplace_back(
                std::move(partial_sig));
        }
    }

    // try to make one partial input per masked address
    partial_inputs_out.reserve(expected_masked_addresses.size());
    std::unordered_set<rct::key> masked_addresses_with_partial_inputs;

    for (const auto &signer_group_partial_sigs : collected_sigs_per_key_per_filter)
    {
        for (const auto &masked_address_partial_sigs : signer_group_partial_sigs.second)
        {
            // skip partial sig sets for masked addresses that already have a completed proof (from a different signer group)
            if (masked_addresses_with_partial_inputs.find(masked_address_partial_sigs.first) != 
                    masked_addresses_with_partial_inputs.end())
                continue;

            // try to make the partial input
            partial_inputs_out.emplace_back();

            if (!try_make_v1_partial_input_v1(mapped_converted_input_proposals[masked_address_partial_sigs.first],
                    expected_proposal_prefix,
                    masked_address_partial_sigs.second,
                    partial_inputs_out.back()))
                partial_inputs_out.pop_back();
            else
                masked_addresses_with_partial_inputs.insert(masked_address_partial_sigs.first);
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
