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
#include "jamtis_address_utils.h"
#include "jamtis_core_utils.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "multisig/multisig_signer_set_filter.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_config_temp.h"
#include "sp_core_enote_utils.h"
#include "sp_crypto_utils.h"
#include "tx_builder_types.h"
#include "tx_builder_types_multisig.h"
#include "tx_builders_mixed.h"
#include "tx_builders_outputs.h"
#include "tx_component_types.h"
#include "tx_discretized_fee.h"
#include "tx_misc_utils.h"
#include "tx_enote_record_types.h"
#include "tx_enote_record_utils.h"

//third party headers
#include <boost/math/special_functions/binomial.hpp>
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
//-------------------------------------------------------------------------------------------------------------------
static bool validate_v1_multisig_input_init_set_for_partial_sig_set_v1(const SpMultisigInputInitSetV1 &input_init_set,
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
    try
    {
        if (!multisig::signer_is_in_filter(input_init_set.m_signer_id,
                multisig_signers,
                expected_aggregate_signer_set_filter))
            return false;
    }
    catch (...) { return false; }

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
static void check_v1_multisig_tx_proposal_semantics_outputs_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const std::vector<SpMultisigInputProposalV1> &converted_input_proposals,
    rct::key &proposal_prefix_out)
{
    /// check semantics of a multisig tx proposal's outputs
    const std::size_t num_outputs{
            multisig_tx_proposal.m_opaque_payments.size() + multisig_tx_proposal.m_explicit_payments.size()
        };

    // 1. convert to a plain tx proposal to validate outputs (should internally call full semantics check of tx proposal)
    // note: for 2-out txs, that semantics check will ensure they share an enote ephemeral pubkey
    SpTxProposalV1 tx_proposal;
    multisig_tx_proposal.get_v1_tx_proposal_v1(tx_proposal);

    // - get prefix from proposal
    tx_proposal.get_proposal_prefix(multisig_tx_proposal.m_version_string, proposal_prefix_out);

    // 2. validate self-sends and enote ephemeral privkeys
    // goal: it should not be possible for a multisig tx proposer to burn funds (either of normal destinations or
    //       of the multisig account) by re-using an enote ephemeral privkey between different txs
    //       - non-self-send opaque outputs are an exception to this in order to permit some tx modularity, BUT to avoid
    //         self-sends getting burnt it isn't permitted for self-sends to be in a 2-out tx with an opaque non-self-send
    //         output (because outputs in 2-out txs share an enote ephemeral privkey, and non-self-send opaque outputs'
    //         enote ephemeral privkeys are not validated)

    // a. make enote view privkeys
    crypto::secret_key enote_ephemeral_privkey_seed;
    make_multisig_enote_ephemeral_privkey_seed_v1(multisig_tx_proposal.m_enote_ephemeral_privkey_entropy,
        converted_input_proposals,
        enote_ephemeral_privkey_seed);

    std::vector<crypto::secret_key> enote_ephemeral_privkeys;
    make_multisig_enote_ephemeral_privkeys_v1(enote_ephemeral_privkey_seed,
        num_outputs == 2 ? 1 : num_outputs,
        enote_ephemeral_privkeys);

    // - sanity check
    CHECK_AND_ASSERT_THROW_MES(enote_ephemeral_privkeys.size() == (num_outputs == 2 ? 1 : num_outputs),
        "multisig tx proposal: incorrect number of enote ephemeral privkeys (bug).");

    std::size_t enote_ephemeral_privkey_index{0};

    // b. explicit outputs' enote ephemeral privkeys should be reproducible
    for (const jamtis::JamtisPaymentProposalV1 &explicit_payment : multisig_tx_proposal.m_explicit_payments)
    {
        CHECK_AND_ASSERT_THROW_MES(explicit_payment.m_enote_ephemeral_privkey ==
                enote_ephemeral_privkeys[enote_ephemeral_privkey_index],
            "multisig tx proposal: an explicit payment did not have a reproducible enote ephemeral privkey.");

        // go to the next enote ephemeral privkey (if there is one)
        if (enote_ephemeral_privkey_index + 1 < enote_ephemeral_privkeys.size())
            ++enote_ephemeral_privkey_index;
    }

    // c. there must be at least one opaque self-send output (all of which have reproducible enote ephemeral privkeys)
    std::vector<jamtis::JamtisEnoteType> self_send_types_found;
    SpEnoteRecordV1 temp_enote_record;
    SpEnoteV1 temp_enote;
    crypto::secret_key temp_address_privkey;
    rct::key temp_reproduced_enote_ephemeral_pubkey;

    crypto::secret_key s_generate_address;
    jamtis::make_jamtis_generateaddress_secret(k_view_balance, s_generate_address);

    for (const SpOutputProposalV1 &output_proposal : multisig_tx_proposal.m_opaque_payments)
    {
        output_proposal.get_enote_v1(temp_enote);

        if (try_get_enote_record_v1_selfsend(temp_enote,
            output_proposal.m_enote_ephemeral_pubkey,
            rct::zero(),
            wallet_spend_pubkey,
            k_view_balance,
            s_generate_address,
            temp_enote_record))
        {
            self_send_types_found.emplace_back(temp_enote_record.m_type);

            // - self-send outputs' enote ephemeral privkeys should be reproducible
            // note: if there are exactly two opaque proposals, one of which is a self-send, then the second branch
            //       will fail (even if the enote ephemeral privkey is reproducible) because there is insufficient
            //       information to validate that case
            if (num_outputs == 2 && multisig_tx_proposal.m_explicit_payments.size() == 1)
            {
                // if our self-send is a 'special' type and there is one explicit payment, then the self-send will share
                //   the explicit payment's enote ephemeral privkey; for sanity, we double-check here (even though the
                //   tx_proposal semantics check should ensure our two outputs have the same enote ephemeral pubkey)
                SpOutputProposalV1 temp_other_proposal;
                multisig_tx_proposal.m_explicit_payments[0].get_output_proposal_v1(rct::zero(), temp_other_proposal);

                CHECK_AND_ASSERT_THROW_MES(temp_other_proposal.m_enote_ephemeral_pubkey ==
                        output_proposal.m_enote_ephemeral_pubkey,
                    "multisig tx proposal: a special self-send did not share its enote ephemeral pubkey with the "
                    "explicit payment in its tx.");
            }
            else
            {
                // otherwise, this should be a normal self-send, so just reproduce the enote ephemeral pubkey

                // address privkey of address that owns this output (k^j_a)
                jamtis::make_jamtis_address_privkey(s_generate_address,
                    temp_enote_record.m_address_index,
                    temp_address_privkey);

                // K_e = r * k^j_a * G
                temp_reproduced_enote_ephemeral_pubkey =
                    rct::scalarmultKey(
                            rct::scalarmultBase(rct::sk2rct(temp_address_privkey)),  //k^j_a * G
                            rct::sk2rct(enote_ephemeral_privkeys[enote_ephemeral_privkey_index])  //r
                        );

                // check that the enote ephemeral pubkey was reproduced
                CHECK_AND_ASSERT_THROW_MES(temp_reproduced_enote_ephemeral_pubkey ==
                        output_proposal.m_enote_ephemeral_pubkey,
                    "multisig tx proposal: could not reproduce the enote ephemeral pubkey for a self-send.");

                // go to the next enote ephemeral privkey (if there is one)
                if (enote_ephemeral_privkey_index + 1 < enote_ephemeral_privkeys.size())
                    ++enote_ephemeral_privkey_index;
            }
        }
    }

    CHECK_AND_ASSERT_THROW_MES(self_send_types_found.size() > 0, "multisig tx proposal: there are no self-send outputs.");

    // d. there cannot be two self-send outputs of the same type and no other outputs (postcondition of the
    //    output set finalizer)
    if (self_send_types_found.size() == 2)
    {
        if (self_send_types_found[0] == self_send_types_found[1])
        {
            CHECK_AND_ASSERT_THROW_MES(num_outputs > 2, "multisig tx proposal: there are two self-send outputs of the "
                "same type but no other outputs (not allowed).");
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void validate_and_prepare_input_inits_for_partial_sig_sets_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const crypto::public_key &local_signer_id,
    const rct::keyV &input_masked_addresses,
    const rct::key &proposal_prefix,
    const SpMultisigInputInitSetV1 &local_input_init_set,
    std::vector<SpMultisigInputInitSetV1> other_input_init_sets,
    std::vector<SpMultisigInputInitSetV1> &all_input_init_sets_out)
{
    /// validate and filter input inits

    // 1) local input init set must be valid
    CHECK_AND_ASSERT_THROW_MES(local_input_init_set.m_signer_id == local_signer_id,
        "multisig input partial sigs: local input init set is not from local signer.");
    CHECK_AND_ASSERT_THROW_MES(validate_v1_multisig_input_init_set_for_partial_sig_set_v1(
            local_input_init_set,
            threshold,
            multisig_signers,
            proposal_prefix,
            multisig_tx_proposal.m_aggregate_signer_set_filter,
            input_masked_addresses),
        "multisig input partial sigs: the local signer's input initializer doesn't match the multisig tx proposal.");

    // 2) weed out invalid other input init sets
    auto removed_end = std::remove_if(other_input_init_sets.begin(), other_input_init_sets.end(),
            [&](const SpMultisigInputInitSetV1 &other_input_init_set) -> bool
            {
                return !validate_v1_multisig_input_init_set_for_partial_sig_set_v1(
                    other_input_init_set,
                    threshold,
                    multisig_signers,
                    proposal_prefix,
                    multisig_tx_proposal.m_aggregate_signer_set_filter,
                    input_masked_addresses);
            }
        );
    other_input_init_sets.erase(removed_end, other_input_init_sets.end());

    // 3) collect all input init sets
    all_input_init_sets_out = std::move(other_input_init_sets);
    all_input_init_sets_out.emplace_back(local_input_init_set);

    // 4) remove inits from duplicate signers (including duplicate local signer inits)
    std::sort(all_input_init_sets_out.begin(), all_input_init_sets_out.end(),
            [](const SpMultisigInputInitSetV1 &set1, const SpMultisigInputInitSetV1 &set2) -> bool
            {
                return set1.m_signer_id < set2.m_signer_id;
            }
        );
    auto unique_end = std::unique(all_input_init_sets_out.begin(), all_input_init_sets_out.end(),
            [](const SpMultisigInputInitSetV1 &set1, const SpMultisigInputInitSetV1 &set2) -> bool
            {
                return set1.m_signer_id == set2.m_signer_id;
            }
        );
    all_input_init_sets_out.erase(unique_end, all_input_init_sets_out.end());
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_v1_multisig_input_partial_sig_sets_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const multisig::multisig_account &signer_account,
    const rct::key &proposal_prefix,
    const rct::keyV &input_masked_addresses,
    const std::vector<multisig::signer_set_filter> &filter_permutations,
    const multisig::signer_set_filter local_signer_filter,
    const std::vector<crypto::public_key> &available_signers,
    const std::vector<SpMultisigInputInitSetV1> &all_input_init_sets,
    const multisig::signer_set_filter available_signers_filter,
    const std::vector<multisig::signer_set_filter> &available_signers_as_filters,
    const std::vector<crypto::secret_key> &squash_prefixes,
    const std::vector<SpMultisigInputProposalV1> &converted_input_proposals,
    SpCompositionProofMultisigNonceRecord &nonce_record_inout,
    std::vector<SpMultisigInputPartialSigSetV1> &input_partial_sig_sets_out)
{
    /// make partial signatures for every available group of signers of size threshold that includes the local signer
    CHECK_AND_ASSERT_THROW_MES(signer_account.multisig_is_ready(),
        "multisig input partial sigs: signer account is not complete, so it can't make partial signatures.");

    // misc from account
    const std::uint32_t threshold{signer_account.get_threshold()};
    const std::vector<crypto::public_key> &multisig_signers{signer_account.get_signers()};
    const crypto::public_key &local_signer_id{signer_account.get_base_pubkey()};

    // checks
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
    signer_pub_nonces_temp.reserve(threshold);

    crypto::secret_key enote_view_privkey_with_squash_prefix, z_temp, z_temp_with_squash_prefix;

    const std::uint32_t expected_num_partial_sig_sets{
            n_choose_k(available_signers.size() - 1, threshold - 1)
        };
    input_partial_sig_sets_out.clear();
    input_partial_sig_sets_out.reserve(expected_num_partial_sig_sets);
    std::uint32_t num_aborted_partial_sig_sets{0};

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
            //   partial signature to succeed; the design implemented here relies on the stronger precondition of 'all or
            //   nothing' because the basic multisig model assumes honest players are 100% honest, and anything less should
            //   be ignored
            input_partial_sig_sets_out.emplace_back();
            try
            {
                // local signer's signing key for this group
                if (!signer_account.try_get_aggregate_signing_key(filter, z_temp))
                    throw;

                // make a partial signature for each input
                input_partial_sig_sets_out.back().m_partial_signatures.reserve(input_masked_addresses.size());

                for (std::size_t input_index{0};
                    input_index < multisig_tx_proposal.m_input_proposals.size();
                    ++input_index)
                {
                    // collect nonces from all signers in this signing group
                    signer_pub_nonces_temp.clear();
                    for (std::size_t signer_index{0}; signer_index < all_input_init_sets.size(); ++signer_index)
                    {
                        if ((available_signers_as_filters[signer_index] & filter) == 0)
                            continue;

                        // indexing:
                        // - this signer's init set
                        // - select the input we are working on (via this input's masked address)
                        // - select the nonces that line up with the signer's nonce tracker
                        signer_pub_nonces_temp.emplace_back();
                        if (!all_input_init_sets[signer_index].try_get_nonces(input_masked_addresses[input_index],
                                signer_nonce_trackers[signer_index],
                                signer_pub_nonces_temp.back()))
                            throw;
                    }

                    // sanity check
                    if (signer_pub_nonces_temp.size() != threshold)
                        throw;

                    // apply squash prefix to signing keys y and z_e
                    sc_mul(to_bytes(enote_view_privkey_with_squash_prefix),
                        to_bytes(squash_prefixes[input_index]),
                        to_bytes(converted_input_proposals[input_index].m_enote_view_privkey));
                    sc_mul(to_bytes(z_temp_with_squash_prefix),
                        to_bytes(squash_prefixes[input_index]),
                        to_bytes(z_temp));

                    // local signer's partial sig for this input
                    input_partial_sig_sets_out.back().m_partial_signatures.emplace_back();

                    if (!try_make_sp_composition_multisig_partial_sig(
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

                // copy miscellanea
                input_partial_sig_sets_out.back().m_signer_id = local_signer_id;
                input_partial_sig_sets_out.back().m_proposal_prefix = proposal_prefix;
                input_partial_sig_sets_out.back().m_signer_set_filter = filter;

                // final sanity check
                check_v1_multisig_input_partial_sig_semantics_v1(input_partial_sig_sets_out.back(), multisig_signers);
            }
            catch (...)
            {
                input_partial_sig_sets_out.pop_back();
                ++num_aborted_partial_sig_sets;
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
    CHECK_AND_ASSERT_THROW_MES(expected_num_partial_sig_sets - num_aborted_partial_sig_sets ==
            input_partial_sig_sets_out.size(),
        "multisig input partial sigs: did not produce expected number of partial sig sets (bug).");
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void check_v1_multisig_public_input_proposal_semantics_v1(const SpMultisigPublicInputProposalV1 &public_input_proposal)
{
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(public_input_proposal.m_address_mask)),
        "multisig public input proposal: bad address mask (zero).");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(public_input_proposal.m_address_mask)) == 0,
        "multisig public input proposal: bad address mask (not canonical).");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(public_input_proposal.m_commitment_mask)),
        "multisig public input proposal: bad address mask (zero).");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(public_input_proposal.m_commitment_mask)) == 0,
        "multisig public input proposal: bad address mask (not canonical).");
}
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

    // make sure it is well-formed
    check_v1_multisig_public_input_proposal_semantics_v1(proposal_out);
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
    const crypto::secret_key &input_amount_blinding_factor,
    const rct::xmr_amount &input_amount,
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
    proposal_out.m_input_amount_blinding_factor = input_amount_blinding_factor;
    proposal_out.m_input_amount = input_amount;

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
        enote_record.m_amount_blinding_factor,
        enote_record.m_amount,
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
            rct::zero(),
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
void make_multisig_enote_ephemeral_privkey_seed_v1(const crypto::secret_key &enote_ephemeral_privkey_entropy,
    const std::vector<crypto::key_image> &multisig_input_key_images,
    crypto::secret_key &enote_ephemeral_privkey_seed_out)
{
    // make an enote ephemeral privkey seed
    static const std::string domain_separator{config::HASH_KEY_MULTISIG_TX_PRIVKEYS_SEED};

    // seed = H("domain-sep", entropy, {KI})
    std::string hash;
    hash.reserve(domain_separator.size() + sizeof(rct::key)*(1 + multisig_input_key_images.size()));
    hash = domain_separator;
    hash.append(enote_ephemeral_privkey_entropy.data, sizeof(crypto::secret_key));  //entropy
    for (const crypto::key_image &key_image : multisig_input_key_images)
        hash.append(key_image.data, sizeof(crypto::key_image));  //{KI}

    // hash to the result
    crypto::cn_fast_hash(hash.data(), hash.size(), enote_ephemeral_privkey_seed_out.data);
}
//-------------------------------------------------------------------------------------------------------------------
void make_multisig_enote_ephemeral_privkey_seed_v1(const crypto::secret_key &enote_ephemeral_privkey_entropy,
    const std::vector<SpMultisigInputProposalV1> &input_proposals,
    crypto::secret_key &enote_ephemeral_privkey_seed_out)
{
    // get key images out of input proposals then make the enote ephemeral privkey seed
    std::vector<crypto::key_image> multisig_input_key_images;
    multisig_input_key_images.reserve(input_proposals.size());

    for (const SpMultisigInputProposalV1 &input_proposal : input_proposals)
    {
        multisig_input_key_images.emplace_back();
        input_proposal.get_key_image(multisig_input_key_images.back());
    }

    make_multisig_enote_ephemeral_privkey_seed_v1(enote_ephemeral_privkey_entropy,
        multisig_input_key_images,
        enote_ephemeral_privkey_seed_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_multisig_enote_ephemeral_privkeys_v1(const crypto::secret_key &enote_ephemeral_privkey_seed,
    const std::size_t num_keys_requested,
    std::vector<crypto::secret_key> &enote_ephemeral_privkeys_out)
{
    static const std::string domain_separator{config::HASH_KEY_MULTISIG_TX_PRIVKEYS};

    // hash chain
    // h1 = H_n(seed, H("domain-sep"))
    // h2 = H_n(seed, h1)
    // h3 = H_n(seed, h2)
    // h4 = ...
    rct::keyV hash_context;
    auto hash_context_wiper = epee::misc_utils::create_scope_leave_handler([&]{
            memwipe(hash_context.data(), hash_context.size());
        });

    hash_context.resize(2);

    hash_context[0] = rct::sk2rct(enote_ephemeral_privkey_seed);  //seed
    rct::cn_fast_hash(hash_context[1], domain_separator.data(), domain_separator.size());  //H("domain-sep")

    enote_ephemeral_privkeys_out.clear();
    enote_ephemeral_privkeys_out.resize(num_keys_requested);

    for (crypto::secret_key &enote_ephemeral_privkey : enote_ephemeral_privkeys_out)
    {
        // advance the hash chain
        hash_context[1] = rct::hash_to_scalar(hash_context);
        // set this key
        enote_ephemeral_privkey = rct::rct2sk(hash_context[1]);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void prepare_multisig_output_proposals_v1(const std::size_t num_explicit_payments,
    std::vector<SpOutputProposalV1> &opaque_payments_inout)
{
    // if there is only one opaque payment and <= 1 explicit payments, add a normal dummy opaque payment prematurely
    // - in multisig, we must avoid the case where an explicit payment in a 2-out tx shares an enote ephemeral privkey
    //   with an opaque output proposal, which could allow the explicit payment to contain a onetime address that already
    //   exists in the ledger (effectively burning funds)
    if (opaque_payments_inout.size() == 1 &&
        num_explicit_payments <= 1)
    {
        opaque_payments_inout.emplace_back();

        // normal dummy
        // - 0 amount
        opaque_payments_inout.back().gen(0, 0);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void finalize_multisig_output_proposals_v1(const std::vector<SpMultisigInputProposalV1> &full_input_proposals,
    const DiscretizedFee &discretized_transaction_fee,
    const jamtis::JamtisDestinationV1 &change_destination,
    const jamtis::JamtisDestinationV1 &dummy_destination,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &enote_ephemeral_privkey_seed,
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> explicit_payments_selfsend,
    std::vector<jamtis::JamtisPaymentProposalV1> &explicit_payments_normal_inout,
    std::vector<SpOutputProposalV1> &opaque_payments_inout)
{
    /// prepare to finalize the output set

    // 1. validate the relative amounts of opaque and explicit payments
    if (opaque_payments_inout.size() == 1 &&
        explicit_payments_normal_inout.size() + explicit_payments_selfsend.size() <= 1)
    {
        CHECK_AND_ASSERT_THROW_MES(false, "finalize multisig output proposals: cannot have only one opaque payment in "
            "combination with <= 1 explicit payments.");
    }

    // 2. prepare enough enote ephemeral privkeys for all explicit payments (finalize will add 1 at most)
    std::vector<crypto::secret_key> enote_ephemeral_privkeys;
    make_multisig_enote_ephemeral_privkeys_v1(enote_ephemeral_privkey_seed,
        explicit_payments_normal_inout.size() + explicit_payments_selfsend.size() + 1,
        enote_ephemeral_privkeys);

    // - sanity check
    CHECK_AND_ASSERT_THROW_MES(enote_ephemeral_privkeys.size() ==
            explicit_payments_normal_inout.size() + explicit_payments_selfsend.size() + 1,
        "finalize multisig output proposals: incorrect number of enote ephemeral privkeys (bug).");

    std::size_t enote_ephemeral_privkey_index{0};

    // 3. reset enote ephemeral privkeys of explicit payments
    // note: the case where explicit proposals passed in have already set up the 2-output shared enote ephemeral pubkey
    //       is NOT supported
    for (jamtis::JamtisPaymentProposalV1 &normal_payment_proposal : explicit_payments_normal_inout)
    {
        normal_payment_proposal.m_enote_ephemeral_privkey = enote_ephemeral_privkeys[enote_ephemeral_privkey_index];
        ++enote_ephemeral_privkey_index;
    }

    for (jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_payment_proposal : explicit_payments_selfsend)
    {
        selfsend_payment_proposal.m_enote_ephemeral_privkey = enote_ephemeral_privkeys[enote_ephemeral_privkey_index];
        ++enote_ephemeral_privkey_index;
    }

    // 4. copy existing output proposals
    std::vector<SpOutputProposalV1> output_proposals_temp;
    output_proposals_temp.reserve(opaque_payments_inout.size() +
        explicit_payments_normal_inout.size() +
        explicit_payments_selfsend.size());
    output_proposals_temp = opaque_payments_inout;

    opaque_payments_inout.reserve(opaque_payments_inout.size() + explicit_payments_selfsend.size() + 2);

    for (const jamtis::JamtisPaymentProposalV1 &normal_payment_proposal : explicit_payments_normal_inout)
    {
        output_proposals_temp.emplace_back();
        normal_payment_proposal.get_output_proposal_v1(rct::zero(), output_proposals_temp.back());
    }

    for (const jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_payment_proposal : explicit_payments_selfsend)
    {
        output_proposals_temp.emplace_back();
        selfsend_payment_proposal.get_output_proposal_v1(k_view_balance, rct::zero(), output_proposals_temp.back());

        // insert to the output opaque set (for efficiency)
        opaque_payments_inout.emplace_back(output_proposals_temp.back());
    }

    // 5. collect total input amount
    boost::multiprecision::uint128_t total_input_amount{0};

    for (const SpMultisigInputProposalV1 &input_proposal : full_input_proposals)
        total_input_amount += input_proposal.m_input_amount;

    // 6. extract raw transaction fee
    rct::xmr_amount raw_transaction_fee;
    CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(discretized_transaction_fee, raw_transaction_fee),
        "finalize multisig output proposals: could not get tx fee from discretized fee.");


    /// finalize the output proposal set

    // 1. finalize
    std::vector<jamtis::JamtisPaymentProposalV1> new_normal_proposals;
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> new_selfsend_proposals;

    finalize_v1_output_proposal_set_v1(total_input_amount,
        raw_transaction_fee,
        change_destination,
        dummy_destination,
        rct::zero(),
        wallet_spend_pubkey,
        k_view_balance,
        output_proposals_temp,
        new_normal_proposals,
        new_selfsend_proposals);

    CHECK_AND_ASSERT_THROW_MES(new_normal_proposals.size() + new_selfsend_proposals.size() <= 2,
        "finalize multisig output proposals: finalizing output proposals added more than 2 proposals (bug).");

    // 2. reset the new selfsend proposals' enote ephemeral privkeys if there are any
    if (new_selfsend_proposals.size() == 1 &&
        output_proposals_temp.size() + new_normal_proposals.size() == 1)
    {
        // special type: do nothing (it must be shared with an explicit payment that was passed in)
    }
    else
    {
        for (jamtis::JamtisPaymentProposalSelfSendV1 &new_selfsend_payment_proposal : new_selfsend_proposals)
        {
            new_selfsend_payment_proposal.m_enote_ephemeral_privkey =
                enote_ephemeral_privkeys[enote_ephemeral_privkey_index];
            ++enote_ephemeral_privkey_index;
        }

        // sanity check
        CHECK_AND_ASSERT_THROW_MES(enote_ephemeral_privkey_index <= enote_ephemeral_privkeys.size(),
            "finalize multisig output proposals: enote ephemeral privkey index error (bug).");
    }


    /// set output variables

    // 1. insert pre-existing self-send proposals to the original opaque output set
    //we did this above

    // 2. add new opaque output proposals to the original opaque output set
    for (const jamtis::JamtisPaymentProposalV1 &new_normal_payment_proposal : new_normal_proposals)
    {
        opaque_payments_inout.emplace_back();
        new_normal_payment_proposal.get_output_proposal_v1(rct::zero(), opaque_payments_inout.back());
    }

    // 3. insert new self-send output proposals to the original opaque output set
    for (const jamtis::JamtisPaymentProposalSelfSendV1 &new_selfsend_payment_proposal : new_selfsend_proposals)
    {
        opaque_payments_inout.emplace_back();
        new_selfsend_payment_proposal.get_output_proposal_v1(k_view_balance, rct::zero(), opaque_payments_inout.back());
    }
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_multisig_tx_proposal_full_balance_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const rct::xmr_amount desired_fee)
{
    // check that a multisig tx proposal covers the full input amount of a tx

    // get input amounts
    std::vector<rct::xmr_amount> in_amounts;
    in_amounts.reserve(multisig_tx_proposal.m_input_proposals.size());

    std::vector<SpMultisigInputProposalV1> converted_input_proposals;
    CHECK_AND_ASSERT_THROW_MES(try_get_v1_multisig_input_proposals_v1(multisig_tx_proposal.m_input_proposals,
            wallet_spend_pubkey,
            k_view_balance,
            converted_input_proposals),
        "multisig tx proposal balance check: could not extract data from an input proposal "
        "(maybe input not owned by user).");

    for (const SpMultisigInputProposalV1 &input_proposal : converted_input_proposals)
        in_amounts.emplace_back(input_proposal.m_input_amount);

    // get output amounts
    SpTxProposalV1 tx_proposal;
    multisig_tx_proposal.get_v1_tx_proposal_v1(tx_proposal);

    // check: sum(input amnts) == sum(output amnts) + fee
    CHECK_AND_ASSERT_THROW_MES(balance_check_in_out_amnts(in_amounts, tx_proposal.m_output_amounts, desired_fee),
        "multisig tx proposal: input/output amounts did not balance with desired fee.");
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_multisig_tx_proposal_full_balance_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const DiscretizedFee &discretized_desired_fee)
{
    // extract the feel value from a discretized fee then check the multisig tx proposal full balance
    rct::xmr_amount raw_transaction_fee;
    CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(discretized_desired_fee, raw_transaction_fee),
        "multisig tx proposal balance check: could not extract fee value from discretized fee.");

    check_v1_multisig_tx_proposal_full_balance_v1(multisig_tx_proposal,
        wallet_spend_pubkey,
        k_view_balance,
        raw_transaction_fee);
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_multisig_tx_proposal_semantics_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const std::string &expected_version_string,
    const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance)
{
    /// multisig signing config checks

    // 1. proposal should contain expected tx version encoding
    CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_version_string == expected_version_string,
        "multisig tx proposal: intended tx version encoding is invalid.");

    // 2. signer set filter must be valid (at least 'threshold' signers allowed, format is valid)
    CHECK_AND_ASSERT_THROW_MES(multisig::validate_aggregate_multisig_signer_set_filter(threshold,
            num_signers,
            multisig_tx_proposal.m_aggregate_signer_set_filter),
        "multisig tx proposal: invalid aggregate signer set filter.");


    /// input/output checks

    // 1. check the public input proposal semantics
    for (const SpMultisigPublicInputProposalV1 &public_input_proposal : multisig_tx_proposal.m_input_proposals)
        check_v1_multisig_public_input_proposal_semantics_v1(public_input_proposal);

    // 2. convert the public input proposals
    std::vector<SpMultisigInputProposalV1> converted_input_proposals;
    CHECK_AND_ASSERT_THROW_MES(try_get_v1_multisig_input_proposals_v1(multisig_tx_proposal.m_input_proposals,
            wallet_spend_pubkey,
            k_view_balance,
            converted_input_proposals),
        "multisig tx proposal: could not extract data from an input proposal (maybe input not owned by user).");

    // 3. should be at least 1 input and 1 output
    CHECK_AND_ASSERT_THROW_MES(converted_input_proposals.size() > 0, "multisig tx proposal: no inputs.");
    CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_explicit_payments.size() +
            multisig_tx_proposal.m_opaque_payments.size() > 0,
        "multisig tx proposal: no outputs.");


    /// output checks
    rct::key proposal_prefix;

    check_v1_multisig_tx_proposal_semantics_outputs_v1(multisig_tx_proposal,
        wallet_spend_pubkey,
        k_view_balance,
        converted_input_proposals,
        proposal_prefix);


    /// input checks

    // 1. input proposals line up 1:1 with input proof proposals, each input has a unique key image
    CHECK_AND_ASSERT_THROW_MES(converted_input_proposals.size() ==
        multisig_tx_proposal.m_input_proof_proposals.size(),
        "multisig tx proposal: input proposals don't line up with input proposal proofs.");

    // 2. assess each input proposal
    rct::key image_address_with_squash_prefix;
    std::vector<crypto::key_image> key_images;
    key_images.reserve(converted_input_proposals.size());

    for (std::size_t input_index{0}; input_index < converted_input_proposals.size(); ++input_index)
    {
        // a. converted proposals should be well-formed
        check_v1_multisig_input_proposal_semantics_v1(converted_input_proposals[input_index]);

        // b. input proof proposal messages all equal proposal prefix of core tx proposal
        CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_input_proof_proposals[input_index].message == proposal_prefix,
            "multisig tx proposal: input proof proposal does not match the tx proposal (different proposal prefix).");

        // c. input proof proposal keys line up 1:1 and match with input proposals
        converted_input_proposals[input_index].m_core.get_masked_address(image_address_with_squash_prefix);
        CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_input_proof_proposals[input_index].K ==
                image_address_with_squash_prefix,
            "multisig tx proposal: input proof proposal does not match input proposal (different proof keys).");

        // d. input proof proposal key images line up 1:1 and match with input proposals
        key_images.emplace_back();
        converted_input_proposals[input_index].get_key_image(key_images.back());
        CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_input_proof_proposals[input_index].KI ==
                key_images.back(),
            "multisig tx proposal: input proof proposal does not match input proposal (different key images).");

        // e. check that the key image obtained is canonical
        CHECK_AND_ASSERT_THROW_MES(key_domain_is_prime_subgroup(rct::ki2rct(key_images.back())),
            "multisig tx proposal: an input's key image is not in the prime subgroup.");
    }

    // 3. key images should be unique
    std::sort(key_images.begin(), key_images.end());
    CHECK_AND_ASSERT_THROW_MES(std::adjacent_find(key_images.begin(), key_images.end()) == key_images.end(),
        "multisig tx proposal: inputs are not unique (found duplicate key image).");
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_tx_proposal_v1(const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const crypto::secret_key &enote_ephemeral_privkey_entropy,
    std::vector<jamtis::JamtisPaymentProposalV1> explicit_payments,
    std::vector<SpOutputProposalV1> opaque_payments,
    TxExtra partial_memo,
    std::string version_string,
    const std::vector<SpMultisigInputProposalV1> &full_input_proposals,
    const multisig::signer_set_filter aggregate_signer_set_filter,
    SpMultisigTxProposalV1 &proposal_out)
{
    // add miscellaneous components
    proposal_out.m_enote_ephemeral_privkey_entropy = enote_ephemeral_privkey_entropy;
    proposal_out.m_explicit_payments = std::move(explicit_payments);
    proposal_out.m_opaque_payments = std::move(opaque_payments);
    proposal_out.m_partial_memo = std::move(partial_memo);
    proposal_out.m_aggregate_signer_set_filter = aggregate_signer_set_filter;
    proposal_out.m_version_string = std::move(version_string);

    // get proposal prefix
    rct::key proposal_prefix;
    SpMultisigTxProposalV1::get_proposal_prefix_v1(proposal_out.m_explicit_payments,
        proposal_out.m_opaque_payments,
        proposal_out.m_partial_memo,
        proposal_out.m_version_string,
        proposal_prefix);

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
        "multisig input initializer: signer is not eligible.");

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

    // check that the input initializer is well-formed
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
    rct::key proposal_prefix;
    multisig_tx_proposal.get_proposal_prefix_v1(proposal_prefix);

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
    CHECK_AND_ASSERT_THROW_MES(signer_account.multisig_is_ready(),
        "multisig input partial sigs: signer account is not complete, so it can't make partial signatures.");

    /// prepare pieces to use below

    // misc. from account
    const crypto::secret_key &k_view_balance{signer_account.get_common_privkey()};
    const std::uint32_t threshold{signer_account.get_threshold()};
    const std::vector<crypto::public_key> &multisig_signers{signer_account.get_signers()};
    const crypto::public_key &local_signer_id{signer_account.get_base_pubkey()};

    // wallet spend pubkey: k_vb X + k_m U
    rct::key wallet_spend_pubkey{rct::pk2rct(signer_account.get_multisig_pubkey())};
    extend_seraphis_spendkey(k_view_balance, wallet_spend_pubkey);

    // misc. from multisig tx proposal
    rct::key proposal_prefix;
    multisig_tx_proposal.get_proposal_prefix_v1(proposal_prefix);
    rct::keyV input_masked_addresses;
    get_masked_addresses(multisig_tx_proposal.m_input_proposals, input_masked_addresses);

    // filter permutations
    std::vector<multisig::signer_set_filter> filter_permutations;
    multisig::aggregate_multisig_signer_set_filter_to_permutations(threshold,
        multisig_signers.size(),
        multisig_tx_proposal.m_aggregate_signer_set_filter,
        filter_permutations);


    /// validate and assemble input inits
    std::vector<SpMultisigInputInitSetV1> all_input_init_sets;

    validate_and_prepare_input_inits_for_partial_sig_sets_v1(multisig_tx_proposal,
        threshold,
        multisig_signers,
        local_signer_id,
        input_masked_addresses,
        proposal_prefix,
        local_input_init_set,
        std::move(other_input_init_sets),
        all_input_init_sets);


    /// prepare for signing

    // 1) save local signer as filter
    multisig::signer_set_filter local_signer_filter;
    multisig::multisig_signer_to_filter(local_signer_id, multisig_signers, local_signer_filter);

    // 2) collect available signers
    std::vector<crypto::public_key> available_signers;
    available_signers.reserve(all_input_init_sets.size());

    for (const SpMultisigInputInitSetV1 &input_init_set : all_input_init_sets)
        available_signers.emplace_back(input_init_set.m_signer_id);

    // give up if not enough signers
    if (available_signers.size() < threshold)
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

    // 5) record input enote squash prefixes
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
            wallet_spend_pubkey,
            k_view_balance,
            converted_input_proposals))
        return false;


    /// make partial signatures
    make_v1_multisig_input_partial_sig_sets_v1(multisig_tx_proposal,
        signer_account,
        proposal_prefix,
        input_masked_addresses,
        filter_permutations,
        local_signer_filter,
        available_signers,
        all_input_init_sets,
        available_signers_filter,
        available_signers_as_filters,
        squash_prefixes,
        converted_input_proposals,
        nonce_record_inout,
        input_partial_sig_sets_out);

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
        // all partial sigs must sign the expected message
        for (const SpCompositionProofMultisigPartial &partial_sig : input_proof_partial_sigs)
        {
            CHECK_AND_ASSERT_THROW_MES(partial_sig.message == expected_proposal_prefix,
                "multisig make partial input: a partial signature's message does not match the expected proposal prefix.");
        }

        // assemble proof (will throw if partial sig assembly doesn't produce a valid proof)
        partial_input_out.m_image_proof.m_composition_proof = sp_composition_prove_multisig_final(input_proof_partial_sigs);

        // copy miscellaneous pieces
        input_proposal.get_enote_image(partial_input_out.m_input_image.m_core);
        partial_input_out.m_address_mask = input_proposal.m_core.m_address_mask;
        partial_input_out.m_commitment_mask = input_proposal.m_core.m_commitment_mask;
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
bool try_make_v1_partial_inputs_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const std::vector<crypto::public_key> &multisig_signers,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    std::unordered_map<crypto::public_key, std::vector<SpMultisigInputPartialSigSetV1>> input_partial_sigs_per_signer,
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
    // and map input proposals to their masked addresses for ease of use later
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
    rct::key expected_proposal_prefix;
    multisig_tx_proposal.get_proposal_prefix_v1(expected_proposal_prefix);

    // filter the partial signatures into maps
    std::unordered_map<multisig::signer_set_filter, std::unordered_set<crypto::public_key>> collected_signers_per_filter;
    std::unordered_map<multisig::signer_set_filter,  //signing group
        std::unordered_map<rct::key,                 //masked address
            std::vector<SpCompositionProofMultisigPartial>>> collected_sigs_per_key_per_filter;

    for (auto &input_partial_sigs_for_signer : input_partial_sigs_per_signer)
    {
        for (SpMultisigInputPartialSigSetV1 &input_partial_sig : input_partial_sigs_for_signer.second)
        {
            // skip sig sets with unknown proposal prefixes
            if (!(input_partial_sig.m_proposal_prefix == expected_proposal_prefix))
                continue;

            // skip sig sets that are invalid
            try { check_v1_multisig_input_partial_sig_semantics_v1(input_partial_sig, multisig_signers); }
            catch (...) { continue; }

            // skip sig sets if their signer ids don't match the input signer ids
            if (!(input_partial_sig.m_signer_id == input_partial_sigs_for_signer.first))
                continue;

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
    }

    // try to make one partial input per masked address
    partial_inputs_out.reserve(expected_masked_addresses.size());
    std::unordered_set<rct::key> masked_addresses_with_partial_inputs;

    for (const auto &signer_group_partial_sigs : collected_sigs_per_key_per_filter)
    {
        for (const auto &masked_address_partial_sigs : signer_group_partial_sigs.second)
        {
            // skip partial sig sets for masked addresses that already have a completed proof (from a different
            //   signer group)
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

    if (partial_inputs_out.size() != expected_masked_addresses.size())
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
