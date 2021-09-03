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
#include "multisig_signing_helper_utils.h"

//local headers
#include "common/container_helpers.h"
#include "crypto/crypto.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "multisig/multisig_signer_set_filter.h"
#include "multisig_nonce_cache.h"
#include "multisig_partial_sig_makers.h"
#include "multisig_signing_errors.h"
#include "multisig_signing_helper_types.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_crypto/math_utils.h"
#include "seraphis_crypto/sp_crypto_utils.h"

//third party headers
#include <boost/multiprecision/cpp_int.hpp>

//standard headers
#include <unordered_map>
#include <unordered_set>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "multisig"

namespace multisig
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void prepare_multisig_init_set_collections_v1(const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const signer_set_filter aggregate_signer_set_filter,
    const crypto::public_key &local_signer_id,
    const std::unordered_map<rct::key, rct::key> &expected_proof_contexts,  //[ proof key : proof message ]
    const std::size_t num_expected_nonce_sets_per_proofkey,
    //[ proof key : init set ]
    std::unordered_map<rct::key, MultisigProofInitSetV1> local_init_set_collection,
    //[ signer id : [ proof key : init set ] ]
    std::unordered_map<crypto::public_key, std::unordered_map<rct::key, MultisigProofInitSetV1>>
        other_init_set_collections,
    std::list<MultisigSigningErrorVariant> &multisig_errors_inout,
    //[ signer id : [ proof key : init set ] ]
    std::unordered_map<crypto::public_key, std::unordered_map<rct::key, MultisigProofInitSetV1>>
        &all_init_set_collections_out)
{
    /// validate and filter inits

    // 1. local init set must always be valid
    auto validation_error_self_init = validate_v1_multisig_init_set_collection_v1(local_init_set_collection,
        threshold,
        multisig_signers,
        aggregate_signer_set_filter,
        local_signer_id,
        expected_proof_contexts,
        num_expected_nonce_sets_per_proofkey);
    CHECK_AND_ASSERT_THROW_MES(!validation_error_self_init,
        "validate and prepare multisig init set collections: the local signer's collection is invalid.");

    // 2. weed out invalid other init set collections
    tools::for_all_in_map_erase_if(other_init_set_collections,
            [&](const auto &other_signer_init_set_collection) -> bool
            {
                auto validation_error = validate_v1_multisig_init_set_collection_v1(
                    other_signer_init_set_collection.second,
                    threshold,
                    multisig_signers,
                    aggregate_signer_set_filter,
                    other_signer_init_set_collection.first, //check that the mapped id is correct
                    expected_proof_contexts,
                    num_expected_nonce_sets_per_proofkey);

                if (validation_error)
                    multisig_errors_inout.emplace_back(validation_error);

                return !validation_error.is_empty();
            }
        );

    // 3. collect all init sets
    all_init_set_collections_out = std::move(other_init_set_collections);
    all_init_set_collections_out[local_signer_id] = std::move(local_init_set_collection);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void prepare_filters_for_multisig_partial_signing(const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const crypto::public_key &local_signer_id,
    const signer_set_filter multisig_proposal_aggregate_signer_set_filter,
    //[ signer id : [ proof key : init set ] ]
    const std::unordered_map<crypto::public_key, std::unordered_map<rct::key, MultisigProofInitSetV1>>
        &all_init_set_collections,
    signer_set_filter &local_signer_filter_out,
    signer_set_filter &available_signers_filter_out,
    //[ signer id : signer as filter ]
    std::unordered_map<crypto::public_key, signer_set_filter> &available_signers_as_filters_out,
    std::vector<signer_set_filter> &filter_permutations_out)
{
    // 1. save local signer as filter
    multisig_signer_to_filter(local_signer_id, multisig_signers, local_signer_filter_out);

    // 2. collect available signers
    std::vector<crypto::public_key> available_signers;
    available_signers.reserve(all_init_set_collections.size());

    for (const auto &input_init_set_collection : all_init_set_collections)
        available_signers.emplace_back(input_init_set_collection.first);

    // 3. available signers as a filter
    multisig_signers_to_filter(available_signers, multisig_signers, available_signers_filter_out);

    // 4. available signers as individual filters (note: available_signers contains no duplicates because it's built
    //    from a map)
    available_signers_as_filters_out.clear();
    available_signers_as_filters_out.reserve(available_signers.size());

    for (const crypto::public_key &available_signer : available_signers)
    {
        multisig_signer_to_filter(available_signer,
            multisig_signers,
            available_signers_as_filters_out[available_signer]);
    }

    // 5. filter permutations (every subgroup of signers that is eligible to make a signature attempt)
    aggregate_multisig_signer_set_filter_to_permutations(threshold,
        multisig_signers.size(),
        multisig_proposal_aggregate_signer_set_filter,
        filter_permutations_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static MultisigSigningErrorVariant try_make_v1_multisig_partial_signatures_v1(
    const std::uint32_t threshold,
    const signer_set_filter filter,
    const std::unordered_map<rct::key, rct::key> &proof_contexts,  //[ proof key : proof message ]
    const std::size_t num_expected_proof_basekeys,
    const std::unordered_map<crypto::public_key, signer_set_filter> &available_signers_as_filters,
    //[ signer id : [ proof key : init set ] ]
    const std::unordered_map<crypto::public_key, std::unordered_map<rct::key, MultisigProofInitSetV1>>
        &all_init_set_collections,
    const std::unordered_map<crypto::public_key, std::size_t> &signer_nonce_trackers,
    const MultisigPartialSigMaker &partial_sig_maker,
    const crypto::secret_key &local_signer_privkey,
    MultisigNonceCache &nonce_record_inout,
    std::unordered_map<rct::key, MultisigPartialSigVariant> &partial_signatures_out)
{
    /// make partial signatures for one group of signers of size threshold that is presumed to include the local signer

    // 1. checks
    CHECK_AND_ASSERT_THROW_MES(all_init_set_collections.size() >= threshold,
        "make multisig partial signatures: there are fewer init sets than the signing threshold of the multisig group.");
    CHECK_AND_ASSERT_THROW_MES(available_signers_as_filters.size() == all_init_set_collections.size(),
        "make multisig partial signatures: available signers as filters don't line up with init sets (bug).");
    CHECK_AND_ASSERT_THROW_MES(signer_nonce_trackers.size() == all_init_set_collections.size(),
        "make multisig partial signatures: signer nonce trackers don't line up with init sets (bug).");

    // 2. try to make the partial signatures (if unable to make a partial signature on all requested proof contexts,
    //    then an error will be returned)
    std::vector<MultisigPubNonces> signer_pub_nonces_set_temp;
    std::vector<std::vector<MultisigPubNonces>> split_signer_pub_nonce_sets_temp;

    partial_signatures_out.clear();

    for (const auto &proof_context : proof_contexts)
    {
        // a. collect nonces from all signers in this signing group
        split_signer_pub_nonce_sets_temp.clear();
        split_signer_pub_nonce_sets_temp.resize(num_expected_proof_basekeys);

        for (const auto &init_set_collection : all_init_set_collections)
        {
            // i. ignore unknown signers
            if (available_signers_as_filters.find(init_set_collection.first) == available_signers_as_filters.end())
                continue;
            if (signer_nonce_trackers.find(init_set_collection.first) == signer_nonce_trackers.end())
                continue;

            // ii. ignore signers not in the requested signing group
            if ((available_signers_as_filters.at(init_set_collection.first) & filter) == 0)
                continue;

            // iii. ignore unknown proof keys
            if (init_set_collection.second.find(proof_context.first) == init_set_collection.second.end())
                continue;

            // iv. get public nonces from this init set collection, indexed by:
            // - this signer's init set
            // - select the proof we are working on (via this proof's proof key)
            // - select the nonces that line up with the signer's nonce tracker (i.e. the nonces associated with this
            //   filter for this signer)
            if (!try_get_nonces(init_set_collection.second.at(proof_context.first),
                    signer_nonce_trackers.at(init_set_collection.first),
                    signer_pub_nonces_set_temp))
            {
                return MultisigSigningErrorBadInitSetCollection{
                        .error_code = MultisigSigningErrorBadInitSetCollection::ErrorCode::GET_NONCES_FAIL,
                        .signer_id  = init_set_collection.first
                    };
            }

            // v. expect nonce sets to be consistently sized
            if (signer_pub_nonces_set_temp.size() != num_expected_proof_basekeys)
            {
                return MultisigSigningErrorBadInitSetCollection{
                        .error_code = MultisigSigningErrorBadInitSetCollection::ErrorCode::INVALID_NONCES_SET_SIZE,
                        .signer_id  = init_set_collection.first
                    };
            }

            // vi. save nonce sets; the set members are split between rows in the split_signer_pub_nonce_sets_temp matrix
            for (std::size_t nonce_set_index{0}; nonce_set_index < num_expected_proof_basekeys; ++nonce_set_index)
            {
                split_signer_pub_nonce_sets_temp[nonce_set_index].emplace_back(
                        signer_pub_nonces_set_temp[nonce_set_index]
                    );
            }
        }

        // b. sanity check
        for (const std::vector<MultisigPubNonces> &signer_pub_nonce_set : split_signer_pub_nonce_sets_temp)
        {
            if (signer_pub_nonce_set.size() != threshold)
            {
                return MultisigSigningErrorMakePartialSigSet{
                        .error_code = MultisigSigningErrorMakePartialSigSet::ErrorCode::INVALID_NONCES_SET_QUANTITY,
                        .signature_set_filter = filter
                    };
            }
        }

        // c. attempt making a partial signature for this: proof message, proof key, signer group (filter)
        try
        {
            partial_sig_maker.attempt_make_partial_sig(proof_context.second,
                proof_context.first,
                filter,
                split_signer_pub_nonce_sets_temp,
                local_signer_privkey,
                nonce_record_inout,
                partial_signatures_out[proof_context.first]);
        }
        catch (const std::exception &exception)
        {
            return MultisigSigningErrorMakePartialSigSet{
                    .error_code = MultisigSigningErrorMakePartialSigSet::ErrorCode::MAKE_SIGNATURE_EXCEPTION,
                    .signature_set_filter = filter,
                    .error_message        = exception.what()
                };
        }
        catch (...)
        {
            return MultisigSigningErrorMakePartialSigSet{
                    .error_code = MultisigSigningErrorMakePartialSigSet::ErrorCode::MAKE_SIGNATURE_EXCEPTION,
                    .signature_set_filter = filter,
                    .error_message        = "unknown exception"
                };
        }
    }

    return boost::none;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_v1_multisig_partial_sig_sets_v1(const multisig_account &signer_account,
    const std::unordered_map<rct::key, rct::key> &proof_contexts,  //[ proof key : proof message ]
    const std::size_t num_expected_proof_basekeys,
    const std::vector<signer_set_filter> &filter_permutations,
    const signer_set_filter local_signer_filter,
    const signer_set_filter available_signers_filter,
    //[ signer id : signer as filter ]
    const std::unordered_map<crypto::public_key, signer_set_filter> &available_signers_as_filters,
    //[ signer id : [ proof key : init set ] ]
    const std::unordered_map<crypto::public_key, std::unordered_map<rct::key, MultisigProofInitSetV1>>
        &all_init_set_collections,
    const MultisigPartialSigMaker &partial_sig_maker,
    std::list<MultisigSigningErrorVariant> &multisig_errors_inout,
    MultisigNonceCache &nonce_record_inout,
    std::vector<MultisigPartialSigSetV1> &partial_sig_sets_out)
{
    /// make partial signatures for every available group of signers of size threshold that includes the local signer
    CHECK_AND_ASSERT_THROW_MES(signer_account.multisig_is_ready(),
        "make multisig partial sigs: signer account is not complete, so it can't make partial signatures.");

    const std::size_t num_available_signers{available_signers_as_filters.size()};

    // signer nonce trackers are pointers into the nonce vectors in each signer's init set
    // - a signer's nonce vectors line up 1:1 with the filters in 'filter_permutations' of which the signer is a member
    // - we want to track through each signers' vectors as we go through the full set of 'filter_permutations'
    std::unordered_map<crypto::public_key, std::size_t> signer_nonce_trackers;
    signer_nonce_trackers.reserve(available_signers_as_filters.size());

    for (const auto &available_signer_filter : available_signers_as_filters)
        signer_nonce_trackers[available_signer_filter.first] = 0;

    // make partial signatures for each filter permutation
    const std::uint32_t expected_num_partial_sig_sets{
            sp::math::n_choose_k(num_available_signers - 1, signer_account.get_threshold() - 1)
        };
    partial_sig_sets_out.clear();
    partial_sig_sets_out.reserve(expected_num_partial_sig_sets);

    std::uint32_t num_aborted_partial_sig_sets{0};
    crypto::secret_key k_e_temp;

    for (const signer_set_filter filter : filter_permutations)
    {
        // for filters that contain only available signers (and include the local signer), make a partial signature set
        // - throw on failure so the partial sig set can be rolled back
        if ((filter & available_signers_filter) == filter &&
            (filter & local_signer_filter))
        {
            // if this throws, then the signer's nonces for this filter/proposal/init_set combo that were used before
            //   the throw will be completely lost (i.e. in the 'nonce_record_inout'); however, if it does throw then
            //   this signing attempt was futile to begin with (it's all or nothing)
            partial_sig_sets_out.emplace_back();
            try
            {
                // 1. get local signer's signing key for this group
                if (!signer_account.try_get_aggregate_signing_key(filter, k_e_temp))
                {
                    multisig_errors_inout.emplace_back(
                            MultisigSigningErrorMakePartialSigSet{
                                    .error_code = MultisigSigningErrorMakePartialSigSet::ErrorCode::GET_KEY_FAIL,
                                    .signature_set_filter = filter
                                }
                        );
                    throw dummy_multisig_exception{};
                }

                // 2. try to make the partial sig set
                if (auto make_sigs_error = try_make_v1_multisig_partial_signatures_v1(signer_account.get_threshold(),
                        filter,
                        proof_contexts,
                        num_expected_proof_basekeys,
                        available_signers_as_filters,
                        all_init_set_collections,
                        signer_nonce_trackers,
                        partial_sig_maker,
                        k_e_temp,
                        nonce_record_inout,
                        partial_sig_sets_out.back().partial_signatures))
                {
                    multisig_errors_inout.emplace_back(make_sigs_error);
                    throw dummy_multisig_exception{};
                }

                // 3. copy miscellanea
                partial_sig_sets_out.back().signer_set_filter = filter;
                partial_sig_sets_out.back().signer_id = signer_account.get_base_pubkey();

                // 4. sanity check
                check_v1_multisig_partial_sig_set_semantics_v1(partial_sig_sets_out.back(), signer_account.get_signers());
            }
            catch (const dummy_multisig_exception&)
            {
                // no error message for dummy exceptions (error message recorded elsewhere)

                partial_sig_sets_out.pop_back();
                ++num_aborted_partial_sig_sets;
            }
            catch (const std::exception &exception)
            {
                multisig_errors_inout.emplace_back(
                        MultisigSigningErrorMakePartialSigSet{
                                .error_code = MultisigSigningErrorMakePartialSigSet::ErrorCode::MAKE_SET_EXCEPTION,
                                .signature_set_filter = filter,
                                .error_message        = exception.what()
                            }
                    );

                partial_sig_sets_out.pop_back();
                ++num_aborted_partial_sig_sets;
            }
            catch (...)
            {
                multisig_errors_inout.emplace_back(
                        MultisigSigningErrorMakePartialSigSet{
                                .error_code = MultisigSigningErrorMakePartialSigSet::ErrorCode::MAKE_SET_EXCEPTION,
                                .signature_set_filter = filter,
                                .error_message        = "unknown exception"
                            }
                    );

                partial_sig_sets_out.pop_back();
                ++num_aborted_partial_sig_sets;
            }
        }

        // increment nonce trackers for all signers in this filter
        for (const auto &available_signer_filter : available_signers_as_filters)
        {
            if (available_signer_filter.second & filter)
                ++signer_nonce_trackers[available_signer_filter.first];
        }
    }

    // sanity check
    CHECK_AND_ASSERT_THROW_MES(expected_num_partial_sig_sets - num_aborted_partial_sig_sets ==
            partial_sig_sets_out.size(),
        "make multisig partial sig sets: did not produce expected number of partial sig sets (bug).");
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void check_v1_multisig_init_set_semantics_v1(const MultisigProofInitSetV1 &init_set,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const std::size_t num_expected_nonce_sets_per_proofkey)
{
    // 1. signer set filter must be valid (at least 'threshold' signers allowed, format is valid)
    CHECK_AND_ASSERT_THROW_MES(validate_aggregate_multisig_signer_set_filter(threshold,
            multisig_signers.size(),
            init_set.aggregate_signer_set_filter),
        "multisig init set semantics: invalid aggregate signer set filter.");

    // the init's signer must be in allowed signers list, and contained in the aggregate filter
    CHECK_AND_ASSERT_THROW_MES(std::find(multisig_signers.begin(), multisig_signers.end(), init_set.signer_id) !=
        multisig_signers.end(), "multisig init set semantics: initializer from unknown signer.");
    CHECK_AND_ASSERT_THROW_MES(signer_is_in_filter(init_set.signer_id,
            multisig_signers,
            init_set.aggregate_signer_set_filter),
        "multisig init set semantics: signer is not eligible.");

    // 2. for each proof key to sign, there should be one nonce set (signing attempt) per signer subgroup that contains the
    //   signer
    // - there are 'num signers requested' choose 'threshold' total signer subgroups who can participate in signing this
    //   proof
    // - remove our init's signer, then choose 'threshold - 1' signers from the remaining 'num signers requested - 1' to
    //   get the number of permutations that include our init's signer
    const std::uint32_t num_sets_with_signer_expected(
            sp::math::n_choose_k(get_num_flags_set(init_set.aggregate_signer_set_filter) - 1, threshold - 1)
        );

    CHECK_AND_ASSERT_THROW_MES(init_set.inits.size() == num_sets_with_signer_expected,
        "multisig init set semantics: don't have expected number of nonce sets (one per signer set that has signer).");

    for (const std::vector<MultisigPubNonces> &nonce_pubkey_set : init_set.inits)
    {
        CHECK_AND_ASSERT_THROW_MES(nonce_pubkey_set.size() == num_expected_nonce_sets_per_proofkey,
            "multisig init set semantics: don't have expected number of nonce pubkey pairs (each proof key should have "
            "(" << num_expected_nonce_sets_per_proofkey << ") nonce pubkey pairs).");
    }
}
//-------------------------------------------------------------------------------------------------------------------
MultisigSigningErrorVariant validate_v1_multisig_init_set_v1(const MultisigProofInitSetV1 &init_set,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const signer_set_filter expected_aggregate_signer_set_filter,
    const crypto::public_key &expected_signer_id,
    const rct::key &expected_proof_message,
    const rct::key &expected_main_proof_key,
    const std::size_t num_expected_nonce_sets_per_proofkey)
{
    // 1. aggregate filter should match the expected aggregate filter
    if (init_set.aggregate_signer_set_filter != expected_aggregate_signer_set_filter)
    {
        return MultisigSigningErrorBadInitSet{
                .error_code = MultisigSigningErrorBadInitSet::ErrorCode::UNEXPECTED_FILTER,
                .aggregate_signer_set_filter = init_set.aggregate_signer_set_filter,
                .signer_id                   = init_set.signer_id,
                .proof_message               = init_set.proof_message,
                .proof_key                   = init_set.proof_key
            };
    }

    // 2. signer should be expected
    if (!(init_set.signer_id == expected_signer_id))
    {
        return MultisigSigningErrorBadInitSet{
                .error_code = MultisigSigningErrorBadInitSet::ErrorCode::UNEXPECTED_SIGNER,
                .aggregate_signer_set_filter = init_set.aggregate_signer_set_filter,
                .signer_id                   = init_set.signer_id,
                .proof_message               = init_set.proof_message,
                .proof_key                   = init_set.proof_key
            };
    }

    // 3. proof message should be expected
    if (!(init_set.proof_message == expected_proof_message))
    {
        return MultisigSigningErrorBadInitSet{
                .error_code = MultisigSigningErrorBadInitSet::ErrorCode::UNEXPECTED_PROOF_MESSAGE,
                .aggregate_signer_set_filter = init_set.aggregate_signer_set_filter,
                .signer_id                   = init_set.signer_id,
                .proof_message               = init_set.proof_message,
                .proof_key                   = init_set.proof_key
            };
    }

    // 4. proof key should be expected
    // NOTE: the relationship between the main proof key and any auxilliary/secondary keys must be implemented by the
    //       caller
    if (!(init_set.proof_key == expected_main_proof_key))
    {
        return MultisigSigningErrorBadInitSet{
                .error_code = MultisigSigningErrorBadInitSet::ErrorCode::UNEXPECTED_MAIN_PROOF_KEY,
                .aggregate_signer_set_filter = init_set.aggregate_signer_set_filter,
                .signer_id                   = init_set.signer_id,
                .proof_message               = init_set.proof_message,
                .proof_key                   = init_set.proof_key
            };
    }

    // 5. init set semantics must be valid
    try
    {
        check_v1_multisig_init_set_semantics_v1(init_set,
            threshold,
            multisig_signers,
            num_expected_nonce_sets_per_proofkey);
    }
    catch (const dummy_multisig_exception&)
    {
        // no error message for dummy exceptions (error message recorded elsewhere)
    }
    catch (const std::exception &exception)
    {
        return MultisigSigningErrorBadInitSet{
                .error_code = MultisigSigningErrorBadInitSet::ErrorCode::SEMANTICS_EXCEPTION,
                .aggregate_signer_set_filter = init_set.aggregate_signer_set_filter,
                .signer_id                   = init_set.signer_id,
                .proof_message               = init_set.proof_message,
                .proof_key                   = init_set.proof_key,
                .error_message               = exception.what()
            };
    }
    catch (...)
    {
        return MultisigSigningErrorBadInitSet{
                .error_code = MultisigSigningErrorBadInitSet::ErrorCode::SEMANTICS_EXCEPTION,
                .aggregate_signer_set_filter = init_set.aggregate_signer_set_filter,
                .signer_id                   = init_set.signer_id,
                .proof_message               = init_set.proof_message,
                .proof_key                   = init_set.proof_key,
                .error_message               = "unknown exception"
            };
    }

    return boost::none;
}
//-------------------------------------------------------------------------------------------------------------------
MultisigSigningErrorVariant validate_v1_multisig_init_set_collection_v1(
    const std::unordered_map<rct::key, MultisigProofInitSetV1> &init_set_collection, //[ proof key : init set ]
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const signer_set_filter expected_aggregate_signer_set_filter,
    const crypto::public_key &expected_signer_id,
    const std::unordered_map<rct::key, rct::key> &expected_proof_contexts,  //[ proof key : proof message ]
    const std::size_t num_expected_nonce_sets_per_proofkey)
{
    // 1. expect the init set collection was built for at least one proof context
    if (expected_proof_contexts.size() == 0)
    {
        return MultisigSigningErrorBadInitSetCollection{
                .error_code = MultisigSigningErrorBadInitSetCollection::ErrorCode::EMPTY_COLLECTION_EXPECTED,
                .signer_id  = expected_signer_id
            };
    }

    // 2. expect the same number of proof messages as init sets in the collection
    if (init_set_collection.size() != expected_proof_contexts.size())
    {
        return MultisigSigningErrorBadInitSetCollection{
                .error_code = MultisigSigningErrorBadInitSetCollection::ErrorCode::PROOF_CONTEXT_MISMATCH,
                .signer_id  = expected_signer_id
            };
    }

    // 3. check that the init set collection maps to its internal proof keys correctly
    if (!tools::keys_match_internal_values(init_set_collection,
                [](const rct::key &key, const MultisigProofInitSetV1 &init_set) -> bool
                {
                    return key == init_set.proof_key;
                }
            ))
    {
        return MultisigSigningErrorBadInitSetCollection{
                .error_code = MultisigSigningErrorBadInitSetCollection::ErrorCode::INVALID_MAPPING,
                .signer_id  = expected_signer_id
            };
    }

    // 4. validate each init set in the input collection
    for (const auto &init_set : init_set_collection)
    {
        // a. check that the init set has one of the expected messages
        // note: using maps ensures the expected proof contexts line up 1:1 with init sets without duplicates
        if (expected_proof_contexts.find(init_set.first) == expected_proof_contexts.end())
        {
            return MultisigSigningErrorBadInitSetCollection{
                    .error_code = MultisigSigningErrorBadInitSetCollection::ErrorCode::PROOF_CONTEXT_MISMATCH,
                    .signer_id  = expected_signer_id
                };
        }

        // b. validate the init set
        if (auto validation_error = validate_v1_multisig_init_set_v1(init_set.second,
                threshold,
                multisig_signers,
                expected_aggregate_signer_set_filter,
                expected_signer_id,
                expected_proof_contexts.at(init_set.first),
                init_set.first,
                num_expected_nonce_sets_per_proofkey))
            return validation_error;
    }

    return boost::none;
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_init_set_v1(const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const signer_set_filter aggregate_signer_set_filter,
    const crypto::public_key &local_signer_id,
    const rct::key &proof_message,
    const rct::key &main_proof_key,
    const rct::keyV &proof_key_base_points,
    MultisigNonceCache &nonce_record_inout,
    MultisigProofInitSetV1 &init_set_out)
{
    // 1. enforce canonical proof keys (NOTE: this is only a sanity check)
    CHECK_AND_ASSERT_THROW_MES(sp::key_domain_is_prime_subgroup(main_proof_key),
        "make multisig proof initializer: found proof key with non-canonical representation!");

    for (const rct::key &proof_key_base_point : proof_key_base_points)
    {
        CHECK_AND_ASSERT_THROW_MES(sp::key_domain_is_prime_subgroup(proof_key_base_point),
            "make multisig proof initializer: found proof key base point with non-canonical representation!");
    }

    // 2. prepare init nonce map
    const std::uint32_t num_sets_with_signer_expected{
            sp::math::n_choose_k(get_num_flags_set(aggregate_signer_set_filter) - 1, threshold - 1)
        };

    init_set_out.inits.clear();
    init_set_out.inits.reserve(num_sets_with_signer_expected);

    // 3. add nonces for every possible signer set that includes the signer
    CHECK_AND_ASSERT_THROW_MES(signer_is_in_filter(local_signer_id, multisig_signers, aggregate_signer_set_filter),
        "make multisig proof initializer: local signer is not in signer list requested!");

    std::vector<signer_set_filter> filter_permutations;
    aggregate_multisig_signer_set_filter_to_permutations(threshold,
        multisig_signers.size(),
        aggregate_signer_set_filter,
        filter_permutations);

    for (const signer_set_filter filter : filter_permutations)
    {
        // a. ignore filters that don't include the signer
        if (!signer_is_in_filter(local_signer_id, multisig_signers, filter))
            continue;

        // b. add new nonces to the nonce record for this <proof message, main proof key, filter> combination
        // - ignore failures to add nonces (re-using existing nonces is allowed)
        // NOTE: the relationship between the main proof key and any auxilliary/secondary keys must be enforced
        //       by the caller (an init set can be used with any auxilliary keys, which may defy the caller's
        //       expectations)
        nonce_record_inout.try_add_nonces(proof_message, main_proof_key, filter);

        // c. add nonces to the inits at this filter permutation for each requested proof base point
        init_set_out.inits.emplace_back();
        init_set_out.inits.back().reserve(proof_key_base_points.size());

        for (const rct::key &proof_base : proof_key_base_points)
        {
            CHECK_AND_ASSERT_THROW_MES(nonce_record_inout.try_get_nonce_pubkeys_for_base(proof_message,
                    main_proof_key,
                    filter,
                    proof_base,
                    tools::add_element(init_set_out.inits.back())),
                "make multisig proof initializer: could not get nonce pubkeys from nonce record (bug).");
        }
    }

    // 5. set cached context
    init_set_out.aggregate_signer_set_filter = aggregate_signer_set_filter;
    init_set_out.signer_id = local_signer_id;
    init_set_out.proof_message = proof_message;
    init_set_out.proof_key = main_proof_key;

    // 6. sanity check that the initializer is well-formed
    check_v1_multisig_init_set_semantics_v1(init_set_out, threshold, multisig_signers, proof_key_base_points.size());
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_init_set_collection_v1(const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const signer_set_filter aggregate_signer_set_filter,
    const crypto::public_key &local_signer_id,
    const std::unordered_map<rct::key, rct::key> &proof_contexts,  //[ proof key : proof message ]
    const std::unordered_map<rct::key, rct::keyV> &proof_key_base_points,  //[ proof key : {proof key base points} ]
    MultisigNonceCache &nonce_record_inout,
    std::unordered_map<rct::key, MultisigProofInitSetV1> &init_set_collection_out) //[ proof key : init set ]
{
    // make an init set for every proof context provided
    init_set_collection_out.clear();
    init_set_collection_out.reserve(proof_contexts.size());

    for (const auto &proof_context : proof_contexts)
    {
        CHECK_AND_ASSERT_THROW_MES(proof_key_base_points.find(proof_context.first) != proof_key_base_points.end(),
            "make multisig init set collection (v1): proof key base points map is missing a requested proof key.");

        make_v1_multisig_init_set_v1(threshold,
            multisig_signers,
            aggregate_signer_set_filter,
            local_signer_id,
            proof_context.second,
            proof_context.first,
            proof_key_base_points.at(proof_context.first),
            nonce_record_inout,
            init_set_collection_out[proof_context.first]);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_multisig_partial_sig_set_semantics_v1(const MultisigPartialSigSetV1 &partial_sig_set,
    const std::vector<crypto::public_key> &multisig_signers)
{
    // 1. signer is in filter
    CHECK_AND_ASSERT_THROW_MES(signer_is_in_filter(partial_sig_set.signer_id,
            multisig_signers,
            partial_sig_set.signer_set_filter),
        "multisig partial sig set semantics: the signer is not a member of the signer group (or the filter is invalid).");

    // 2. the partial signatures map to their proof keys properly
    CHECK_AND_ASSERT_THROW_MES(tools::keys_match_internal_values(partial_sig_set.partial_signatures,
                [](const rct::key &key, const MultisigPartialSigVariant &partial_sig) -> bool
                {
                    return key == proof_key_ref(partial_sig);
                }
            ),
        "multisig partial sig set semantics: a partial signature's mapped proof key does not match its stored key.");

    // 3. all partial sigs must have the same underlying type
    CHECK_AND_ASSERT_THROW_MES(std::adjacent_find(partial_sig_set.partial_signatures.begin(),
            partial_sig_set.partial_signatures.end(),
            [](const auto &v1, const auto &v2) -> bool
            {
                // find an adjacent pair that DONT have the same type
                return !MultisigPartialSigVariant::same_type(v1.second, v2.second);
            }) == partial_sig_set.partial_signatures.end(),
        "multisig partial sig set semantics: partial signatures are not all the same type.");
}
//-------------------------------------------------------------------------------------------------------------------
bool try_make_v1_multisig_partial_sig_sets_v1(const multisig_account &signer_account,
    const cryptonote::account_generator_era expected_multisig_account_era,
    const signer_set_filter aggregate_signer_set_filter,
    const std::unordered_map<rct::key, rct::key> &expected_proof_contexts,  //[ proof key : proof message ]
    const std::size_t num_expected_proof_basekeys,
    const MultisigPartialSigMaker &partial_sig_maker,
    //[ proof key : init set ]
    std::unordered_map<rct::key, MultisigProofInitSetV1> local_init_set_collection,
    //[ signer id : [ proof key : init set ] ]
    std::unordered_map<crypto::public_key, std::unordered_map<rct::key, MultisigProofInitSetV1>>
        other_init_set_collections,
    std::list<MultisigSigningErrorVariant> &multisig_errors_inout,
    MultisigNonceCache &nonce_record_inout,
    std::vector<MultisigPartialSigSetV1> &partial_sig_sets_out)
{
    CHECK_AND_ASSERT_THROW_MES(signer_account.multisig_is_ready(),
        "multisig input partial sigs: signer account is not complete, so it can't make partial signatures.");
    CHECK_AND_ASSERT_THROW_MES(signer_account.get_era() == expected_multisig_account_era,
        "multisig input partial sigs: signer account does not have the expected account era.");

    partial_sig_sets_out.clear();

    // if there are no proof contexts to sign, then we succeed 'automatically'
    if (expected_proof_contexts.size() == 0)
        return true;


    /// prepare pieces to use below

    // 1. misc. from account
    const std::uint32_t threshold{signer_account.get_threshold()};
    const std::vector<crypto::public_key> &multisig_signers{signer_account.get_signers()};
    const crypto::public_key &local_signer_id{signer_account.get_base_pubkey()};

    // 2. validate and assemble all inits
    std::unordered_map<crypto::public_key, std::unordered_map<rct::key, MultisigProofInitSetV1>>
        all_init_set_collections;  //[ signer id : [ proof key : init set ] ]

    prepare_multisig_init_set_collections_v1(threshold,
        multisig_signers,
        aggregate_signer_set_filter,
        local_signer_id,
        expected_proof_contexts,
        num_expected_proof_basekeys,
        std::move(local_init_set_collection),
        std::move(other_init_set_collections),
        multisig_errors_inout,
        all_init_set_collections);

    // 3. prepare filters for signing
    signer_set_filter local_signer_filter;
    signer_set_filter available_signers_filter;
    std::unordered_map<crypto::public_key, signer_set_filter> available_signers_as_filters;
    std::vector<signer_set_filter> filter_permutations;

    prepare_filters_for_multisig_partial_signing(threshold,
        multisig_signers,
        local_signer_id,
        aggregate_signer_set_filter,
        all_init_set_collections,
        local_signer_filter,
        available_signers_filter,
        available_signers_as_filters,
        filter_permutations);

    // 4. check how the available signers line up against the signers allowed to participate in this multisig ceremony
    // note: signers not permitted by the ceremony should not make it this far, but we record them just in case; the
    //       partial signature maker will ignore them
    if (available_signers_filter != aggregate_signer_set_filter)
    {
        multisig_errors_inout.emplace_back(
                MultisigSigningErrorAvailableSigners{
                        .error_code = MultisigSigningErrorAvailableSigners::ErrorCode::INCOMPLETE_AVAILABLE_SIGNERS,
                        .missing_signers =
                            static_cast<signer_set_filter>(
                                    (~available_signers_filter) & aggregate_signer_set_filter
                                ),
                        .unexpected_available_signers =
                            static_cast<signer_set_filter>(
                                    (~aggregate_signer_set_filter) & available_signers_filter
                                )
                    }
            );
    }


    /// give up if not enough signers provided material to initialize a signature
    if (available_signers_as_filters.size() < threshold)
        return false;


    /// make partial signature sets
    make_v1_multisig_partial_sig_sets_v1(signer_account,
        expected_proof_contexts,
        num_expected_proof_basekeys,
        filter_permutations,
        local_signer_filter,
        available_signers_filter,
        available_signers_as_filters,
        all_init_set_collections,
        partial_sig_maker,
        multisig_errors_inout,
        nonce_record_inout,
        partial_sig_sets_out);

    if (partial_sig_sets_out.size() == 0)
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void filter_multisig_partial_signatures_for_combining_v1(const std::vector<crypto::public_key> &multisig_signers,
    const std::unordered_map<rct::key, rct::key> &allowed_proof_contexts,  //[ proof key : proof message ]
    const int expected_partial_sig_variant_index,
    const std::unordered_map<crypto::public_key, std::vector<MultisigPartialSigSetV1>> &partial_sigs_per_signer,
    std::list<MultisigSigningErrorVariant> &multisig_errors_inout,
    std::unordered_map<signer_set_filter,  //signing group
        std::unordered_map<rct::key,       //proof key
            std::vector<MultisigPartialSigVariant>>> &collected_sigs_per_key_per_filter_out)
{
    collected_sigs_per_key_per_filter_out.clear();

    // filter the partial signatures passed in into the 'collected sigs' output map
    std::unordered_map<signer_set_filter, std::unordered_set<crypto::public_key>> collected_signers_per_filter;

    if (partial_sigs_per_signer.size() > 0)
    {
        // estimate total number of filters: num filters for the first signer * num signers available
        // note: we optimize performance for non-adversarial multisig interactions, which should be the norm
        collected_signers_per_filter.reserve(
                partial_sigs_per_signer.begin()->second.size() * partial_sigs_per_signer.size()
            );
    }

    for (const auto &partial_sigs_for_signer : partial_sigs_per_signer)
    {
        for (const MultisigPartialSigSetV1 &partial_sig_set : partial_sigs_for_signer.second)
        {
            // a. skip sig sets that are invalid
            try { check_v1_multisig_partial_sig_set_semantics_v1(partial_sig_set, multisig_signers); }
            catch (const std::exception &exception)
            {
                multisig_errors_inout.emplace_back(
                        MultisigSigningErrorBadPartialSigSet{
                                .error_code = MultisigSigningErrorBadPartialSigSet::ErrorCode::SEMANTICS_EXCEPTION,
                                .signature_set_filter = partial_sig_set.signer_set_filter,
                                .signer_id            = partial_sig_set.signer_id,
                                .error_message        = exception.what()
                            }
                    );

                continue;
            }
            catch (...)
            {
                multisig_errors_inout.emplace_back(
                        MultisigSigningErrorBadPartialSigSet{
                                .error_code = MultisigSigningErrorBadPartialSigSet::ErrorCode::SEMANTICS_EXCEPTION,
                                .signature_set_filter = partial_sig_set.signer_set_filter,
                                .signer_id            = partial_sig_set.signer_id,
                                .error_message        = "unknown exception"
                            }
                    );

                continue;
            }

            // b. skip sig sets that don't map to their signer ids properly
            if (!(partial_sig_set.signer_id == partial_sigs_for_signer.first))
            {
                multisig_errors_inout.emplace_back(
                        MultisigSigningErrorBadPartialSigSet{
                                .error_code = MultisigSigningErrorBadPartialSigSet::ErrorCode::INVALID_MAPPING,
                                .signature_set_filter = partial_sig_set.signer_set_filter,
                                .signer_id            = partial_sig_set.signer_id
                            }
                    );

                continue;
            }

            // c. skip sig sets that look like duplicates (same signer group and signer)
            // - do this after checking sig set validity to avoid inserting invalid filters into the collected signers
            //   map, which could allow a malicious signer to block signer groups they aren't a member of
            if (collected_signers_per_filter[partial_sig_set.signer_set_filter].find(partial_sig_set.signer_id) !=
                    collected_signers_per_filter[partial_sig_set.signer_set_filter].end())
                continue;

            // d. record the partial sigs
            collected_sigs_per_key_per_filter_out[partial_sig_set.signer_set_filter]
                .reserve(partial_sig_set.partial_signatures.size());

            for (const auto &partial_sig : partial_sig_set.partial_signatures)
            {
                // i. skip partial sigs with unknown proof keys
                if (allowed_proof_contexts.find(partial_sig.first) == allowed_proof_contexts.end())
                {
                    multisig_errors_inout.emplace_back(
                            MultisigSigningErrorBadPartialSig{
                                    .error_code =
                                        MultisigSigningErrorBadPartialSig::ErrorCode::UNEXPECTED_MAIN_PROOF_KEY,
                                    .proof_key     = proof_key_ref(partial_sig.second),
                                    .proof_message = message_ref(partial_sig.second)
                                }
                        );

                    continue;
                }

                // ii. skip sig sets with unexpected proof messages
                if (!(allowed_proof_contexts.at(partial_sig.first) == message_ref(partial_sig.second)))
                {
                    multisig_errors_inout.emplace_back(
                            MultisigSigningErrorBadPartialSig{
                                    .error_code =
                                        MultisigSigningErrorBadPartialSig::ErrorCode::UNEXPECTED_PROOF_MESSAGE,
                                    .proof_key     = proof_key_ref(partial_sig.second),
                                    .proof_message = message_ref(partial_sig.second)
                                }
                        );

                    continue;
                }

                // iii. skip partial sigs with unexpected internal variant type
                if (partial_sig.second.index() != expected_partial_sig_variant_index)
                {
                    multisig_errors_inout.emplace_back(
                            MultisigSigningErrorBadPartialSig{
                                    .error_code =
                                        MultisigSigningErrorBadPartialSig::ErrorCode::UNEXPECTED_VARIANT_TYPE,
                                    .proof_key     = proof_key_ref(partial_sig.second),
                                    .proof_message = message_ref(partial_sig.second)
                                }
                        );

                    continue;
                }

                // iv. add this signer's partial signature for this proof key for this signer group
                collected_sigs_per_key_per_filter_out[partial_sig_set.signer_set_filter][partial_sig.first]
                    .emplace_back(partial_sig.second);
            }

            // e. record that this signer/filter combo has been used
            collected_signers_per_filter[partial_sig_set.signer_set_filter].insert(partial_sig_set.signer_id);
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace multisig
