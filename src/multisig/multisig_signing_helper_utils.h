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

// Utilities to assist with multisig signing ceremonies.
// IMPORTANT: These utilities should enforce strong guarantees about signer ID consistency. It is imperative that
//            a malicious signer not be allowed to pretend they are a different signer or part of signer subgroup
//            they aren't actually a member of.

#pragma once

//local headers
#include "common/container_helpers.h"
#include "crypto/crypto.h"
#include "multisig_account.h"
#include "multisig_signer_set_filter.h"
#include "multisig_signing_errors.h"
#include "multisig_signing_helper_types.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <functional>
#include <unordered_map>
#include <utility>
#include <vector>

//forward declarations
namespace multisig
{
    class MultisigNonceCache;
    class MultisigPartialSigMaker;
}

namespace multisig
{

/**
* brief: check_v1_multisig_init_set_semantics_v1 - check semantics of a multisig initializer set
*   - throws if a check fails
* param: init_set -
* param: threshold -
* param: multisig_signers -
* param: num_expected_nonce_sets_per_proofkey -
*/
void check_v1_multisig_init_set_semantics_v1(const MultisigProofInitSetV1 &init_set,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const std::size_t num_expected_nonce_sets_per_proofkey);
/**
* brief: validate_v1_multisig_init_set_v1 - validate a multisig init set (non-throwing)
* param: init_set -
* param: threshold -
* param: multisig_signers -
* param: expected_aggregate_signer_set_filter -
* param: expected_signer_id -
* param: expected_proof_message -
* param: expected_main_proof_key -
* param: num_expected_nonce_sets_per_proofkey -
* return: empty variant if the init set is valid, otherwise a multisig error
*/
MultisigSigningErrorVariant validate_v1_multisig_init_set_v1(const MultisigProofInitSetV1 &init_set,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const signer_set_filter expected_aggregate_signer_set_filter,
    const crypto::public_key &expected_signer_id,
    const rct::key &expected_proof_message,
    const rct::key &expected_main_proof_key,
    const std::size_t num_expected_nonce_sets_per_proofkey);
MultisigSigningErrorVariant validate_v1_multisig_init_set_collection_v1(
    const std::unordered_map<rct::key, MultisigProofInitSetV1> &init_set_collection, //[ proof key : init set ]
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const signer_set_filter expected_aggregate_signer_set_filter,
    const crypto::public_key &expected_signer_id,
    const std::unordered_map<rct::key, rct::key> &expected_proof_contexts,  //[ proof key : proof message ]
    const std::size_t num_expected_nonce_sets_per_proofkey);
/**
* brief: make_v1_multisig_init_set_v1 - make a multisig initialization set for specified proof info
* param: threshold -
* param: multisig_signers -
* param: aggregate_signer_set_filter -
* param: local_signer_id -
* param: proof_message -
* param: main_proof_key -
* param: proof_key_base_points -
* inoutparam: nonce_record_inout -
* outparam: init_set_out -
*/
void make_v1_multisig_init_set_v1(const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const signer_set_filter aggregate_signer_set_filter,
    const crypto::public_key &local_signer_id,
    const rct::key &proof_message,
    const rct::key &main_proof_key,
    const rct::keyV &proof_key_base_points,
    MultisigNonceCache &nonce_record_inout,
    MultisigProofInitSetV1 &init_set_out);
void make_v1_multisig_init_set_collection_v1(const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const signer_set_filter aggregate_signer_set_filter,
    const crypto::public_key &local_signer_id,
    const std::unordered_map<rct::key, rct::key> &proof_contexts,  //[ proof key : proof message ]
    const std::unordered_map<rct::key, rct::keyV> &proof_key_base_points,  //[ proof key : {proof key base points} ]
    MultisigNonceCache &nonce_record_inout,
    std::unordered_map<rct::key, MultisigProofInitSetV1> &init_set_collection_out); //[ proof key : init set ]
/**
* brief: check_v1_multisig_partial_sig_set_semantics_v1 - check semantics of a multisig partial signature set
*   - throws if a check fails
* param: partial_sig_set -
* param: multisig_signers -
*/
void check_v1_multisig_partial_sig_set_semantics_v1(const MultisigPartialSigSetV1 &partial_sig_set,
    const std::vector<crypto::public_key> &multisig_signers);
/**
* brief: try_make_v1_multisig_partial_sig_sets_v1 - try to make multisig partial signature sets with an injected partial
*        sig maker
*   - weak preconditions: ignores invalid initializers from non-local signers
*   - will throw if local signer is not in the aggregate signer filter (or has an invalid initializer)
*   - will only return true if at least one partial sig set can be made containing a partial sig for each of the 
*     requested proof contexts
* param: signer_account -
* param: expected_multisig_account_era -
* param: aggregate_signer_set_filter -
* param: expected_proof_contexts -
* param: num_expected_proof_basekeys -
* param: partial_sig_maker -
* param: local_init_set_collection -
* param: other_init_set_collections -
* inoutparam: multisig_errors_inout -
* inoutparam: nonce_record_inout -
* outparam: partial_sig_sets_out -
*/
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
    std::vector<MultisigPartialSigSetV1> &partial_sig_sets_out);
/**
* brief: filter_multisig_partial_signatures_for_combining_v1 - filter multisig partial signature sets into a convenient
*        map for combining them into complete signatures
*   - weak preconditions: ignores signature sets that don't conform to expectations
* param: multisig_signers -
* param: allowed_proof_contexts -
* param: expected_partial_sig_variant_index -
* param: partial_sigs_per_signer -
* inoutparam: multisig_errors_inout -
* outparam: collected_sigs_per_key_per_filter_out -
*/
void filter_multisig_partial_signatures_for_combining_v1(const std::vector<crypto::public_key> &multisig_signers,
    const std::unordered_map<rct::key, rct::key> &allowed_proof_contexts,  //[ proof key : proof message ]
    const int expected_partial_sig_variant_index,
    const std::unordered_map<crypto::public_key, std::vector<MultisigPartialSigSetV1>> &partial_sigs_per_signer,
    std::list<MultisigSigningErrorVariant> &multisig_errors_inout,
    std::unordered_map<signer_set_filter,  //signing group
        std::unordered_map<rct::key,       //proof key
            std::vector<MultisigPartialSigVariant>>> &collected_sigs_per_key_per_filter_out);
/**
* brief: collect_partial_sigs_v1 - unwrap multisig partial signatures
* type: PartialSigT -
* param: type_erased_partial_sigs -
* outparam: partial_sigs_out -
*/
template <typename PartialSigT>
void collect_partial_sigs_v1(const std::vector<MultisigPartialSigVariant> &type_erased_partial_sigs,
    std::vector<PartialSigT> &partial_sigs_out)
{
    partial_sigs_out.clear();
    partial_sigs_out.reserve(type_erased_partial_sigs.size());

    for (const MultisigPartialSigVariant &type_erased_partial_sig : type_erased_partial_sigs)
    {
        // skip partial signatures of undesired types
        if (!type_erased_partial_sig.is_type<PartialSigT>())
            continue;

        partial_sigs_out.emplace_back(type_erased_partial_sig.unwrap<PartialSigT>());
    }
}
/**
* brief: try_assemble_multisig_partial_sigs - try to combine multisig partial signatures into full signatures of
*        type ResultSigT using an injected function for merging partial signatures
*   - takes as input a set of {proof key, {partial signatures}} pairs, and only succeeds if each of those pairs can be
*     resolved to a complete signature
* type: PartialSigT -
* type: ResultSigT -
* param: collected_sigs_per_key -
* param: try_assemble_partial_sigs_func -
* outparam: result_sigs_out -
* return: true if a complete signature was assembled for every {proof key, {partial signatures}} pair passed in
*/
template <typename PartialSigT, typename ResultSigT>
bool try_assemble_multisig_partial_sigs(
    //[ proof key : partial signatures ]
    const std::unordered_map<rct::key, std::vector<MultisigPartialSigVariant>> &collected_sigs_per_key,
    const std::function<bool(const rct::key&, const std::vector<PartialSigT>&, ResultSigT&)>
        &try_assemble_partial_sigs_func,
    std::vector<ResultSigT> &result_sigs_out)
{
    result_sigs_out.clear();
    result_sigs_out.reserve(collected_sigs_per_key.size());
    std::vector<PartialSigT> partial_sigs_temp;

    for (const auto &proof_key_and_partial_sigs : collected_sigs_per_key)
    {
        // a. convert type-erased partial sigs to the type we want
        collect_partial_sigs_v1<PartialSigT>(proof_key_and_partial_sigs.second, partial_sigs_temp);

        // b. try to make the contextual signature
        if (!try_assemble_partial_sigs_func(proof_key_and_partial_sigs.first,
                partial_sigs_temp,
                tools::add_element(result_sigs_out)))
            return false;
    }

    return true;
}
/**
* brief: try_assemble_multisig_partial_sigs_signer_group_attempts - try to combine multisig partial signatures into full
*        signatures of type ResultSigT using an injected function for merging partial signatures; makes attempts for
*        multiple signer groups
*   - note: it is the responsibility of the caller to validate the 'collected_sigs_per_key_per_filter' map; failing to
*           validate it could allow a malicious signer to pollute the signature attempts of signer subgroups they aren't
*           a member of, or lead to unexpected failures where the signatures output from here are invalid according to
*           a broader context (e.g. undesired proof keys or proof messages, etc.)
* type: PartialSigT -
* type: ResultSigT -
* param: num_expected_completed_sigs -
* param: collected_sigs_per_key_per_filter -
* param: try_assemble_partial_sigs_func -
* inoutparam: multisig_errors_inout -
* outparam: result_sigs_out -
* return: true if the requested number of signatures were assembled (e.g. one per proof key represented in the
*         collected_sigs_per_key_per_filter input)
*/
template <typename PartialSigT, typename ResultSigT>
bool try_assemble_multisig_partial_sigs_signer_group_attempts(const std::size_t num_expected_completed_sigs,
    const std::unordered_map<signer_set_filter,  //signing group
        std::unordered_map<rct::key,             //proof key 
            std::vector<MultisigPartialSigVariant>>> &collected_sigs_per_key_per_filter,
    const std::function<bool(const rct::key&, const std::vector<PartialSigT>&, ResultSigT&)>
        &try_assemble_partial_sigs_func,
    std::list<MultisigSigningErrorVariant> &multisig_errors_inout,
    std::vector<ResultSigT> &result_sigs_out)
{
    // try to assemble a collection of signatures from partial signatures provided by different signer groups
    // - all-or-nothing: a signer group must produce the expected number of completed signatures for their signatures
    //                   to be used
    std::vector<PartialSigT> partial_sigs_temp;

    for (const auto &signer_group_partial_sigs : collected_sigs_per_key_per_filter)
    {
        // a. skip this signer group if it doesn't have enough proof keys
        if (signer_group_partial_sigs.second.size() != num_expected_completed_sigs)
        {
            multisig_errors_inout.emplace_back(
                    MultisigSigningErrorBadSigAssembly{
                            .error_code = MultisigSigningErrorBadSigAssembly::ErrorCode::PROOF_KEYS_MISMATCH,
                            .signer_set_filter = signer_group_partial_sigs.first
                        }
                );
            continue;
        }

        // b. try to assemble the set of signatures that this signer group is working on
        if (try_assemble_multisig_partial_sigs<PartialSigT, ResultSigT>(signer_group_partial_sigs.second,
                try_assemble_partial_sigs_func,
                result_sigs_out)
            &&
            result_sigs_out.size() == num_expected_completed_sigs)
            break;
        else
        {
            multisig_errors_inout.emplace_back(
                    MultisigSigningErrorBadSigAssembly{
                            .error_code = MultisigSigningErrorBadSigAssembly::ErrorCode::SIG_ASSEMBLY_FAIL,
                            .signer_set_filter = signer_group_partial_sigs.first
                        }
                );
        }
    }

    if (result_sigs_out.size() != num_expected_completed_sigs)
    {
        multisig_errors_inout.emplace_back(
                MultisigSigningErrorBadSigSet{
                        .error_code = MultisigSigningErrorBadSigSet::ErrorCode::INVALID_SIG_SET
                    }
            );
        return false;
    }

    return true;
}

} //namespace multisig
