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

#include "crypto/crypto.h"
#include "multisig/account_generator_era.h"
#include "multisig/multisig_account.h"
#include "multisig/multisig_signer_set_filter.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis/sp_composition_proof.h"
#include "seraphis/sp_core_enote_utils.h"
#include "seraphis/sp_crypto_utils.h"

#include "gtest/gtest.h"

#include <memory>
#include <vector>


//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_multisig_accounts(const cryptonote::account_generator_era account_era,
    const std::uint32_t threshold,
    const std::uint32_t num_signers,
    std::vector<multisig::multisig_account> &accounts_out)
{
  std::vector<crypto::public_key> signers;
  std::vector<multisig::multisig_kex_msg> current_round_msgs;
  std::vector<multisig::multisig_kex_msg> next_round_msgs;
  accounts_out.clear();
  accounts_out.reserve(num_signers);
  signers.reserve(num_signers);
  next_round_msgs.reserve(accounts_out.size());

  // create multisig accounts for each signer
  for (std::size_t account_index{0}; account_index < num_signers; ++account_index)
  {
    // create account [[ROUND 0]]
    accounts_out.emplace_back(account_era, rct::rct2sk(rct::skGen()), rct::rct2sk(rct::skGen()));

    // collect signer
    signers.emplace_back(accounts_out.back().get_base_pubkey());

    // collect account's first kex msg
    next_round_msgs.emplace_back(accounts_out.back().get_next_kex_round_msg());
  }

  // perform key exchange rounds until the accounts are ready
  while (accounts_out.size() && !accounts_out[0].multisig_is_ready())
  {
    current_round_msgs = std::move(next_round_msgs);
    next_round_msgs.clear();
    next_round_msgs.reserve(accounts_out.size());

    for (multisig::multisig_account &account : accounts_out)
    {
        // initialize or update account
        if (!account.account_is_active())
            account.initialize_kex(threshold, signers, current_round_msgs);  //[[ROUND 1]]
        else
            account.kex_update(current_round_msgs);  //[[ROUND 2+]]

        next_round_msgs.emplace_back(account.get_next_kex_round_msg());
    }
  }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool composition_proof_multisig_test(const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const crypto::secret_key &x)
{
    try
    {
        // prepare multisig accounts (for seraphis)
        std::vector<multisig::multisig_account> accounts;
        make_multisig_accounts(cryptonote::account_generator_era::seraphis, threshold, num_signers, accounts);
        if (accounts.size() == 0)
            return false;

        // make a seraphis composition proof pubkey: x G + y X + z U
        rct::key K{rct::pk2rct(accounts[0].get_multisig_pubkey())};  //start with base key: z U
        sp::extend_seraphis_spendkey(accounts[0].get_common_privkey(), K);  //+ y X
        sp::mask_key(x, K, K);  //+ x G

        // make the corresponding key image: (z/y) U
        crypto::key_image KI;
        sp::make_seraphis_key_image(accounts[0].get_common_privkey(), rct::pk2rct(accounts[0].get_multisig_pubkey()), KI);

        // tx proposer: make proposal and specify which other signers should try to co-sign (all of them)
        rct::key message{rct::zero()};
        sp::SpCompositionProofMultisigProposal proposal{sp::sp_composition_multisig_proposal(message, K, KI)};
        multisig::signer_set_filter aggregate_filter;
        multisig::multisig_signers_to_filter(accounts[0].get_signers(), accounts[0].get_signers(), aggregate_filter);

        // get signer group permutations (all signer groups that can complete a signature)
        std::vector<multisig::signer_set_filter> filter_permutations;
        multisig::aggregate_multisig_signer_set_filter_to_permutations(threshold,
            num_signers,
            aggregate_filter,
            filter_permutations);

        // each signer prepares for each signer group it is a member of
        std::vector<sp::SpCompositionProofMultisigNonceRecord> signer_nonce_records(num_signers);

        for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
        {
            for (std::size_t filter_index{0}; filter_index < filter_permutations.size(); ++filter_index)
            {
                if (!multisig::signer_is_in_filter(accounts[signer_index].get_base_pubkey(),
                        accounts[signer_index].get_signers(),
                        filter_permutations[filter_index]))
                    continue;

                sp::SpCompositionProofMultisigPrep prep_temp{sp::sp_composition_multisig_init()};
                signer_nonce_records[signer_index][proposal.message][filter_permutations[filter_index]] = prep_temp;
            }
        }

        // complete and validate each signature attempt
        std::vector<sp::SpCompositionProofMultisigPartial> partial_sigs;
        std::vector<rct::key> signer_nonces_1_pubs;
        std::vector<rct::key> signer_nonces_2_pubs;
        crypto::secret_key z_temp;
        sp::SpCompositionProof proof;

        for (const multisig::signer_set_filter filter : filter_permutations)
        {
            signer_nonces_1_pubs.clear();
            signer_nonces_2_pubs.clear();
            partial_sigs.clear();
            signer_nonces_1_pubs.reserve(threshold);
            signer_nonces_2_pubs.reserve(threshold);
            partial_sigs.reserve(threshold);

            // assemble nonce pubkeys for this signing attempt
            for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
            {
                if (!multisig::signer_is_in_filter(accounts[signer_index].get_base_pubkey(),
                        accounts[signer_index].get_signers(),
                        filter))
                    continue;

                const auto &prep = signer_nonce_records[signer_index][proposal.message][filter];

                signer_nonces_1_pubs.emplace_back(prep.signature_nonce_1_KI_pub);
                signer_nonces_2_pubs.emplace_back(prep.signature_nonce_2_KI_pub);
            }

            // each signer partially signs for this attempt
            for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
            {
                if (!accounts[signer_index].try_get_aggregate_signing_key(filter, z_temp))
                    continue;

                partial_sigs.emplace_back();
                EXPECT_TRUE(try_get_sp_composition_multisig_partial_sig(
                    proposal,
                    x,
                    accounts[signer_index].get_common_privkey(),
                    z_temp,
                    signer_nonces_1_pubs,
                    signer_nonces_2_pubs,
                    filter,
                    signer_nonce_records[signer_index],
                    partial_sigs.back()));
            }

            // sanity checks
            EXPECT_TRUE(signer_nonces_1_pubs.size() == threshold);
            EXPECT_TRUE(signer_nonces_2_pubs.size() == threshold);
            EXPECT_TRUE(partial_sigs.size() == threshold);

            // make proof
            proof = sp::sp_composition_prove_multisig_final(partial_sigs);

            // verify proof
            if (!sp::sp_composition_verify(proof, message, K, KI))
                return false;
        }
    }
    catch (...)
    {
        return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_multisig, composition_proof_multisig)
{
    // test various account combinations
    EXPECT_TRUE(composition_proof_multisig_test(1, 2, rct::rct2sk(rct::skGen())));
    EXPECT_TRUE(composition_proof_multisig_test(2, 2, rct::rct2sk(rct::skGen())));
    EXPECT_TRUE(composition_proof_multisig_test(1, 3, rct::rct2sk(rct::skGen())));
    EXPECT_TRUE(composition_proof_multisig_test(2, 3, rct::rct2sk(rct::skGen())));
    EXPECT_TRUE(composition_proof_multisig_test(3, 3, rct::rct2sk(rct::skGen())));
    EXPECT_TRUE(composition_proof_multisig_test(2, 4, rct::rct2sk(rct::skGen())));

    // test that setting x to zero still works
    EXPECT_TRUE(composition_proof_multisig_test(2, 2, rct::rct2sk(rct::zero())));
    EXPECT_TRUE(composition_proof_multisig_test(2, 3, rct::rct2sk(rct::zero())));
}
//-------------------------------------------------------------------------------------------------------------------
