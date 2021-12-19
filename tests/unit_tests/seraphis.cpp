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
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "device/device.hpp"
#include "misc_language.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis/sp_composition_proof.h"
#include "seraphis/sp_core_utils.h"
#include "seraphis/sp_crypto_utils.h"
#include "seraphis/sp_tx_component_types.h"
#include "seraphis/sp_tx_misc_utils.h"
#include "seraphis/sp_tx_utils.h"
#include "seraphis/sp_txtype_concise_v1.h"
#include "seraphis/sp_txtype_squashed_v1.h"

#include "gtest/gtest.h"

#include <vector>


//-------------------------------------------------------------------------------------------------------------------
static void make_secret_key(crypto::secret_key &skey_out)
{
    skey_out = rct::rct2sk(rct::zero());

    while (skey_out == rct::rct2sk(rct::zero()))
        skey_out = rct::rct2sk(rct::skGen());
}
//-------------------------------------------------------------------------------------------------------------------
static void make_pubkey(rct::key &pkey_out)
{
    pkey_out = rct::identity();

    while (pkey_out == rct::identity())
        pkey_out = rct::pkGen();
}
//-------------------------------------------------------------------------------------------------------------------
static void make_fake_sp_masked_address(crypto::secret_key &mask,
    crypto::secret_key &view_stuff,
    std::vector<crypto::secret_key> &spendkeys,
    rct::key &masked_address)
{
    const std::size_t num_signers{spendkeys.size()};
    EXPECT_TRUE(num_signers > 0);

    make_secret_key(mask);
    make_secret_key(view_stuff);

    // for multisig, there can be multiple signers
    crypto::secret_key spendkey_sum{rct::rct2sk(rct::zero())};
    for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
    {
        make_secret_key(spendkeys[signer_index]);

        sc_add(&spendkey_sum, &spendkey_sum, &spendkeys[signer_index]);
    }

    rct::keyV privkeys;
    rct::keyV pubkeys;
    privkeys.reserve(3);
    pubkeys.reserve(2);

    privkeys.push_back(rct::sk2rct(view_stuff));
    pubkeys.push_back(sp::get_X_gen());
    privkeys.push_back(rct::sk2rct(spendkey_sum));
    pubkeys.push_back(sp::get_U_gen());
    privkeys.push_back(rct::sk2rct(mask));
    //G implicit

    // K' = x G + kv_stuff X + ks U
    sp::multi_exp(privkeys, pubkeys, masked_address);
}
//-------------------------------------------------------------------------------------------------------------------
static void make_fake_sp_user_keys(rct::key &recipient_DH_base_out,
    crypto::secret_key &recipient_view_privkey_out,
    crypto::secret_key &recipient_spendbase_privkey_out)
{
    make_pubkey(recipient_DH_base_out);
    make_secret_key(recipient_view_privkey_out);
    make_secret_key(recipient_spendbase_privkey_out);
}
//-------------------------------------------------------------------------------------------------------------------
static std::shared_ptr<sp::SpTxConciseV1> make_sp_txtype_concise_v1(const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const std::size_t max_rangeproof_splits,
    const std::vector<rct::xmr_amount> &in_amounts,
    const std::vector<rct::xmr_amount> &out_amounts,
    const sp::SpTxConciseV1::ValidationRulesVersion validation_rules_version,
    std::shared_ptr<sp::MockLedgerContext> ledger_context_inout)
{
    /// build a tx from base components
    using namespace sp;

    CHECK_AND_ASSERT_THROW_MES(in_amounts.size() > 0, "Tried to make tx without any inputs.");
    CHECK_AND_ASSERT_THROW_MES(out_amounts.size() > 0, "Tried to make tx without any outputs.");
    CHECK_AND_ASSERT_THROW_MES(balance_check_in_out_amnts(in_amounts, out_amounts),
        "Tried to make tx with unbalanced amounts.");

    // make mock inputs
    // enote, ks, view key stuff, amount, amount blinding factor
    std::vector<SpInputProposalV1> input_proposals{gen_mock_sp_input_proposals_v1(in_amounts)};

    // make mock destinations
    // - (in practice) for 2-out tx, need special treatment when making change/dummy destination
    std::vector<SpDestinationV1> destinations{gen_mock_sp_destinations_v1(out_amounts)};

    // membership proof ref sets
    std::vector<SpENoteV1> input_enotes;
    input_enotes.reserve(input_proposals.size());

    for (const auto &input_proposal : input_proposals)
        input_enotes.emplace_back(input_proposal.m_enote);

    std::vector<SpMembershipReferenceSetV1> membership_ref_sets{
            gen_mock_sp_membership_ref_sets_v1(input_enotes,
                ref_set_decomp_n,
                ref_set_decomp_m,
                ledger_context_inout)
        };

    // versioning for proofs (v1)
    std::string version_string;
    version_string.reserve(3);
    SpTxConciseV1::get_versioning_string(validation_rules_version, version_string);

    /// make tx
    // tx components
    std::vector<SpENoteImageV1> input_images;
    std::vector<SpENoteV1> outputs;
    std::shared_ptr<SpBalanceProofV1> balance_proof;
    std::vector<SpImageProofV1> tx_image_proofs;
    std::vector<SpMembershipProofSortableV1> tx_membership_proofs_sortable;
    std::vector<SpMembershipProofV1> tx_membership_proofs;
    SpTxSupplementV1 tx_supplement;

    // info shuttles for making components
    std::vector<rct::xmr_amount> output_amounts;
    std::vector<crypto::secret_key> output_amount_commitment_blinding_factors;
    std::vector<crypto::secret_key> image_address_masks;
    std::vector<crypto::secret_key> image_amount_masks;
    std::vector<crypto::secret_key> input_image_amount_commitment_blinding_factors;

    make_v1_tx_outputs_sp_v1(destinations,
        outputs,
        output_amounts,  //slightly redundant here with 'out_amounts', but added to demonstrate API
        output_amount_commitment_blinding_factors,
        tx_supplement);
    make_v1_tx_images_sp_v1(input_proposals,
        input_images,
        image_address_masks,
        image_amount_masks);
    std::vector<rct::xmr_amount> input_amounts_dummy;
    prepare_input_commitment_factors_for_balance_proof_v1(
        input_proposals,
        image_amount_masks,
        input_amounts_dummy,
        input_image_amount_commitment_blinding_factors);
    make_v1_tx_balance_proof_sp_v1(output_amounts,
        input_image_amount_commitment_blinding_factors,
        output_amount_commitment_blinding_factors,
        max_rangeproof_splits,
        balance_proof);
    rct::key image_proofs_message{get_tx_image_proof_message_sp_v1(version_string, outputs, tx_supplement)};
    make_v1_tx_image_proofs_sp_v1(input_proposals,
        input_images,
        image_address_masks,
        image_proofs_message,
        tx_image_proofs);
    make_v1_tx_membership_proofs_sp_v1(membership_ref_sets,
        image_address_masks,
        image_amount_masks,
        tx_membership_proofs_sortable);
    sort_tx_inputs_sp_v1(tx_membership_proofs_sortable, tx_membership_proofs, input_images, tx_image_proofs);

    return std::make_shared<SpTxConciseV1>(std::move(input_images), std::move(outputs),
        std::move(balance_proof), std::move(tx_image_proofs), std::move(tx_membership_proofs),
        std::move(tx_supplement), SpTxConciseV1::ValidationRulesVersion::ONE);
}
//-------------------------------------------------------------------------------------------------------------------
static std::shared_ptr<sp::SpTxSquashedV1> make_sp_txtype_squashed_v1(const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const std::size_t max_rangeproof_splits,
    const std::vector<rct::xmr_amount> &in_amounts,
    const std::vector<rct::xmr_amount> &out_amounts,
    const sp::SpTxSquashedV1::ValidationRulesVersion validation_rules_version,
    std::shared_ptr<sp::MockLedgerContext> ledger_context_inout)
{
    /// build a tx from base components
    using namespace sp;

    CHECK_AND_ASSERT_THROW_MES(in_amounts.size() > 0, "Tried to make tx without any inputs.");
    CHECK_AND_ASSERT_THROW_MES(out_amounts.size() > 0, "Tried to make tx without any outputs.");
    CHECK_AND_ASSERT_THROW_MES(balance_check_in_out_amnts(in_amounts, out_amounts),
        "Tried to make tx with unbalanced amounts.");

    // make mock inputs
    // enote, ks, view key stuff, amount, amount blinding factor
    std::vector<SpInputProposalV1> input_proposals{gen_mock_sp_input_proposals_v1(in_amounts)};

    // make mock destinations
    // - (in practice) for 2-out tx, need special treatment when making change/dummy destination
    std::vector<SpDestinationV1> destinations{gen_mock_sp_destinations_v1(out_amounts)};

    // make mock membership proof ref sets
    std::vector<SpENoteV1> input_enotes;
    input_enotes.reserve(input_proposals.size());

    for (const auto &input_proposal : input_proposals)
        input_enotes.emplace_back(input_proposal.m_enote);

    std::vector<SpMembershipReferenceSetV1> membership_ref_sets{
            gen_mock_sp_membership_ref_sets_v2(input_enotes,
                ref_set_decomp_n,
                ref_set_decomp_m,
                ledger_context_inout)
        };

    // versioning for proofs
    std::string version_string;
    version_string.reserve(3);
    SpTxSquashedV1::get_versioning_string(validation_rules_version, version_string);

    // tx components
    std::vector<SpENoteImageV1> input_images;
    std::vector<SpENoteV1> outputs;
    std::shared_ptr<SpBalanceProofV1> balance_proof;
    std::vector<SpImageProofV1> tx_image_proofs;
    std::vector<SpMembershipProofSortableV1> tx_membership_proofs_sortable;
    std::vector<SpMembershipProofV1> tx_membership_proofs;
    SpTxSupplementV1 tx_supplement;

    // info shuttles for making components
    std::vector<rct::xmr_amount> output_amounts;
    std::vector<crypto::secret_key> output_amount_commitment_blinding_factors;
    std::vector<crypto::secret_key> image_address_masks;
    std::vector<crypto::secret_key> image_amount_masks;

    make_v1_tx_outputs_sp_v1(destinations,
        outputs,
        output_amounts,
        output_amount_commitment_blinding_factors,
        tx_supplement);
    make_v1_tx_images_sp_v2(input_proposals,
        input_images,
        image_address_masks,
        image_amount_masks);
    rct::key image_proofs_message{get_tx_image_proof_message_sp_v1(version_string, outputs, tx_supplement)};
    make_v1_tx_image_proofs_sp_v3(input_proposals,
        input_images,
        image_address_masks,
        image_proofs_message,
        tx_image_proofs);
    // sort inputs in preparation for making a balance proof
    const std::vector<std::size_t> input_sort_order{get_tx_input_sort_order_v1(input_images)};
    CHECK_AND_ASSERT_THROW_MES(
        rearrange_vector(input_sort_order, input_images)        &&
        rearrange_vector(input_sort_order, image_address_masks) &&
        rearrange_vector(input_sort_order, image_amount_masks)  &&
        rearrange_vector(input_sort_order, tx_image_proofs)     &&
        rearrange_vector(input_sort_order, membership_ref_sets) &&
        rearrange_vector(input_sort_order, input_proposals),
        "rearranging inputs failed");
    std::vector<rct::xmr_amount> input_amounts;
    std::vector<crypto::secret_key> input_image_amount_commitment_blinding_factors;
    prepare_input_commitment_factors_for_balance_proof_v1(input_proposals,
        image_amount_masks,
        input_amounts,
        input_image_amount_commitment_blinding_factors);
    make_v1_tx_balance_proof_sp_v2(input_amounts, //note: must range proof input image commitments in squashed enote model
        output_amounts,
        input_image_amount_commitment_blinding_factors,
        output_amount_commitment_blinding_factors,
        max_rangeproof_splits,
        balance_proof);
    make_v1_tx_membership_proofs_sp_v2(membership_ref_sets,
        image_address_masks,
        image_amount_masks,
        tx_membership_proofs_sortable);  //could also obtain sortable membership proofs as inputs
    align_v1_tx_membership_proofs_sp_v1(input_images, tx_membership_proofs_sortable, tx_membership_proofs);

    return std::make_shared<SpTxSquashedV1>(std::move(input_images), std::move(outputs),
        std::move(balance_proof), std::move(tx_image_proofs), std::move(tx_membership_proofs),
        std::move(tx_supplement), SpTxSquashedV1::ValidationRulesVersion::ONE);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, multi_exp)
{
    rct::key test_key;
    rct::key check;
    rct::key temp;

    // works normally
    for (std::size_t i = 1; i < 5; ++i)
    {
        check = rct::identity();

        rct::keyV pubkeys;
        rct::keyV privkeys;
        pubkeys.reserve(i);
        privkeys.reserve(i);

        for (std::size_t j = 0; j < i; ++j)
        {
            pubkeys.push_back(rct::pkGen());
            privkeys.push_back(rct::skGen());

            rct::scalarmultKey(temp, pubkeys.back(), privkeys.back());
            rct::addKeys(check, check, temp);
        }

        sp::multi_exp(privkeys, pubkeys, test_key);
        EXPECT_TRUE(test_key == check);
        sp::multi_exp_vartime(privkeys, pubkeys, test_key);
        EXPECT_TRUE(test_key == check);
    }

    // privkey == 1 optimization works
    for (std::size_t i = 4; i < 7; ++i)
    {
        check = rct::identity();

        rct::keyV pubkeys;
        rct::keyV privkeys;
        pubkeys.reserve(i);
        privkeys.reserve(i);

        for (std::size_t j = 0; j < i; ++j)
        {
            pubkeys.push_back(rct::pkGen());
            if (j < i/2)
                privkeys.push_back(rct::identity());
            else
                privkeys.push_back(rct::skGen());

            rct::scalarmultKey(temp, pubkeys.back(), privkeys.back());
            rct::addKeys(check, check, temp);
        }

        sp::multi_exp(privkeys, pubkeys, test_key);
        EXPECT_TRUE(test_key == check);
        sp::multi_exp_vartime(privkeys, pubkeys, test_key);
        EXPECT_TRUE(test_key == check);
    }

    // pubkey = G optimization works
    for (std::size_t i = 1; i < 5; ++i)
    {
        check = rct::identity();

        rct::keyV pubkeys;
        rct::keyV privkeys;
        pubkeys.reserve(i);
        privkeys.reserve(i);

        for (std::size_t j = 0; j < i; ++j)
        {
            privkeys.push_back(rct::skGen());

            if (j < i/2)
            {
                pubkeys.push_back(rct::pkGen());
                rct::scalarmultKey(temp, pubkeys.back(), privkeys.back());
            }
            // for j >= i/2 it will be privkey*G
            else
            {
                rct::scalarmultBase(temp, privkeys.back());
            }

            rct::addKeys(check, check, temp);
        }

        sp::multi_exp(privkeys, pubkeys, test_key);
        EXPECT_TRUE(test_key == check);
        sp::multi_exp_vartime(privkeys, pubkeys, test_key);
        EXPECT_TRUE(test_key == check);
    }
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, composition_proof)
{
    rct::keyV K;
    std::vector<crypto::key_image> KI;
    std::vector<crypto::secret_key> x, y, z;
    rct::key message{rct::zero()};
    sp::SpCompositionProof proof;

    // degenerate case works (1 key)
    // normal cases work (>1 key)
    for (std::size_t num_keys{1}; num_keys < 5; ++num_keys)
    {
        K.resize(num_keys);
        KI.resize(num_keys);
        x.resize(num_keys);
        y.resize(num_keys);
        z.resize(num_keys);

        try
        {
            for (std::size_t i{0}; i < num_keys; ++i)
            {
                std::vector<crypto::secret_key> temp_z = {z[i]};
                make_fake_sp_masked_address(x[i], y[i], temp_z, K[i]);
                z[i] = temp_z[0];
                sp::make_seraphis_key_image(y[i], z[i], KI[i]);
            }

            proof = sp::sp_composition_prove(K, x, y, z, message);

            EXPECT_TRUE(sp::sp_composition_verify(proof, K, KI, message));
        }
        catch (...)
        {
            EXPECT_TRUE(false);
        }
    }

    // works even if x = 0
    {
        K.resize(1);
        KI.resize(1);
        x.resize(1);
        y.resize(1);
        z.resize(1);

        try
        {
            std::vector<crypto::secret_key> temp_z = {z[0]};
            make_fake_sp_masked_address(x[0], y[0], temp_z, K[0]);
            z[0] = temp_z[0];

            rct::key xG;
            rct::scalarmultBase(xG, rct::sk2rct(x[0]));
            rct::subKeys(K[0], K[0], xG);   // kludge: remove x part manually
            x[0] = rct::rct2sk(rct::zero());

            sp::make_seraphis_key_image(y[0], z[0], KI[0]);

            proof = sp::sp_composition_prove(K, x, y, z, message);

            EXPECT_TRUE(sp::sp_composition_verify(proof, K, KI, message));
        }
        catch (...)
        {
            EXPECT_TRUE(false);
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, composition_proof_multisig)
{
    rct::keyV K, signer_nonces_1_pubs, signer_nonces_2_pubs;
    std::vector<crypto::key_image> KI;
    std::vector<crypto::secret_key> x, y, z_pieces_temp;
    std::vector<std::vector<crypto::secret_key>> z_pieces;
    rct::key message{rct::zero()};
    std::vector<sp::SpCompositionProofMultisigPrep> signer_preps;
    std::vector<sp::SpCompositionProofMultisigPartial> partial_sigs;
    sp::SpCompositionProof proof;

    // works even if x = 0 (kludge test)
    // degenerate case works (1 key)
    // normal cases work (>1 key)
    // range of co-signers works (1-3 signers)
    for (const bool test_x_0 : {true, false})
    {
    for (std::size_t num_keys{1}; num_keys < 4; ++num_keys)
    {
        K.resize(num_keys);
        KI.resize(num_keys);
        x.resize(num_keys);
        y.resize(num_keys);

        for (std::size_t num_signers{1}; num_signers < 4; ++num_signers)
        {
            z_pieces_temp.resize(num_signers);
            z_pieces.resize(num_signers);
            for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
            {
                z_pieces[signer_index].resize(num_keys);
            }
            signer_preps.resize(num_signers);
            signer_nonces_1_pubs.resize(num_signers);
            signer_nonces_2_pubs.resize(num_signers);
            partial_sigs.resize(num_signers);

            try
            {
                // prepare keys to sign with
                for (std::size_t i{0}; i < num_keys; ++i)
                {
                    // each signer gets their own z value for each key to sign with
                    make_fake_sp_masked_address(x[i], y[i], z_pieces_temp, K[i]);

                    for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
                    {
                        // have to map between different indexing views
                        z_pieces[signer_index][i] = z_pieces_temp[signer_index];
                    }

                    // add z pieces together from all signers to build the key image
                    crypto::secret_key z{rct::rct2sk(rct::zero())};
                    for (const auto &z_piece : z_pieces_temp)
                        sc_add(&z, &z, &z_piece);

                    sp::make_seraphis_key_image(y[i], z, KI[i]);
                }

                // kludge test: remove x component
                if (test_x_0)
                {
                    rct::key xG;
                    rct::scalarmultBase(xG, rct::sk2rct(x[0]));
                    rct::subKeys(K[0], K[0], xG);
                    x[0] = rct::rct2sk(rct::zero());
                }

                // tx proposer: make proposal
                sp::SpCompositionProofMultisigProposal proposal{sp::sp_composition_multisig_proposal(KI, K, message)};

                // all participants: signature openers
                for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
                {
                    signer_preps[signer_index] = sp::sp_composition_multisig_init();
                    signer_nonces_1_pubs[signer_index] = signer_preps[signer_index].signature_nonce_1_KI_pub;
                    signer_nonces_2_pubs[signer_index] = signer_preps[signer_index].signature_nonce_2_KI_pub;
                }

                // all participants: respond
                for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
                {
                    partial_sigs[signer_index] = sp::sp_composition_multisig_partial_sig(
                            proposal,
                            x,
                            y,
                            z_pieces[signer_index],
                            signer_nonces_1_pubs,
                            signer_nonces_2_pubs,
                            signer_preps[signer_index].signature_nonce_1_KI_priv,
                            signer_preps[signer_index].signature_nonce_2_KI_priv
                        );
                }

                // assemble tx
                proof = sp::sp_composition_prove_multisig_final(partial_sigs);

                // verify tx
                EXPECT_TRUE(sp::sp_composition_verify(proof, K, KI, message));


                /// test: rearranging nonces between signers makes a valid proof

                // all participants: respond
                for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
                {
                    if (signer_index == 1)
                    {
                        std::swap(signer_nonces_1_pubs[0], signer_nonces_1_pubs[1]);
                        std::swap(signer_nonces_2_pubs[0], signer_nonces_2_pubs[1]);
                    }

                    partial_sigs[signer_index] = sp::sp_composition_multisig_partial_sig(
                            proposal,
                            x,
                            y,
                            z_pieces[signer_index],
                            signer_nonces_1_pubs,
                            signer_nonces_2_pubs,
                            signer_preps[signer_index].signature_nonce_1_KI_priv,
                            signer_preps[signer_index].signature_nonce_2_KI_priv
                        );
                }

                // assemble tx again
                proof = sp::sp_composition_prove_multisig_final(partial_sigs);

                // verify tx again
                EXPECT_TRUE(sp::sp_composition_verify(proof, K, KI, message));
            }
            catch (...)
            {
                EXPECT_TRUE(false);
            }
        }
    }
    }
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, information_recovery_pieces)
{
    // different methods for making key images all have same results
    crypto::secret_key y, z, k_a_sender, k_a_recipient;
    rct::key zU, k_bU;
    crypto::key_image key_image1, key_image2, key_image3;

    make_secret_key(y);
    k_a_sender = y;
    k_a_recipient = y;
    sc_add(&y, &y, &y);
    make_secret_key(z);
    sp::make_seraphis_spendbase(z, zU);
    sp::make_seraphis_spendbase(z, k_bU);

    sp::make_seraphis_key_image(y, z, key_image1);
    sp::make_seraphis_key_image(y, zU, key_image2);
    sp::make_seraphis_key_image_from_parts(k_a_sender, k_a_recipient, k_bU, key_image3);

    EXPECT_TRUE(key_image1 == key_image2);
    EXPECT_TRUE(key_image2 == key_image3);

    // encoding/decoding amounts succeeds
    crypto::secret_key sender_receiver_secret = rct::rct2sk(rct::identity());
    while (sender_receiver_secret == rct::rct2sk(rct::identity()))
        sender_receiver_secret = rct::rct2sk(rct::skGen());

    rct::xmr_amount amount = rct::randXmrAmount(rct::xmr_amount{static_cast<rct::xmr_amount>(-1)});
    rct::xmr_amount encoded_amount{sp::enc_dec_seraphis_amount(sender_receiver_secret, rct::zero(), amount)};
    rct::xmr_amount decoded_amount{sp::enc_dec_seraphis_amount(sender_receiver_secret, rct::zero(), encoded_amount)};

    EXPECT_TRUE(encoded_amount != amount);
    EXPECT_TRUE(decoded_amount == amount);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, enote_v1_information_recovery)
{
    // prepare to make enote
    rct::key recipient_DH_base;
    crypto::secret_key recipient_view_privkey;
    rct::key recipient_view_key;
    crypto::secret_key recipient_spendbase_privkey;
    rct::key recipient_spend_key;
    rct::xmr_amount amount = rct::randXmrAmount(rct::xmr_amount{static_cast<rct::xmr_amount>(-1)});
    std::size_t enote_index = static_cast<std::size_t>(rct::randXmrAmount(rct::xmr_amount{16}));

    make_fake_sp_user_keys(recipient_DH_base, recipient_view_privkey, recipient_spendbase_privkey);  // {K^DH, k^vr, k^s}
    rct::scalarmultKey(recipient_view_key, recipient_DH_base, rct::sk2rct(recipient_view_privkey));  // K^vr
    sp::make_seraphis_spendkey(recipient_view_privkey, recipient_spendbase_privkey, recipient_spend_key);  // K^s

    // make enote
    crypto::secret_key enote_privkey = rct::rct2sk(rct::identity());
    while (enote_privkey == rct::rct2sk(rct::identity()))
        enote_privkey = rct::rct2sk(rct::skGen());

    rct::key enote_pubkey;
    sp::SpENoteV1 enote;

    enote.make(enote_privkey,
        recipient_DH_base,
        recipient_view_key,
        recipient_spend_key,
        amount,
        enote_index,
        false,
        enote_pubkey);

    // recover information
    rct::key nominal_recipient_spendkey;
    rct::xmr_amount amount_recovered;
    rct::key sender_receiver_secret;
    rct::key sender_receiver_secret2;
    crypto::key_derivation derivation;
    auto a_wiper = epee::misc_utils::create_scope_leave_handler([&]{
        // demo: must always memwipe these secrets after use
        memwipe(&derivation, sizeof(crypto::key_derivation));
        memwipe(&sender_receiver_secret, sizeof(rct::key));
        memwipe(&sender_receiver_secret2, sizeof(rct::key));
    });

    hw::get_device("default").generate_key_derivation(rct::rct2pk(enote_pubkey), recipient_view_privkey, derivation);

    EXPECT_TRUE(sp::try_get_seraphis_nominal_spend_key(derivation,
            enote_index,
            enote.m_onetime_address,
            enote.m_view_tag,
            sender_receiver_secret,
            nominal_recipient_spendkey)
        );
    EXPECT_TRUE(nominal_recipient_spendkey == recipient_spend_key);
    EXPECT_TRUE(sp::try_get_seraphis_amount(rct::rct2sk(sender_receiver_secret),
            rct::zero(),
            enote.m_amount_commitment,
            enote.m_encoded_amount,
            amount_recovered)
        );
    EXPECT_TRUE(amount_recovered == amount);

    // check: can reproduce sender-receiver secret
    sp::make_seraphis_sender_receiver_secret(recipient_view_privkey,
        enote_pubkey,
        enote_index,
        hw::get_device("default"),
        sender_receiver_secret2);
    EXPECT_TRUE(sender_receiver_secret2 == sender_receiver_secret);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, sp_txtype_concise_v1)
{
    // demo making SpTxTypeConciseV1 with raw tx builder API

    // fake ledger context for this test
    std::shared_ptr<sp::MockLedgerContext> ledger_context = std::make_shared<sp::MockLedgerContext>();

    // 3 tx, 11 inputs/outputs each, range proofs split x3
    std::vector<std::shared_ptr<sp::SpTxConciseV1>> txs;
    txs.reserve(3);

    std::vector<rct::xmr_amount> in_amounts;
    std::vector<rct::xmr_amount> out_amounts;

    for (int i{0}; i < 11; ++i)
    {
        in_amounts.push_back(2);
        out_amounts.push_back(2);
    }

    for (std::size_t tx_index{0}; tx_index < 3; ++tx_index)
    {
        txs.emplace_back(
                make_sp_txtype_concise_v1(2, 3, 3, in_amounts, out_amounts,
                    sp::SpTxConciseV1::ValidationRulesVersion::ONE, ledger_context)
            );
    }

    EXPECT_TRUE(sp::validate_mock_txs<sp::SpTxConciseV1>(txs, ledger_context));

    // insert key images to ledger
    for (const auto &tx : txs)
        sp::add_tx_to_ledger<sp::SpTxConciseV1>(ledger_context, *tx);

    // validation should fail due to double-spend
    EXPECT_FALSE(sp::validate_mock_txs<sp::SpTxConciseV1>(txs, ledger_context));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, sp_txtype_squashed_v1)
{
    // demo making SpTxTypeSquasedV1 with raw tx builder API

    // fake ledger context for this test
    std::shared_ptr<sp::MockLedgerContext> ledger_context = std::make_shared<sp::MockLedgerContext>();

    // 3 tx, 11 inputs/outputs each, range proofs split x3
    std::vector<std::shared_ptr<sp::SpTxSquashedV1>> txs;
    txs.reserve(3);

    std::vector<rct::xmr_amount> in_amounts;
    std::vector<rct::xmr_amount> out_amounts;

    for (int i{0}; i < 11; ++i)
    {
        in_amounts.push_back(2);
        out_amounts.push_back(2);
    }

    for (std::size_t tx_index{0}; tx_index < 3; ++tx_index)
    {
        txs.emplace_back(
                make_sp_txtype_squashed_v1(2, 3, 3, in_amounts, out_amounts,
                    sp::SpTxSquashedV1::ValidationRulesVersion::ONE, ledger_context)
            );
    }

    EXPECT_TRUE(sp::validate_mock_txs<sp::SpTxSquashedV1>(txs, ledger_context));

    // insert key images to ledger
    for (const auto &tx : txs)
        sp::add_tx_to_ledger<sp::SpTxSquashedV1>(ledger_context, *tx);

    // validation should fail due to double-spend
    EXPECT_FALSE(sp::validate_mock_txs<sp::SpTxSquashedV1>(txs, ledger_context));
}
//-------------------------------------------------------------------------------------------------------------------
