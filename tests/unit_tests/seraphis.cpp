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
#include "mock_tx/mock_sp_component_types.h"
#include "mock_tx/mock_sp_core_utils.h"
#include "mock_tx/mock_tx_utils.h"
#include "mock_tx/seraphis_composition_proof.h"
#include "mock_tx/seraphis_crypto_utils.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

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
                mock_tx::make_seraphis_key_image(y[i], z[i], KI[i]);
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

            mock_tx::make_seraphis_key_image(y[0], z[0], KI[0]);

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

                    mock_tx::make_seraphis_key_image(y[i], z, KI[i]);
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
    mock_tx::make_seraphis_spendbase(z, zU);
    mock_tx::make_seraphis_spendbase(z, k_bU);

    mock_tx::make_seraphis_key_image(y, z, key_image1);
    mock_tx::make_seraphis_key_image(y, zU, key_image2);
    mock_tx::make_seraphis_key_image_from_parts(k_a_sender, k_a_recipient, k_bU, key_image3);

    EXPECT_TRUE(key_image1 == key_image2);
    EXPECT_TRUE(key_image2 == key_image3);

    // encoding/decoding amounts succeeds
    crypto::secret_key sender_receiver_secret = rct::rct2sk(rct::identity());
    while (sender_receiver_secret == rct::rct2sk(rct::identity()))
        sender_receiver_secret = rct::rct2sk(rct::skGen());

    rct::xmr_amount amount = rct::randXmrAmount(rct::xmr_amount{static_cast<rct::xmr_amount>(-1)});
    rct::xmr_amount encoded_amount{mock_tx::enc_dec_seraphis_amount(sender_receiver_secret, amount)};
    rct::xmr_amount decoded_amount{mock_tx::enc_dec_seraphis_amount(sender_receiver_secret, encoded_amount)};

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
    mock_tx::make_seraphis_spendkey(recipient_view_privkey, recipient_spendbase_privkey, recipient_spend_key);  // K^s

    // make enote
    crypto::secret_key enote_privkey = rct::rct2sk(rct::identity());
    while (enote_privkey == rct::rct2sk(rct::identity()))
        enote_privkey = rct::rct2sk(rct::skGen());

    rct::key enote_pubkey;
    mock_tx::MockENoteSpV1 enote;

    enote.make(enote_privkey,
        recipient_DH_base,
        recipient_view_key,
        recipient_spend_key,
        amount,
        enote_index,
        enote_pubkey);

    // recover information
    rct::key nominal_recipient_spendkey;
    rct::xmr_amount amount_recovered;
    crypto::secret_key sender_receiver_secret;

    mock_tx::make_seraphis_sender_receiver_secret(recipient_view_privkey,
        enote_pubkey,
        enote_index,
        hw::get_device("default"),
        sender_receiver_secret);

    EXPECT_TRUE(mock_tx::try_get_seraphis_nominal_spend_key(sender_receiver_secret,
            enote.m_onetime_address,
            enote.m_view_tag,
            nominal_recipient_spendkey)
        );
    EXPECT_TRUE(nominal_recipient_spendkey == recipient_spend_key);
    EXPECT_TRUE(mock_tx::try_get_seraphis_amount(sender_receiver_secret,
            enote.m_amount_commitment,
            enote.m_encoded_amount,
            amount_recovered)
        );
    EXPECT_TRUE(amount_recovered == amount);
}
//-------------------------------------------------------------------------------------------------------------------
