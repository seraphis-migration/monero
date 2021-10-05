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

extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "mock_tx/seraphis_composition_proof.h"
#include "mock_tx/seraphis_crypto_utils.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

#include "gtest/gtest.h"


//-------------------------------------------------------------------------------------------------------------------
static void make_fake_sp_masked_address(rct::key &mask,
    rct::key &view_stuff,
    rct::keyV &spendkeys,
    rct::key &masked_address)
{
    const std::size_t num_signers{spendkeys.size()};
    EXPECT_TRUE(num_signers > 0);

    mask = rct::zero();
    view_stuff = rct::zero();

    while (mask == rct::zero())
        mask = rct::skGen();

    while (view_stuff == rct::zero())
        view_stuff = rct::skGen();

    // for multisig, there can be multiple signers
    rct::key spendkey_sum{rct::zero()};
    for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
    {
        spendkeys[signer_index] = rct::zero();

        while (spendkeys[signer_index] == rct::zero())
            spendkeys[signer_index] = rct::skGen();

        sc_add(spendkey_sum.bytes, spendkey_sum.bytes, spendkeys[signer_index].bytes);
    }

    rct::keyV privkeys;
    rct::keyV pubkeys;
    privkeys.reserve(3);
    pubkeys.reserve(2);

    privkeys.push_back(view_stuff);
    pubkeys.push_back(sp::get_X_gen());
    privkeys.push_back(spendkey_sum);
    pubkeys.push_back(sp::get_U_gen());
    privkeys.push_back(mask);
    //G implicit

    // K' = x G + kv_stuff X + ks U
    sp::multi_exp(privkeys, pubkeys, masked_address);
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
    }

    // privkey == 1 optimization works
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
            if (j < i/2)
                privkeys.push_back(rct::identity());
            else
                privkeys.push_back(rct::skGen());

            rct::scalarmultKey(temp, pubkeys.back(), privkeys.back());
            rct::addKeys(check, check, temp);
        }

        sp::multi_exp(privkeys, pubkeys, test_key);

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
    }
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, composition_proof)
{
    rct::keyV K, KI, x, y, z;
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
                rct::keyV temp_z = {z[i]};
                make_fake_sp_masked_address(x[i], y[i], temp_z, K[i]);
                z[i] = temp_z[0];
                sp::seraphis_key_image_from_privkeys(z[i], y[i], KI[i]);
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
            rct::keyV temp_z = {z[0]};
            make_fake_sp_masked_address(x[0], y[0], temp_z, K[0]);
            z[0] = temp_z[0];

            rct::key xG;
            rct::scalarmultBase(xG, x[0]);
            rct::subKeys(K[0], K[0], xG);   // kludge: remove x part manually
            x[0] = rct::zero();

            sp::seraphis_key_image_from_privkeys(z[0], y[0], KI[0]);

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
    rct::keyV K, KI, x, y, signer_openers_pubs, z_pieces_temp;;
    rct::keyM z_pieces;
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
            signer_openers_pubs.resize(num_signers);
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
                    rct::key z{rct::zero()};
                    for (const auto &z_piece : z_pieces_temp)
                        sc_add(z.bytes, z.bytes, z_piece.bytes);

                    sp::seraphis_key_image_from_privkeys(z, y[i], KI[i]);
                }

                // kludge test: remove x component
                if (test_x_0)
                {
                    rct::key xG;
                    rct::scalarmultBase(xG, x[0]);
                    rct::subKeys(K[0], K[0], xG);
                    x[0] = rct::zero();
                }

                // tx proposer: make proposal
                sp::SpCompositionProofMultisigProposal proposal{sp::sp_composition_multisig_proposal(KI, K, message)};

                // all participants: signature openers
                for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
                {
                    signer_preps[signer_index] = sp::sp_composition_multisig_init();
                    signer_openers_pubs[signer_index] = signer_preps[signer_index].signature_opening_KI_pub;
                }

                // all participants: respond
                for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
                {
                    partial_sigs[signer_index] = sp::sp_composition_multisig_partial_sig(
                            proposal,
                            x,
                            y,
                            z_pieces[signer_index],
                            signer_openers_pubs,
                            signer_preps[signer_index].signature_opening_KI_priv
                        );
                }

                // assemble tx
                proof = sp::sp_composition_prove_multisig_final(partial_sigs);

                // verify tx
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
