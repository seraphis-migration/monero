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

#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "crypto/eclib_test.h"
#include "crypto/generators.h"
#include "crypto/x25519.h"
#include "device/device.hpp"
#include "misc_language.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/sp_core_enote_utils.h"
#include "seraphis_core/sp_core_types.h"
#include "seraphis_crypto/matrix_proof.h"
#include "seraphis_crypto/sp_composition_proof.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_crypto/sp_generator_factory.h"
#include "seraphis_crypto/sp_multiexp.h"

#include "gtest/gtest.h"

#include <memory>
#include <vector>


//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static crypto::secret_key make_secret_key()
{
    return rct::rct2sk(rct::skGen());
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_secret_key(crypto::secret_key &skey_out)
{
    skey_out = make_secret_key();
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_fake_sp_address(crypto::secret_key &x_out,
    crypto::secret_key &y_out,
    crypto::secret_key &z_out,
    rct::key &address_out)
{
    make_secret_key(x_out);
    make_secret_key(y_out);
    make_secret_key(z_out);

    // K" = x G + y X + z U
    sp::make_seraphis_spendkey(y_out, z_out, address_out);
    sp::mask_key(x_out, address_out, address_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_crypto, composition_proof)
{
    rct::key K;
    crypto::key_image KI;
    crypto::secret_key x, y, z;
    const rct::key message{rct::zero()};
    sp::SpCompositionProof proof;

    try
    {
        make_fake_sp_address(x, y, z, K);
        sp::make_sp_composition_proof(message, K, x, y, z, proof);

        sp::make_seraphis_key_image(y, z, KI);
        EXPECT_TRUE(sp::verify_sp_composition_proof(proof, message, K, KI));
    }
    catch (...)
    {
        EXPECT_TRUE(false);
    }
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_crypto, matrix_proof)
{
    sp::MatrixProof proof;

    auto make_keys =
        [](const std::size_t num_keys) -> std::vector<crypto::secret_key>
        {
            std::vector<crypto::secret_key> skeys;
            skeys.reserve(num_keys);
            for (std::size_t i{0}; i < num_keys; ++i) { skeys.emplace_back(rct::rct2sk(rct::skGen())); }
            return skeys;
        };

    const crypto::public_key Pk{rct::rct2pk(rct::pkGen())};
    const crypto::public_key gen_G{crypto::get_G()};
    const crypto::public_key gen_U{crypto::get_U()};

    // 0 keys
    EXPECT_ANY_THROW(sp::make_matrix_proof(rct::zero(), {}, make_keys(0), proof));
    EXPECT_ANY_THROW(sp::make_matrix_proof(rct::zero(), {gen_G, gen_G}, make_keys(0), proof));

    EXPECT_ANY_THROW(sp::make_matrix_proof(rct::zero(), {gen_G}, make_keys(0), proof));
    EXPECT_ANY_THROW(sp::make_matrix_proof(rct::zero(), {gen_G, gen_G}, make_keys(0), proof));

    // 1 key
    EXPECT_ANY_THROW(sp::make_matrix_proof(rct::zero(), {}, make_keys(1), proof));

    EXPECT_NO_THROW(sp::make_matrix_proof(rct::zero(), {gen_G}, make_keys(1), proof));  //base key: G
    EXPECT_TRUE(sp::verify_matrix_proof(proof, {gen_G}));

    EXPECT_NO_THROW(sp::make_matrix_proof(rct::zero(), {Pk}, make_keys(1), proof));  //base key: Pk
    EXPECT_TRUE(sp::verify_matrix_proof(proof, {Pk}));
    EXPECT_ANY_THROW(sp::verify_matrix_proof(proof, {gen_G, gen_U}));
    EXPECT_FALSE(sp::verify_matrix_proof(proof, {gen_G}));

    EXPECT_NO_THROW(sp::make_matrix_proof(rct::zero(), {gen_G, gen_G}, make_keys(1), proof));  //base keys: G, G
    EXPECT_TRUE(sp::verify_matrix_proof(proof, {gen_G, gen_G}));
    EXPECT_FALSE(sp::verify_matrix_proof(proof, {gen_G, gen_U}));
    EXPECT_FALSE(sp::verify_matrix_proof(proof, {gen_U, gen_G}));
    EXPECT_FALSE(sp::verify_matrix_proof(proof, {gen_U, gen_U}));

    // 2 keys
    EXPECT_NO_THROW(sp::make_matrix_proof(rct::zero(), {Pk}, make_keys(2), proof));  //base key: Pk
    EXPECT_TRUE(sp::verify_matrix_proof(proof, {Pk}));
    EXPECT_ANY_THROW(sp::verify_matrix_proof(proof, {gen_G, gen_U}));
    EXPECT_FALSE(sp::verify_matrix_proof(proof, {gen_G}));

    EXPECT_NO_THROW(sp::make_matrix_proof(rct::zero(), {gen_G, gen_G}, make_keys(2), proof));  //base keys: G, G
    EXPECT_TRUE(sp::verify_matrix_proof(proof, {gen_G, gen_G}));
    EXPECT_FALSE(sp::verify_matrix_proof(proof, {gen_G, gen_U}));
    EXPECT_FALSE(sp::verify_matrix_proof(proof, {gen_U, gen_G}));
    EXPECT_FALSE(sp::verify_matrix_proof(proof, {gen_U, gen_U}));

    EXPECT_NO_THROW(sp::make_matrix_proof(rct::zero(), {gen_G, gen_U}, make_keys(2), proof));  //base key: G, U
    EXPECT_TRUE(sp::verify_matrix_proof(proof, {gen_G, gen_U}));

    // U, G, 3 keys
    EXPECT_NO_THROW(sp::make_matrix_proof(rct::zero(), {gen_U, gen_G}, make_keys(3), proof));  //base keys: U, G
    EXPECT_TRUE(sp::verify_matrix_proof(proof, {gen_U, gen_G}));

    // U, U, 3 keys
    EXPECT_NO_THROW(sp::make_matrix_proof(rct::zero(), {gen_U, gen_U}, make_keys(3), proof));  //base keys: U, U
    EXPECT_TRUE(sp::verify_matrix_proof(proof, {gen_U, gen_U}));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_crypto, multiexp_utility)
{
    rct::key result;

    // {1 G} == G
    sp::SpMultiexpBuilder builder1{rct::identity(), 0, 0};
    builder1.add_G_element(rct::identity());

    sp::SpMultiexp{{builder1}}.get_result(result);
    ASSERT_TRUE(result == crypto::get_G());

    // {I + 1 G} == G
    sp::SpMultiexpBuilder builder2{rct::identity(), 0, 1};
    builder2.add_element(rct::identity(), rct::identity());
    builder2.add_G_element(rct::identity());

    sp::SpMultiexp{{builder2}}.get_result(result);
    ASSERT_TRUE(result == crypto::get_G());

    // {1 G + I} == G
    sp::SpMultiexpBuilder builder3{rct::identity(), 0, 1};
    builder3.add_G_element(rct::identity());
    builder3.add_element(rct::identity(), rct::identity());

    sp::SpMultiexp{{builder3}}.get_result(result);
    ASSERT_TRUE(result == crypto::get_G());

    // {1 G + 1 G} == 2 G
    sp::SpMultiexpBuilder builder4{rct::identity(), 0, 0};
    std::vector<rct::MultiexpData> rct_builder4;
    builder4.add_G_element(rct::identity());
    rct_builder4.emplace_back(rct::identity(), crypto::get_G_p3());
    builder4.add_G_element(rct::identity());
    rct_builder4.emplace_back(rct::identity(), crypto::get_G_p3());

    sp::SpMultiexp{{builder4}}.get_result(result);
    ASSERT_TRUE(result == rct::pippenger(rct_builder4));

    // {1 G + 2 H + 3 U + 4 X} == G + H + U + X
    sp::SpMultiexpBuilder builder5{rct::identity(), 0, 0};
    std::vector<rct::MultiexpData> rct_builder5;
    rct::key temp_int_5{rct::identity()};
    builder5.add_G_element(temp_int_5);
    rct_builder5.emplace_back(temp_int_5, crypto::get_G_p3());
    sc_add(temp_int_5.bytes, temp_int_5.bytes, rct::identity().bytes);
    builder5.add_H_element(temp_int_5);
    rct_builder5.emplace_back(temp_int_5, crypto::get_H_p3());
    sc_add(temp_int_5.bytes, temp_int_5.bytes, rct::identity().bytes);
    builder5.add_U_element(temp_int_5);
    rct_builder5.emplace_back(temp_int_5, crypto::get_U_p3());
    sc_add(temp_int_5.bytes, temp_int_5.bytes, rct::identity().bytes);
    builder5.add_X_element(temp_int_5);
    rct_builder5.emplace_back(temp_int_5, crypto::get_X_p3());

    sp::SpMultiexp{{builder5}}.get_result(result);
    ASSERT_TRUE(result == rct::pippenger(rct_builder5));

    // {1 G + 1 P} == G + P
    sp::SpMultiexpBuilder builder6{rct::identity(), 0, 1};
    std::vector<rct::MultiexpData> rct_builder6;
    builder6.add_G_element(rct::identity());
    rct_builder6.emplace_back(rct::identity(), crypto::get_G_p3());
    rct::key temp_pk6{rct::pkGen()};
    builder6.add_element(rct::identity(), temp_pk6);
    rct_builder6.emplace_back(rct::identity(), temp_pk6);

    sp::SpMultiexp{{builder6}}.get_result(result);
    ASSERT_TRUE(result == rct::pippenger(rct_builder6));

    // {x G} == x G
    sp::SpMultiexpBuilder builder7{rct::identity(), 0, 0};
    std::vector<rct::MultiexpData> rct_builder7;
    rct::key temp_sk7{rct::skGen()};
    builder7.add_G_element(temp_sk7);
    rct_builder7.emplace_back(temp_sk7, crypto::get_G_p3());

    sp::SpMultiexp{{builder7}}.get_result(result);
    ASSERT_TRUE(result == rct::pippenger(rct_builder7));

    // {x G + y P} == x G + y P
    sp::SpMultiexpBuilder builder8{rct::identity(), 0, 1};
    std::vector<rct::MultiexpData> rct_builder8;
    rct::key temp_sk8_1{rct::skGen()};
    rct::key temp_sk8_2{rct::skGen()};
    rct::key temp_pk8{rct::pkGen()};
    builder8.add_G_element(temp_sk8_1);
    rct_builder8.emplace_back(temp_sk8_1, crypto::get_G_p3());
    builder8.add_element(temp_sk8_2, temp_pk8);
    rct_builder8.emplace_back(temp_sk8_2, temp_pk8);

    sp::SpMultiexp{{builder8}}.get_result(result);
    ASSERT_TRUE(result == rct::pippenger(rct_builder8));

    // {x G + y G[0] + z G[1]} == x G + y G[0] + z G[1]
    sp::SpMultiexpBuilder builder9{rct::identity(), 2, 0};
    std::vector<rct::MultiexpData> rct_builder9;
    rct::key temp_sk9_1{rct::skGen()};
    rct::key temp_sk9_2{rct::skGen()};
    rct::key temp_sk9_3{rct::skGen()};
    builder9.add_G_element(temp_sk9_1);
    rct_builder9.emplace_back(temp_sk9_1, crypto::get_G_p3());
    builder9.add_element_at_generator_index(temp_sk9_2, 0);
    rct_builder9.emplace_back(temp_sk9_2, rct::pk2rct(sp::generator_factory::get_generator_at_index(0)));
    builder9.add_element_at_generator_index(temp_sk9_3, 1);
    rct_builder9.emplace_back(temp_sk9_3, rct::pk2rct(sp::generator_factory::get_generator_at_index(1)));

    sp::SpMultiexp{{builder9}}.get_result(result);
    ASSERT_TRUE(result == rct::pippenger(rct_builder9));

    // w * {x P1 + y P2} == w*(x P1 + y P2)
    rct::key weight{rct::skGen()};
    sp::SpMultiexpBuilder builder10{weight, 0, 1};
    std::vector<rct::MultiexpData> rct_builder10;
    rct::key temp_sk10_1{rct::skGen()};
    rct::key temp_sk10_2{rct::skGen()};
    rct::key temp_pk10_1{rct::pkGen()};
    rct::key temp_pk10_2{rct::pkGen()};
    builder10.add_element(temp_sk10_1, temp_pk10_1);
    rct_builder10.emplace_back(temp_sk10_1, temp_pk10_1);
    builder10.add_element(temp_sk10_2, temp_pk10_2);
    rct_builder10.emplace_back(temp_sk10_2, temp_pk10_2);

    sp::SpMultiexp{{builder10}}.get_result(result);
    ASSERT_TRUE(result == rct::scalarmultKey(rct::pippenger(rct_builder10), weight));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_crypto, eclib_test)
{
    using eclib = crypto::eclib_test;

    const eclib::key constant{20};
    eclib::key temp;

    eclib::core_func(constant, temp);
    EXPECT_TRUE(temp == 200);
    eclib::utils::util_func(constant, temp);
    EXPECT_TRUE(temp == 40);
}
//-------------------------------------------------------------------------------------------------------------------
