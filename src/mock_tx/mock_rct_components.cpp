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
#include "mock_rct_components.h"

//local headers
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "device/device.hpp"
#include "misc_log_ex.h"
#include "mock_rct_base.h"
#include "mock_tx_utils.h"
#include "ringct/bulletproofs_plus.h"
#include "ringct/rctOps.h"
#include "ringct/rctSigs.h"
#include "ringct/rctTypes.h"
#include "ringct/triptych.h"

//third party headers

//standard headers
#include <memory>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "mock_tx"

namespace mock_tx
{
//-------------------------------------------------------------------------------------------------------------------
void MockENoteRctV1::make_v1(const crypto::secret_key &onetime_privkey,
    const crypto::secret_key &amount_blinding_factor,
    const rct::xmr_amount amount)
{
    // make base of enote
    this->make_base(onetime_privkey, amount_blinding_factor, amount);

    // memo: random
    m_enote_pubkey = rct::rct2pk(rct::pkGen());
    m_encoded_amount = rct::randXmrAmount(rct::xmr_amount{static_cast<rct::xmr_amount>(-1)});
}
//-------------------------------------------------------------------------------------------------------------------
void MockENoteRctV1::gen_v1()
{
    // gen base of enote
    this->gen_base();

    // memo: random
    m_enote_pubkey = rct::rct2pk(rct::pkGen());
    m_encoded_amount = rct::randXmrAmount(rct::xmr_amount{static_cast<rct::xmr_amount>(-1)});
}
//-------------------------------------------------------------------------------------------------------------------
MockENoteImageRctV1 MockInputRctV1::to_enote_image_v1(const crypto::secret_key &pseudo_blinding_factor) const
{
    MockENoteImageRctV1 image;

    // C' = x' G + a H
    image.m_pseudo_amount_commitment = rct::rct2pk(rct::commit(m_amount, rct::sk2rct(pseudo_blinding_factor)));

    // KI = ko * Hp(Ko)
    crypto::public_key pubkey;
    CHECK_AND_ASSERT_THROW_MES(crypto::secret_key_to_public_key(m_onetime_privkey, pubkey), "Failed to derive public key");
    crypto::generate_key_image(pubkey, m_onetime_privkey, image.m_key_image);

    // KI_stored = (1/8)*KI
    // - for efficiently checking that the key image is in the prime subgroup during tx verification
    rct::key storable_ki;
    rct::scalarmultKey(storable_ki, rct::ki2rct(image.m_key_image), rct::INV_EIGHT);
    image.m_key_image = rct::rct2ki(storable_ki);

    return image;
}
MockENoteImageRctV1 MockInputRctV1::to_enote_image_v2(const crypto::secret_key &pseudo_blinding_factor) const
{
    MockENoteImageRctV1 image;

    // C' = x' G + a H
    image.m_pseudo_amount_commitment = rct::rct2pk(rct::commit(m_amount, rct::sk2rct(pseudo_blinding_factor)));

    // KI = 1/ko * U
    rct::key inv_ko{rct::invert(rct::sk2rct(m_onetime_privkey))};
    rct::key key_image{rct::scalarmultKey(rct::get_gen_U(), inv_ko)};

    // KI_stored = (1/8)*KI
    // - for efficiently checking that the key image is in the prime subgroup during tx verification
    rct::key storable_ki;
    rct::scalarmultKey(storable_ki, key_image, rct::INV_EIGHT);
    image.m_key_image = rct::rct2ki(storable_ki);

    return image;
}
//-------------------------------------------------------------------------------------------------------------------
void MockInputRctV1::gen_v1(const rct::xmr_amount amount, const std::size_t ref_set_size)
{
    // \pi = rand()
    m_input_ref_set_real_index = crypto::rand_idx(ref_set_size);

    // prep real input
    m_onetime_privkey = rct::rct2sk(rct::skGen());
    m_amount_blinding_factor = rct::rct2sk(rct::skGen());
    m_amount = amount;

    // construct reference set
    m_input_ref_set.resize(ref_set_size);

    for (std::size_t ref_index{0}; ref_index < ref_set_size; ++ref_index)
    {
        // insert real input at \pi
        if (ref_index == m_input_ref_set_real_index)
        {
            // make an enote at m_input_ref_set[ref_index]
            m_input_ref_set[ref_index].make_v1(m_onetime_privkey,
                    m_amount_blinding_factor,
                    m_amount);
        }
        // add random enote
        else
        {
            // generate a random enote at m_input_ref_set[ref_index]
            m_input_ref_set[ref_index].gen_v1();
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
MockENoteRctV1 MockDestRctV1::to_enote_v1() const
{
    MockENoteRctV1 enote;
    MockDestRct::to_enote_rct_base(enote);

    return enote;
}
//-------------------------------------------------------------------------------------------------------------------
void MockDestRctV1::gen_v1(const rct::xmr_amount amount)
{
    // gen base of dest
    this->gen_base(amount);

    // memo parts: random
    m_enote_pubkey = rct::rct2pk(rct::pkGen());
    m_encoded_amount = rct::randXmrAmount(rct::xmr_amount{static_cast<rct::xmr_amount>(-1)});
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t MockRctProofV1::get_size_bytes() const
{
    // note: ignore the key image stored in the clsag, it is double counted by the input's enote image struct
    return 32 * (2 + m_clsag_proof.s.size());
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t MockRctProofV2::get_size_bytes() const
{
    // note: ignore the key image stored in the Triptych proof, it is double counted by the input's enote image struct
    return 32 * (8 + m_triptych_proof.X.size() + m_triptych_proof.Y.size() + m_ref_set_decomp_n * m_ref_set_decomp_m);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t MockRctBalanceProofV1::get_size_bytes() const
{
    // note: ignore the amount commitment set stored in the range proofs, they are double counted by the output set
    std::size_t size{0};

    for (const auto &proof : m_bpp_proofs)
        size += 32 * (6 + proof.L.size() + proof.R.size());;

    return size;
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<MockInputRctV1> gen_mock_rct_inputs_v1(const std::vector<rct::xmr_amount> &amounts,
    const std::size_t ref_set_size)
{
    CHECK_AND_ASSERT_THROW_MES(ref_set_size > 0, "Tried to create inputs with no ref set size.");

    std::vector<MockInputRctV1> inputs;

    if (amounts.size() > 0)
    {
        inputs.resize(amounts.size());

        for (std::size_t input_index{0}; input_index < amounts.size(); ++input_index)
        {
            inputs[input_index].gen_v1(amounts[input_index], ref_set_size);
        }
    }

    return inputs;
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<MockDestRctV1> gen_mock_rct_dests_v1(const std::vector<rct::xmr_amount> &amounts)
{
    std::vector<MockDestRctV1> destinations;

    if (amounts.size() > 0)
    {
        destinations.resize(amounts.size());

        for (std::size_t dest_index{0}; dest_index < amounts.size(); ++dest_index)
        {
            destinations[dest_index].gen_v1(amounts[dest_index]);
        }
    }

    return destinations;
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<crypto::secret_key> get_rct_pseudo_blinding_factors_v1(const std::size_t num_factors,
    const std::vector<rct::key> &output_amount_commitment_blinding_factors)
{
    CHECK_AND_ASSERT_THROW_MES(num_factors > 0, "There must be > 0 pseudo amount commitments.");

    std::vector<crypto::secret_key> pseudo_blinding_factors;
    pseudo_blinding_factors.reserve(num_factors);

    // add together output blinding factors
    crypto::secret_key sum_output_blinding_factors = rct::rct2sk(rct::zero());

    for (const auto &y : output_amount_commitment_blinding_factors)
        sc_add(&sum_output_blinding_factors, &sum_output_blinding_factors, y.bytes);

    // all but last blinding factor are random
    for (std::size_t factor_index{0}; factor_index + 1 < num_factors; ++factor_index)
    {
        crypto::secret_key pseudo_blinding_factor{rct::rct2sk(rct::skGen())};

        // subtract blinding factor from sum
        sc_sub(&sum_output_blinding_factors, &sum_output_blinding_factors, &pseudo_blinding_factor);

        // save input's pseudo amount commitment blinding factor
        pseudo_blinding_factors.emplace_back(pseudo_blinding_factor);
    }

    // set last pseudo blinding factor equal to
    //    sum(output blinding factors) - sum(input image blinding factors)_except_last
    pseudo_blinding_factors.emplace_back(sum_output_blinding_factors);

    return pseudo_blinding_factors;
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_outputs_rct_v1(const std::vector<MockDestRctV1> &destinations,
    std::vector<MockENoteRctV1> &outputs_out,
    std::vector<rct::xmr_amount> &output_amounts_out,
    std::vector<rct::key> &output_amount_commitment_blinding_factors_out)
{
    // note: blinding factors need to balance for balance proof
    outputs_out.clear();
    outputs_out.reserve(destinations.size());;
    output_amounts_out.clear();
    output_amounts_out.reserve(destinations.size());
    output_amount_commitment_blinding_factors_out.clear();
    output_amount_commitment_blinding_factors_out.reserve(destinations.size());

    for (const auto &dest : destinations)
    {
        // build output set
        outputs_out.emplace_back(dest.to_enote_v1());

        // prepare for range proofs
        output_amounts_out.emplace_back(dest.m_amount);
        output_amount_commitment_blinding_factors_out.emplace_back(rct::sk2rct(dest.m_amount_blinding_factor));
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_images_rct_v1(const std::vector<MockInputRctV1> &inputs_to_spend,
    const std::vector<rct::key> &output_amount_commitment_blinding_factors,
    std::vector<MockENoteImageRctV1> &input_images_out,
    std::vector<crypto::secret_key> &pseudo_blinding_factors_out)
{
    input_images_out.clear();
    input_images_out.reserve(inputs_to_spend.size());
    pseudo_blinding_factors_out.clear();

    // get pseudo blinding factors: last factor = sum(output factors) - sum(pseudo factors)_except_last
    pseudo_blinding_factors_out = 
        get_rct_pseudo_blinding_factors_v1(inputs_to_spend.size(), output_amount_commitment_blinding_factors);

    CHECK_AND_ASSERT_THROW_MES(pseudo_blinding_factors_out.size() == inputs_to_spend.size(), "Vector size mismatch.");

    // create images with CLSAG style
    for (std::size_t input_index{0}; input_index < inputs_to_spend.size(); ++input_index)
    {
        input_images_out.emplace_back(
                inputs_to_spend[input_index].to_enote_image_v1(pseudo_blinding_factors_out[input_index])
            );
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_images_rct_v2(const std::vector<MockInputRctV1> &inputs_to_spend,
    const std::vector<rct::key> &output_amount_commitment_blinding_factors,
    std::vector<MockENoteImageRctV1> &input_images_out,
    std::vector<crypto::secret_key> &pseudo_blinding_factors_out)
{
    input_images_out.clear();
    input_images_out.reserve(inputs_to_spend.size());
    pseudo_blinding_factors_out.clear();

    // get pseudo blinding factors: last factor = sum(output factors) - sum(pseudo factors)_except_last
    pseudo_blinding_factors_out = 
        get_rct_pseudo_blinding_factors_v1(inputs_to_spend.size(), output_amount_commitment_blinding_factors);

    CHECK_AND_ASSERT_THROW_MES(pseudo_blinding_factors_out.size() == inputs_to_spend.size(), "Vector size mismatch.");

    // construct images with Triptych style
    for (std::size_t input_index{0}; input_index < inputs_to_spend.size(); ++input_index)
    {
        input_images_out.emplace_back(
                inputs_to_spend[input_index].to_enote_image_v2(pseudo_blinding_factors_out[input_index])
            );
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_input_proofs_rct_v1(const std::vector<MockInputRctV1> &inputs_to_spend,
    const std::vector<crypto::secret_key> &pseudo_blinding_factors,
    std::vector<MockRctProofV1> &proofs_out)
{
    // membership + ownership/unspentness proofs
    // - clsag for each input
    for (std::size_t input_index{0}; input_index < inputs_to_spend.size(); ++input_index)
    {
        // convert tx info to form expected by proveRctCLSAGSimple()
        rct::ctkeyV referenced_enotes_converted;
        rct::ctkey spent_enote_converted;
        referenced_enotes_converted.reserve(inputs_to_spend[0].m_input_ref_set.size());

        // vector of pairs <onetime addr, amount commitment>
        for (const auto &input_ref : inputs_to_spend[input_index].m_input_ref_set)
            referenced_enotes_converted.emplace_back(rct::ctkey{rct::pk2rct(input_ref.m_onetime_address),
                rct::pk2rct(input_ref.m_amount_commitment)});

        // spent enote privkeys <ko, x>
        spent_enote_converted.dest = rct::sk2rct(inputs_to_spend[input_index].m_onetime_privkey);
        spent_enote_converted.mask = rct::sk2rct(inputs_to_spend[input_index].m_amount_blinding_factor);

        // create CLSAG proof and save it
        MockRctProofV1 mock_clsag_proof;
        mock_clsag_proof.m_clsag_proof = rct::proveRctCLSAGSimple(
                rct::zero(),                  // empty message for mockup
                referenced_enotes_converted,  // vector of pairs <Ko_i, C_i> for referenced enotes
                spent_enote_converted,        // pair <ko, x> for input's onetime privkey and amount blinding factor
                rct::sk2rct(pseudo_blinding_factors[input_index]),       // pseudo-output blinding factor x'
                rct::commit(inputs_to_spend[input_index].m_amount, rct::sk2rct(pseudo_blinding_factors[input_index])),  // pseudo-output commitment C'
                nullptr, nullptr, nullptr,    // no multisig
                inputs_to_spend[input_index].m_input_ref_set_real_index,  // real index in input set
                hw::get_device("default")
            );

        mock_clsag_proof.m_referenced_enotes_converted = std::move(referenced_enotes_converted);

        proofs_out.emplace_back(mock_clsag_proof);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v2_tx_input_proofs_rct_v1(const std::vector<MockInputRctV1> &inputs_to_spend,
    const std::vector<MockENoteImageRctV1> &input_images,
    const std::vector<crypto::secret_key> &pseudo_blinding_factors,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    std::vector<MockRctProofV2> &proofs_out)
{
    // membership + ownership/unspentness proofs
    // - Triptych for each input
    for (std::size_t input_index{0}; input_index < inputs_to_spend.size(); ++input_index)
    {
        CHECK_AND_ASSERT_THROW_MES(ref_set_size_from_decomp(ref_set_decomp_n, ref_set_decomp_m) ==
                    inputs_to_spend[input_index].m_input_ref_set.size(),
                "Decomposition factors don't match ref set size."
            );

        CHECK_AND_ASSERT_THROW_MES(inputs_to_spend[input_index].m_input_ref_set_real_index <
                    inputs_to_spend[input_index].m_input_ref_set.size(),
                "Real proof index out of bounds."
            );

        MockRctProofV2 mock_Triptych_proof;

        // convert tx info to form expected by triptych_prove()
        mock_Triptych_proof.m_onetime_addresses.reserve(inputs_to_spend[input_index].m_input_ref_set.size());
        mock_Triptych_proof.m_commitments.reserve(inputs_to_spend[input_index].m_input_ref_set.size());

        for (const auto &input_ref : inputs_to_spend[input_index].m_input_ref_set)
        {
            mock_Triptych_proof.m_onetime_addresses.emplace_back(rct::pk2rct(input_ref.m_onetime_address));
            mock_Triptych_proof.m_commitments.emplace_back(rct::pk2rct(input_ref.m_amount_commitment));
        }

        mock_Triptych_proof.m_pseudo_amount_commitment = rct::pk2rct(input_images[input_index].m_pseudo_amount_commitment);

        // commitment to zero privkey: C - C' = (x - x')*G
        rct::key c_to_zero_privkey;
        sc_sub(c_to_zero_privkey.bytes,
            &(inputs_to_spend[input_index].m_amount_blinding_factor),
            &(pseudo_blinding_factors[input_index]));

        // decomposition, ref set size: n^m
        mock_Triptych_proof.m_ref_set_decomp_n = ref_set_decomp_n;
        mock_Triptych_proof.m_ref_set_decomp_m = ref_set_decomp_m;

        // create Triptych proof
        mock_Triptych_proof.m_triptych_proof = rct::triptych_prove(
                mock_Triptych_proof.m_onetime_addresses,                     // one-time pubkeys Ko
                mock_Triptych_proof.m_commitments,                           // output commitments C
                mock_Triptych_proof.m_pseudo_amount_commitment,              // pseudo-output commitment C'
                inputs_to_spend[input_index].m_input_ref_set_real_index,     // real spend index \pi
                rct::sk2rct(inputs_to_spend[input_index].m_onetime_privkey), // one-time privkey ko
                c_to_zero_privkey,                                           // commitment to zero blinding factor (x - x')
                mock_Triptych_proof.m_ref_set_decomp_n,                      // decomp n
                mock_Triptych_proof.m_ref_set_decomp_m,                      // decomp m
                rct::zero()                                                  // empty message for mockup
            );

        proofs_out.emplace_back(std::move(mock_Triptych_proof));
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_balance_proof_rct_v1(const std::vector<rct::xmr_amount> &output_amounts,
    const std::vector<rct::key> &amount_commitment_blinding_factors,
    const std::size_t max_rangeproof_splits,
    std::shared_ptr<MockRctBalanceProofV1> &balance_proof_out)
{
    if (balance_proof_out.get() == nullptr)
        balance_proof_out = std::make_shared<MockRctBalanceProofV1>();

    // make range proofs (punt to BP+ builder)
    std::vector<rct::BulletproofPlus> range_proofs;

    make_bpp_rangeproofs(output_amounts,
        amount_commitment_blinding_factors,
        max_rangeproof_splits,
        range_proofs);

    balance_proof_out->m_bpp_proofs = std::move(range_proofs);
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_mock_tx_rct_semantics_component_counts_v1(const std::size_t num_input_proofs,
        const std::size_t num_input_images,
        const std::size_t num_outputs,
        const std::shared_ptr<MockRctBalanceProofV1> &balance_proof)
{
    CHECK_AND_ASSERT_THROW_MES(num_input_proofs > 0, "Tried to validate tx that has no input proofs.");
    CHECK_AND_ASSERT_THROW_MES(num_input_images > 0, "Tried to validate tx that has no input images.");
    CHECK_AND_ASSERT_THROW_MES(num_outputs > 0, "Tried to validate tx that has no outputs.");
    CHECK_AND_ASSERT_THROW_MES(balance_proof.get() != nullptr, "Tried to validate tx that has no balance.");
    CHECK_AND_ASSERT_THROW_MES(balance_proof->m_bpp_proofs.size() > 0, "Tried to validate tx that has no range proofs.");
    CHECK_AND_ASSERT_THROW_MES(balance_proof->m_bpp_proofs[0].V.size() > 0, "Tried to validate tx that has no range proofs.");

    // input proofs
    if (num_input_proofs != num_input_images)
        return false;

    // range proofs: must be one range-proofed commitment per output
    std::size_t num_rangeproofed_commitments{0};

    for (const auto &range_proof : balance_proof->m_bpp_proofs)
        num_rangeproofed_commitments += range_proof.V.size();

    if (num_rangeproofed_commitments != num_outputs)
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_mock_tx_rct_semantics_ref_set_size_v1(const std::vector<MockRctProofV1> &tx_proofs,
    const std::size_t ref_set_size)
{
    // all proofs must have same ref set size
    for (const auto &tx_proof : tx_proofs)
    {
        if (tx_proof.m_referenced_enotes_converted.size() != ref_set_size)
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_mock_tx_rct_semantics_ref_set_size_v2(const std::vector<MockRctProofV2> &tx_proofs,
        const std::size_t ref_set_decomp_n,
        const std::size_t ref_set_decomp_m)
{
    std::size_t ref_set_size{ref_set_size_from_decomp(ref_set_decomp_n, ref_set_decomp_m)};

    // all proofs must have the same decomposition: ref set size = n^m
    for (const auto &tx_proof : tx_proofs)
    {
        if (tx_proof.m_ref_set_decomp_n != ref_set_decomp_n ||
            tx_proof.m_ref_set_decomp_m != ref_set_decomp_m ||
            tx_proof.m_onetime_addresses.size() != ref_set_size ||
            tx_proof.m_commitments.size() != ref_set_size)
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_mock_tx_rct_semantics_linking_tags_v1(const std::vector<MockENoteImageRctV1> input_images,
    const std::vector<MockRctProofV1> tx_proofs)
{
    // sanity check
    if (input_images.size() != tx_proofs.size())
        return false;

    // input linking tags must be in the prime subgroup: KI = 8*[(1/8) * KI]
    // note: I cheat a bit here for the mock-up. The linking tags in the clsag_proof are not mul(1/8), but the
    //       tags in input images are.
    for (std::size_t input_index{0}; input_index < input_images.size(); ++input_index)
    {
        if (!(rct::scalarmult8(rct::ki2rct(input_images[input_index].m_key_image)) ==
                tx_proofs[input_index].m_clsag_proof.I))
            return false;

        // sanity check
        if (tx_proofs[input_index].m_clsag_proof.I == rct::identity())
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_mock_tx_rct_semantics_linking_tags_v2(const std::vector<MockENoteImageRctV1> input_images,
    const std::vector<MockRctProofV2> tx_proofs)
{
    // sanity check
    if (input_images.size() != tx_proofs.size())
        return false;

    // input linking tags must be in the prime subgroup: KI = 8*[(1/8) * KI]
    // note: I cheat a bit here for the mock-up. The linking tags in the Triptych_proof are not mul(1/8), but the
    //       tags in m_input_images are.
    for (std::size_t input_index{0}; input_index < input_images.size(); ++input_index)
    {
        if (!(rct::scalarmult8(rct::ki2rct(input_images[input_index].m_key_image)) ==
                tx_proofs[input_index].m_triptych_proof.J))
            return false;

        // sanity check
        if (tx_proofs[input_index].m_triptych_proof.J == rct::identity())
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_mock_tx_rct_linking_tags_v1(const std::vector<MockRctProofV1> &proofs,
    const std::vector<MockENoteImageRctV1> &images)
{
    // input linking tags must not exist in the blockchain
    //not implemented for mockup

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_mock_tx_rct_linking_tags_v2(const std::vector<MockRctProofV2> &proofs,
    const std::vector<MockENoteImageRctV1> &images)
{
    // input linking tags must not exist in the blockchain
    //not implemented for mockup

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_mock_tx_rct_amount_balance_v1(const std::vector<MockENoteImageRctV1> &images,
    const std::vector<MockENoteRctV1> &outputs,
    const std::shared_ptr<MockRctBalanceProofV1> balance_proof,
    const bool defer_batchable)
{
    if (balance_proof.get() == nullptr)
        return false;

    const std::vector<rct::BulletproofPlus> &range_proofs = balance_proof->m_bpp_proofs;

    // sanity check
    if (range_proofs.size() == 0)
        return false;

    // check that amount commitments balance
    rct::keyV pseudo_commitments;
    rct::keyV output_commitments;
    pseudo_commitments.reserve(images.size());
    output_commitments.reserve(outputs.size());

    for (const auto &input_image : images)
        pseudo_commitments.emplace_back(rct::pk2rct(input_image.m_pseudo_amount_commitment));

    std::size_t range_proof_index{0};
    std::size_t range_proof_grouping_size = range_proofs[0].V.size();

    for (std::size_t output_index{0}; output_index < outputs.size(); ++output_index)
    {
        output_commitments.emplace_back(rct::pk2rct(outputs[output_index].m_amount_commitment));

        // assume range proofs are partitioned into groups of size 'range_proof_grouping_size' (except last one)
        if (range_proofs[range_proof_index].V.size() == output_index - range_proof_index*range_proof_grouping_size)
            ++range_proof_index;

        // sanity checks
        if (range_proofs.size() <= range_proof_index)
            return false;
        if (range_proofs[range_proof_index].V.size() <= output_index - range_proof_index*range_proof_grouping_size)
            return false;

        // double check that the two stored copies of output commitments match
        if (outputs[output_index].m_amount_commitment !=
                rct::rct2pk(rct::scalarmult8(range_proofs[range_proof_index].V[output_index -
                    range_proof_index*range_proof_grouping_size])))
            return false;
    }

    // sum(pseudo output commitments) ?= sum(output commitments)
    if (!balance_check_equality(pseudo_commitments, output_commitments))
        return false;

    // range proofs must be valid
    if (!defer_batchable)
    {
        std::vector<const rct::BulletproofPlus*> range_proof_ptrs;
        range_proof_ptrs.reserve(range_proofs.size());

        for (const auto &range_proof : range_proofs)
            range_proof_ptrs.push_back(&range_proof);

        if (!rct::bulletproof_plus_VERIFY(range_proof_ptrs))
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_mock_tx_rct_proofs_v1(const std::vector<MockRctProofV1> &proofs,
    const std::vector<MockENoteImageRctV1> &images)
{
    // verify membership/ownership/unspentness proofs
    for (std::size_t input_index{0}; input_index < images.size(); ++input_index)
    {
        if (!rct::verRctCLSAGSimple(rct::zero(),  // empty message for mockup
                proofs[input_index].m_clsag_proof,
                proofs[input_index].m_referenced_enotes_converted,
                rct::pk2rct(images[input_index].m_pseudo_amount_commitment)))
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_mock_tx_rct_proofs_v2(const std::vector<MockRctProofV2> &proofs)
{
    // verify input membership/ownership/unspentness proofs
    for (std::size_t input_index{0}; input_index < proofs.size(); ++input_index)
    {
        std::vector<const rct::TriptychProof*> proof;
        proof.emplace_back(&(proofs[input_index].m_triptych_proof));

        // note: only verify one triptych proof at a time (not batchable in my approach where all inputs define separate rings)
        if (!rct::triptych_verify(
                proofs[input_index].m_onetime_addresses,
                proofs[input_index].m_commitments,
                rct::keyV{proofs[input_index].m_pseudo_amount_commitment},
                proof,
                proofs[input_index].m_ref_set_decomp_n,
                proofs[input_index].m_ref_set_decomp_m,
                rct::keyV{rct::zero()}))  // empty message for mockup
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace mock_tx
