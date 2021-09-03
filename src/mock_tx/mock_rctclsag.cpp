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

//paired header
#include "mock_rctclsag.h"

//local headers
#include "crypto/crypto.h"
#include "crypto/crypto-ops.h"
#include "device/device.hpp"
#include "ringct/multiexp.h"
#include "ringct/bulletproofs_plus.h"
#include "ringct/rctOps.h"
#include "ringct/rctSigs.h"
#include "ringct/rctTypes.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <memory>
#include <vector>


//-----------------------------------------------------------------
// type conversions for easier calls to sc_add(), sc_sub()
static inline unsigned char *operator &(crypto::ec_scalar &scalar)
{
    return &reinterpret_cast<unsigned char &>(scalar);
}
//-----------------------------------------------------------------
static inline const unsigned char *operator &(const crypto::ec_scalar &scalar)
{
    return &reinterpret_cast<const unsigned char &>(scalar);
}
//-----------------------------------------------------------------
namespace mock_tx
{
//-----------------------------------------------------------------
bool balance_check(const rct::keyV &commitment_set1, const rct::keyV &commitment_set2)
{
    // balance check method chosen from perf test: tests/performance_tests/balance_check.h
    return rct::equalKeys(rct::addKeys(commitment_set1), rct::addKeys(commitment_set2));
}
//-----------------------------------------------------------------
MockCLSAGENoteImage MockTxCLSAGInput::to_enote_image(const crypto::secret_key &pseudo_blinding_factor) const
{
    MockCLSAGENoteImage image;

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
//-----------------------------------------------------------------
MockCLSAGENote MockTxCLSAGDest::to_enote() const
{
    MockCLSAGENote enote;

    enote.m_enote_pubkey = m_enote_pubkey;
    enote.m_encoded_amount = m_encoded_amount;
    enote.m_onetime_address = m_onetime_address;

    // C = x G + a H
    enote.m_amount_commitment = rct::rct2pk(rct::commit(m_amount, rct::sk2rct(m_amount_blinding_factor)));

    return enote;
}
//-----------------------------------------------------------------
MockCLSAGENote make_mock_tx_clsag_enote(const crypto::secret_key &onetime_privkey,
    const crypto::secret_key &amount_blinding_factor, const rct::xmr_amount amount)
{
    MockCLSAGENote enote;

    // Ko = ko G
    CHECK_AND_ASSERT_THROW_MES(crypto::secret_key_to_public_key(onetime_privkey, enote.m_onetime_address),
        "Failed to derive public key");

    // C = x G + a H
    enote.m_amount_commitment = rct::rct2pk(rct::commit(amount, rct::sk2rct(amount_blinding_factor)));

    // memo: random
    enote.m_enote_pubkey = rct::rct2pk(rct::pkGen());
    enote.m_encoded_amount = rct::randXmrAmount(rct::xmr_amount{static_cast<rct::xmr_amount>(-1)});

    return enote;
}
//-----------------------------------------------------------------
MockCLSAGENote gen_mock_tx_clsag_enote()
{
    MockCLSAGENote enote;

    // all random
    enote.m_onetime_address = rct::rct2pk(rct::pkGen());
    enote.m_amount_commitment = rct::rct2pk(rct::pkGen());
    enote.m_enote_pubkey = rct::rct2pk(rct::pkGen());
    enote.m_encoded_amount = rct::randXmrAmount(rct::xmr_amount{static_cast<rct::xmr_amount>(-1)});

    return enote;
}
//-----------------------------------------------------------------
std::vector<MockTxCLSAGInput> gen_mock_tx_clsag_inputs(const std::vector<rct::xmr_amount> &amounts,
    const std::size_t ref_set_size)
{
    CHECK_AND_ASSERT_THROW_MES(ref_set_size > 0, "Tried to create inputs with no ref set size.");

    std::vector<MockTxCLSAGInput> inputs;

    if (amounts.size() > 0)
    {
        inputs.resize(amounts.size());

        for (std::size_t input_index{0}; input_index < amounts.size(); ++input_index)
        {
            // \pi = rand()
            inputs[input_index].m_input_ref_set_real_index = crypto::rand_idx(ref_set_size);

            // prep real input
            inputs[input_index].m_onetime_privkey = rct::rct2sk(rct::skGen());
            inputs[input_index].m_amount_blinding_factor = rct::rct2sk(rct::skGen());
            inputs[input_index].m_amount = amounts[input_index];

            // construct reference set
            inputs[input_index].m_input_ref_set.reserve(ref_set_size);

            for (std::size_t ref_index{0}; ref_index < ref_set_size; ++ref_index)
            {
                // insert real input at \pi
                if (ref_index == inputs[input_index].m_input_ref_set_real_index)
                {
                    inputs[input_index].m_input_ref_set.emplace_back(
                            make_mock_tx_clsag_enote(inputs[input_index].m_onetime_privkey,
                                    inputs[input_index].m_amount_blinding_factor,
                                    inputs[input_index].m_amount)
                        );
                }
                // add random enote
                else
                {
                    inputs[input_index].m_input_ref_set.emplace_back(gen_mock_tx_clsag_enote());
                }
            }
        }
    }

    return inputs;
}
//-----------------------------------------------------------------
std::vector<MockTxCLSAGDest> gen_mock_tx_clsag_dests(const std::vector<rct::xmr_amount> &amounts)
{
    std::vector<MockTxCLSAGDest> destinations;

    if (amounts.size() > 0)
    {
        destinations.resize(amounts.size());

        for (std::size_t dest_index{0}; dest_index < amounts.size(); ++dest_index)
        {
            // all random except amount
            destinations[dest_index].m_onetime_address = rct::rct2pk(rct::pkGen());
            destinations[dest_index].m_amount_blinding_factor = rct::rct2sk(rct::skGen());
            destinations[dest_index].m_amount = amounts[dest_index];
            destinations[dest_index].m_enote_pubkey = rct::rct2pk(rct::pkGen());
            destinations[dest_index].m_encoded_amount = rct::randXmrAmount(rct::xmr_amount{static_cast<rct::xmr_amount>(-1)});
        }
    }

    return destinations;
}
//-----------------------------------------------------------------
MockTxCLSAG::MockTxCLSAG(const std::vector<MockTxCLSAGInput> &inputs_to_spend,
    const std::vector<MockTxCLSAGDest> &destinations)
{
    CHECK_AND_ASSERT_THROW_MES(destinations.size() > 0, "Tried to make tx without any destinations.");
    CHECK_AND_ASSERT_THROW_MES(inputs_to_spend.size() > 0, "Tried to make tx without any inputs.");

    // amounts must balance
    using boost::multiprecision::uint128_t;
    uint128_t input_sum{0};
    uint128_t output_sum{0};

    for (const auto &input : inputs_to_spend)
        input_sum += input.m_amount;

    for (const auto &dest : destinations)
        output_sum += dest.m_amount;

    CHECK_AND_ASSERT_THROW_MES(input_sum == output_sum, "Tried to make tx with unbalanced amounts.");

    // validate inputs
    std::size_t ref_set_size{inputs_to_spend[0].m_input_ref_set.size()};

    for (const auto &input : inputs_to_spend)
    {
        // inputs must have same number of ring members
        CHECK_AND_ASSERT_THROW_MES(ref_set_size == input.m_input_ref_set.size(),
            "Tried to make tx with inputs that don't have the same input reference set sizes.");

        // input real spend indices must not be malformed
        CHECK_AND_ASSERT_THROW_MES(input.m_input_ref_set_real_index < input.m_input_ref_set.size(),
            "Tried to make tx with an input that has a malformed real spend index.");
    }

    make_tx(inputs_to_spend, destinations);
}
//-----------------------------------------------------------------
void MockTxCLSAG::make_tx(const std::vector<MockTxCLSAGInput> &inputs_to_spend,
    const std::vector<MockTxCLSAGDest> &destinations)
{
    CHECK_AND_ASSERT_THROW_MES(m_outputs.size() == 0, "Tried to make tx when tx already exists.");

    /// prepare tx
    m_outputs.clear();
    m_input_images.clear();
    m_tx_proofs.clear();
    m_outputs.reserve(destinations.size());
    m_input_images.reserve(inputs_to_spend.size());
    m_tx_proofs.reserve(inputs_to_spend.size());


    /// balance proof
    // - blinding factors need to balance

    // 1. get aggregate blinding factor of outputs
    crypto::secret_key sum_output_blinding_factors = rct::rct2sk(rct::zero());

    std::vector<rct::xmr_amount> output_amounts;
    std::vector<rct::key> output_amount_commitment_blinding_factors;
    output_amounts.reserve(destinations.size());
    output_amount_commitment_blinding_factors.reserve(destinations.size());

    for (const auto &dest : destinations)
    {
        // build output set
        m_outputs.emplace_back(dest.to_enote());

        // add output's amount commitment blinding factor
        sc_add(&sum_output_blinding_factors, &sum_output_blinding_factors, &dest.m_amount_blinding_factor);

        // prepare for range proofs
        output_amounts.emplace_back(dest.m_amount);
        output_amount_commitment_blinding_factors.emplace_back(rct::sk2rct(dest.m_amount_blinding_factor));
    }

    // 2. create all but last input image with random pseudo blinding factor
    std::vector<crypto::secret_key> pseudo_blinding_factors;
    pseudo_blinding_factors.resize(inputs_to_spend.size(), rct::rct2sk(rct::zero()));

    for (std::size_t input_index{0}; input_index + 1 < inputs_to_spend.size(); ++input_index)
    {
        // built input image set
        crypto::secret_key pseudo_blinding_factor{rct::rct2sk(rct::skGen())};
        m_input_images.emplace_back(inputs_to_spend[input_index].to_enote_image(pseudo_blinding_factor));

        // subtract blinding factor from sum
        sc_sub(&sum_output_blinding_factors, &sum_output_blinding_factors, &pseudo_blinding_factor);

        // save input's pseudo amount commitment blinding factor
        pseudo_blinding_factors[input_index] = pseudo_blinding_factor;
    }

    // 3. set last input image's pseudo blinding factor equal to
    //    sum(output blinding factors) - sum(input image blinding factors)_except_last
    m_input_images.emplace_back(inputs_to_spend.back().to_enote_image(sum_output_blinding_factors));
    pseudo_blinding_factors.back() = sum_output_blinding_factors;


    /// range proofs
    // - for output amount commitments
    m_range_proof = rct::bulletproof_plus_PROVE(output_amounts, output_amount_commitment_blinding_factors);


    /// membership + ownership/unspentness proofs
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
        MockCLSAGProof mock_clsag_proof;
        mock_clsag_proof.m_clsag_proof = rct::proveRctCLSAGSimple(
                rct::zero(),                  // empty message for mockup
                referenced_enotes_converted,  // vector of pairs <Ko_i, C_i> for referenced enotes
                spent_enote_converted,        // pair <ko, x> for input's onetime privkey and amount blinding factor
                rct::sk2rct(pseudo_blinding_factors[input_index]),       // pseudo-output blinding factor x'
                rct::pk2rct(m_input_images[input_index].m_pseudo_amount_commitment),  // pseudo-output commitment C'
                nullptr, nullptr, nullptr,    // no multisig
                inputs_to_spend[input_index].m_input_ref_set_real_index,  // real index in input set
                hw::get_device("default")
            );

        mock_clsag_proof.m_referenced_enotes_converted = std::move(referenced_enotes_converted);

        m_tx_proofs.emplace_back(mock_clsag_proof);
    }
}
//-----------------------------------------------------------------
bool MockTxCLSAG::validate() const
{
    CHECK_AND_ASSERT_THROW_MES(m_outputs.size() > 0, "Tried to validate tx that has no outputs.");
    CHECK_AND_ASSERT_THROW_MES(m_input_images.size() > 0, "Tried to validate tx that has no input images.");
    CHECK_AND_ASSERT_THROW_MES(m_tx_proofs.size() > 0, "Tried to validate tx that has no input proofs.");
    CHECK_AND_ASSERT_THROW_MES(m_range_proof.V.size() > 0, "Tried to validate tx that has no range proofs.");

    /// there must be the correct number of proofs
    if (m_tx_proofs.size() != m_input_images.size() || m_range_proof.V.size() != m_outputs.size())
        return false;


    /// all inputs must have the same reference set size
    std::size_t ref_set_size{m_tx_proofs[0].m_referenced_enotes_converted.size()};

    for (const auto &tx_proof : m_tx_proofs)
    {
        if (tx_proof.m_referenced_enotes_converted.size() != ref_set_size)
            return false;
    }

    /// input linking tags must be in the prime subgroup: KI = 8*[(1/8) * KI]
    // note: I cheat a bit here for the mock-up. The linking tags in the clsag_proof are not mul(1/8), but the
    //       tags in m_input_images are.
    for (std::size_t input_index{0}; input_index < m_input_images.size(); ++input_index)
    {
        if (!(rct::scalarmult8(rct::ki2rct(m_input_images[input_index].m_key_image)) ==
                m_tx_proofs[input_index].m_clsag_proof.I))
            return false;

        // sanity check
        if (m_tx_proofs[input_index].m_clsag_proof.I == rct::identity())
            return false;
    }


    /// input linking tags must not exist in the blockchain
    //not implemented for mockup


    /// check that amount commitments balance
    rct::keyV pseudo_commitments;
    rct::keyV output_commitments;
    pseudo_commitments.reserve(m_input_images.size());
    output_commitments.reserve(m_outputs.size());

    for (const auto &input_image : m_input_images)
        pseudo_commitments.emplace_back(rct::pk2rct(input_image.m_pseudo_amount_commitment));

    for (std::size_t output_index{0}; output_index < m_outputs.size(); ++output_index)
    {
        output_commitments.emplace_back(rct::pk2rct(m_outputs[output_index].m_amount_commitment));

        // double check that the two stored copies of output commitments match
        if (m_outputs[output_index].m_amount_commitment != rct::rct2pk(rct::scalarmult8(m_range_proof.V[output_index])))
            return false;
    }

    // sum(pseudo output commitments) ?= sum(output commitments)
    if (!balance_check(pseudo_commitments, output_commitments))
        return false;


    /// check range proof on output enotes
    if (!rct::bulletproof_plus_VERIFY(m_range_proof))
        return false;


    /// verify input membership/ownership/unspentness proofs
    for (std::size_t input_index{0}; input_index < m_input_images.size(); ++input_index)
    {
        if (!rct::verRctCLSAGSimple(rct::zero(),  // empty message for mockup
                m_tx_proofs[input_index].m_clsag_proof,
                m_tx_proofs[input_index].m_referenced_enotes_converted,
                rct::pk2rct(m_input_images[input_index].m_pseudo_amount_commitment)))
            return false;
    }

    return true;
}
//-----------------------------------------------------------------
std::size_t MockTxCLSAG::get_size_bytes() const
{
    // doesn't include (compared to a real tx):
    // - ring member references (e.g. indices or explicit copies)
    // - tx fees
    // - miscellaneous serialization bytes

    // assumes
    // - each output has its own enote pub key

    std::size_t size{0};
    size += m_input_images.size() * MockCLSAGENoteImage::get_size_bytes();
    size += m_outputs.size() * MockCLSAGENote::get_size_bytes();
    // note: ignore the amount commitment set stored in the rangee proof, they are double counted by the output set
    size += 32 * (6 + m_range_proof.L.size() + m_range_proof.R.size());

    if (m_tx_proofs.size())
        // note: ignore the key image stored in the clsag, it is double counted by the input's MockCLSAGENoteImage struct
        size += m_tx_proofs.size() * (32 * (2 + m_tx_proofs[0].m_clsag_proof.s.size()));

    return size;
}
//-----------------------------------------------------------------
} //namespace mock_tx
