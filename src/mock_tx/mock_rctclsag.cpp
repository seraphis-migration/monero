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
#include "mock_rctclsag.h"

//local headers
#include "crypto/crypto.h"
#include "crypto/crypto-ops.h"
#include "device/device.hpp"
#include "mock_tx_common_rct.h"
#include "mock_tx_interface.h"
#include "ringct/bulletproofs_plus.h"
#include "ringct/rctOps.h"
#include "ringct/rctSigs.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <memory>
#include <vector>


namespace mock_tx
{
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
    MockDestRCT::to_enote_rct(enote);

    return enote;
}
//-----------------------------------------------------------------
std::vector<MockTxCLSAGInput> gen_mock_tx_inputs(const std::vector<rct::xmr_amount> &amounts,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m)
{
    CHECK_AND_ASSERT_THROW_MES(ref_set_decomp_n > 0, "Tried to create inputs with no ref set size.");
    std::size_t ref_set_size{ref_set_size_from_decomp(ref_set_decomp_n, ref_set_decomp_m)};

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
            inputs[input_index].m_input_ref_set.resize(ref_set_size);

            for (std::size_t ref_index{0}; ref_index < ref_set_size; ++ref_index)
            {
                // insert real input at \pi
                if (ref_index == inputs[input_index].m_input_ref_set_real_index)
                {
                    // make an enote at m_input_ref_set[ref_index]
                    make_mock_tx_enote_rct(inputs[input_index].m_onetime_privkey,
                            inputs[input_index].m_amount_blinding_factor,
                            inputs[input_index].m_amount,
                            inputs[input_index].m_input_ref_set[ref_index]);
                }
                // add random enote
                else
                {
                    // generate a random enote at m_input_ref_set[ref_index]
                    gen_mock_tx_enote_rct(inputs[input_index].m_input_ref_set[ref_index]);
                }
            }
        }
    }

    return inputs;
}
//-----------------------------------------------------------------
std::vector<MockTxCLSAGDest> gen_mock_tx_dests(const std::vector<rct::xmr_amount> &amounts)
{
    std::vector<MockTxCLSAGDest> destinations;

    if (amounts.size() > 0)
    {
        destinations.resize(amounts.size());

        for (std::size_t dest_index{0}; dest_index < amounts.size(); ++dest_index)
        {
            gen_mock_tx_dest_rct(amounts[dest_index], destinations[dest_index]);
        }
    }

    return destinations;
}
//-----------------------------------------------------------------
void MockTxCLSAG::make_tx_transfers(const std::vector<MockTxCLSAGInput> &inputs_to_spend,
    const std::vector<MockTxCLSAGDest> &destinations,
    std::vector<rct::xmr_amount> &output_amounts,
    std::vector<rct::key> &output_amount_commitment_blinding_factors,
    std::vector<crypto::secret_key> &pseudo_blinding_factors)
{
    // note: blinding factors need to balance for balance proof
    output_amounts.clear();
    output_amount_commitment_blinding_factors.clear();
    pseudo_blinding_factors.clear();

    // 1. get aggregate blinding factor of outputs
    crypto::secret_key sum_output_blinding_factors = rct::rct2sk(rct::zero());

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
}
//-----------------------------------------------------------------
void MockTxCLSAG::make_tx_rangeproofs(const std::vector<rct::xmr_amount> &output_amounts,
    const std::vector<rct::key> &output_amount_commitment_blinding_factors,
    const std::size_t max_rangeproof_splits)
{
    /// range proofs
    // - for output amount commitments

    // get number of amounts to aggregate in each proof
    std::size_t split_size{compute_rangeproof_grouping_size(output_amounts.size(), max_rangeproof_splits)};

    // make the range proofs
    for (std::size_t output_index{0}; output_index < output_amounts.size(); output_index += split_size)
    {
        std::vector<rct::xmr_amount> output_amounts_group;
        std::vector<rct::key> output_amount_commitment_blinding_factors_group;
        output_amounts_group.reserve(split_size);
        output_amount_commitment_blinding_factors_group.reserve(split_size);

        for (std::size_t chunk_index{output_index};
            chunk_index < (output_index + split_size) && chunk_index < output_amounts.size();
            ++chunk_index)
        {
            output_amounts_group.emplace_back(output_amounts[chunk_index]);
            output_amount_commitment_blinding_factors_group.emplace_back(output_amount_commitment_blinding_factors[chunk_index]);
        }

        m_range_proofs.emplace_back(
            rct::bulletproof_plus_PROVE(output_amounts_group, output_amount_commitment_blinding_factors_group));
    }
}
//-----------------------------------------------------------------
void MockTxCLSAG::make_tx_input_proofs(const std::vector<MockTxCLSAGInput> &inputs_to_spend,
    const std::vector<crypto::secret_key> &pseudo_blinding_factors)
{
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
void MockTxCLSAG::make_tx(const std::vector<MockTxCLSAGInput> &inputs_to_spend,
        const std::vector<MockTxCLSAGDest> &destinations,
        const MockTxParamPack<MockTxCLSAG> &param_pack)
{
    /// validate inputs and prepare to make tx
    CHECK_AND_ASSERT_THROW_MES(m_outputs.size() == 0, "Tried to make tx when tx already exists.");
    CHECK_AND_ASSERT_THROW_MES(destinations.size() > 0, "Tried to make tx without any destinations.");
    CHECK_AND_ASSERT_THROW_MES(inputs_to_spend.size() > 0, "Tried to make tx without any inputs.");

    // amounts must balance
    CHECK_AND_ASSERT_THROW_MES(balance_check_in_out_amnts(inputs_to_spend, destinations),
        "Tried to make tx with unbalanced amounts.");

    // validate tx inputs
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

    /// prepare tx
    m_outputs.clear();
    m_input_images.clear();
    m_tx_proofs.clear();
    m_outputs.reserve(destinations.size());
    m_input_images.reserve(inputs_to_spend.size());
    m_tx_proofs.reserve(inputs_to_spend.size());

    /// make tx
    std::vector<rct::xmr_amount> output_amounts;
    std::vector<rct::key> output_amount_commitment_blinding_factors;
    std::vector<crypto::secret_key> pseudo_blinding_factors;

    make_tx_transfers(inputs_to_spend,
        destinations,
        output_amounts,
        output_amount_commitment_blinding_factors,
        pseudo_blinding_factors);
    make_tx_rangeproofs(output_amounts,
        output_amount_commitment_blinding_factors,
        param_pack.max_rangeproof_splits);
    make_tx_input_proofs(inputs_to_spend,
        pseudo_blinding_factors);
}
//-----------------------------------------------------------------
bool MockTxCLSAG::validate_tx_semantics() const
{
    CHECK_AND_ASSERT_THROW_MES(m_outputs.size() > 0, "Tried to validate tx that has no outputs.");
    CHECK_AND_ASSERT_THROW_MES(m_input_images.size() > 0, "Tried to validate tx that has no input images.");
    CHECK_AND_ASSERT_THROW_MES(m_tx_proofs.size() > 0, "Tried to validate tx that has no input proofs.");
    CHECK_AND_ASSERT_THROW_MES(m_range_proofs.size() > 0, "Tried to validate tx that has no range proofs.");
    CHECK_AND_ASSERT_THROW_MES(m_range_proofs[0].V.size() > 0, "Tried to validate tx that has no range proofs.");

    /// there must be the correct number of proofs
    if (m_tx_proofs.size() != m_input_images.size())
        return false;

    std::size_t num_rangeproofed_commitments{0};
    for (const auto &range_proof : m_range_proofs)
        num_rangeproofed_commitments += range_proof.V.size();

    if (num_rangeproofed_commitments != m_outputs.size())
        return false;


    /// all inputs must have the same reference set size
    std::size_t ref_set_size{m_tx_proofs[0].m_referenced_enotes_converted.size()};

    for (const auto &tx_proof : m_tx_proofs)
    {
        if (tx_proof.m_referenced_enotes_converted.size() != ref_set_size)
            return false;
    }

    return true;
}
//-----------------------------------------------------------------
bool MockTxCLSAG::validate_tx_linking_tags() const
{
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

    return true;
}
//-----------------------------------------------------------------
bool MockTxCLSAG::validate_tx_amount_balance() const
{
    /// check that amount commitments balance
    rct::keyV pseudo_commitments;
    rct::keyV output_commitments;
    pseudo_commitments.reserve(m_input_images.size());
    output_commitments.reserve(m_outputs.size());

    for (const auto &input_image : m_input_images)
        pseudo_commitments.emplace_back(rct::pk2rct(input_image.m_pseudo_amount_commitment));

    std::size_t range_proof_index{0};
    std::size_t range_proof_grouping_size = m_range_proofs[0].V.size();

    for (std::size_t output_index{0}; output_index < m_outputs.size(); ++output_index)
    {
        output_commitments.emplace_back(rct::pk2rct(m_outputs[output_index].m_amount_commitment));

        // double check that the two stored copies of output commitments match
        if (m_range_proofs[range_proof_index].V.size() == output_index - range_proof_index*range_proof_grouping_size)
            ++range_proof_index;

        if (m_outputs[output_index].m_amount_commitment !=
                rct::rct2pk(rct::scalarmult8(m_range_proofs[range_proof_index].V[output_index -
                    range_proof_index*range_proof_grouping_size])))
            return false;
    }

    // sum(pseudo output commitments) ?= sum(output commitments)
    if (!balance_check_equality(pseudo_commitments, output_commitments))
        return false;

    return true;
}
//-----------------------------------------------------------------
bool MockTxCLSAG::validate_tx_rangeproofs(defer_batchable) const
{
    /// check range proof on output enotes
    if (!defer_batchable)
    {
        std::vector<const rct::BulletproofPlus*> range_proofs;
        range_proofs.reserve(m_range_proofs.size());

        for (const auto &range_proof : m_range_proofs)
            range_proofs.push_back(&range_proof);

        if (!rct::bulletproof_plus_VERIFY(range_proofs))
            return false;
    }

    return true;
}
//-----------------------------------------------------------------
bool MockTxCLSAG::validate_tx_input_proofs() const
{
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
bool MockTxCLSAG::validate(const bool defer_batchable) const
{
    if (!validate_tx_semantics())
        return false;

    if (!validate_tx_linking_tags())
        return false;

    if (!validate_tx_amount_balance())
        return false;

    if (!validate_tx_rangeproofs(defer_batchable))
        return false;

    if (!validate_tx_input_proofs())
        return false;

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
    // note: ignore the amount commitment set stored in the range proofs, they are double counted by the output set
    for (const auto &range_proof : m_range_proofs)
        size += 32 * (6 + range_proof.L.size() + range_proof.R.size());

    if (m_tx_proofs.size())
        // note: ignore the key image stored in the clsag, it is double counted by the input's MockCLSAGENoteImage struct
        size += m_tx_proofs.size() * (32 * (2 + m_tx_proofs[0].m_clsag_proof.s.size()));

    return size;
}
//-----------------------------------------------------------------
bool validate_mock_txs(const std::vector<std::shared_ptr<MockTxCLSAG>> &txs_to_validate)
{
    std::vector<const rct::BulletproofPlus*> range_proofs;
    range_proofs.reserve(txs_to_validate.size()*10);

    for (const auto &tx : txs_to_validate)
    {
        // validate unbatchable parts of tx
        if (!tx->validate(true))
            return false;

        // gather range proofs
        for (const auto &range_proof : tx->get_range_proofs())
            range_proofs.push_back(&range_proof);
    }

    // batch verify range proofs
    if (!rct::bulletproof_plus_VERIFY(range_proofs))
        return false;

    return true;
}
//-----------------------------------------------------------------
} //namespace mock_tx
