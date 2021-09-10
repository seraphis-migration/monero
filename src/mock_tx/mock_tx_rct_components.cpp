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
#include "mock_tx_rct_components.h"

//local headers
#include "crypto/crypto.h"
#include "crypto/crypto-ops.h"
#include "device/device.hpp"
#include "misc_log_ex.h"
#include "mock_tx_rct_base.h"
#include "mock_tx_utils.h"
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
//-----------------------------------------------------------------
MockENoteRctV1 MockDestRctV1::to_enote_v1() const
{
    MockENoteRctV1 enote;
    MockDestRCT::to_enote_rct(enote);

    return enote;
}
//-----------------------------------------------------------------
void make_mock_tx_rct_enote_v1(const crypto::secret_key &onetime_privkey,
    const crypto::secret_key &amount_blinding_factor,
    const rct::xmr_amount amount,
    MockENoteRctV1 &enote_out)
{
    // make base of enote
    make_mock_tx_rct_enote(onetime_privkey, amount_blinding_factor, enote_out);

    // memo: random
    enote_out.m_enote_pubkey = rct::rct2pk(rct::pkGen());
    enote_out.m_encoded_amount = rct::randXmrAmount(rct::xmr_amount{static_cast<rct::xmr_amount>(-1)});
}
//-----------------------------------------------------------------
void gen_mock_tx_rct_enote_v1(MockENoteRctV1 &enote_out)
{
    // gen base of enote
    gen_mock_tx_rct_enote(enote_out);

    // memo: random
    enote_out.m_enote_pubkey = rct::rct2pk(rct::pkGen());
    enote_out.m_encoded_amount = rct::randXmrAmount(rct::xmr_amount{static_cast<rct::xmr_amount>(-1)});
}
//-----------------------------------------------------------------
void gen_mock_tx_rct_dest_v1(const rct::xmr_amount amount, MockDestRctV1 &dest_out)
{
    // gen base of dest
    gen_mock_tx_rct_dest(amount, dest_out);

    // memo parts: random
    dest_inout.m_enote_pubkey = rct::rct2pk(rct::pkGen());
    dest_inout.m_encoded_amount = rct::randXmrAmount(rct::xmr_amount{static_cast<rct::xmr_amount>(-1)});
}
//-----------------------------------------------------------------
void gen_mock_tx_rct_input_v1(const rct::xmr_amount amount, const std::size_t ref_set_size, MockInputRctV1 &input_out)
{
    // \pi = rand()
    input_out.m_input_ref_set_real_index = crypto::rand_idx(ref_set_size);

    // prep real input
    input_out.m_onetime_privkey = rct::rct2sk(rct::skGen());
    input_out.m_amount_blinding_factor = rct::rct2sk(rct::skGen());
    input_out.m_amount = amounts[input_index];

    // construct reference set
    input_out.m_input_ref_set.resize(ref_set_size);

    for (std::size_t ref_index{0}; ref_index < ref_set_size; ++ref_index)
    {
        // insert real input at \pi
        if (ref_index == input_out.m_input_ref_set_real_index)
        {
            // make an enote at m_input_ref_set[ref_index]
            make_mock_tx_rct_enote_v1(input_out.m_onetime_privkey,
                    input_out.m_amount_blinding_factor,
                    input_out.m_amount,
                    input_out.m_input_ref_set[ref_index]);
        }
        // add random enote
        else
        {
            // generate a random enote at m_input_ref_set[ref_index]
            gen_mock_tx_rct_enote_v1(input_out.m_input_ref_set[ref_index]);
        }
    }
}
//-----------------------------------------------------------------
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
            gen_mock_tx_rct_input_v1(amounts[input_index], ref_set_size, inputs[input_index]);
        }
    }

    return inputs;
}
//-----------------------------------------------------------------
std::vector<MockDestRctV1> gen_mock_rct_dests_v1(const std::vector<rct::xmr_amount> &amounts)
{
    std::vector<MockDestRctV1> destinations;

    if (amounts.size() > 0)
    {
        destinations.resize(amounts.size());

        for (std::size_t dest_index{0}; dest_index < amounts.size(); ++dest_index)
        {
            gen_mock_tx_rct_dest_v1(amounts[dest_index], destinations[dest_index]);
        }
    }

    return destinations;
}
//-----------------------------------------------------------------
void MockTxCLSAG::make_tx_transfers(const std::vector<MockInputRctV1> &inputs_to_spend,
    const std::vector<MockDestRctV1> &destinations,
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
void MockTxCLSAG::make_tx_input_proofs(const std::vector<MockInputRctV1> &inputs_to_spend,
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
bool validate_mock_tx_rct_linking_tags_v1(const std::vector<MockRctProofV1> &proofs,
    const std::vector<MockENoteImageRctV1> &images)
{
    /// input linking tags must be in the prime subgroup: KI = 8*[(1/8) * KI]
    // note: I cheat a bit here for the mock-up. The linking tags in the clsag_proof are not mul(1/8), but the
    //       tags in input images are.
    for (std::size_t input_index{0}; input_index < images.size(); ++input_index)
    {
        if (!(rct::scalarmult8(rct::ki2rct(images[input_index].m_key_image)) ==
                proofs[input_index].m_clsag_proof.I))
            return false;

        // sanity check
        if (proofs[input_index].m_clsag_proof.I == rct::identity())
            return false;
    }


    /// input linking tags must not exist in the blockchain
    //not implemented for mockup

    return true;
}
//-----------------------------------------------------------------
bool validate_mock_tx_rct_amount_balance_v1(const std::vector<MockENoteImageRctV1> &images,
    const std::vector<MockENoteRctV1> &outputs,
    const std::vector<BulletproofPlus> &range_proofs,
    const bool defer_batchable)
{
    /// check that amount commitments balance
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

        // double check that the two stored copies of output commitments match
        if (range_proofs[range_proof_index].V.size() == output_index - range_proof_index*range_proof_grouping_size)
            ++range_proof_index;

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
        range_proof_ptrs.reserve(m_range_proofs.size());

        for (const auto &range_proof : m_range_proofs)
            range_proof_ptrs.push_back(&range_proof);

        if (!rct::bulletproof_plus_VERIFY(range_proof_ptrs))
            return false;
    }

    return true;
}
//-----------------------------------------------------------------
bool validate_mock_tx_rct_proofs_v1(const std::vector<MockRctProofV1> &proofs,
    const std::vector<MockENoteImageRctV1> &images)
{
    /// verify membership/ownership/unspentness proofs
    for (std::size_t input_index{0}; input_index < images.size(); ++input_index)
    {
        if (!rct::verRctCLSAGSimple(rct::zero(),  // empty message for mockup
                m_tx_proofs[input_index].m_clsag_proof,
                m_tx_proofs[input_index].m_referenced_enotes_converted,
                rct::pk2rct(images[input_index].m_pseudo_amount_commitment)))
            return false;
    }

    return true;
}
//-----------------------------------------------------------------
} //namespace mock_tx
