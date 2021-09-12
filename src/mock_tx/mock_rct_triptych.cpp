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
#include "mock_rct_triptych.h"

//local headers
#include "misc_log_ex.h"
#include "mock_tx_rct_base.h"
#include "mock_tx_rct_components.h"
#include "mock_tx_utils.h"
#include "ringct/bulletproofs_plus.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <memory>
#include <vector>


namespace mock_tx
{
//-----------------------------------------------------------------
bool MockTxTriptych::validate_tx_semantics() const
{
    CHECK_AND_ASSERT_THROW_MES(m_outputs.size() > 0, "Tried to validate tx that has no outputs.");
    CHECK_AND_ASSERT_THROW_MES(m_input_images.size() > 0, "Tried to validate tx that has no input images.");
    CHECK_AND_ASSERT_THROW_MES(m_tx_proofs.size() > 0, "Tried to validate tx that has no input proofs.");
    CHECK_AND_ASSERT_THROW_MES(m_range_proofs.size() > 0, "Tried to validate tx that has no range proofs.");
    CHECK_AND_ASSERT_THROW_MES(m_range_proofs[0].V.size() > 0, "Tried to validate tx that has no range proofs.");

    /// there must be the correct number of proofs
    // input proofs
    if (m_tx_proofs.size() != m_input_images.size())
        return false;

    // range proofs
    std::size_t num_rangeproofed_commitments{0};
    for (const auto &range_proof : m_range_proofs)
        num_rangeproofed_commitments += range_proof.V.size();

    if (num_rangeproofed_commitments != m_outputs.size())
        return false;


    /// all inputs must have the same reference set size and decomposition
    std::size_t decomp_n{m_tx_proofs[0].m_ref_set_decomp_n};
    std::size_t decomp_m{m_tx_proofs[0].m_ref_set_decomp_m};

    for (const auto &tx_proof : m_tx_proofs)
    {
        std::size_t ref_set_size{ref_set_size_from_decomp(tx_proof.m_ref_set_decomp_n, tx_proof.m_ref_set_decomp_m)};

        if (tx_proof.m_ref_set_decomp_n != decomp_n ||
            tx_proof.m_ref_set_decomp_m != decomp_m ||
            tx_proof.m_onetime_addresses.size() != ref_set_size ||
            tx_proof.m_commitments.size() != ref_set_size)
            return false;
    }


    /// input linking tags must be in the prime subgroup: KI = 8*[(1/8) * KI]
    // note: I cheat a bit here for the mock-up. The linking tags in the Triptych_proof are not mul(1/8), but the
    //       tags in m_input_images are.
    for (std::size_t input_index{0}; input_index < m_input_images.size(); ++input_index)
    {
        if (!(rct::scalarmult8(rct::ki2rct(m_input_images[input_index].m_key_image)) ==
                m_tx_proofs[input_index].m_triptych_proof.J))
            return false;

        // sanity check
        if (m_tx_proofs[input_index].m_triptych_proof.J == rct::identity())
            return false;
    }

    return true;
}
//-----------------------------------------------------------------
bool MockTxTriptych::validate_tx_linking_tags() const
{
    if (!validate_mock_tx_rct_linking_tags_v2(m_tx_proofs, m_input_images))
        return false;

    return true;
}
//-----------------------------------------------------------------
bool MockTxTriptych::validate_tx_amount_balance(const bool defer_batchable) const
{
    if (!validate_mock_tx_rct_amount_balance_v1(m_input_images, m_outputs, m_range_proofs, defer_batchable))
        return false;

    return true;
}
//-----------------------------------------------------------------
bool MockTxTriptych::validate_tx_input_proofs(const bool defer_batchable) const
{
    if (!validate_mock_tx_rct_proofs_v2(m_tx_proofs))
        return false;

    return true;
}
//-----------------------------------------------------------------
std::size_t MockTxTriptych::get_size_bytes() const
{
    // doesn't include (compared to a real tx):
    // - ring member references (e.g. indices or explicit copies)
    // - tx fees
    // - miscellaneous serialization bytes

    // assumes
    // - each output has its own enote pub key

    std::size_t size{0};
    size += m_input_images.size() * MockENoteImageRctV1::get_size_bytes();
    size += m_outputs.size() * MockENoteRctV1::get_size_bytes();
    // note: ignore the amount commitment set stored in the range proofs, they are double counted by the output set
    for (const auto &range_proof : m_range_proofs)
        size += 32 * (6 + range_proof.L.size() + range_proof.R.size());

    if (m_tx_proofs.size())
    {
        // note: ignore the key image stored in the Triptych proof, it is double counted by the input's enote image struct
        size += m_tx_proofs.size() * (32 * (8 + 
                        m_tx_proofs[0].m_triptych_proof.X.size() +
                        m_tx_proofs[0].m_triptych_proof.Y.size() +
                        m_tx_proofs[0].m_ref_set_decomp_n * m_tx_proofs[0].m_ref_set_decomp_m));
    }

    return size;
}
//-----------------------------------------------------------------
template <>
std::shared_ptr<MockTxTriptych> make_mock_tx<MockTxTriptych>(const MockTxParamPack &params,
    const std::vector<rct::xmr_amount> &in_amounts,
    const std::vector<rct::xmr_amount> &out_amounts)
{
    CHECK_AND_ASSERT_THROW_MES(in_amounts.size() > 0, "Tried to make tx without any inputs.");
    CHECK_AND_ASSERT_THROW_MES(out_amounts.size() > 0, "Tried to make tx without any outputs.");
    CHECK_AND_ASSERT_THROW_MES(balance_check_in_out_amnts(in_amounts, out_amounts),
        "Tried to make tx with unbalanced amounts.");

    std::size_t ref_set_size{ref_set_size_from_decomp(params.ref_set_decomp_n, params.ref_set_decomp_m)};

    // make mock inputs
    std::vector<MockInputRctV1> inputs_to_spend{gen_mock_rct_inputs_v1(in_amounts, ref_set_size)};

    // make mock destinations
    std::vector<MockDestRctV1> destinations{gen_mock_rct_dests_v1(out_amounts)};

    /// make tx
    // tx components
    std::vector<MockENoteImageRctV1> input_images;
    std::vector<MockENoteRctV1> outputs;
    std::vector<rct::BulletproofPlus> range_proofs;
    std::vector<MockRctProofV2> tx_proofs;

    // info shuttles for making components
    std::vector<rct::xmr_amount> output_amounts;
    std::vector<rct::key> output_amount_commitment_blinding_factors;
    std::vector<crypto::secret_key> pseudo_blinding_factors;

    make_tx_transfers_rct_v1(inputs_to_spend,
        destinations,
        outputs,
        output_amounts,
        output_amount_commitment_blinding_factors,
        pseudo_blinding_factors);
    make_tx_images_rct_v2(inputs_to_spend,
        pseudo_blinding_factors,
        input_images);
    make_bpp_rangeproofs(output_amounts,
        output_amount_commitment_blinding_factors,
        params.max_rangeproof_splits,
        range_proofs);
    make_tx_input_proofs_rct_v2(inputs_to_spend,
        input_images,
        pseudo_blinding_factors,
        params.ref_set_decomp_n,
        params.ref_set_decomp_m,
        tx_proofs);

    return std::make_shared<MockTxTriptych>(input_images, outputs, range_proofs, tx_proofs);
}
//-----------------------------------------------------------------
template <>
bool validate_mock_txs<MockTxTriptych>(const std::vector<std::shared_ptr<MockTxTriptych>> &txs_to_validate)
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
