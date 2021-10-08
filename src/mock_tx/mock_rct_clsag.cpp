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
#include "mock_rct_clsag.h"

//local headers
#include "ledger_context.h"
#include "misc_log_ex.h"
#include "mock_ledger_context.h"
#include "mock_rct_base.h"
#include "mock_rct_components.h"
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
//-------------------------------------------------------------------------------------------------------------------
bool MockTxCLSAG::validate_tx_semantics() const
{
    // validate component counts (num inputs/outputs/etc.)
    if (!validate_mock_tx_rct_semantics_component_counts_v1(m_tx_proofs.size(),
        m_input_images.size(),
        m_outputs.size(),
        m_balance_proof))
    {
        return false;
    }

    // validate input proof reference set sizes
    if (!validate_mock_tx_rct_semantics_ref_set_size_v1(m_tx_proofs, m_tx_proofs[0].m_referenced_enotes_converted.size()))
    {
        return false;
    }

    // validate linking tag semantics
    if (!validate_mock_tx_rct_semantics_linking_tags_v1(m_input_images, m_tx_proofs))
    {
        return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool MockTxCLSAG::validate_tx_linking_tags(const std::shared_ptr<const LedgerContext> ledger_context) const
{
    if (!validate_mock_tx_rct_linking_tags_v1(m_tx_proofs, m_input_images))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool MockTxCLSAG::validate_tx_amount_balance(const bool defer_batchable) const
{
    if (!validate_mock_tx_rct_amount_balance_v1(m_input_images, m_outputs, m_balance_proof, defer_batchable))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool MockTxCLSAG::validate_tx_input_proofs(const std::shared_ptr<const LedgerContext> ledger_context,
    const bool defer_batchable) const
{
    if (!validate_mock_tx_rct_proofs_v1(m_tx_proofs, m_input_images))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t MockTxCLSAG::get_size_bytes() const
{
    // doesn't include (compared to a real tx):
    // - ring member references (e.g. indices or explicit copies)
    // - tx fees
    // - miscellaneous serialization bytes

    // assumes
    // - each output has its own enote pub key

    std::size_t size{0};

    // input images
    size += m_input_images.size() * MockENoteImageRctV1::get_size_bytes();

    // outputs
    size += m_outputs.size() * MockENoteRctV1::get_size_bytes();

    // input proofs
    if (m_tx_proofs.size())
        // note: ignore the key image stored in the clsag, it is double counted by the input's enote image struct
        size += m_tx_proofs.size() * m_tx_proofs[0].get_size_bytes();

    // balance proof
    if (m_balance_proof.get() != nullptr)
        size += m_balance_proof->get_size_bytes();

    return size;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
std::shared_ptr<MockTxCLSAG> make_mock_tx<MockTxCLSAG>(const MockTxParamPack &params,
    const std::vector<rct::xmr_amount> &in_amounts,
    const std::vector<rct::xmr_amount> &out_amounts,
    std::shared_ptr<MockLedgerContext> ledger_context)
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
    std::shared_ptr<MockRctBalanceProofV1> balance_proof;
    std::vector<MockRctProofV1> tx_proofs;

    // info shuttles for making components
    std::vector<rct::xmr_amount> output_amounts;
    std::vector<rct::key> output_amount_commitment_blinding_factors;
    std::vector<crypto::secret_key> pseudo_blinding_factors;

    make_v1_tx_outputs_rct_v1(destinations,
        outputs,
        output_amounts,
        output_amount_commitment_blinding_factors);
    make_v1_tx_images_rct_v1(inputs_to_spend,
        output_amount_commitment_blinding_factors,
        input_images,
        pseudo_blinding_factors);
    make_v1_tx_input_proofs_rct_v1(inputs_to_spend,
        pseudo_blinding_factors,
        tx_proofs);
    make_v1_tx_balance_proof_rct_v1(output_amounts,
        output_amount_commitment_blinding_factors,
        params.max_rangeproof_splits,
        balance_proof);

    return std::make_shared<MockTxCLSAG>(input_images, outputs, balance_proof, tx_proofs);
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_mock_txs<MockTxCLSAG>(const std::vector<std::shared_ptr<MockTxCLSAG>> &txs_to_validate,
    const std::shared_ptr<const LedgerContext> ledger_context)
{
    std::vector<const rct::BulletproofPlus*> range_proofs;
    range_proofs.reserve(txs_to_validate.size()*10);

    for (const auto &tx : txs_to_validate)
    {
        if (tx.get() == nullptr)
            return false;

        // validate unbatchable parts of tx
        if (!tx->validate(ledger_context, true))
            return false;

        // gather range proofs
        const std::shared_ptr<MockRctBalanceProofV1> balance_proof{tx->get_balance_proof()};

        if (balance_proof.get() == nullptr)
            return false;

        for (const auto &range_proof : balance_proof->m_bpp_proofs)
            range_proofs.push_back(&range_proof);
    }

    // batch verify range proofs
    if (!rct::bulletproof_plus_VERIFY(range_proofs))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace mock_tx
