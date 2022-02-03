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
#include "tx_builders_outputs.h"

//local headers
#include "crypto/crypto.h"
#include "cryptonote_config.h"
#include "misc_log_ex.h"
#include "ringct/rctTypes.h"
#include "tx_builder_types.h"
#include "tx_component_types.h"

//third party headers

//standard headers
#include <algorithm>
#include <string>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void finalize_v1_output_proposal_set_sp_v1()
{
    //TODO
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_output_proposals_semantics_sp_v1(const std::vector<SpOutputProposalV1> &output_proposals)
{
    // num proposals must be in range [2, MAX_OUTS]
    CHECK_AND_ASSERT_THROW_MES(output_proposals.size() >= 2,
        "Semantics check output proposals v1: insufficient outputs.");
    CHECK_AND_ASSERT_THROW_MES(output_proposals.size() <= config::SP_MAX_OUTPUTS_V1,
        "Semantics check output proposals v1: too many outputs.");

    // if 2 proposals, must be a shared enote ephemeral pubkey
    if (output_proposals.size() == 2)
    {
        CHECK_AND_ASSERT_THROW_MES(output_proposals[0].m_enote_ephemeral_pubkey == 
            output_proposals[1].m_enote_ephemeral_pubkey,
            "Semantics check output proposals v1: there are 2 outputs but they don't share an enote ephemeral pubkey.");
    }

    // if >2 proposals, all enote ephemeral pubkeys should be unique
    if (output_proposals.size() > 2)
    {
        for (auto output_it{output_proposals.begin()}; output_it != output_proposals.end(); ++output_it)
        {
            CHECK_AND_ASSERT_THROW_MES(std::find_if(output_proposals.begin(), output_it,
                        [](const SpOutputProposalV1 &proposal_1, const SpOutputProposalV1 &proposal_2) -> bool
                        {
                            return proposal_1.m_enote_ephemeral_pubkey == proposal_2.m_enote_ephemeral_pubkey;
                        }
                    ) == output_it,
                "Semantics check output proposals v1: there are >2 outputs but their enote ephemeral pubkeys aren't all
                unique.");
        }
    }

    // all onetime addresses should be unique
    for (auto output_it{output_proposals.begin()}; output_it != output_proposals.end(); ++output_it)
    {
        CHECK_AND_ASSERT_THROW_MES(std::find_if(output_proposals.begin(), output_it,
                    [](const SpOutputProposalV1 &proposal_1, const SpOutputProposalV1 &proposal_2) -> bool
                    {
                        return proposal_1.m_proposal_core.m_onetime_address ==
                            proposal_2.m_proposal_core.m_onetime_address;
                    }
                ) == output_it,
            "Semantics check output proposals v1: output onetime addresses are not all unique.");
    }

    // proposals should be sorted
    CHECK_AND_ASSERT_THROW_MES(std::is_sorted(output_proposals.begin(), output_proposals.end()),
        "Semantics check output proposals v1: outputs aren't sorted.");
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_tx_supplement_semantics_sp_v1(const SpTxSupplementV1 &tx_supplement, const std::size_t num_outputs)
{
    // there may be either 1 or 3+ enote pubkeys
    if (num_outputs == 2)
    {
        CHECK_AND_ASSERT_THROW_MES(tx_supplement.m_output_enote_pubkeys.size() == 1 ||
                tx_supplement.m_output_enote_pubkeys.size() >= 3,
            "Semantics check tx supplement v1: there must be 1 enote pubkey if there are 2 outputs.");
    }
    else if (num_outputs >= 3)
    {
        CHECK_AND_ASSERT_THROW_MES(tx_supplement.m_output_enote_pubkeys.size() == num_outputs,
            "Semantics check tx supplement v1: there must be one enote pubkey for each output when there are 3+ outputs.");
    }
    else //num_outputs == 1
    {
        CHECK_AND_ASSERT_THROW_MES(false, "Semantics check tx supplement v1: one output is not allowed.");
    }

    // if 3+ enote pubkeys, all should be unique
    if (tx_supplement.m_output_enote_pubkeys.size() >= 3)
    {
        for (auto enote_pubkey_it{tx_supplement.m_output_enote_pubkeys.begin()};
            enote_pubkey_it != tx_supplement.m_output_enote_pubkeys.end();
            ++enote_pubkey_it)
        {
            CHECK_AND_ASSERT_THROW_MES(std::find(tx_supplement.m_output_enote_pubkeys.begin(), enote_pubkey_it,
                    *enote_pubkey_it) == enote_pubkey_it,
                "Semantics check tx supplement v1: enote pubkeys must be unique.");
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_outputs_sp_v1(const std::vector<SpOutputProposalV1> &output_proposals,
    std::vector<SpEnoteV1> &outputs_out,
    std::vector<rct::xmr_amount> &output_amounts_out,
    std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors_out,
    SpTxSupplementV1 &tx_supplement_inout)
{
    outputs_out.clear();
    outputs_out.resize(output_proposals.size());
    output_amounts_out.clear();
    output_amounts_out.reserve(output_proposals.size());
    output_amount_commitment_blinding_factors_out.clear();
    output_amount_commitment_blinding_factors_out.resize(output_proposals.size());
    tx_supplement_inout.m_output_enote_pubkeys.clear();
    tx_supplement_inout.m_output_enote_pubkeys.reserve(output_proposals.size());

    for (std::size_t output_index{0}; output_index < output_proposals.size(); ++output_index)
    {
        const SpOutputProposalV1 &proposal{output_proposals[output_index]};

        // convert to enote
        proposal.get_enote_v1(outputs_out[output_index]);

        // prepare for range proofs
        output_amounts_out.emplace_back(proposal.m_amount);
        output_amount_commitment_blinding_factors_out.emplace_back(proposal.m_proposal_core.m_amount_blinding_factor);

        // copy non-duplicate enote pubkeys to tx supplement
        if (std::find(tx_supplement_inout.m_output_enote_pubkeys.begin(), tx_supplement_inout.m_output_enote_pubkeys.end(),
            proposal.m_enote_ephemeral_pubkey) == tx_supplement_inout.m_output_enote_pubkeys.end())
        {
            tx_supplement_inout.m_output_enote_pubkeys.emplace_back(proposal.m_enote_ephemeral_pubkey);
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<SpOutputProposalV1> gen_mock_sp_output_proposals_v1(const std::vector<rct::xmr_amount> &out_amounts)
{
    // generate random proposals
    std::vector<SpOutputProposalV1> output_proposals;
    output_proposals.resize(out_amounts.size());

    for (std::size_t output_index{0}; output_index < out_amounts.size(); ++output_index)
    {
        output_proposals[output_index].gen(out_amounts[output_index]);
    }

    // sort them
    std::sort(output_proposals.begin(), output_proposals.end());

    return output_proposals;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
