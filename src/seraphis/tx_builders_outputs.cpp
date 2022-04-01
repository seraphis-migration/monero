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
#include "seraphis_config_temp.h"
#include "jamtis_core_utils.h"
#include "jamtis_destination.h"
#include "jamtis_payment_proposal.h"
#include "jamtis_support_types.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "tx_builder_types.h"
#include "tx_component_types.h"
#include "tx_misc_utils.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <algorithm>
#include <string>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
// check that all enote ephemeral pubkeys in an output proposal set are unique
//-------------------------------------------------------------------------------------------------------------------
static bool check_output_proposal_set_unique_ephemeral_pubkeys_v1(const std::vector<SpOutputProposalV1> &output_proposals)
{
    for (auto output_it = output_proposals.begin(); output_it != output_proposals.end(); ++output_it)
    {
        if (std::find_if(output_proposals.begin(), output_it,
                    [&output_it](const SpOutputProposalV1 &previous_proposal) -> bool
                    {
                        return previous_proposal.m_enote_ephemeral_pubkey == output_it->m_enote_ephemeral_pubkey;
                    }
                ) != output_it)
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void check_v1_output_proposal_set_semantics_v1(const std::vector<SpOutputProposalV1> &output_proposals)
{
    CHECK_AND_ASSERT_THROW_MES(output_proposals.size() >= 1, "Semantics check output proposals v1: insufficient outputs.");

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
        for (auto output_it = output_proposals.begin(); output_it != output_proposals.end(); ++output_it)
        {
            CHECK_AND_ASSERT_THROW_MES(check_output_proposal_set_unique_ephemeral_pubkeys_v1(output_proposals),
                "Semantics check output proposals v1: there are >2 outputs but their enote ephemeral pubkeys aren't all "
                "unique.");
        }
    }

    // proposals should be sorted
    CHECK_AND_ASSERT_THROW_MES(std::is_sorted(output_proposals.begin(), output_proposals.end()),
        "Semantics check output proposals v1: outputs aren't sorted.");

    // proposals should be unique (can use adjacent_find when sorted)
    CHECK_AND_ASSERT_THROW_MES(std::adjacent_find(output_proposals.begin(), output_proposals.end(), equals_from_less{})
            == output_proposals.end(),
        "Semantics check output proposals v1: output onetime addresses are not all unique.");

    // proposal onetime addresses should be canonical (sanity check so our tx outputs don't have duplicate key images)
    for (const SpOutputProposalV1 &output_proposal : output_proposals)
    {
        CHECK_AND_ASSERT_THROW_MES(output_proposal.m_core.onetime_address_is_canonical(),
            "Semantics check output proposals v1: an output onetime address is not in the prime subgroup.");
    }
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_tx_supplement_semantics_v1(const SpTxSupplementV1 &tx_supplement, const std::size_t num_outputs)
{
    // there may be either 1 or 3+ enote pubkeys
    if (num_outputs == 2)
    {
        CHECK_AND_ASSERT_THROW_MES(tx_supplement.m_output_enote_ephemeral_pubkeys.size() == 1,
            "Semantics check tx supplement v1: there must be 1 enote pubkey if there are 2 outputs.");
    }
    else if (num_outputs >= 3)
    {
        CHECK_AND_ASSERT_THROW_MES(tx_supplement.m_output_enote_ephemeral_pubkeys.size() == num_outputs,
            "Semantics check tx supplement v1: there must be one enote pubkey for each output when there are 3+ outputs.");
    }

    // if 3+ enote pubkeys, all should be unique
    if (tx_supplement.m_output_enote_ephemeral_pubkeys.size() >= 3)
    {
        for (auto enote_pubkey_it = tx_supplement.m_output_enote_ephemeral_pubkeys.begin();
            enote_pubkey_it != tx_supplement.m_output_enote_ephemeral_pubkeys.end();
            ++enote_pubkey_it)
        {
            CHECK_AND_ASSERT_THROW_MES(std::find(tx_supplement.m_output_enote_ephemeral_pubkeys.begin(), enote_pubkey_it,
                    *enote_pubkey_it) == enote_pubkey_it,
                "Semantics check tx supplement v1: enote pubkeys must be unique.");
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_outputs_v1(const std::vector<SpOutputProposalV1> &output_proposals,
    std::vector<SpEnoteV1> &outputs_out,
    std::vector<rct::xmr_amount> &output_amounts_out,
    std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors_out,
    std::vector<rct::key> &output_enote_ephemeral_pubkeys_out)
{
    outputs_out.clear();
    outputs_out.reserve(output_proposals.size());
    output_amounts_out.clear();
    output_amounts_out.reserve(output_proposals.size());
    output_amount_commitment_blinding_factors_out.clear();
    output_amount_commitment_blinding_factors_out.reserve(output_proposals.size());
    output_enote_ephemeral_pubkeys_out.clear();
    output_enote_ephemeral_pubkeys_out.reserve(output_proposals.size());

    for (const SpOutputProposalV1 &proposal : output_proposals)
    {
        // convert to enote
        outputs_out.emplace_back();
        proposal.get_enote_v1(outputs_out.back());

        // prepare for range proofs
        output_amounts_out.emplace_back(proposal.m_core.m_amount);
        output_amount_commitment_blinding_factors_out.emplace_back(proposal.m_core.m_amount_blinding_factor);

        // copy non-duplicate enote pubkeys to tx supplement
        if (std::find(output_enote_ephemeral_pubkeys_out.begin(),
            output_enote_ephemeral_pubkeys_out.end(),
            proposal.m_enote_ephemeral_pubkey) == output_enote_ephemeral_pubkeys_out.end())
        {
            output_enote_ephemeral_pubkeys_out.emplace_back(proposal.m_enote_ephemeral_pubkey);
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
void finalize_v1_output_proposal_set_v1(const boost::multiprecision::uint128_t &total_input_amount,
    const rct::xmr_amount transaction_fee,
    const jamtis::JamtisDestinationV1 &change_destination,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    std::vector<SpOutputProposalV1> &output_proposals_inout)
{
    // get change amount
    boost::multiprecision::uint128_t output_sum{transaction_fee};

    for (const SpOutputProposalV1 &proposal : output_proposals_inout)
        output_sum += proposal.m_core.m_amount;

    CHECK_AND_ASSERT_THROW_MES(total_input_amount >= output_sum, "Finalize output proposals: input amount is too small.");
    CHECK_AND_ASSERT_THROW_MES(total_input_amount - output_sum <= static_cast<rct::xmr_amount>(-1),
        "Finalize output proposals: change amount exceeds maximum value allowed.");

    const rct::xmr_amount change_amount{total_input_amount - output_sum};

    // finalize the output proposal set: add zero or more of the following
    // - normal dummy output
    // - normal change output
    // - special dummy output
    // - special change output
    if (output_proposals_inout.size() == 0)
    {
        // txs should have at least 1 non-change output

        CHECK_AND_ASSERT_THROW_MES(false, "Finalize output proposals: 0 outputs specified. If you want to send money to "
            "yourself, use a self-spend enote type instead of forcing it via a change enote type.");
    }
    else if (output_proposals_inout.size() == 1)
    {
        if (change_amount == 0)
        {
            // txs need at least 2 outputs

            // add a special dummy output
            // - 0 amount
            // - make sure the final proposal set will have 1 unique enote ephemeral pubkey
            output_proposals_inout.emplace_back();
            output_proposals_inout.back().gen(0, 0);
            output_proposals_inout.back().m_enote_ephemeral_pubkey = output_proposals_inout[0].m_enote_ephemeral_pubkey;
        }
        else if /*change_amount > 0 &&*/
            (!jamtis::is_self_send_output_proposal(output_proposals_inout[0], wallet_spend_pubkey, k_view_balance))
        {
            // if there is 1 normal output and non-zero change, then make a special change enote that shares
            //   the normal output's enote ephemeral pubkey

            // add a special change output
            // - 'change' amount
            // - make sure the final proposal set will have 1 unique enote ephemeral pubkey
            crypto::secret_key findreceived_key;
            jamtis::make_jamtis_findreceived_key(k_view_balance, findreceived_key);
            const rct::key special_change_addr_K2{
                    rct::scalarmultKey(output_proposals_inout[0].m_enote_ephemeral_pubkey, rct::sk2rct(findreceived_key))
                };  //k_fr * K_e_other

            jamtis::JamtisPaymentProposalSelfSendV1 special_change;
            special_change.m_destination = change_destination;
            special_change.m_destination.m_addr_K2 = special_change_addr_K2;  //k_fr * K_e_other
            special_change.m_destination.m_addr_K3 = output_proposals_inout[0].m_enote_ephemeral_pubkey;  //K_e_other
            special_change.m_amount = change_amount;
            special_change.m_type = jamtis::JamtisSelfSendMAC::CHANGE;
            special_change.m_enote_ephemeral_privkey = rct::rct2sk(rct::identity());  //r = 1 (not needed)
            special_change.m_viewbalance_privkey = k_view_balance;

            output_proposals_inout.emplace_back();
            special_change.get_output_proposal_v1(output_proposals_inout.back());
        }
        else //(change_amount > 0 && single output is self-send)
        {
            // 2-out txs may not have 2 self-send type enotes from the same wallet, so we can't have a special change here

            // add a normal dummy output
            // - 0 amount
            output_proposals_inout.emplace_back();
            output_proposals_inout.back().gen(0, 0);

            // add a normal change output
            // - 'change' amount
            jamtis::JamtisPaymentProposalSelfSendV1 normal_change;
            normal_change.m_destination = change_destination;
            normal_change.m_amount = change_amount;
            normal_change.m_type = jamtis::JamtisSelfSendMAC::CHANGE;
            normal_change.m_enote_ephemeral_privkey = rct::rct2sk(rct::skGen());
            normal_change.m_viewbalance_privkey = k_view_balance;

            output_proposals_inout.emplace_back();
            normal_change.get_output_proposal_v1(output_proposals_inout.back());
        }
    }
    else if (output_proposals_inout.size() == 2 &&
        !(output_proposals_inout[0].m_enote_ephemeral_pubkey == output_proposals_inout[1].m_enote_ephemeral_pubkey))
    {
        if (change_amount == 0)
        {
            // 2-out txs need 1 shared enote ephemeral pubkey; add a dummy output here since the outputs have different
            //   enote ephemeral pubkeys

            // add a normal dummy output
            // - 0 amount
            output_proposals_inout.emplace_back();
            output_proposals_inout.back().gen(0, 0);
        }
        else //(change_amount > 0)
        {
            // 2 separate outputs + 1 change output = a simple 3-out tx

            // add a normal change output
            // - 'change' amount
            jamtis::JamtisPaymentProposalSelfSendV1 normal_change;
            normal_change.m_destination = change_destination;
            normal_change.m_amount = change_amount;
            normal_change.m_type = jamtis::JamtisSelfSendMAC::CHANGE;
            normal_change.m_enote_ephemeral_privkey = rct::rct2sk(rct::skGen());
            normal_change.m_viewbalance_privkey = k_view_balance;

            output_proposals_inout.emplace_back();
            normal_change.get_output_proposal_v1(output_proposals_inout.back());
        }
    }
    else if (output_proposals_inout.size() == 2 &&
        output_proposals_inout[0].m_enote_ephemeral_pubkey == output_proposals_inout[1].m_enote_ephemeral_pubkey)
    {
        if (change_amount == 0)
        {
            if (jamtis::is_self_send_output_proposal(output_proposals_inout[0], wallet_spend_pubkey, k_view_balance) &&
                jamtis::is_self_send_output_proposal(output_proposals_inout[1], wallet_spend_pubkey, k_view_balance))
            {
                CHECK_AND_ASSERT_THROW_MES(false, "Finalize output proposals: there are 2 self-send outputs that share "
                    "an enote ephemeral pubkey, but this can reduce user privacy. If you want to send money to yourself, "
                    "make independent self-spend types, or avoid calling this function (not recommended).");
            }
            else //(at most 1 output proposal is a self-send)
            {
                // do nothing: the proposal set is already 'final'
            }
        }
        else //(change_amount > 0)
        {
            CHECK_AND_ASSERT_THROW_MES(false, "Finalize output proposals: there are 2 outputs that share "
                "an enote ephemeral pubkey, but a non-zero change amount. In >2-out txs, all enote ephemeral pubkeys should "
                "be unique, so adding a change output isn't feasible here. You need to make independent output proposals, "
                "or avoid calling this function (not recommended).");
        }
    }
    else //(output_proposals_inout.size() > 2)
    {
        CHECK_AND_ASSERT_THROW_MES(check_output_proposal_set_unique_ephemeral_pubkeys_v1(output_proposals_inout),
            "Finalize output proposals: there are >2 outputs but their enote ephemeral pubkeys aren't all unique.");

        if (change_amount == 0)
        {
            // do nothing: the proposal set is already 'final'
        }
        else //(change_amount > 0)
        {
            // >2 separate outputs + 1 change output = a simple tx with 3+ outputs

            // add a normal change output
            // - 'change' amount
            jamtis::JamtisPaymentProposalSelfSendV1 normal_change;
            normal_change.m_destination = change_destination;
            normal_change.m_amount = change_amount;
            normal_change.m_type = jamtis::JamtisSelfSendMAC::CHANGE;
            normal_change.m_enote_ephemeral_privkey = rct::rct2sk(rct::skGen());
            normal_change.m_viewbalance_privkey = k_view_balance;

            output_proposals_inout.emplace_back();
            normal_change.get_output_proposal_v1(output_proposals_inout.back());
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_proposal_v1(std::vector<SpOutputProposalV1> output_proposals,
    std::vector<ExtraFieldElement> additional_memo_elements,
    SpTxProposalV1 &proposal_out)
{
    // outputs should be sorted by onetime address
    std::sort(output_proposals.begin(), output_proposals.end());

    // sanity-check semantics
    check_v1_output_proposal_set_semantics_v1(output_proposals);

    // make outputs
    // make tx supplement
    // prepare for range proofs
    make_v1_outputs_v1(output_proposals,
        proposal_out.m_outputs,
        proposal_out.m_output_amounts,
        proposal_out.m_output_amount_commitment_blinding_factors,
        proposal_out.m_tx_supplement.m_output_enote_ephemeral_pubkeys);

    // add all memo fields to the tx supplement
    for (const SpOutputProposalV1 &output_proposal : output_proposals)
        accumulate_extra_field_elements(output_proposal.m_partial_memo, additional_memo_elements);

    make_tx_extra(std::move(additional_memo_elements), proposal_out.m_tx_supplement.m_tx_extra);

    // sanity-check semantics
    check_v1_tx_supplement_semantics_v1(proposal_out.m_tx_supplement, proposal_out.m_outputs.size());
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<SpOutputProposalV1> gen_mock_sp_output_proposals_v1(const std::vector<rct::xmr_amount> &out_amounts,
    const std::size_t num_random_memo_elements)
{
    // generate random output proposals
    std::vector<SpOutputProposalV1> output_proposals;
    output_proposals.reserve(out_amounts.size());

    for (const rct::xmr_amount out_amount : out_amounts)
    {
        output_proposals.emplace_back();
        output_proposals.back().gen(out_amount, num_random_memo_elements);
    }

    // sort them
    std::sort(output_proposals.begin(), output_proposals.end());

    return output_proposals;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
