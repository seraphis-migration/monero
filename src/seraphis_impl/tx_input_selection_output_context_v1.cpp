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

//paired header
#include "tx_input_selection_output_context_v1.h"

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_payment_proposal.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_main/tx_builders_outputs.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <unordered_set>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_impl"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
// check that all enote ephemeral pubkeys in an output proposal set are unique
//-------------------------------------------------------------------------------------------------------------------
static bool ephemeral_pubkeys_are_unique(const std::vector<jamtis::JamtisPaymentProposalV1> &normal_payment_proposals,
    const std::vector<jamtis::JamtisPaymentProposalSelfSendV1> &selfsend_payment_proposals)
{
    std::unordered_set<crypto::x25519_pubkey> enote_ephemeral_pubkeys;
    enote_ephemeral_pubkeys.reserve(normal_payment_proposals.size() + selfsend_payment_proposals.size());
    crypto::x25519_pubkey temp_enote_ephemeral_pubkey;

    for (const jamtis::JamtisPaymentProposalV1 &normal_proposal : normal_payment_proposals)
    {
        jamtis::get_enote_ephemeral_pubkey(normal_proposal, temp_enote_ephemeral_pubkey);
        enote_ephemeral_pubkeys.insert(temp_enote_ephemeral_pubkey);
    }

    for (const jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_proposal : selfsend_payment_proposals)
    {
        jamtis::get_enote_ephemeral_pubkey(selfsend_proposal, temp_enote_ephemeral_pubkey);
        enote_ephemeral_pubkeys.insert(temp_enote_ephemeral_pubkey);
    }

    return enote_ephemeral_pubkeys.size() == normal_payment_proposals.size() + selfsend_payment_proposals.size();
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool need_additional_output(const std::size_t num_outputs,
    const bool output_ephemeral_pubkeys_are_unique,
    const std::vector<jamtis::JamtisSelfSendType> &self_send_output_types,
    const rct::xmr_amount change_amount)
{
    // see if we need an additional output
    return static_cast<bool>(try_get_additional_output_type_for_output_set_v1(num_outputs,
        self_send_output_types,
        output_ephemeral_pubkeys_are_unique,
        change_amount));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
OutputSetContextForInputSelectionV1::OutputSetContextForInputSelectionV1(
    const std::vector<jamtis::JamtisPaymentProposalV1> &normal_payment_proposals,
    const std::vector<jamtis::JamtisPaymentProposalSelfSendV1> &selfsend_payment_proposals) :
        m_num_outputs{normal_payment_proposals.size() + selfsend_payment_proposals.size()},
        m_output_ephemeral_pubkeys_are_unique{
                ephemeral_pubkeys_are_unique(normal_payment_proposals, selfsend_payment_proposals)
            }
{
    // 1. collect self-send output types
    m_self_send_output_types.reserve(selfsend_payment_proposals.size());

    for (const jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_proposal : selfsend_payment_proposals)
        m_self_send_output_types.emplace_back(selfsend_proposal.type);

    // 2. collect total amount
    m_total_output_amount = 0;

    for (const jamtis::JamtisPaymentProposalV1 &normal_proposal : normal_payment_proposals)
        m_total_output_amount += normal_proposal.amount;

    for (const jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_proposal : selfsend_payment_proposals)
        m_total_output_amount += selfsend_proposal.amount;
}
//-------------------------------------------------------------------------------------------------------------------
boost::multiprecision::uint128_t OutputSetContextForInputSelectionV1::total_amount() const
{
    return m_total_output_amount;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t OutputSetContextForInputSelectionV1::num_outputs_nochange() const
{
    const bool need_additional_output_no_change{
            need_additional_output(m_num_outputs, m_output_ephemeral_pubkeys_are_unique, m_self_send_output_types, 0)
        };

    return m_num_outputs + (need_additional_output_no_change ? 1 : 0);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t OutputSetContextForInputSelectionV1::num_outputs_withchange() const
{
    const bool need_additional_output_with_change{
            need_additional_output(m_num_outputs, m_output_ephemeral_pubkeys_are_unique, m_self_send_output_types, 1)
        };

    return m_num_outputs + (need_additional_output_with_change ? 1 : 0);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
