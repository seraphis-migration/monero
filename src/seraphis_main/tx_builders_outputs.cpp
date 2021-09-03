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
#include "tx_builders_outputs.h"

//local headers
#include "common/container_helpers.h"
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "cryptonote_config.h"
#include "enote_record_types.h"
#include "enote_record_utils.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_core_utils.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_core/jamtis_payment_proposal.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_core/tx_extra.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "tx_builder_types.h"
#include "tx_component_types.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"
#include "boost/optional/optional.hpp"

//standard headers
#include <algorithm>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool ephemeral_pubkeys_are_unique(const std::vector<SpCoinbaseOutputProposalV1> &output_proposals)
{
    std::unordered_set<crypto::x25519_pubkey> enote_ephemeral_pubkeys;
    enote_ephemeral_pubkeys.reserve(output_proposals.size());

    for (const SpCoinbaseOutputProposalV1 &output_proposal : output_proposals)
        enote_ephemeral_pubkeys.insert(output_proposal.enote_ephemeral_pubkey);

    return enote_ephemeral_pubkeys.size() == output_proposals.size();
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool ephemeral_pubkeys_are_unique(const std::vector<SpOutputProposalV1> &output_proposals)
{
    std::unordered_set<crypto::x25519_pubkey> enote_ephemeral_pubkeys;
    enote_ephemeral_pubkeys.reserve(output_proposals.size());

    for (const SpOutputProposalV1 &output_proposal : output_proposals)
        enote_ephemeral_pubkeys.insert(output_proposal.enote_ephemeral_pubkey);

    return enote_ephemeral_pubkeys.size() == output_proposals.size();
}
//-------------------------------------------------------------------------------------------------------------------
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
static void make_additional_output_normal_dummy_v1(jamtis::JamtisPaymentProposalV1 &dummy_proposal_out)
{
    // make random payment proposal for a 'normal' dummy output
    dummy_proposal_out.destination             = jamtis::gen_jamtis_destination_v1();
    dummy_proposal_out.amount                  = 0;
    dummy_proposal_out.enote_ephemeral_privkey = crypto::x25519_secret_key_gen();
    dummy_proposal_out.partial_memo            = TxExtra{};
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_additional_output_special_dummy_v1(const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    jamtis::JamtisPaymentProposalV1 &dummy_proposal_out)
{
    // make random payment proposal for a 'special' dummy output that uses a shared enote ephemeral pubkey
    dummy_proposal_out.destination             = jamtis::gen_jamtis_destination_v1();
    crypto::x25519_invmul_key({crypto::x25519_eight()},
        enote_ephemeral_pubkey,
        dummy_proposal_out.destination.addr_K3);  //(1/8) * xK_e_other
    dummy_proposal_out.amount                  = 0;
    dummy_proposal_out.enote_ephemeral_privkey = crypto::x25519_eight();  //r = 8 (can't do r = 1 for x25519)
    dummy_proposal_out.partial_memo            = TxExtra{};
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_additional_output_normal_self_send_v1(const jamtis::JamtisSelfSendType self_send_type,
    const jamtis::JamtisDestinationV1 &destination,
    const rct::xmr_amount amount,
    jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_proposal_out)
{
    // build payment proposal for a 'normal' self-send
    selfsend_proposal_out.destination             = destination;
    selfsend_proposal_out.amount                  = amount;
    selfsend_proposal_out.type                    = self_send_type;
    selfsend_proposal_out.enote_ephemeral_privkey = crypto::x25519_secret_key_gen();
    selfsend_proposal_out.partial_memo            = TxExtra{};
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_additional_output_special_self_send_v1(const jamtis::JamtisSelfSendType self_send_type,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const jamtis::JamtisDestinationV1 &destination,
    const crypto::secret_key &k_view_balance,
    const rct::xmr_amount amount,
    jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_proposal_out)
{
    // build payment proposal for a 'special' self-send that uses a shared enote ephemeral pubkey

    // 1. edit the destination to use adjusted DH keys so the proposal's ephemeral pubkey will match the input value
    //    while still allowing balance recovery with our xk_fr
    crypto::x25519_secret_key xk_find_received;
    jamtis::make_jamtis_findreceived_key(k_view_balance, xk_find_received);

    crypto::x25519_pubkey special_addr_K2;
    crypto::x25519_scmul_key(xk_find_received, enote_ephemeral_pubkey, special_addr_K2);  //xk_fr * xK_e_other

    selfsend_proposal_out.destination = destination;
    crypto::x25519_invmul_key({crypto::x25519_eight()},
        special_addr_K2,
        selfsend_proposal_out.destination.addr_K2);  //(1/8) * xk_fr * xK_e_other
    crypto::x25519_invmul_key({crypto::x25519_eight()},
        enote_ephemeral_pubkey,
        selfsend_proposal_out.destination.addr_K3);  //(1/8) * xK_e_other

    // 2. complete the proposal
    selfsend_proposal_out.amount                  = amount;
    selfsend_proposal_out.type                    = self_send_type;
    selfsend_proposal_out.enote_ephemeral_privkey = crypto::x25519_eight();  //r = 8 (can't do r = 1 for x25519)
    selfsend_proposal_out.partial_memo            = TxExtra{};
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void check_jamtis_payment_proposal_selfsend_semantics_v1(
    const jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_payment_proposal,
    const rct::key &input_context,
    const rct::key &spend_pubkey,
    const crypto::secret_key &k_view_balance)
{
    // 1. convert to an output proposal
    SpOutputProposalV1 output_proposal;
    make_v1_output_proposal_v1(selfsend_payment_proposal, k_view_balance, input_context, output_proposal);

    // 2. extract enote from output proposal
    SpEnoteV1 temp_enote;
    get_enote_v1(output_proposal, temp_enote);

    // 3. try to get an enote record from the enote (via selfsend path)
    SpEnoteRecordV1 temp_enote_record;
    CHECK_AND_ASSERT_THROW_MES(try_get_enote_record_v1_selfsend(temp_enote,
            output_proposal.enote_ephemeral_pubkey,
            input_context,
            spend_pubkey,
            k_view_balance,
            temp_enote_record),
        "semantics check jamtis self-send payment proposal v1: failed to extract enote record from the proposal.");

    // 4. extract the self-send type
    jamtis::JamtisSelfSendType dummy_type;
    CHECK_AND_ASSERT_THROW_MES(jamtis::try_get_jamtis_self_send_type(temp_enote_record.type, dummy_type),
        "semantics check jamtis self-send payment proposal v1: failed to convert enote type to self-send type (bug).");
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_coinbase_output_proposal_semantics_v1(const SpCoinbaseOutputProposalV1 &output_proposal)
{
    std::vector<ExtraFieldElement> additional_memo_elements;
    CHECK_AND_ASSERT_THROW_MES(try_get_extra_field_elements(output_proposal.partial_memo, additional_memo_elements),
        "coinbase output proposal semantics (v1): invalid partial memo.");
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_coinbase_output_proposal_set_semantics_v1(const std::vector<SpCoinbaseOutputProposalV1> &output_proposals)
{
    CHECK_AND_ASSERT_THROW_MES(output_proposals.size() >= 1,
        "Semantics check coinbase output proposals v1: insufficient outputs.");

    // 1. output proposals should be internally valid
    for (const SpCoinbaseOutputProposalV1 &output_proposal : output_proposals)
        check_v1_coinbase_output_proposal_semantics_v1(output_proposal);

    // 2. all enote ephemeral pubkeys should be unique in coinbase output sets
    CHECK_AND_ASSERT_THROW_MES(ephemeral_pubkeys_are_unique(output_proposals),
        "Semantics check coinbase output proposals v1: enote ephemeral pubkeys aren't all unique.");

    // 3. proposals should be sorted and unique
    CHECK_AND_ASSERT_THROW_MES(tools::is_sorted_and_unique(output_proposals, compare_Ko),
        "Semantics check output proposals v1: output onetime addresses are not sorted and unique.");

    // 4. proposal onetime addresses should be canonical (sanity check so our tx outputs don't end up with duplicate
    //    key images)
    for (const SpCoinbaseOutputProposalV1 &output_proposal : output_proposals)
    {
        CHECK_AND_ASSERT_THROW_MES(onetime_address_is_canonical(output_proposal.enote.core),
            "Semantics check coinbase output proposals v1: an output onetime address is not in the prime subgroup.");
    }
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_output_proposal_semantics_v1(const SpOutputProposalV1 &output_proposal)
{
    std::vector<ExtraFieldElement> additional_memo_elements;
    CHECK_AND_ASSERT_THROW_MES(try_get_extra_field_elements(output_proposal.partial_memo, additional_memo_elements),
        "output proposal semantics (v1): invalid partial memo.");
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_output_proposal_set_semantics_v1(const std::vector<SpOutputProposalV1> &output_proposals)
{
    CHECK_AND_ASSERT_THROW_MES(output_proposals.size() >= 1, "Semantics check output proposals v1: insufficient outputs.");

    // 1. output proposals should be internally valid
    for (const SpOutputProposalV1 &output_proposal : output_proposals)
        check_v1_output_proposal_semantics_v1(output_proposal);

    // 2. if 2 proposals, must be a shared enote ephemeral pubkey
    if (output_proposals.size() == 2)
    {
        CHECK_AND_ASSERT_THROW_MES(output_proposals[0].enote_ephemeral_pubkey == 
                output_proposals[1].enote_ephemeral_pubkey,
            "Semantics check output proposals v1: there are 2 outputs but they don't share an enote ephemeral pubkey.");
    }

    // 3. if >2 proposals, all enote ephemeral pubkeys should be unique
    if (output_proposals.size() > 2)
    {
        CHECK_AND_ASSERT_THROW_MES(ephemeral_pubkeys_are_unique(output_proposals),
            "Semantics check output proposals v1: there are >2 outputs but their enote ephemeral pubkeys aren't all "
            "unique.");
    }

    // 4. proposals should be sorted and unique
    CHECK_AND_ASSERT_THROW_MES(tools::is_sorted_and_unique(output_proposals, compare_Ko),
        "Semantics check output proposals v1: output onetime addresses are not sorted and unique.");

    // 5. proposal onetime addresses should be canonical (sanity check so our tx outputs don't end up with duplicate
    //    key images)
    for (const SpOutputProposalV1 &output_proposal : output_proposals)
    {
        CHECK_AND_ASSERT_THROW_MES(onetime_address_is_canonical(output_proposal.core),
            "Semantics check output proposals v1: an output onetime address is not in the prime subgroup.");
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_coinbase_output_proposal_v1(const jamtis::JamtisPaymentProposalV1 &proposal,
    const std::uint64_t block_height,
    SpCoinbaseOutputProposalV1 &output_proposal_out)
{
    jamtis::get_coinbase_output_proposal_v1(proposal,
        block_height,
        output_proposal_out.enote.core,
        output_proposal_out.enote_ephemeral_pubkey,
        output_proposal_out.enote.addr_tag_enc,
        output_proposal_out.enote.view_tag,
        output_proposal_out.partial_memo);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_output_proposal_v1(const jamtis::JamtisPaymentProposalV1 &proposal,
    const rct::key &input_context,
    SpOutputProposalV1 &output_proposal_out)
{
    jamtis::get_output_proposal_v1(proposal,
        input_context,
        output_proposal_out.core,
        output_proposal_out.enote_ephemeral_pubkey,
        output_proposal_out.encoded_amount,
        output_proposal_out.addr_tag_enc,
        output_proposal_out.view_tag,
        output_proposal_out.partial_memo);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_output_proposal_v1(const jamtis::JamtisPaymentProposalSelfSendV1 &proposal,
    const crypto::secret_key &k_view_balance,
    const rct::key &input_context,
    SpOutputProposalV1 &output_proposal_out)
{
    jamtis::get_output_proposal_v1(proposal,
        k_view_balance,
        input_context,
        output_proposal_out.core,
        output_proposal_out.enote_ephemeral_pubkey,
        output_proposal_out.encoded_amount,
        output_proposal_out.addr_tag_enc,
        output_proposal_out.view_tag,
        output_proposal_out.partial_memo);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_coinbase_outputs_v1(const std::vector<SpCoinbaseOutputProposalV1> &output_proposals,
    std::vector<SpCoinbaseEnoteV1> &outputs_out,
    std::vector<crypto::x25519_pubkey> &output_enote_ephemeral_pubkeys_out)
{
    // 1. output proposal set should be valid
    check_v1_coinbase_output_proposal_set_semantics_v1(output_proposals);

    // 2. extract tx output information from output proposals
    outputs_out.clear();
    outputs_out.reserve(output_proposals.size());
    output_enote_ephemeral_pubkeys_out.clear();
    output_enote_ephemeral_pubkeys_out.reserve(output_proposals.size());

    for (const SpCoinbaseOutputProposalV1 &output_proposal : output_proposals)
    {
        // a. convert to enote
        outputs_out.emplace_back(output_proposal.enote);

        // b. copy unique enote pubkeys to tx supplement (note: the semantics checker should prevent duplicates)
        if (std::find(output_enote_ephemeral_pubkeys_out.begin(),
                output_enote_ephemeral_pubkeys_out.end(),
                output_proposal.enote_ephemeral_pubkey) == output_enote_ephemeral_pubkeys_out.end())
            output_enote_ephemeral_pubkeys_out.emplace_back(output_proposal.enote_ephemeral_pubkey);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_outputs_v1(const std::vector<SpOutputProposalV1> &output_proposals,
    std::vector<SpEnoteV1> &outputs_out,
    std::vector<rct::xmr_amount> &output_amounts_out,
    std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors_out,
    std::vector<crypto::x25519_pubkey> &output_enote_ephemeral_pubkeys_out)
{
    // 1. output proposal set should be valid
    check_v1_output_proposal_set_semantics_v1(output_proposals);

    // 2. extract tx output information from output proposals
    outputs_out.clear();
    outputs_out.reserve(output_proposals.size());
    output_amounts_out.clear();
    output_amounts_out.reserve(output_proposals.size());
    output_amount_commitment_blinding_factors_out.clear();
    output_amount_commitment_blinding_factors_out.reserve(output_proposals.size());
    output_enote_ephemeral_pubkeys_out.clear();
    output_enote_ephemeral_pubkeys_out.reserve(output_proposals.size());

    for (const SpOutputProposalV1 &output_proposal : output_proposals)
    {
        // a. sanity check
        // note: a blinding factor of 0 is allowed (but not recommended)
        CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(output_proposal.core.amount_blinding_factor)) == 0,
            "making v1 outputs: invalid amount blinding factor (non-canonical).");

        // b. convert to enote
        get_enote_v1(output_proposal, tools::add_element(outputs_out));

        // c. cache amount commitment information for range proofs
        output_amounts_out.emplace_back(amount_ref(output_proposal));
        output_amount_commitment_blinding_factors_out.emplace_back(output_proposal.core.amount_blinding_factor);

        // d. copy unique enote pubkeys to tx supplement
        if (std::find(output_enote_ephemeral_pubkeys_out.begin(),
                output_enote_ephemeral_pubkeys_out.end(),
                output_proposal.enote_ephemeral_pubkey) == output_enote_ephemeral_pubkeys_out.end())
            output_enote_ephemeral_pubkeys_out.emplace_back(output_proposal.enote_ephemeral_pubkey);
    }
}
//-------------------------------------------------------------------------------------------------------------------
boost::optional<OutputProposalSetExtraTypeV1> try_get_additional_output_type_for_output_set_v1(
    const std::size_t num_outputs,
    const std::vector<jamtis::JamtisSelfSendType> &self_send_output_types,
    const bool output_ephemeral_pubkeys_are_unique,
    const rct::xmr_amount change_amount)
{
    // 1. txs should have at least 1 non-change output
    CHECK_AND_ASSERT_THROW_MES(num_outputs > 0, "Additional output type v1: 0 outputs specified. If you want to send "
        "money to yourself, use a self-spend enote type instead of forcing it via a change enote type.");

    // 2. sanity check
    CHECK_AND_ASSERT_THROW_MES(self_send_output_types.size() <= num_outputs,
        "Additional output type v1: there are more self-send outputs than outputs.");

    // 3. if an extra output is needed, get it
    if (num_outputs == 1)
    {
        if (change_amount == 0)
        {
            if (self_send_output_types.size() == 1)
            {
                // txs need at least 2 outputs; we already have a self-send, so make a random special dummy output

                // add a special dummy output
                // - 0 amount
                // - make sure the final proposal set will have 1 unique enote ephemeral pubkey
                return OutputProposalSetExtraTypeV1::SPECIAL_DUMMY;
            }
            else //(no self-send)
            {
                // txs need at least 2 outputs, with at least 1 self-send enote type

                // add a special self-send dummy output
                // - 0 amount
                // - make sure the final proposal set will have 1 unique enote ephemeral pubkey
                return OutputProposalSetExtraTypeV1::SPECIAL_SELF_SEND_DUMMY;
            }
        }
        else if (/*change_amount > 0 &&*/
            self_send_output_types.size() == 1 &&
            self_send_output_types[0] == jamtis::JamtisSelfSendType::CHANGE)
        {
            // 2-out txs may not have 2 self-send type enotes of the same type from the same wallet, so since
            //   we already have a change output (for some dubious reason) we can't have a special change here
            // reason: the outputs in a 2-out tx with 2 same-type self-sends would have the same sender-receiver shared
            //         secret, which could cause problems (e.g. the outputs would have the same view tags, and could even
            //         have the same onetime address if the destinations of the two outputs are the same)

            // two change outputs doesn't make sense, so just ban it
            CHECK_AND_ASSERT_THROW_MES(false, "Additional output type v1: there is 1 change-type output already "
                "specified, but the change amount is non-zero and a tx with just two change outputs is not allowed "
                "for privacy reasons. If you want to make a tx with just two change outputs, avoid calling this function "
                "(not recommended).");
        }
        else //(change_amount > 0 && single output is not a self-send change)
        {
            // if there is 1 non-change output and non-zero change, then make a special change output that shares
            //   the other output's enote ephemeral pubkey

            // add a special change output
            // - 'change' amount
            // - make sure the final proposal set will have 1 unique enote ephemeral pubkey
            return OutputProposalSetExtraTypeV1::SPECIAL_CHANGE;
        }
    }
    else if (num_outputs == 2 && output_ephemeral_pubkeys_are_unique)
    {
        if (change_amount == 0)
        {
            // 2-out txs need 1 shared enote ephemeral pubkey; add a dummy output here since the outputs have different
            //   enote ephemeral pubkeys

            if (self_send_output_types.size() > 0)
            {
                // if we have at least 1 self-send already, we can just make a normal dummy output

                // add a normal dummy output
                // - 0 amount
                return OutputProposalSetExtraTypeV1::NORMAL_DUMMY;
            }
            else //(no self-sends)
            {
                // if there are no self-sends, then we need to add a dummy self-send

                // add a normal self-send dummy output
                // - 0 amount
                return OutputProposalSetExtraTypeV1::NORMAL_SELF_SEND_DUMMY;
            }
        }
        else //(change_amount > 0)
        {
            // 2 separate outputs + 1 change output = a simple 3-out tx

            // add a normal change output
            // - 'change' amount
            return OutputProposalSetExtraTypeV1::NORMAL_CHANGE;
        }
    }
    else if (num_outputs == 2 && !output_ephemeral_pubkeys_are_unique)
    {
        if (change_amount == 0)
        {
            if (self_send_output_types.size() == 2 &&
                self_send_output_types[0] == self_send_output_types[1])
            {
                CHECK_AND_ASSERT_THROW_MES(false, "Additional output type v1: there are 2 self-send outputs with the "
                    "same type that share an enote ephemeral pubkey, but this can reduce user privacy. If you want to "
                    "send money to yourself, then make independent self-spend types, or avoid calling this function (not "
                    "recommended).");
            }
            else if (self_send_output_types.size() > 0)
            {
                // do nothing: the proposal set is already 'final'
            }
            else //(no self-sends)
            {
                CHECK_AND_ASSERT_THROW_MES(false, "Additional output type v1: there are 2 normal outputs that share "
                    "an enote ephemeral pubkey, but every tx needs at least one self-send output (since the "
                    "2 outputs share an enote ephemeral pubkey, we can't add a dummy self-send). If you want "
                    "to make a 2-output tx with no self-sends, then avoid calling this function (not recommended).");
            }
        }
        else //(change_amount > 0)
        {
            CHECK_AND_ASSERT_THROW_MES(false, "Additional output type v1: there are 2 outputs that share "
                "an enote ephemeral pubkey, but a non-zero change amount. In >2-out txs, all enote ephemeral pubkeys "
                "should be unique, so adding a change output isn't feasible here. You need to make independent output "
                "proposals, or avoid calling this function (not recommended).");
        }
    }
    else //(num_outputs > 2)
    {
        CHECK_AND_ASSERT_THROW_MES(output_ephemeral_pubkeys_are_unique,
            "Additional output type v1: there are >2 outputs but their enote ephemeral pubkeys aren't all unique.");

        if (change_amount == 0)
        {
            if (self_send_output_types.size() > 0)
            {
                // do nothing: the proposal set is already 'final'
            }
            else //(no self-sends)
            {
                // every tx made by this function needs a self-send output, so make a dummy self-send here

                // add a normal self-send dummy output
                // - 0 amount
                return OutputProposalSetExtraTypeV1::NORMAL_SELF_SEND_DUMMY;
            }
        }
        else //(change_amount > 0)
        {
            // >2 separate outputs + 1 change output = a simple tx with 4+ outputs

            // add a normal change output
            // - 'change' amount
            return OutputProposalSetExtraTypeV1::NORMAL_CHANGE;
        }
    }

    return boost::none;
}
//-------------------------------------------------------------------------------------------------------------------
void make_additional_output_dummy_v1(const OutputProposalSetExtraTypeV1 additional_output_type,
    const crypto::x25519_pubkey &first_enote_ephemeral_pubkey,
    jamtis::JamtisPaymentProposalV1 &normal_proposal_out)
{
    // choose which output type to make, and make it
    if (additional_output_type == OutputProposalSetExtraTypeV1::NORMAL_DUMMY)
    {
        // normal dummy
        // - 0 amount
        make_additional_output_normal_dummy_v1(normal_proposal_out);
    }
    else if (additional_output_type == OutputProposalSetExtraTypeV1::SPECIAL_DUMMY)
    {
        // special dummy
        // - 0 amount
        // - shared enote ephemeral pubkey
        make_additional_output_special_dummy_v1(first_enote_ephemeral_pubkey, normal_proposal_out);
    }
    else
    {
        CHECK_AND_ASSERT_THROW_MES(false, "Unknown output proposal set extra type (dummy).");
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_additional_output_selfsend_v1(const OutputProposalSetExtraTypeV1 additional_output_type,
    const crypto::x25519_pubkey &first_enote_ephemeral_pubkey,
    const jamtis::JamtisDestinationV1 &change_destination,
    const jamtis::JamtisDestinationV1 &dummy_destination,
    const crypto::secret_key &k_view_balance,
    const rct::xmr_amount change_amount,
    jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_proposal_out)
{
    // choose which output type to make, and make it
    if (additional_output_type == OutputProposalSetExtraTypeV1::NORMAL_SELF_SEND_DUMMY)
    {
        // normal self-send dummy
        // - 0 amount
        make_additional_output_normal_self_send_v1(jamtis::JamtisSelfSendType::DUMMY,
            dummy_destination,
            0,
            selfsend_proposal_out);
    }
    else if (additional_output_type == OutputProposalSetExtraTypeV1::NORMAL_CHANGE)
    {
        // normal change
        // - 'change' amount
        make_additional_output_normal_self_send_v1(jamtis::JamtisSelfSendType::CHANGE,
            change_destination,
            change_amount,
            selfsend_proposal_out);
    }
    else if (additional_output_type == OutputProposalSetExtraTypeV1::SPECIAL_SELF_SEND_DUMMY)
    {
        // special self-send dummy
        // - 0 amount
        // - shared enote ephemeral pubkey
        make_additional_output_special_self_send_v1(jamtis::JamtisSelfSendType::DUMMY,
            first_enote_ephemeral_pubkey,
            dummy_destination,
            k_view_balance,
            0,
            selfsend_proposal_out);
    }
    else if (additional_output_type == OutputProposalSetExtraTypeV1::SPECIAL_CHANGE)
    {
        // special change
        // - 'change' amount
        // - shared enote ephemeral pubkey
        make_additional_output_special_self_send_v1(jamtis::JamtisSelfSendType::CHANGE,
            first_enote_ephemeral_pubkey,
            change_destination,
            k_view_balance,
            change_amount,
            selfsend_proposal_out);
    }
    else
    {
        CHECK_AND_ASSERT_THROW_MES(false, "Unknown output proposal set extra type (self-send).");
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_additional_output_v1(const jamtis::JamtisDestinationV1 &change_destination,
    const jamtis::JamtisDestinationV1 &dummy_destination,
    const crypto::secret_key &k_view_balance,
    const rct::xmr_amount change_amount,
    const OutputProposalSetExtraTypeV1 additional_output_type,
    const crypto::x25519_pubkey &first_enote_ephemeral_pubkey,
    std::vector<jamtis::JamtisPaymentProposalV1> &normal_payment_proposals_inout,
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> &selfsend_payment_proposals_inout)
{
    if (additional_output_type == OutputProposalSetExtraTypeV1::NORMAL_DUMMY ||
        additional_output_type == OutputProposalSetExtraTypeV1::SPECIAL_DUMMY)
    {
        make_additional_output_dummy_v1(additional_output_type,
            first_enote_ephemeral_pubkey,
            tools::add_element(normal_payment_proposals_inout));
    }
    else
    {
        make_additional_output_selfsend_v1(additional_output_type,
            first_enote_ephemeral_pubkey,
            change_destination,
            dummy_destination,
            k_view_balance,
            change_amount,
            tools::add_element(selfsend_payment_proposals_inout));
    }
}
//-------------------------------------------------------------------------------------------------------------------
void finalize_v1_output_proposal_set_v1(const boost::multiprecision::uint128_t &total_input_amount,
    const rct::xmr_amount transaction_fee,
    const jamtis::JamtisDestinationV1 &change_destination,
    const jamtis::JamtisDestinationV1 &dummy_destination,
    const crypto::secret_key &k_view_balance,
    std::vector<jamtis::JamtisPaymentProposalV1> &normal_payment_proposals_inout,
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> &selfsend_payment_proposals_inout)
{
    // 1. get change amount
    boost::multiprecision::uint128_t output_sum{transaction_fee};

    for (const jamtis::JamtisPaymentProposalV1 &normal_proposal : normal_payment_proposals_inout)
        output_sum += normal_proposal.amount;

    for (const jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_proposal : selfsend_payment_proposals_inout)
        output_sum += selfsend_proposal.amount;

    CHECK_AND_ASSERT_THROW_MES(total_input_amount >= output_sum,
        "Finalize output proposals v1: input amount is too small.");
    CHECK_AND_ASSERT_THROW_MES(total_input_amount - output_sum <= static_cast<rct::xmr_amount>(-1),
        "Finalize output proposals v1: change amount exceeds maximum value allowed.");

    const rct::xmr_amount change_amount{total_input_amount - output_sum};

    // 2. collect self-send output types
    std::vector<jamtis::JamtisSelfSendType> self_send_output_types;
    self_send_output_types.reserve(selfsend_payment_proposals_inout.size());

    for (const jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_proposal : selfsend_payment_proposals_inout)
        self_send_output_types.emplace_back(selfsend_proposal.type);

    // 3. set the shared enote ephemeral pubkey here: it will always be the first one when it is needed
    crypto::x25519_pubkey first_enote_ephemeral_pubkey{};

    if (normal_payment_proposals_inout.size() > 0)
        jamtis::get_enote_ephemeral_pubkey(normal_payment_proposals_inout[0], first_enote_ephemeral_pubkey);
    else if (selfsend_payment_proposals_inout.size() > 0)
        jamtis::get_enote_ephemeral_pubkey(selfsend_payment_proposals_inout[0], first_enote_ephemeral_pubkey);

    // 4. add an additional output if necessary
    if (const auto additional_output_type =
            try_get_additional_output_type_for_output_set_v1(
                normal_payment_proposals_inout.size() + selfsend_payment_proposals_inout.size(),
                self_send_output_types,
                ephemeral_pubkeys_are_unique(normal_payment_proposals_inout, selfsend_payment_proposals_inout),
                change_amount)
        )
    {
        make_additional_output_v1(change_destination,
            dummy_destination,
            k_view_balance,
            change_amount,
            *additional_output_type,
            first_enote_ephemeral_pubkey,
            normal_payment_proposals_inout,
            selfsend_payment_proposals_inout);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void finalize_tx_extra_v1(const TxExtra &partial_memo,
    const std::vector<SpCoinbaseOutputProposalV1> &output_proposals,
    TxExtra &tx_extra_out)
{
    // 1. collect all memo elements
    std::vector<ExtraFieldElement> collected_memo_elements;
    accumulate_extra_field_elements(partial_memo, collected_memo_elements);

    for (const SpCoinbaseOutputProposalV1 &output_proposal : output_proposals)
        accumulate_extra_field_elements(output_proposal.partial_memo, collected_memo_elements);

    // 2. finalize the extra field
    make_tx_extra(std::move(collected_memo_elements), tx_extra_out);
}
//-------------------------------------------------------------------------------------------------------------------
void finalize_tx_extra_v1(const TxExtra &partial_memo,
    const std::vector<SpOutputProposalV1> &output_proposals,
    TxExtra &tx_extra_out)
{
    // 1. collect all memo elements
    std::vector<ExtraFieldElement> collected_memo_elements;
    accumulate_extra_field_elements(partial_memo, collected_memo_elements);

    for (const SpOutputProposalV1 &output_proposal : output_proposals)
        accumulate_extra_field_elements(output_proposal.partial_memo, collected_memo_elements);

    // 2. finalize the extra field
    make_tx_extra(std::move(collected_memo_elements), tx_extra_out);
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_tx_supplement_semantics_v1(const SpTxSupplementV1 &tx_supplement, const std::size_t num_outputs)
{
    // 1. num enote ephemeral pubkeys == num outputs
    CHECK_AND_ASSERT_THROW_MES(tx_supplement.output_enote_ephemeral_pubkeys.size() == num_outputs,
        "Semantics check tx supplement v1: there must be one enote pubkey for each output.");

    // 2. all enote pubkeys should be unique
    CHECK_AND_ASSERT_THROW_MES(keys_are_unique(tx_supplement.output_enote_ephemeral_pubkeys),
        "Semantics check tx supplement v1: enote pubkeys must be unique.");

    // 3. enote ephemeral pubkeys should not be zero
    // note: this is an easy check to do, but in no way guarantees the enote ephemeral pubkeys are valid/usable
    for (const crypto::x25519_pubkey &enote_ephemeral_pubkey : tx_supplement.output_enote_ephemeral_pubkeys)
    {
        CHECK_AND_ASSERT_THROW_MES(!(enote_ephemeral_pubkey == crypto::x25519_pubkey{}),
            "Semantics check tx supplement v1: an enote ephemeral pubkey is zero.");
    }

    // 4. the tx extra must be well-formed
    std::vector<ExtraFieldElement> extra_field_elements;
    CHECK_AND_ASSERT_THROW_MES(try_get_extra_field_elements(tx_supplement.tx_extra, extra_field_elements),
        "Semantics check tx supplement v1: could not extract extra field elements.");
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_tx_supplement_semantics_v2(const SpTxSupplementV1 &tx_supplement, const std::size_t num_outputs)
{
    // 1. there may be either 1 or 3+ enote pubkeys
    if (num_outputs <= 2)
    {
        CHECK_AND_ASSERT_THROW_MES(tx_supplement.output_enote_ephemeral_pubkeys.size() == 1,
            "Semantics check tx supplement v2: there must be 1 enote pubkey if there are <= 2 outputs.");
    }
    else
    {
        CHECK_AND_ASSERT_THROW_MES(tx_supplement.output_enote_ephemeral_pubkeys.size() == num_outputs,
            "Semantics check tx supplement v2: there must be one enote pubkey for each output when there are > 2 outputs.");
    }

    // 2. all enote pubkeys should be unique
    CHECK_AND_ASSERT_THROW_MES(keys_are_unique(tx_supplement.output_enote_ephemeral_pubkeys),
        "Semantics check tx supplement v2: enote pubkeys must be unique.");

    // 3. enote ephemeral pubkeys should not be zero
    // note: this is an easy check to do, but in no way guarantees the enote ephemeral pubkeys are valid/usable
    for (const crypto::x25519_pubkey &enote_ephemeral_pubkey : tx_supplement.output_enote_ephemeral_pubkeys)
    {
        CHECK_AND_ASSERT_THROW_MES(!(enote_ephemeral_pubkey == crypto::x25519_pubkey{}),
            "Semantics check tx supplement v2: an enote ephemeral pubkey is zero.");
    }

    // 4. the tx extra must be well-formed
    std::vector<ExtraFieldElement> extra_field_elements;
    CHECK_AND_ASSERT_THROW_MES(try_get_extra_field_elements(tx_supplement.tx_extra, extra_field_elements),
        "Semantics check tx supplement v2: could not extract extra field elements.");
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
