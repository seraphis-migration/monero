// Copyright (c) 2024, The Monero Project
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
#include "carrot_tx_builder.h"

//local headers
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "carrot_core/output_set_finalization.h"
#include "carrot_tx_format_utils.h"
#include "ringct/rctOps.h"
#include "tx_builder_inputs.h"

//third party headers

//standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "carrot_impl"

namespace carrot
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void append_additional_payment_proposal_if_necessary(
    std::vector<CarrotPaymentProposalV1>& normal_payment_proposals_inout,
    std::vector<CarrotPaymentProposalSelfSendV1> &selfsend_payment_proposals_inout,
    const crypto::public_key &change_address_spend_pubkey)
{
    struct append_additional_payment_proposal_if_necessary_visitor
    {
        void operator()(boost::blank) const {}
        void operator()(const CarrotPaymentProposalV1 &p) const { normal_proposals_inout.push_back(p); }
        void operator()(const CarrotPaymentProposalSelfSendV1 &p) const { selfsend_proposals_inout.push_back(p); }

        std::vector<CarrotPaymentProposalV1>& normal_proposals_inout;
        std::vector<CarrotPaymentProposalSelfSendV1> &selfsend_proposals_inout;
    };

    bool have_payment_type_selfsend = false;
    for (const CarrotPaymentProposalSelfSendV1 &selfsend_payment_proposal : selfsend_payment_proposals_inout)
    {
        if (selfsend_payment_proposal.enote_type == CarrotEnoteType::PAYMENT)
        {
            have_payment_type_selfsend = true;
            break;
        }
    }

    const auto additional_output_proposal = get_additional_output_proposal(normal_payment_proposals_inout.size(),
        selfsend_payment_proposals_inout.size(),
        /*needed_change_amount=*/0,
        have_payment_type_selfsend,
        change_address_spend_pubkey);

    additional_output_proposal.visit(append_additional_payment_proposal_if_necessary_visitor{
        normal_payment_proposals_inout,
        selfsend_payment_proposals_inout
    });
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void make_unsigned_transaction(std::vector<CarrotPaymentProposalV1> &normal_payment_proposals_inout,
    std::vector<CarrotPaymentProposalSelfSendV1> &selfsend_payment_proposals_inout,
    const rct::xmr_amount fee_per_weight,
    select_inputs_func_t &&select_inputs,
    carve_fees_and_balance_func_t &&carve_fees_and_balance,
    const view_balance_secret_device *s_view_balance_dev,
    const view_incoming_key_device *k_view_dev,
    const crypto::public_key &account_spend_pubkey,
    cryptonote::transaction &tx_out,
    std::vector<crypto::secret_key> &output_amount_blinding_factors_out)
{
    output_amount_blinding_factors_out.clear();

    // add an additional payment proposal to satisfy scanning/consensus rules, if applicable
    append_additional_payment_proposal_if_necessary(normal_payment_proposals_inout,
        selfsend_payment_proposals_inout,
        account_spend_pubkey);

    // generate random X25519 ephemeral pubkeys for selfsend proposals if not explicitly provided in a >2-out tx
    const size_t num_outs = normal_payment_proposals_inout.size() + selfsend_payment_proposals_inout.size();
    const bool will_shared_ephemeral_pubkey = num_outs == 2;
    if (!will_shared_ephemeral_pubkey)
    {
        for (CarrotPaymentProposalSelfSendV1 &selfsend_payment_proposal : selfsend_payment_proposals_inout)
        {
            if (!selfsend_payment_proposal.enote_ephemeral_pubkey)
                selfsend_payment_proposal.enote_ephemeral_pubkey = gen_x25519_pubkey();
        }
    }

    // calculate size of tx.extra
    const size_t tx_extra_size = get_carrot_default_tx_extra_size(num_outs);

    // calculate the concrete fee for this transaction for each possible valid input count
    std::map<size_t, rct::xmr_amount> fee_per_input_count;
    for (size_t num_ins = 1; num_ins <= CARROT_MAX_TX_INPUTS; ++num_ins)
    {
        const size_t tx_weight = get_fcmppp_tx_weight(num_ins, num_outs, tx_extra_size);
        const rct::xmr_amount fee = tx_weight * fee_per_weight; // @TODO: check for overflow here
        fee_per_input_count.emplace(num_ins, fee);
    }

    // calculate sum of payment proposal amounts before fee carving
    boost::multiprecision::int128_t nominal_output_amount_sum = 0;
    for (const CarrotPaymentProposalV1 &normal_proposal : normal_payment_proposals_inout)
        nominal_output_amount_sum += normal_proposal.amount;
    for (const CarrotPaymentProposalSelfSendV1 &selfsend_proposal : selfsend_payment_proposals_inout)
        nominal_output_amount_sum += selfsend_proposal.amount;

    // callback to select inputs given nominal output sum and fee per input count
    std::vector<CarrotSelectedInput> selected_inputs;
    select_inputs(nominal_output_amount_sum, fee_per_input_count, selected_inputs);

    // get fee given the number of selected inputs
    // note: this will fail if input selection returned a bad number of inputs
    const rct::xmr_amount fee = fee_per_input_count.at(selected_inputs.size());

    // calculate input amount sum
    boost::multiprecision::int128_t input_amount_sum = 0;
    for (const CarrotSelectedInput &selected_input : selected_inputs)
        input_amount_sum += selected_input.amount;

    // callback to balance the outputs with the fee and input sum
    carve_fees_and_balance(input_amount_sum, fee, normal_payment_proposals_inout, selfsend_payment_proposals_inout);

    // sanity check balance
    input_amount_sum -= fee;
    for (const CarrotPaymentProposalV1 &normal_payment_proposal : normal_payment_proposals_inout)
        input_amount_sum -= normal_payment_proposal.amount;
    for (const CarrotPaymentProposalSelfSendV1 &selfsend_payment_proposal : selfsend_payment_proposals_inout)
        input_amount_sum -= selfsend_payment_proposal.amount;
    CHECK_AND_ASSERT_THROW_MES(input_amount_sum == 0,
        "make unsigned transaction: post-carved transaction does not balance");

    // sort inputs by key image and get first key image
    std::sort(selected_inputs.begin(), selected_inputs.end(), [](const auto &a, const auto &b){
        return compare_input_key_images(a.key_image, b.key_image);
    });
    const crypto::key_image &tx_first_key_image = selected_inputs.at(0).key_image;

    // finalize payment proposals into enotes
    std::vector<RCTOutputEnoteProposal> output_enote_proposals;
    encrypted_payment_id_t encrypted_payment_id;
    get_output_enote_proposals(normal_payment_proposals_inout,
        selfsend_payment_proposals_inout,
        s_view_balance_dev,
        k_view_dev,
        account_spend_pubkey,
        tx_first_key_image,
        output_enote_proposals,
        encrypted_payment_id);

    // collect enotes and blinding factors
    std::vector<CarrotEnoteV1> enotes;
    enotes.reserve(output_enote_proposals.size());
    output_amount_blinding_factors_out.reserve(output_enote_proposals.size());
    for (const RCTOutputEnoteProposal &e : output_enote_proposals)
    {
        enotes.push_back(e.enote);
        output_amount_blinding_factors_out.push_back(e.amount_blinding_factor);
    }

    // collect key images
    std::vector<crypto::key_image> key_images;
    key_images.reserve(selected_inputs.size());
    for (const CarrotSelectedInput &selected_input : selected_inputs)
        key_images.push_back(selected_input.key_image);

    // serialize pruned transaction
    tx_out = store_carrot_to_transaction_v1(enotes, key_images, fee, encrypted_payment_id);
}
//-------------------------------------------------------------------------------------------------------------------
void make_unsigned_transaction_transfer_subtractable(
    std::vector<CarrotPaymentProposalV1> &normal_payment_proposals_inout,
    std::vector<CarrotPaymentProposalSelfSendV1> &selfsend_payment_proposals_inout,
    const rct::xmr_amount fee_per_weight,
    select_inputs_func_t &&select_inputs,
    const view_balance_secret_device *s_view_balance_dev,
    const view_incoming_key_device *k_view_dev,
    const crypto::public_key &account_spend_pubkey,
    const std::set<std::size_t> &subtractable_normal_payment_proposals,
    const std::set<std::size_t> &subtractable_selfsend_payment_proposals,
    cryptonote::transaction &tx_out,
    std::vector<crypto::secret_key> &output_amount_blinding_factors_out)
{
    // always add implicit selfsend enote, so resultant enotes' amounts mirror given payments set close as possible 
    // note: we always do this, even if the amount ends up being 0 and we already have a selfsend. this is because if we
    //       realize later that the change output we added here has a 0 amount, and we try removing it, then the fee
    //       would go down and then the change amount *wouldn't* be 0, so it must stay. Although technically,
    //       the scenario could arise where a change in input selection changes the input sum amount and fee exactly
    //       such that we could remove the implicit change output and it happens to balance. IMO, handling this edge
    //       case isn't worth the additional code complexity, and may cause unexpected uniformity issues. The calling
    //       code might expect that transfers to N destinations always produces a transaction with N+1 outputs
    const bool add_payment_type_selfsend = normal_payment_proposals_inout.empty() &&
        selfsend_payment_proposals_inout.size() == 1 &&
        selfsend_payment_proposals_inout.at(0).enote_type == CarrotEnoteType::CHANGE;

    selfsend_payment_proposals_inout.push_back(CarrotPaymentProposalSelfSendV1{
        .destination_address_spend_pubkey = account_spend_pubkey,
        .amount = 0,
        .enote_type = add_payment_type_selfsend ? CarrotEnoteType::PAYMENT : CarrotEnoteType::CHANGE
    });

    // define carves fees and balance callback
    carve_fees_and_balance_func_t carve_fees_and_balance =
    [
        &subtractable_normal_payment_proposals,
        &subtractable_selfsend_payment_proposals
    ]
    (
        const boost::multiprecision::int128_t &input_sum_amount,
        const rct::xmr_amount fee,
        std::vector<CarrotPaymentProposalV1> &normal_payment_proposals,
        std::vector<CarrotPaymentProposalSelfSendV1> &selfsend_payment_proposals
    )
    {
        const bool has_subbable_normal = !subtractable_normal_payment_proposals.empty();
        const bool has_subbable_selfsend = !subtractable_selfsend_payment_proposals.empty();
        const size_t num_normal = normal_payment_proposals.size();
        const size_t num_selfsend = selfsend_payment_proposals.size();

        // check subbable indices invariants
        CHECK_AND_ASSERT_THROW_MES(
            !has_subbable_normal || *subtractable_normal_payment_proposals.crbegin() < num_normal,
            "make unsigned transaction transfer subtractable: subtractable normal proposal index out of bounds");
        CHECK_AND_ASSERT_THROW_MES(
            !has_subbable_selfsend || *subtractable_selfsend_payment_proposals.crbegin() < num_selfsend,
            "make unsigned transaction transfer subtractable: subtractable selfsend proposal index out of bounds");
        CHECK_AND_ASSERT_THROW_MES(has_subbable_normal || has_subbable_selfsend,
            "make unsigned transaction transfer subtractable: no subtractable indices");

        // check selfsend proposal invariants
        CHECK_AND_ASSERT_THROW_MES(!selfsend_payment_proposals.empty(),
            "make unsigned transaction transfer subtractable: missing a selfsend proposal");
        CHECK_AND_ASSERT_THROW_MES(selfsend_payment_proposals.back().amount == 0,
            "make unsigned transaction transfer subtractable: bug: added implicit change output has non-zero amount");

        // start by setting the last selfsend amount equal to (inputs - outputs), before fee
        boost::multiprecision::int128_t implicit_change_amount = input_sum_amount;
        for (const CarrotPaymentProposalV1 &normal_payment_proposal : normal_payment_proposals)
            implicit_change_amount -= normal_payment_proposal.amount;
        for (const CarrotPaymentProposalSelfSendV1 &selfsend_payment_proposal : selfsend_payment_proposals)
            implicit_change_amount -= selfsend_payment_proposal.amount;
        
        selfsend_payment_proposals.back().amount = boost::numeric_cast<rct::xmr_amount>(implicit_change_amount);

        // deduct an even fee amount from all subtractable outputs
        const size_t num_subtractble_normal = subtractable_normal_payment_proposals.size();
        const size_t num_subtractable_selfsend = subtractable_selfsend_payment_proposals.size();
        const size_t num_subtractable = num_subtractble_normal + num_subtractable_selfsend;
        const rct::xmr_amount minimum_subtraction = fee / num_subtractable; // no div by 0 since we checked subtractable
        for (size_t normal_sub_idx : subtractable_normal_payment_proposals)
        {
            CarrotPaymentProposalV1 &normal_payment_proposal = normal_payment_proposals[normal_sub_idx];
            CHECK_AND_ASSERT_THROW_MES(normal_payment_proposal.amount >= minimum_subtraction,
                "make unsigned transaction transfer subtractable: not enough funds in subtractable payment");
            normal_payment_proposal.amount -= minimum_subtraction;
        }
        for (size_t selfsend_sub_idx : subtractable_selfsend_payment_proposals)
        {
            CarrotPaymentProposalSelfSendV1 &selfsend_payment_proposal = selfsend_payment_proposals[selfsend_sub_idx];
            CHECK_AND_ASSERT_THROW_MES(selfsend_payment_proposal.amount >= minimum_subtraction,
                "make unsigned transaction transfer subtractable: not enough funds in subtractable payment");
            selfsend_payment_proposal.amount -= minimum_subtraction;
        }

        // deduct 1 at a time from selfsend proposals
        rct::xmr_amount fee_remainder = fee % num_subtractable;
        for (size_t selfsend_sub_idx : subtractable_selfsend_payment_proposals)
        {
            if (fee_remainder == 0)
                break;

            CarrotPaymentProposalSelfSendV1 &selfsend_payment_proposal = selfsend_payment_proposals[selfsend_sub_idx];
            CHECK_AND_ASSERT_THROW_MES(selfsend_payment_proposal.amount >= 1,
                "make unsigned transaction transfer subtractable: not enough funds in subtractable payment");
            selfsend_payment_proposal.amount -= 1;
            fee_remainder -= 1;
        }

        // now deduct 1 at a time from normal proposals, shuffled
        if (fee_remainder != 0)
        {
            // create vector of shuffled subtractble normal payment indices
            // note: we do this to hide the order that the normal payment proposals were described in this call, in case
            //       the recipients collude
            std::vector<size_t> shuffled_normal_subtractable(subtractable_normal_payment_proposals.cbegin(),
                subtractable_normal_payment_proposals.cend());
            std::shuffle(shuffled_normal_subtractable.begin(),
                shuffled_normal_subtractable.end(),
                crypto::random_device{});
            
            for (size_t normal_sub_idx : shuffled_normal_subtractable)
            {
                if (fee_remainder == 0)
                    break;

                CarrotPaymentProposalV1 &normal_payment_proposal = normal_payment_proposals[normal_sub_idx];
                CHECK_AND_ASSERT_THROW_MES(normal_payment_proposal.amount >= 1,
                    "make unsigned transaction transfer subtractable: not enough funds in subtractable payment");
                normal_payment_proposal.amount -= 1;
                fee_remainder -= 1;
            }
        }

        CHECK_AND_ASSERT_THROW_MES(fee_remainder == 0,
            "make unsigned transaction transfer subtractable: bug: fee remainder at end of carve function");
    }; //end carve_fees_and_balance

    // make unsigned transaction with fee carving callback
    make_unsigned_transaction(normal_payment_proposals_inout,
        selfsend_payment_proposals_inout,
        fee_per_weight,
        std::forward<select_inputs_func_t>(select_inputs),
        std::move(carve_fees_and_balance),
        s_view_balance_dev,
        k_view_dev,
        account_spend_pubkey,
        tx_out,
        output_amount_blinding_factors_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_unsigned_transaction_transfer(
    std::vector<CarrotPaymentProposalV1> &normal_payment_proposals_inout,
    std::vector<CarrotPaymentProposalSelfSendV1> &selfsend_payment_proposals_inout,
    const rct::xmr_amount fee_per_weight,
    select_inputs_func_t &&select_inputs,
    const view_balance_secret_device *s_view_balance_dev,
    const view_incoming_key_device *k_view_dev,
    const crypto::public_key &account_spend_pubkey,
    cryptonote::transaction &tx_out,
    std::vector<crypto::secret_key> &output_amount_blinding_factors_out)
{
    make_unsigned_transaction_transfer_subtractable(
        normal_payment_proposals_inout,
        selfsend_payment_proposals_inout,
        fee_per_weight,
        std::forward<select_inputs_func_t>(select_inputs),
        s_view_balance_dev,
        k_view_dev,
        account_spend_pubkey,
        /*subtractable_normal_payment_proposals=*/{},
        /*subtractable_selfsend_payment_proposals=*/{selfsend_payment_proposals_inout.size()},
        tx_out,
        output_amount_blinding_factors_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_unsigned_transaction_sweep(
    const tools::variant<CarrotPaymentProposalV1, CarrotPaymentProposalSelfSendV1> &payment_proposal,
    const rct::xmr_amount fee_per_weight,
    std::vector<CarrotSelectedInput> &&selected_inputs,
    const view_balance_secret_device *s_view_balance_dev,
    const view_incoming_key_device *k_view_dev,
    const crypto::public_key &account_spend_pubkey,
    cryptonote::transaction &tx_out,
    std::vector<crypto::secret_key> &output_amount_blinding_factors_out)
{
    // initialize payment proposals list from `payment_proposal`
    std::vector<CarrotPaymentProposalV1> normal_payment_proposals;
    std::vector<CarrotPaymentProposalSelfSendV1> selfsend_payment_proposals;
    struct add_payment_proposal_visitor
    {
        void operator()(const CarrotPaymentProposalV1 &p) const { normal_payment_proposals.push_back(p); }
        void operator()(const CarrotPaymentProposalSelfSendV1 &p) const { selfsend_payment_proposals.push_back(p); }
        std::vector<CarrotPaymentProposalV1> &normal_payment_proposals;
        std::vector<CarrotPaymentProposalSelfSendV1> &selfsend_payment_proposals;
    };
    payment_proposal.visit(add_payment_proposal_visitor{normal_payment_proposals, selfsend_payment_proposals});

    const bool is_selfsend_sweep = !selfsend_payment_proposals.empty();

    // define input selection callback, which is just a shuttle for `selected_inputs`
    select_inputs_func_t select_inputs = [&selected_inputs]
    (
        const boost::multiprecision::int128_t&,
        const std::map<std::size_t, rct::xmr_amount>&,
        std::vector<CarrotSelectedInput> &selected_inputs_out
    )
    {
        selected_inputs_out = std::move(selected_inputs);
    }; //end select_inputs

    // define carves fees and balance callback
    carve_fees_and_balance_func_t carve_fees_and_balance = [is_selfsend_sweep]
    (
        const boost::multiprecision::int128_t &input_sum_amount,
        const rct::xmr_amount fee,
        std::vector<CarrotPaymentProposalV1> &normal_payment_proposals,
        std::vector<CarrotPaymentProposalSelfSendV1> &selfsend_payment_proposals
    )
    {
        // get pointer to sweep destination amount
        rct::xmr_amount *amount_ptr = nullptr;
        if (is_selfsend_sweep)
        {
            CHECK_AND_ASSERT_THROW_MES(!selfsend_payment_proposals.empty(),
                "make unsigned transaction sweep: bug: missing selfsend proposal");
            amount_ptr = &selfsend_payment_proposals.front().amount;
        }
        else
        {
            CHECK_AND_ASSERT_THROW_MES(!normal_payment_proposals.empty(),
                "make unsigned transaction sweep: bug: missing normal proposal");
            amount_ptr = &normal_payment_proposals.front().amount;
        }

        // set amount
        const boost::multiprecision::int128_t sweep_output_amount = input_sum_amount - fee;
        *amount_ptr = boost::numeric_cast<rct::xmr_amount>(sweep_output_amount);
    }; //end carve_fees_and_balance

    // make unsigned transaction with sweep carving callback and selected inputs
    make_unsigned_transaction(normal_payment_proposals,
        selfsend_payment_proposals,
        fee_per_weight,
        std::move(select_inputs),
        std::move(carve_fees_and_balance),
        s_view_balance_dev,
        k_view_dev,
        account_spend_pubkey,
        tx_out,
        output_amount_blinding_factors_out);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace carrot
