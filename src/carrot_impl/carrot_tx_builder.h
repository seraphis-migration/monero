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

#pragma once

//local headers
#include "carrot_core/payment_proposal.h"
#include "cryptonote_basic/cryptonote_basic.h"

//third party headers
#include <boost/multiprecision/cpp_int.hpp>

//standard headers
#include <cstddef>
#include <functional>
#include <map>
#include <set>

//forward declarations

namespace carrot
{
struct CarrotSelectedInput
{
    rct::xmr_amount amount;
    crypto::key_image key_image;
};

using select_inputs_func_t = std::function<void(
        const boost::multiprecision::int128_t&,        // nominal output sum, w/o fee
        const std::map<std::size_t, rct::xmr_amount>&, // absolute fee per input count
        std::vector<CarrotSelectedInput>&              // selected inputs result
    )>;

using carve_fees_and_balance_func_t = std::function<void(
        const boost::multiprecision::int128_t&,       // input sum amount
        const rct::xmr_amount,                        // fee
        std::vector<CarrotPaymentProposalV1>&,        // normal payment proposals [inout]
        std::vector<CarrotPaymentProposalSelfSendV1>& // selfsend payment proposals [inout]
    )>;

static inline std::size_t get_carrot_default_tx_extra_size(const std::size_t num_outputs)
{
    // @TODO: actually implement
    return num_outputs * (32 + 1) + (8 + 2);
}

std::size_t get_carrot_coinbase_default_tx_extra_size(const std::size_t num_outputs);

static inline std::size_t get_fcmppp_tx_weight(const std::size_t num_inputs,
    const std::size_t num_outputs,
    const std::size_t tx_extra_size)
{
    // @TODO: actually implement
    return 200 + num_inputs * 1000 + num_outputs * 100 + tx_extra_size;
}

std::size_t get_fcmppp_coinbase_tx_weight(const std::size_t num_outputs,
    const std::size_t tx_extra_size);

void make_unsigned_transaction(std::vector<CarrotPaymentProposalV1> &normal_payment_proposals_inout,
    std::vector<CarrotPaymentProposalSelfSendV1> &selfsend_payment_proposals_inout,
    const rct::xmr_amount fee_per_weight,
    select_inputs_func_t &&select_inputs,
    carve_fees_and_balance_func_t &&carve_fees_and_balance,
    const view_balance_secret_device *s_view_balance_dev,
    const view_incoming_key_device *k_view_dev,
    const crypto::public_key &account_spend_pubkey,
    cryptonote::transaction &tx_out,
    std::vector<crypto::secret_key> &output_amount_blinding_factors_out);

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
    std::vector<crypto::secret_key> &output_amount_blinding_factors_out);

void make_unsigned_transaction_transfer(
    std::vector<CarrotPaymentProposalV1> &normal_payment_proposals_inout,
    std::vector<CarrotPaymentProposalSelfSendV1> &selfsend_payment_proposals_inout,
    const rct::xmr_amount fee_per_weight,
    select_inputs_func_t &&select_inputs,
    const view_balance_secret_device *s_view_balance_dev,
    const view_incoming_key_device *k_view_dev,
    const crypto::public_key &account_spend_pubkey,
    cryptonote::transaction &tx_out,
    std::vector<crypto::secret_key> &output_amount_blinding_factors_out);

void make_unsigned_transaction_sweep(
    const tools::variant<CarrotPaymentProposalV1, CarrotPaymentProposalSelfSendV1> &payment_proposal,
    const rct::xmr_amount fee_per_weight,
    std::vector<CarrotSelectedInput> &&selected_inputs,
    const view_balance_secret_device *s_view_balance_dev,
    const view_incoming_key_device *k_view_dev,
    const crypto::public_key &account_spend_pubkey,
    cryptonote::transaction &tx_out,
    std::vector<crypto::secret_key> &output_amount_blinding_factors_out);
} //namespace carrot
