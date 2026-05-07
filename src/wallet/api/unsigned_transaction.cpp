// Copyright (c) 2014-2024, The Monero Project
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
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "unsigned_transaction.h"
#include "wallet.h"
#include "common_defines.h"

#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"

#include <memory>
#include <vector>
#include <sstream>
#include <boost/format.hpp>

using namespace std;

namespace Monero {

UnsignedTransaction::~UnsignedTransaction() {}


UnsignedTransactionImpl::UnsignedTransactionImpl(WalletImpl &wallet)
    : m_wallet(wallet)
{
  m_status = Status_Ok;
}

UnsignedTransactionImpl::~UnsignedTransactionImpl()
{
    LOG_PRINT_L3("Unsigned tx deleted");
}

int UnsignedTransactionImpl::status() const
{
    return m_status;
}

string UnsignedTransactionImpl::errorString() const
{
    return m_errorString;
}

bool UnsignedTransactionImpl::sign(const std::string &signedFileName)
{
  if(m_wallet.watchOnly())
  {
     m_errorString = tr("This is a watch only wallet");
     m_status = Status_Error;
     return false;
  }
  std::vector<tools::wallet2::pending_tx> ptx;
  try
  {
    bool r = m_wallet.m_wallet->sign_tx(m_unsigned_tx_set, signedFileName, ptx);
    if (!r)
    {
      m_errorString = tr("Failed to sign transaction");
      m_status = Status_Error;
      return false;
    }
  }
  catch (const std::exception &e)
  {
    m_errorString = string(tr("Failed to sign transaction")) + e.what();
    m_status = Status_Error;
    return false;
  }
  return true;
}

//----------------------------------------------------------------------------------------------------
bool UnsignedTransactionImpl::checkLoadedTx(const std::string &extra_message)
{
    if (m_tx_proposals.size() != num_unsigned_txs_ref(m_unsigned_tx_set))
    {
        m_status = Status_Error;
        m_errorString = tr("length of expanded unsigned tx set differs");
        return false;
    }
    //! @TODO: more consistency checks b/t `m_tx_proposals` and `m_unsigned_tx_set`

    const auto addr_dev = m_wallet.m_wallet->get_cryptonote_address_device();

    // gather info to ask the user
    uint64_t amount = 0, amount_to_dests = 0, change = 0;
    uint64_t min_ring_size = ~0;
    std::unordered_map<cryptonote::account_public_address, std::pair<std::string, uint64_t>> dests;
    std::optional<cryptonote::tx_destination_entry> first_known_non_zero_change_dst;
    std::string payment_id_string = "";
    for (size_t n = 0; n < m_tx_proposals.size(); ++n)
    {
        const tools::wallet::tx_reconstruct_variant_t &cd = m_tx_proposals.at(n);

        const std::optional<crypto::hash8> payment_id8 = short_payment_id(cd);
        const std::optional<crypto::hash> payment_id32 = long_payment_id(cd);

        if (payment_id8 && *payment_id8 != crypto::null_hash8)
        {
            if (!payment_id_string.empty())
                payment_id_string += ", ";
            payment_id_string = std::string("encrypted payment ID ") + epee::string_tools::pod_to_hex(*payment_id8);
        }
        else if (payment_id32 && *payment_id32 != crypto::null_hash)
        {
            if (!payment_id_string.empty())
                payment_id_string += ", ";
            payment_id_string = std::string("unencrypted payment ID ") + epee::string_tools::pod_to_hex(*payment_id32);
        }

        amount += boost::numeric_cast<rct::xmr_amount>(input_amount_total(cd));

        for (const std::uint64_t ring_size : ring_sizes(cd))
            if (ring_size < min_ring_size)
                min_ring_size = ring_size;

        for (const cryptonote::tx_destination_entry &entry : finalized_destinations(cd, *addr_dev))
        {
            std::string address, standard_address = get_account_address_as_str(m_wallet.m_wallet->nettype(),
                entry.is_subaddress, entry.addr);
            if (payment_id8 && !entry.is_subaddress)
            {
                address = get_account_integrated_address_as_str(m_wallet.m_wallet->nettype(), entry.addr, *payment_id8);
                address += std::string(" (" + standard_address + " with encrypted payment id " + epee::string_tools::pod_to_hex(*payment_id8) + ")");
            }
            else
                address = standard_address;
            auto i = dests.find(entry.addr);
            if (i == dests.end())
                dests.insert(std::make_pair(entry.addr, std::make_pair(address, entry.amount)));
            else
                i->second.second += entry.amount;
            amount_to_dests += entry.amount;
        }
        const cryptonote::tx_destination_entry change_dst = change_destination(cd, *addr_dev);
        if (change_dst.amount > 0)
        {
            auto it = dests.find(change_dst.addr);
            if (it == dests.end())
            {
                m_status = Status_Error;
                m_errorString = tr("Claimed change does not go to a paid address");
                return false;
            }
            if (it->second.second < change_dst.amount)
            {
                m_status = Status_Error;
                m_errorString = tr("Claimed change is larger than payment to the change address");
                return  false;
            }
            if (!first_known_non_zero_change_dst)
                first_known_non_zero_change_dst = change_dst;
            if (change_dst.addr != first_known_non_zero_change_dst->addr)
            {
                m_status = Status_Error;
                m_errorString = tr("Change goes to more than one address");
                return false;
            }

            change += change_dst.amount;
            it->second.second -= change_dst.amount;
            if (it->second.second == 0)
                dests.erase(change_dst.addr);
        }
    }
    std::string dest_string;
    for (auto i = dests.begin(); i != dests.end(); )
    {
        dest_string += (boost::format(tr("sending %s to %s")) % cryptonote::print_money(i->second.second) % i->second.first).str();
        ++i;
        if (i != dests.end())
            dest_string += ", ";
    }
    if (dest_string.empty())
        dest_string = tr("with no destinations");

    std::string change_string;
    if (change > 0)
    {
        std::string address = get_account_address_as_str(m_wallet.m_wallet->nettype(),
            first_known_non_zero_change_dst->is_subaddress,
            first_known_non_zero_change_dst->addr);
        change_string += (boost::format(tr("%s change to %s")) % cryptonote::print_money(change) % address).str();
    }
    else
        change_string += tr("no change");

    const uint64_t fee = amount - amount_to_dests;
    m_confirmationMessage = (boost::format(tr("Loaded %lu transactions, for %s, fee %s, %s, %s, with min ring size %lu. %s"))
        % (unsigned long)m_tx_proposals.size()
        % cryptonote::print_money(amount)
        % cryptonote::print_money(fee)
        % dest_string
        % change_string
        % (unsigned long)min_ring_size
        % extra_message).str();
    return true;
}

std::vector<uint64_t> UnsignedTransactionImpl::amount() const
{
    wallet2_basic::transfer_container transfers;
    m_wallet.m_wallet->get_transfers(transfers);

    std::vector<uint64_t> result;
    result.reserve(8 * m_tx_proposals.size()); // just a guess
    for (const tools::wallet::tx_reconstruct_variant_t &tx_proposal : m_tx_proposals) {
        const auto selected_transfers = tools::wallet::collect_selected_transfer_indices(tx_proposal, transfers);
        for (const std::size_t selected_transfer_idx : selected_transfers)
            result.push_back(transfers.at(selected_transfer_idx).amount());
    }
    return result;
}

std::vector<uint64_t> UnsignedTransactionImpl::fee() const
{
    std::vector<uint64_t> res;
    res.reserve(m_tx_proposals.size());
    for (const tools::wallet::tx_reconstruct_variant_t &tx_proposal : m_tx_proposals)
        res.push_back(tools::wallet::fee(tx_proposal));
    return res;
}

std::vector<uint64_t> UnsignedTransactionImpl::mixin() const
{
    std::vector<uint64_t> result;
    for (const tools::wallet::tx_reconstruct_variant_t &tx_proposal : m_tx_proposals) {
        std::uint64_t min_mixin = ~0;
        for (const std::uint64_t ring_size : ring_sizes(tx_proposal)) {
            const std::uint64_t mixin = ring_size ? (ring_size - 1) : 0;
            if (mixin < min_mixin)
                min_mixin = mixin;
        }
        result.push_back(min_mixin);
    }
    return result;
}    

uint64_t UnsignedTransactionImpl::txCount() const
{
    return m_tx_proposals.size();
}

std::vector<std::string> UnsignedTransactionImpl::paymentId() const 
{
    std::vector<string> result;
    result.reserve(m_tx_proposals.size());
    for (const tools::wallet::tx_reconstruct_variant_t &tx_proposal: m_tx_proposals) {
        const std::optional<crypto::hash8> pid8 = short_payment_id(tx_proposal);
        const std::optional<crypto::hash> pid32 = long_payment_id(tx_proposal);
        if (pid8 && *pid8 != crypto::null_hash8)
            result.push_back(epee::string_tools::pod_to_hex(*pid8));
        else if (pid32 && *pid32 != crypto::null_hash)
            result.push_back(epee::string_tools::pod_to_hex(*pid32));
        else
            result.push_back("");
    }
    return result;
}

std::vector<std::string> UnsignedTransactionImpl::recipientAddress() const 
{
    const auto addr_dev = m_wallet.m_wallet->get_cryptonote_address_device();

    // TODO: return integrated address if short payment ID exists
    std::vector<string> result;
    result.reserve(m_tx_proposals.size());
    for (const tools::wallet::tx_reconstruct_variant_t &tx_proposal: m_tx_proposals) {
        const auto dsts = finalized_destinations(tx_proposal, *addr_dev);
        if (dsts.empty()) {
          MERROR("empty destinations, skipped");
          continue;
        }
        result.push_back(cryptonote::get_account_address_as_str(m_wallet.m_wallet->nettype(),
            dsts.at(0).is_subaddress,
            dsts.at(0).addr));
    }
    return result;
}

uint64_t UnsignedTransactionImpl::minMixinCount() const
{    
    uint64_t min_mixin = ~0;  
    for (const tools::wallet::tx_reconstruct_variant_t &tx_proposal: m_tx_proposals) {
        for (const std::uint64_t ring_size : ring_sizes(tx_proposal)) {
            const std::uint64_t mixin = ring_size ? (ring_size - 1) : 0;
            if (mixin < min_mixin)
                min_mixin = mixin;
        }
    }
    return min_mixin;
}

} // namespace
