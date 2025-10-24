// Copyright (c) 2025, The Monero Project
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
#include "knowledge_proofs.h"

//local headers
#include "scanning_tools.h"

//third party headers

//standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.knowledge"

namespace tools
{
namespace wallet
{
namespace knowledge
{
//-------------------------------------------------------------------------------------------------------------------
void check_tx_key(const cryptonote::transaction &tx,
    const crypto::key_derivation &derivation,
    const epee::span<const crypto::key_derivation> additional_derivations,
    const cryptonote::account_public_address &address,
    uint64_t &received_out)
{
    received_out = 0;

    const auto enote_scan_infos = wallet::view_incoming_scan_transaction_as_sender(tx,
        {&derivation, 1},
        additional_derivations,
        address);

    for (const auto &enote_scan_info : enote_scan_infos)
        if (enote_scan_info && enote_scan_info->address_spend_pubkey == address.m_spend_public_key)
            received_out += enote_scan_info->amount; //! @TODO: check overflow
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace knowledge
} //namespace wallet
} //namespace tools
