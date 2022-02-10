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

// Interface for interacting with a ledger when validating a tx.
// NOT FOR PRODUCTION

#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <vector>

//forward declarations
namespace sp
{
    struct SpEnoteV1;
    struct SpTxSquashedV1;
}


namespace sp
{

class LedgerContext
{
public:
    /// default destructor
    virtual ~LedgerContext() = default;
    /**
    * brief: linking_tag_exists_sp_v1 - checks if a Seraphis linking tag exists in the ledger
    * param: linking_tag -
    * return: true/false on check result
    */
    virtual bool linking_tag_exists_sp_v1(const crypto::key_image &linking_tag) const = 0;
    /**
    * brief: get_reference_set_sp_v1 - gets Seraphis enotes stored in the ledger
    * param: indices -
    * outparam: enotes_out - 
    */
    virtual void get_reference_set_sp_v1(const std::vector<std::size_t> &indices,
        std::vector<SpEnoteV1> &enotes_out) const = 0;
    /**
    * brief: get_reference_set_proof_elements_sp_v1 - gets Seraphis squashed enotes stored in the ledger
    * param: indices -
    * outparam: proof_elements_out - {{squashed enote}}
    */
    virtual void get_reference_set_proof_elements_sp_v1(const std::vector<std::size_t> &indices,
        rct::keyM &proof_elements_out) const = 0;
    /**
    * brief: try_add_transaction_sp_squashed_v1 - try to add a SpTxSquashedV1 transaction to the ledger
    * param: tx_to_add -
    * bool: true if adding tx succeeded
    */
    virtual bool try_add_transaction_sp_squashed_v1(const SpTxSquashedV1 &tx_to_add) = 0;
};

template<typename TxType>
bool try_add_tx_to_ledger(LedgerContext &ledger_context, const TxType &tx_to_add);

template<>
inline bool try_add_tx_to_ledger<SpTxSquashedV1>(LedgerContext &ledger_context,
    const SpTxSquashedV1 &tx_to_add)
{
    return ledger_context.try_add_transaction_sp_squashed_v1(tx_to_add);
}

} //namespace sp
