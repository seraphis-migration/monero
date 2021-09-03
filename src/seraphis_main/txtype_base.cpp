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
#include "txtype_base.h"

//local headers

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
// brief: validate_txs_impl - validate a set of tx (use batching if possible)
// type: SpTxType - transaction type
// param: txs - set of tx pointers
// param: tx_validation_context - injected validation context (e.g. for obtaining ledger-related information)
// return: true/false on verification result
//-------------------------------------------------------------------------------------------------------------------
template <typename SpTxType>
static bool validate_txs_impl(const std::vector<const SpTxType*> &txs, const TxValidationContext &tx_validation_context)
{
    try
    {
        // validate non-batchable
        for (const SpTxType *tx : txs)
        {
            if (!tx)
                return false;

            if (!validate_tx_semantics(*tx))
                return false;

            if (!validate_tx_key_images(*tx, tx_validation_context))
                return false;

            if (!validate_tx_amount_balance(*tx))
                return false;

            if (!validate_tx_input_proofs(*tx, tx_validation_context))
                return false;
        }

        // validate batchable
        if (!validate_txs_batchable(txs, tx_validation_context))
            return false;
    }
    catch (...) { return false; }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
bool validate_tx(const SpTxCoinbaseV1 &tx, const TxValidationContext &tx_validation_context)
{
    return validate_txs_impl<SpTxCoinbaseV1>({&tx}, tx_validation_context);
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_txs(const std::vector<const SpTxCoinbaseV1*> &txs, const TxValidationContext &tx_validation_context)
{
    return validate_txs_impl<SpTxCoinbaseV1>(txs, tx_validation_context);
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_tx(const SpTxSquashedV1 &tx, const TxValidationContext &tx_validation_context)
{
    return validate_txs_impl<SpTxSquashedV1>({&tx}, tx_validation_context);
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_txs(const std::vector<const SpTxSquashedV1*> &txs, const TxValidationContext &tx_validation_context)
{
    return validate_txs_impl<SpTxSquashedV1>(txs, tx_validation_context);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
