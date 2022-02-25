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

// base tx interface

#pragma once

//local headers

//third party headers

//standard headers
#include <string>
#include <vector>

//forward declarations
namespace rct { using xmr_amount = uint64_t; }
namespace sp
{
    class LedgerContext;
    class MockLedgerContext;
}


namespace sp
{

//// must be implemented by each tx type

/// short description of the tx type (e.g. 'Sp-Squashed-V1')
template <typename SpTxType>
std::string get_descriptor();

/// tx structure version (e.g. from struct TxStructureVersionSp)
template <typename SpTxType>
unsigned char get_structure_version();

/// transaction validators
template <typename SpTxType>
bool validate_tx_semantics(const SpTxType &tx);
template <typename SpTxType>
bool validate_tx_linking_tags(const SpTxType &tx, const LedgerContext &ledger_context);
template <typename SpTxType>
bool validate_tx_amount_balance(const SpTxType &tx, const bool defer_batchable);
template <typename SpTxType>
bool validate_tx_input_proofs(const SpTxType &tx, const LedgerContext &ledger_context, const bool defer_batchable);
template <typename SpTxType>
bool validate_txs_batchable(const std::vector<const SpTxType*> &txs, const LedgerContext &ledger_context);


//// Versioning

/// Transaction protocol era: following CryptoNote (1) and RingCT (2)
constexpr unsigned char TxEraSp{3};

/// Transaction structure types: tx types within era 'TxEraSp'
enum class TxStructureVersionSp : unsigned char
{
    /// mining transaction (TODO)
    TxTypeSpMining = 0,
    /// concise grootle in the squashed enote model + seraphis composition proofs + BP+ range proofs with p > 0 balance proof
    TxTypeSpSquashedV1 = 1
};

/// get the tx version string: era | format | semantic rules
inline void get_versioning_string_tx_base(const unsigned char tx_era_version,
    const unsigned char tx_structure_version,
    const unsigned char tx_semantic_rules_version,
    std::string &version_string)
{
    /// era of the tx (e.g. CryptoNote/RingCT/Seraphis)
    version_string += static_cast<char>(tx_era_version);
    /// structure version of the tx within its era
    version_string += static_cast<char>(tx_structure_version);
    /// a tx format's validation rules version
    version_string += static_cast<char>(tx_semantic_rules_version);
}

/// get the tx version string for seraphis txs: TxEraSp | format | semantic rules
inline void get_versioning_string_seraphis_base(const unsigned char tx_structure_version,
    const unsigned char tx_semantic_rules_version,
    std::string &version_string)
{
    get_versioning_string_tx_base(TxEraSp, tx_structure_version, tx_semantic_rules_version, version_string);
}

/// get the tx version string for a specific seraphis tx type
template <typename SpTxType>
void get_versioning_string(const unsigned char tx_semantic_rules_version, std::string &version_string)
{
    get_versioning_string_seraphis_base(get_structure_version<SpTxType>(), tx_semantic_rules_version, version_string);
}


//// core validators

/**
* brief: validate_tx - validate a seraphis transaction
* param: tx -
* param: ledger_context -
* param: defer_batchable - if set, then batchable validation steps shouldn't be executed
* return: true/false on validation result
*/
template <typename SpTxType>
bool validate_tx(const SpTxType &tx, const LedgerContext &ledger_context, const bool defer_batchable)
{
    if (!validate_tx_semantics(tx))
        return false;

    if (!validate_tx_linking_tags(tx, ledger_context))
        return false;

    if (!validate_tx_amount_balance(tx, defer_batchable))
        return false;

    if (!validate_tx_input_proofs(tx, ledger_context, defer_batchable))
        return false;

    return true;
}
/**
* brief: validate_txs - validate a set of tx (use batching if possible)
* type: SpTxType - 
* param: txs -
* param: ledger_context -
* return: true/false on verification result
*/
template <typename SpTxType>
bool validate_txs(const std::vector<const SpTxType*> &txs, const LedgerContext &ledger_context)
{
    // validate non-batchable
    for (const SpTxType *tx : txs)
    {
        if (!tx || !validate_tx(*tx, ledger_context, true))
            return false;
    }

    // validate batchable
    if (!validate_txs_batchable(txs, ledger_context))
        return false;

    return true;
}


//// mock-ups

////
// SpTxParamPack - parameter pack (for unit tests/mockups/etc.)
///
struct SpTxParamPack
{
    std::size_t ref_set_decomp_n;
    std::size_t ref_set_decomp_m;
};
/**
* brief: make_mock_tx - make a mock transaction
* type: SpTxType - 
* type: SpTxParamsT -
* param: params -
* param: in_amounts -
* param: out_amounts -
* inoutparam: ledger_context -
* outparam: tx_out -
*/
template <typename SpTxType, typename SpTxParamsT = SpTxParamPack>
void make_mock_tx(const SpTxParamsT &params,
    const std::vector<rct::xmr_amount> &in_amounts,
    const std::vector<rct::xmr_amount> &out_amounts,
    MockLedgerContext &ledger_context,
    SpTxType &tx_out);

} //namespace sp
