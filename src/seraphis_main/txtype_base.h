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

// Base tx interface for Seraphis.
// WARNING: This file MUST NOT acquire more includes (may open a hole for overload injection).

#pragma once

//local headers

//third party headers

//standard headers
#include <cstdint>
#include <string>
#include <vector>

//forward declarations
namespace rct { using xmr_amount = uint64_t; }
namespace sp
{
    struct SpTxCoinbaseV1;
    struct SpTxSquashedV1;
    class TxValidationContext;
}

namespace sp
{

//// must be implemented by each tx type

/// short description of the tx type (e.g. 'SpSquashedV1')
template <typename SpTxType>
std::string tx_descriptor();

/// tx structure version (e.g. from struct TxStructureVersionSp)
template <typename SpTxType>
unsigned char tx_structure_version();

/// transaction validators
template <typename SpTxType>
bool validate_tx_semantics(const SpTxType &tx);
template <typename SpTxType>
bool validate_tx_key_images(const SpTxType &tx, const TxValidationContext &tx_validation_context);
template <typename SpTxType>
bool validate_tx_amount_balance(const SpTxType &tx);
template <typename SpTxType>
bool validate_tx_input_proofs(const SpTxType &tx, const TxValidationContext &tx_validation_context);
template <typename SpTxType>
bool validate_txs_batchable(const std::vector<const SpTxType*> &txs, const TxValidationContext &tx_validation_context);


//// Versioning

/// Transaction protocol era: following CryptoNote (1) and RingCT (2)
constexpr unsigned char TxEraSp{3};

/// Transaction structure types: tx types within era 'TxEraSp'
enum class TxStructureVersionSp : unsigned char
{
    /// coinbase transaction
    TxTypeSpCoinbaseV1 = 0,
    /// normal transaction: squashed v1
    TxTypeSpSquashedV1 = 1
};

/// get the tx version: era | format | semantic rules
struct tx_version_t final
{
    unsigned char bytes[3];
};
inline bool operator==(const tx_version_t &a, const tx_version_t &b)
{ return (a.bytes[0] == b.bytes[0]) && (a.bytes[1] == b.bytes[1]) && (a.bytes[2] == b.bytes[2]); }

inline tx_version_t tx_version_tx_base_from(const unsigned char tx_era_version,
    const unsigned char tx_structure_version,
    const unsigned char tx_semantic_rules_version)
{
    tx_version_t tx_version;

    /// era of the tx (e.g. CryptoNote/RingCT/Seraphis)
    tx_version.bytes[0] = tx_era_version;
    /// structure version of the tx within its era
    tx_version.bytes[1] = tx_structure_version;
    /// a tx format's validation rules version
    tx_version.bytes[2] = tx_semantic_rules_version;

    return tx_version;
}

/// get the tx version for seraphis txs: TxEraSp | format | semantic rules
inline tx_version_t tx_version_seraphis_base_from(const unsigned char tx_structure_version,
    const unsigned char tx_semantic_rules_version)
{
    return tx_version_tx_base_from(TxEraSp, tx_structure_version, tx_semantic_rules_version);
}

/// get the tx version for a specific seraphis tx type
template <typename SpTxType>
tx_version_t tx_version_from(const unsigned char tx_semantic_rules_version)
{
    return tx_version_seraphis_base_from(tx_structure_version<SpTxType>(), tx_semantic_rules_version);
}


//// core validators

/// specialize the following functions with definitions in txtype_base.cpp, so the validate_txs_impl() function from that
///   file will be explicitly instantiated using the formula written there (this way maliciously injected overloads
///   of validate_txs_impl() won't be available to the compiler)
/// bool validate_tx(const SpTxType &tx, const TxValidationContext &tx_validation_context);
/// bool validate_txs(const std::vector<const SpTxType*> &txs, const TxValidationContext &tx_validation_context);

/// SpTxCoinbaseV1
bool validate_tx(const SpTxCoinbaseV1 &tx, const TxValidationContext &tx_validation_context);
bool validate_txs(const std::vector<const SpTxCoinbaseV1*> &txs, const TxValidationContext &tx_validation_context);
/// SpTxSquashedV1
bool validate_tx(const SpTxSquashedV1 &tx, const TxValidationContext &tx_validation_context);
bool validate_txs(const std::vector<const SpTxSquashedV1*> &txs, const TxValidationContext &tx_validation_context);

} //namespace sp
