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

// A coinbase Seraphis transaction.

#pragma once

//local headers
#include "crypto/crypto.h"
#include "misc_log_ex.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_payment_proposal.h"
#include "seraphis_core/sp_core_types.h"
#include "tx_builder_types.h"
#include "tx_component_types.h"
#include "tx_validation_context.h"
#include "tx_validators.h"
#include "txtype_base.h"

//third party headers

//standard headers
#include <string>
#include <vector>

//forward declarations


namespace sp
{

////
// Seraphis coinbase tx
// - input: block height + block reward amount
// - outputs: cleartext amounts
// - memo field: sorted TLV format
///
struct SpTxCoinbaseV1 final
{
    enum class SemanticRulesVersion : unsigned char
    {
        MOCK = 0,
        ONE = 1
    };

    /// semantic rules version
    SemanticRulesVersion tx_semantic_rules_version;

    /// height of the block whose block reward this coinbase tx disperses
    std::uint64_t block_height;
    /// tx outputs (new coinbase enotes)
    std::vector<SpCoinbaseEnoteV1> outputs;
    /// supplemental data for tx
    SpTxSupplementV1 tx_supplement;
};

/// get size of a possible tx
std::size_t sp_tx_coinbase_v1_size_bytes(const std::size_t num_outputs, const std::size_t tx_extra_size);
/// get size of the tx
std::size_t sp_tx_coinbase_v1_size_bytes(const SpTxCoinbaseV1 &tx);
/// get weight of a possible tx (weight == size)
std::size_t sp_tx_coinbase_v1_weight(const std::size_t num_outputs, const TxExtra &tx_extra);
/// get weight of the tx (weight == size)
std::size_t sp_tx_coinbase_v1_weight(const SpTxCoinbaseV1 &tx);

/**
* brief: get_sp_tx_coinbase_v1_txid - get the transaction id
* param: tx -
* outparam: tx_id_out -
*/
void get_sp_tx_coinbase_v1_txid(const SpTxCoinbaseV1 &tx, rct::key &tx_id_out);
/**
* brief: make_seraphis_tx_coinbase_v1 - make an SpTxCoinbaseV1 transaction
* ...
* outparam: tx_out -
*/
void make_seraphis_tx_coinbase_v1(const SpTxCoinbaseV1::SemanticRulesVersion semantic_rules_version,
    const std::uint64_t block_height,
    std::vector<SpCoinbaseEnoteV1> outputs,
    SpTxSupplementV1 tx_supplement,
    SpTxCoinbaseV1 &tx_out);
void make_seraphis_tx_coinbase_v1(const SpTxCoinbaseV1::SemanticRulesVersion semantic_rules_version,
    const SpCoinbaseTxProposalV1 &tx_proposal,
    SpTxCoinbaseV1 &tx_out);
void make_seraphis_tx_coinbase_v1(const SpTxCoinbaseV1::SemanticRulesVersion semantic_rules_version,
    const std::uint64_t block_height,
    std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals,
    std::vector<ExtraFieldElement> additional_memo_elements,
    SpTxCoinbaseV1 &tx_out);

/**
* brief: semantic_config_coinbase_component_counts_v1 - component count configuration for a given semantics rule version
* param: tx_semantic_rules_version -
* return: allowed component counts for the given semantics rules version
*/
SemanticConfigCoinbaseComponentCountsV1 semantic_config_coinbase_component_counts_v1(
    const SpTxCoinbaseV1::SemanticRulesVersion tx_semantic_rules_version);


//// tx base concept implementations

/// short descriptor of the tx type
template <>
inline std::string tx_descriptor<SpTxCoinbaseV1>() { return "SpCoinbaseV1"; }

/// tx structure version
template <>
inline unsigned char tx_structure_version<SpTxCoinbaseV1>()
{
    return static_cast<unsigned char>(TxStructureVersionSp::TxTypeSpCoinbaseV1);
}

/// versioning for an SpTxCoinbaseV1 tx
inline tx_version_t tx_version_from(const SpTxCoinbaseV1::SemanticRulesVersion tx_semantic_rules_version)
{
    return tx_version_from<SpTxCoinbaseV1>(static_cast<unsigned char>(tx_semantic_rules_version));
}

/// transaction validators
template <>
bool validate_tx_semantics<SpTxCoinbaseV1>(const SpTxCoinbaseV1 &tx);
template <>
bool validate_tx_key_images<SpTxCoinbaseV1>(const SpTxCoinbaseV1&, const TxValidationContext&);
template <>
bool validate_tx_amount_balance<SpTxCoinbaseV1>(const SpTxCoinbaseV1 &tx);
template <>
bool validate_tx_input_proofs<SpTxCoinbaseV1>(const SpTxCoinbaseV1&, const TxValidationContext&);
template <>
bool validate_txs_batchable<SpTxCoinbaseV1>(const std::vector<const SpTxCoinbaseV1*>&, const TxValidationContext&);

/// contextual validation id
/// - can be used for checking if an already-validated tx (whose contextual validation id was recorded) is still valid
///   against a validation context that may have changed (e.g. due to a reorg)
bool try_get_tx_contextual_validation_id(const SpTxCoinbaseV1 &tx, const TxValidationContext&, rct::key &validation_id_out);

} //namespace sp
