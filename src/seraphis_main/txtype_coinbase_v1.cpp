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
#include "txtype_coinbase_v1.h"

//local headers
#include "cryptonote_config.h"
#include "misc_log_ex.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/sp_core_enote_utils.h"
#include "seraphis_core/sp_core_types.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_crypto/sp_hash_functions.h"
#include "seraphis_crypto/sp_transcript.h"
#include "tx_builder_types.h"
#include "tx_builders_mixed.h"
#include "tx_builders_outputs.h"
#include "tx_component_types.h"
#include "tx_validation_context.h"
#include "tx_validators.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_tx_coinbase_v1_size_bytes(const std::size_t num_outputs, const std::size_t tx_extra_size)
{
    // size of the transaction as represented in C++
    std::size_t size{0};

    // coinbase input (block height and block reward)
    size += 8 + 8;

    // outputs
    size += num_outputs * sp_coinbase_enote_v1_size_bytes();

    // extra data in tx
    size += sp_tx_supplement_v1_size_bytes(num_outputs, tx_extra_size, false);  //without shared ephemeral pubkey assumption

    return size;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_tx_coinbase_v1_size_bytes(const SpTxCoinbaseV1 &tx)
{
    return sp_tx_coinbase_v1_size_bytes(tx.outputs.size(), tx.tx_supplement.tx_extra.size());
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_tx_coinbase_v1_weight(const std::size_t num_outputs, const std::size_t tx_extra_size)
{
    return sp_tx_coinbase_v1_size_bytes(num_outputs, tx_extra_size);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_tx_coinbase_v1_weight(const SpTxCoinbaseV1 &tx)
{
    return sp_tx_coinbase_v1_weight(tx.outputs.size(), tx.tx_supplement.tx_extra.size());
}
//-------------------------------------------------------------------------------------------------------------------
void get_sp_tx_coinbase_v1_txid(const SpTxCoinbaseV1 &tx, rct::key &tx_id_out)
{
    // tx_id = H_32(tx version, block height, block reward, output enotes, tx supplement)
    const tx_version_t tx_version{tx_version_from(tx.tx_semantic_rules_version)};

    SpFSTranscript transcript{
            config::HASH_KEY_SERAPHIS_TRANSACTION_TYPE_COINBASE_V1,
            sizeof(tx_version) +
                16 +
                tx.outputs.size()*sp_coinbase_enote_v1_size_bytes() +
                sp_tx_supplement_v1_size_bytes(tx.tx_supplement)
        };
    transcript.append("tx_version", tx_version.bytes);
    transcript.append("block_height", tx.block_height);
    transcript.append("output_enotes", tx.outputs);
    transcript.append("tx_supplement", tx.tx_supplement);

    sp_hash_to_32(transcript.data(), transcript.size(), tx_id_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_tx_coinbase_v1(const SpTxCoinbaseV1::SemanticRulesVersion semantic_rules_version,
    const std::uint64_t block_height,
    std::vector<SpCoinbaseEnoteV1> outputs,
    SpTxSupplementV1 tx_supplement,
    SpTxCoinbaseV1 &tx_out)
{
    tx_out.tx_semantic_rules_version = semantic_rules_version;
    tx_out.block_height              = block_height;
    tx_out.outputs                   = std::move(outputs);
    tx_out.tx_supplement             = std::move(tx_supplement);

    CHECK_AND_ASSERT_THROW_MES(validate_tx_semantics(tx_out), "Failed to assemble an SpTxCoinbaseV1.");
    CHECK_AND_ASSERT_THROW_MES(validate_tx_amount_balance(tx_out),
        "Failed to assemble an SpTxCoinbaseV1: amount balancing");
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_tx_coinbase_v1(const SpTxCoinbaseV1::SemanticRulesVersion semantic_rules_version,
    const SpCoinbaseTxProposalV1 &tx_proposal,
    SpTxCoinbaseV1 &tx_out)
{
    // 1. check tx proposal semantics
    check_v1_coinbase_tx_proposal_semantics_v1(tx_proposal);

    // 2. extract outputs from the tx proposal
    std::vector<SpCoinbaseOutputProposalV1> output_proposals;
    get_coinbase_output_proposals_v1(tx_proposal, output_proposals);

    // 3. extract info from output proposals
    std::vector<SpCoinbaseEnoteV1> output_enotes;
    SpTxSupplementV1 tx_supplement;
    make_v1_coinbase_outputs_v1(output_proposals, output_enotes, tx_supplement.output_enote_ephemeral_pubkeys);

    // 4. collect full memo
    finalize_tx_extra_v1(tx_proposal.partial_memo, output_proposals, tx_supplement.tx_extra);

    // 5. finish tx
    make_seraphis_tx_coinbase_v1(semantic_rules_version,
        tx_proposal.block_height,
        std::move(output_enotes),
        std::move(tx_supplement),
        tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_tx_coinbase_v1(const SpTxCoinbaseV1::SemanticRulesVersion semantic_rules_version,
    const std::uint64_t block_height,
    std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals,
    std::vector<ExtraFieldElement> additional_memo_elements,
    SpTxCoinbaseV1 &tx_out)
{
    // make a coinbase tx proposal
    SpCoinbaseTxProposalV1 tx_proposal;
    make_v1_coinbase_tx_proposal_v1(block_height,
        std::move(normal_payment_proposals),
        std::move(additional_memo_elements),
        tx_proposal);

    // finish tx
    make_seraphis_tx_coinbase_v1(semantic_rules_version, tx_proposal, tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
SemanticConfigCoinbaseComponentCountsV1 semantic_config_coinbase_component_counts_v1(
    const SpTxCoinbaseV1::SemanticRulesVersion tx_semantic_rules_version)
{
    SemanticConfigCoinbaseComponentCountsV1 config{};

    if (tx_semantic_rules_version == SpTxCoinbaseV1::SemanticRulesVersion::MOCK)
    {
        config.min_outputs = 1;
        config.max_outputs = 100000;
    }
    else if (tx_semantic_rules_version == SpTxCoinbaseV1::SemanticRulesVersion::ONE)
    {
        config.min_outputs = 1;
        config.max_outputs = config::SP_MAX_COINBASE_OUTPUTS_V1;
    }
    else  //unknown semantic rules version
    {
        CHECK_AND_ASSERT_THROW_MES(false, "Tried to get semantic config for component counts with unknown rules version.");
    }

    return config;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_tx_semantics<SpTxCoinbaseV1>(const SpTxCoinbaseV1 &tx)
{
    // validate component counts (num outputs, etc.)
    if (!validate_sp_semantics_coinbase_component_counts_v1(
            semantic_config_coinbase_component_counts_v1(tx.tx_semantic_rules_version),
            tx.outputs.size(),
            tx.tx_supplement.output_enote_ephemeral_pubkeys.size()))
        return false;

    // validate output serialization semantics
    if (!validate_sp_semantics_output_serialization_v1(tx.outputs))
        return false;

    // validate layout (sorting, uniqueness) of outputs and tx supplement
    if (!validate_sp_semantics_coinbase_layout_v1(tx.outputs,
            tx.tx_supplement.output_enote_ephemeral_pubkeys,
            tx.tx_supplement.tx_extra))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_tx_key_images<SpTxCoinbaseV1>(const SpTxCoinbaseV1&, const TxValidationContext&)
{
    // coinbase txs have no key images
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_tx_amount_balance<SpTxCoinbaseV1>(const SpTxCoinbaseV1 &tx)
{
    // balance proof
    if (!validate_sp_coinbase_amount_overflow_v1(tx.outputs))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_tx_input_proofs<SpTxCoinbaseV1>(const SpTxCoinbaseV1&, const TxValidationContext&)
{
    // coinbase txs have no input prooofs
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_txs_batchable<SpTxCoinbaseV1>(const std::vector<const SpTxCoinbaseV1*>&, const TxValidationContext&)
{
    // coinbase txs have no batchable proofs to verify
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_tx_contextual_validation_id(const SpTxCoinbaseV1 &tx, const TxValidationContext&, rct::key &validation_id_out)
{
    try
    {
        // 1. tx id
        rct::key tx_id;
        get_sp_tx_coinbase_v1_txid(tx, tx_id);

        // 2. validation_id = H_32(tx_id)
        SpFSTranscript transcript{config::HASH_KEY_SERAPHIS_TX_CONTEXTUAL_VALIDATION_ID_V1, sizeof(tx_id)};
        transcript.append("tx_id", tx_id);

        sp_hash_to_32(transcript.data(), transcript.size(), validation_id_out.bytes);
    } catch (...) { return false; }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
