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

// Mock tx: RingCT component implementations
// NOT FOR PRODUCTION

#pragma once

//local headers
#include "crypto/crypto.h"
#include "mock_tx_rct_base.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace mock_tx
{

////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////// Types ////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

////
// MockENoteRctV1 - RCT ENote V1
///
struct MockENoteRctV1 final : public MockENoteRct
{
    /// memo
    crypto::public_key m_enote_pubkey;
    rct::xmr_amount m_encoded_amount;

    static std::size_t get_size_bytes()
    {
        return get_size_bytes_base() + 32 + 8;
    }

    /**
    * brief: make_v1 - make a V1 RCT ENote
    * param: onetime_privkey -
    * param: amount_blinding_factor -
    * param: amount -
    */
    void make_v1(const crypto::secret_key &onetime_privkey,
        const crypto::secret_key &amount_blinding_factor,
        const rct::xmr_amount amount);
    /**
    * brief: gen_v1 - generate a V1 RCT ENote (random)
    */
    void gen_v1();
};

////
// MockENoteImageRctV1 - RCT ENote Image V1
///
struct MockENoteImageRctV1 final : public MockENoteImageRct
{
    static std::size_t get_size_bytes() { return get_size_bytes_base(); }
};

////
// MockInputRctV1 - RCT Input V1
///
struct MockInputRctV1 final : public MockInputRct<MockENoteRctV1>
{
    /// convert this input to an e-note-image (CryptoNote style)
    MockENoteImageRctV1 to_enote_image_v1(const crypto::secret_key &pseudo_blinding_factor) const;

    /// convert this input to an e-note-image (Triptych style)
    MockENoteImageRctV1 to_enote_image_v2(const crypto::secret_key &pseudo_blinding_factor) const;

    /**
    * brief: gen_v1 - generate a V1 RCT Input (random)
    * param: amount -
    * param: ref_set_size -
    */
    void gen_v1(const rct::xmr_amount amount, const std::size_t ref_set_size);
};

////
// MockDestRctV1 - RCT Destination V1
///
struct MockDestRctV1 final : public MockDestRct
{
    /// memo
    crypto::public_key m_enote_pubkey;
    rct::xmr_amount m_encoded_amount;

    /// convert this destination into a V1 enote
    MockENoteRctV1 to_enote_v1() const;

    /**
    * brief: gen_mock_tx_rct_dest_v1 - generate a V1 RCT Destination (random)
    * param: amount -
    */
    void gen_v1(const rct::xmr_amount amount);
};

////
// MockRctProofV1 - RCT Input Proof V1
// - CLSAG
///
struct MockRctProofV1 final
{
    /// a CLSAG proof
    rct::clsag m_clsag_proof;
    /// vector of pairs <Ko_i, C_i> for referenced enotes
    rct::ctkeyV m_referenced_enotes_converted;

    std::size_t get_size_bytes() const;
};

////
// MockRctProofV2 - RCT Input Proof V2
// - Triptych
///
struct MockRctProofV2 final
{
    /// the Triptych proof
    rct::TriptychProof m_triptych_proof;
    /// onetime addresses Ko
    rct::keyV m_onetime_addresses;
    /// output commitments C
    rct::keyV m_commitments;
    /// pseudo-output commitment C'
    rct::key m_pseudo_amount_commitment;
    /// decomposition n^m
    std::size_t m_ref_set_decomp_n;
    std::size_t m_ref_set_decomp_m;

    std::size_t get_size_bytes() const;
};

////
// MockRctBalanceProofV1 - RCT Balance Proof V1
// - balance proof: implicit [sum(inputs) == sum(outputs)]
// - range proof: Bulletproofs+
///
struct MockRctBalanceProofV1 final
{
    /// a set of BP+ proofs
    std::vector<rct::BulletproofPlus> m_bpp_proofs;

    std::size_t get_size_bytes() const;
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////// Make Mock Pieces ///////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
* brief: gen_mock_rct_inputs_v1 - generate a set of V1 RCT Inputs (all random)
*   - The number of inputs to make is inferred from amounts.size().
* param: amounts -
* param: ref_set_size -
* return: set of V1 RCT Inputs
*/
std::vector<MockInputRctV1> gen_mock_rct_inputs_v1(const std::vector<rct::xmr_amount> &amounts,
    const std::size_t ref_set_size);
/**
* brief: gen_mock_rct_dests_v1 - generate a set of V1 RCT Destinations (all random)
*   - The number of inputs to make is inferred from amounts.size().
* param: amounts -
* return: set of V1 RCT Destinations
*/
std::vector<MockDestRctV1> gen_mock_rct_dests_v1(const std::vector<rct::xmr_amount> &amounts);


////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////// Make Tx Components ///////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
* brief: get_rct_pseudo_blinding_factors_v1 - make pseudo blinding factors
*   - The first 'num_factors - 1' blinding factors are random.
*   - The last blinding factor equals sum(output factors) - sum(pseudo factors)_except_last
* param: destinations -
* outparam: outputs_out -
* outparam: output_amounts_out -
* outparam: output_amount_commitment_blinding_factors_out -
* return: set of pseudo amount commitment blinding factors
*/
std::vector<crypto::secret_key> get_rct_pseudo_blinding_factors_v1(const std::size_t num_factors,
    const std::vector<rct::key> &output_amount_commitment_blinding_factors);
/**
* brief: make_tx_outputs_rct_v1 - make V1 RCT outputs
* param: destinations -
* outparam: outputs_out -
* outparam: output_amounts_out -
* outparam: output_amount_commitment_blinding_factors_out -
*/
void make_v1_tx_outputs_rct_v1(const std::vector<MockDestRctV1> &destinations,
    std::vector<MockENoteRctV1> &outputs_out,
    std::vector<rct::xmr_amount> &output_amounts_out,
    std::vector<rct::key> &output_amount_commitment_blinding_factors_out);
/**
* brief: make_tx_images_rct_v1 - make V1 RCT enote images (CryptoNote style)
* param: inputs_to_spend -
* param: output_amount_commitment_blinding_factors -
* outparam: input_images_out -
* outparam: pseudo_blinding_factors_out -
*/
void make_v1_tx_images_rct_v1(const std::vector<MockInputRctV1> &inputs_to_spend,
    const std::vector<rct::key> &output_amount_commitment_blinding_factors,
    std::vector<MockENoteImageRctV1> &input_images_out,
    std::vector<crypto::secret_key> &pseudo_blinding_factors_out);
/**
* brief: make_tx_images_rct_v2 - make V1 RCT enote images (Triptych style)
* param: inputs_to_spend -
* param: output_amount_commitment_blinding_factors -
* outparam: input_images_out -
* outparam: pseudo_blinding_factors_out -
*/
void make_v1_tx_images_rct_v2(const std::vector<MockInputRctV1> &inputs_to_spend,
    const std::vector<rct::key> &output_amount_commitment_blinding_factors,
    std::vector<MockENoteImageRctV1> &input_images_out,
    std::vector<crypto::secret_key> &pseudo_blinding_factors_out);
/**
* brief: make_tx_input_proofs_rct_v1 - make V1 RCT input proofs (CLSAGs)
*   - input proofs: membership, ownership, unspentness (i.e. prove key images are constructed correctly)
* param: inputs_to_spend -
* param: pseudo_blinding_factors -
* outparam: proofs_out -
*/
void make_v1_tx_input_proofs_rct_v1(const std::vector<MockInputRctV1> &inputs_to_spend,
    const std::vector<crypto::secret_key> &pseudo_blinding_factors,
    std::vector<MockRctProofV1> &proofs_out);
/**
* brief: make_tx_input_proofs_rct_v2 - make V2 RCT input proofs (Triptych proofs)
*   - input proofs: membership, ownership, unspentness (i.e. prove key images are constructed correctly)
* param: inputs_to_spend -
* param: input_images -
* param: pseudo_blinding_factors -
* param: ref_set_decomp_n -
* param: ref_set_decomp_m -
* outparam: proofs_out -
*/
void make_v2_tx_input_proofs_rct_v1(const std::vector<MockInputRctV1> &inputs_to_spend,
    const std::vector<MockENoteImageRctV1> &input_images,
    const std::vector<crypto::secret_key> &pseudo_blinding_factors,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    std::vector<MockRctProofV2> &proofs_out);
/**
* brief: make_v1_tx_balance_proof_rct_v1 - make V1 RCT balance proof
*   - BP+ range proofs for all output amounts
* param: output_amounts -
* param: amount_commitment_blinding_factors -
* param: max_rangeproof_splits -
* outparam: balance_proof_out -
*/
void make_v1_tx_balance_proof_rct_v1(const std::vector<rct::xmr_amount> &output_amounts,
    const std::vector<rct::key> &amount_commitment_blinding_factors,
    const std::size_t max_rangeproof_splits,
    std::shared_ptr<MockRctBalanceProofV1> &balance_proof_out);

////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////// Validate Tx Components ////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
* brief: validate_mock_tx_rct_semantics_proofcounts_v1 - check component counts for a transaction
* param: num_input_proofs -
* param: num_input_images -
* param: num_outputs -
* param: range_proofs -
* return: true/false on verification result
*/
bool validate_mock_tx_rct_semantics_component_counts_v1(const std::size_t num_input_proofs,
        const std::size_t num_input_images,
        const std::size_t num_outputs,
        const std::shared_ptr<MockRctBalanceProofV1> &balance_proof);
/**
* brief: validate_mock_tx_rct_semantics_ref_set_size_v1 - check reference set semenatics (v1 proofs: CLSAG)
* param: tx_proofs -
* param: ref_set_size -
* return: true/false on verification result
*/
bool validate_mock_tx_rct_semantics_ref_set_size_v1(const std::vector<MockRctProofV1> &tx_proofs,
        const std::size_t ref_set_size);
/**
* brief: validate_mock_tx_rct_semantics_ref_set_size_v2 - check reference set semenatics (v2 proofs: Triptych)
* param: tx_proofs -
* param: ref_set_decomp_n -
* param: ref_set_decomp_m -
* return: true/false on verification result
*/
bool validate_mock_tx_rct_semantics_ref_set_size_v2(const std::vector<MockRctProofV2> &tx_proofs,
        const std::size_t ref_set_decomp_n,
        const std::size_t ref_set_decomp_m);
/**
* brief: validate_mock_tx_rct_semantics_linking_tags_v1 - check linking tag semenatics (v1 proofs: CLSAG)
*   - Stored images must be in large-prime Ed25519 subgroup.
*   - Stored images must match between two storage locations (duplication in mock up).
* param: input_images -
* param: tx_proofs -
* return: true/false on verification result
*/
bool validate_mock_tx_rct_semantics_linking_tags_v1(const std::vector<MockENoteImageRctV1> input_images,
    const std::vector<MockRctProofV1> tx_proofs);
/**
* brief: validate_mock_tx_rct_semantics_linking_tags_v2 - check linking tag semenatics (v2 proofs: Triptych)
*   - Stored images must be in large-prime Ed25519 subgroup.
*   - Stored images must match between two storage locations (duplication in mock up).
* param: input_images -
* param: tx_proofs -
* return: true/false on verification result
*/
bool validate_mock_tx_rct_semantics_linking_tags_v2(const std::vector<MockENoteImageRctV1> input_images,
    const std::vector<MockRctProofV2> tx_proofs);
/**
* brief: validate_mock_tx_rct_linking_tags_v1 - validate linking tags in V1 RCT input proofs and images
* param: proofs -
* param: images -
* return: true/false on verification result
*/
bool validate_mock_tx_rct_linking_tags_v1(const std::vector<MockRctProofV1> &proofs,
    const std::vector<MockENoteImageRctV1> &images);
/**
* brief: validate_mock_tx_rct_linking_tags_v1 - validate linking tags in V2 RCT input proofs and images
* param: proofs -
* param: images -
* return: true/false on verification result
*/
bool validate_mock_tx_rct_linking_tags_v2(const std::vector<MockRctProofV2> &proofs,
    const std::vector<MockENoteImageRctV1> &images);
/**
* brief: validate_mock_tx_rct_amount_balance_v1 - validate a set of V1 RCT balance proofs from a tx
*   - validate amount balance between inputs and outputs
*   - includes checking BP+ range proofs on output commitments
* param: images -
* param: outputs -
* param: range_proofs -
* param: defer_batchable -
* return: true/false on verification result
*/
bool validate_mock_tx_rct_amount_balance_v1(const std::vector<MockENoteImageRctV1> &images,
    const std::vector<MockENoteRctV1> &outputs,
    const std::shared_ptr<MockRctBalanceProofV1> balance_proof,
    const bool defer_batchable);
/**
* brief: validate_mock_tx_rct_proofs_v1 - validate a set of V1 RCT proofs from a tx
*   - CLSAG proofs for: membership, ownership, unspentness
* param: proofs -
* param: images -
* return: true/false on verification result
*/
bool validate_mock_tx_rct_proofs_v1(const std::vector<MockRctProofV1> &proofs,
    const std::vector<MockENoteImageRctV1> &images);
/**
* brief: validate_mock_tx_rct_proofs_v2 - validate a set of V2 RCT proofs from a tx
*   - Triptych proofs for: membership, ownership, unspentness
* param: proofs -
* param: images -
* return: true/false on verification result
*/
bool validate_mock_tx_rct_proofs_v2(const std::vector<MockRctProofV2> &proofs);

} //namespace mock_tx










