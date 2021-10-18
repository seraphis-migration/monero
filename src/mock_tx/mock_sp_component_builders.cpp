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

//paired header
#include "mock_sp_component_builders.h"

//local headers
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_config.h"
#include "device/device.hpp"
#include "grootle.h"
#include "misc_log_ex.h"
#include "mock_ledger_context.h"
#include "mock_sp_component_types.h"
#include "mock_sp_core.h"
#include "mock_tx_utils.h"
#include "ringct/bulletproofs_plus.h"
#include "ringct/rctOps.h"
#include "ringct/rctSigs.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <memory>
#include <vector>


namespace mock_tx
{
//-------------------------------------------------------------------------------------------------------------------
rct::key get_tx_membership_proof_message_sp_v1()
{
    rct::key hash_result;
    std::string hash{CRYPTONOTE_NAME};
    rct::hash_to_scalar(hash_result, hash.data(), hash.size());

    return hash_result;
}
//-------------------------------------------------------------------------------------------------------------------
rct::key get_tx_image_proof_message_sp_v1(const std::string &version_string,
    const std::vector<MockENoteSpV1> &output_enotes,
    const MockBalanceProofSpV1 &balance_proof,
    const MockSupplementSpV1 &tx_supplement)
{
    rct::key hash_result;
    std::string hash;
    hash.reserve(sizeof(CRYPTONOTE_NAME) +
        version_string.size() +
        output_enotes.size()*MockENoteSpV1::get_size_bytes() +
        balance_proof.get_size_bytes() +
        tx_supplement.m_output_enote_pubkeys.size());
    hash += CRYPTONOTE_NAME;
    for (const auto &output_enote : output_enotes)
    {
        output_enote.append_to_string(hash);
    }
    balance_proof.append_to_string(false, hash);  // don't append amount commitments here (they were appended by enotes)
    for (const auto &enote_pubkey : tx_supplement.m_output_enote_pubkeys)
    {
        hash.append((const char*) enote_pubkey.bytes, sizeof(enote_pubkey));
    }

    rct::hash_to_scalar(hash_result, hash.data(), hash.size());

    return hash_result;
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<MockInputSpV1> gen_mock_sp_inputs_v1(const std::vector<rct::xmr_amount> in_amounts)
{
    std::vector<MockInputSpV1> inputs;
    inputs.resize(in_amounts.size());

    for (std::size_t input_index{0}; input_index < in_amounts.size(); ++input_index)
    {
        inputs[input_index].gen(in_amounts[input_index]);
    }

    return inputs;
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<MockMembershipReferenceSetSpV1> gen_mock_sp_membership_ref_sets_v1(const std::vector<MockInputSpV1> &inputs,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    std::shared_ptr<MockLedgerContext> ledger_context_inout)
{
    std::vector<MockMembershipReferenceSetSpV1> reference_sets;
    reference_sets.resize(inputs.size());

    std::size_t ref_set_size{ref_set_size_from_decomp(ref_set_decomp_n, ref_set_decomp_m)};  // n^m

    for (std::size_t input_index{0}; input_index < inputs.size(); ++input_index)
    {
        reference_sets[input_index].m_ref_set_decomp_n = ref_set_decomp_n;
        reference_sets[input_index].m_ref_set_decomp_m = ref_set_decomp_m;
        reference_sets[input_index].m_real_spend_index_in_set = crypto::rand_idx(ref_set_size);  // pi

        reference_sets[input_index].m_enote_ledger_indices.resize(ref_set_size);
        reference_sets[input_index].m_referenced_enotes.resize(ref_set_size);

        for (std::size_t ref_index{0}; ref_index < ref_set_size; ++ref_index)
        {
            // add real input at pi
            if (ref_index == reference_sets[input_index].m_real_spend_index_in_set)
            {
                reference_sets[input_index].m_referenced_enotes[ref_index] = inputs[input_index].m_enote;
            }
            // add dummy enote
            else
            {
                reference_sets[input_index].m_referenced_enotes[ref_index].gen();
            }

            // insert referenced enote into mock ledger
            // note: in a real context, you would instead 'get' the enote's index from the ledger, and error if not found
            reference_sets[input_index].m_enote_ledger_indices[ref_index] =
                ledger_context_inout->add_enote_sp_v1(reference_sets[input_index].m_referenced_enotes[ref_index]);
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<MockDestSpV1> gen_mock_sp_dests_v1(const std::vector<rct::xmr_amount> &out_amounts)
{

}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_outputs_sp_v1(const std::vector<MockDestSpV1> &destinations,
        std::vector<MockENoteSpV1> &outputs_out,
        std::vector<rct::xmr_amount> &output_amounts_out,
        std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors_out,
        MockSupplementSpV1 &tx_supplement_inout)
{

}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_images_sp_v1(const std::vector<MockInputSpV1> &inputs_to_spend,
    const std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors,
    std::vector<MockENoteImageSpV1> &input_images_out,
    std::vector<crypto::secret_key> &image_address_masks_out,
    std::vector<crypto::secret_key> &image_amount_masks_out)
{

}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_image_proofs_sp_v1(const std::vector<MockInputSpV1> &inputs_to_spend,
    const std::vector<MockENoteImageSpV1> &input_images,
    const std::vector<crypto::secret_key> &image_address_masks,
    const std::vector<crypto::secret_key> &image_amount_masks,
    const rct::key &message,
    std::vector<MockImageProofSpV1> &tx_image_proofs_out)
{

}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_balance_proof_rct_v1(const std::vector<rct::xmr_amount> &output_amounts,
    const std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors,
    const std::size_t max_rangeproof_splits,
    std::shared_ptr<MockBalanceProofSpV1> &balance_proof_out)
{

}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_tx_membership_proofs_sp_v1(const std::vector<MockMembershipReferenceSetSpV1> &membership_ref_sets,
    const std::vector<crypto::secret_key> &image_address_masks,
    const std::vector<crypto::secret_key> &image_amount_masks,
    const rct::key &message,
    std::vector<MockMembershipProofSpV1> &tx_membership_proofs_out)
{

}
//-------------------------------------------------------------------------------------------------------------------
} //namespace mock_tx
