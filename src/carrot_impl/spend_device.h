// Copyright (c) 2025-2026, The Monero Project
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

#pragma once

//local headers
#include "key_image_device.h"
#include "knowledge_proof_types.h"
#include "tx_proposal.h"

//third party headers

//standard headers
#include <functional>
#include <map>

//forward declarations

namespace carrot
{
/**
 * @brief Interface to request spending signatures, while hiding the private spends keys
 */
struct spend_device: public key_image_device
{
    /**
     * @brief Maps KI -> (OTA, SA/L) in consensus ordering
     */
    using signed_input_set_t = std::map<crypto::key_image,
        std::pair<crypto::public_key, fcmp_pp::FcmpPpSalProof>,
        std::greater<crypto::key_image>>;

    /**
     * @brief Attempt to request FCMP++ SA/L signatures for each input in the given Carrot v1 transaction proposal
     * @param tx_proposal Carrot v1 transaction proposal
     * @param rerandomized_outputs map of (one-time address -> rerandomized output)
     * @param[out] signable_tx_hash_out signable transaction hash (mainly useful for checking parity with device)
     * @param[out] signed_inputs_out signed input set containing key images and FCMP++ SA/L signatures
     * @return false if spend-side user confirmation is denied, true if accepted and signed
     */
    virtual bool try_sign_carrot_transaction_proposal_v1(const CarrotTransactionProposalV1 &tx_proposal,
        const std::unordered_map<crypto::public_key, FcmpRerandomizedOutputCompressed> &rerandomized_outputs,
        crypto::hash &signable_tx_hash_out,
        signed_input_set_t &signed_inputs_out
    ) const = 0;

    /**
     * @brief Attempt to request key image association proof for given input
     * @param opening_hint -
     * @param[out] key_image_out key image associated to one-time address in `opening_hint`
     * @param[out] ki_proof_out key image association proof for `key_image_out` and `opening_hint`
     * @return false if spend-side user confirmation is denied, true if accepted and signed
     *
     * @TODO: Move this interface to `key_image_device` once there is code to prove key image
     *        associations without knowledge of the spend key
     */
    virtual bool try_make_key_image_association_proof(const OutputOpeningHintVariant &opening_hint,
        crypto::key_image &key_image_out,
        KeyImageProofVariant &ki_proof_out) const = 0;
};
} //namespace carrot
