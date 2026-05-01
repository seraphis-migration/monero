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

#pragma once

//local headers
#include "knowledge_proofs.h"
#include "spend_device_ram_borrowed.h"

//third party headers

//standard headers

//forward declarations

namespace carrot
{
struct knowledge_proof_ram_borrowed_device:
    public spend_device_ram_borrowed,
    public knowledge_proof_device
{
    /// @brief device composed, carrot XOR legacy, plus ram-borrowed G/T openings to K_s
    knowledge_proof_ram_borrowed_device(std::shared_ptr<view_incoming_key_device> k_view_incoming_dev,
        std::shared_ptr<view_balance_secret_device> s_view_balance_dev,
        std::shared_ptr<address_device> address_dev,
        const crypto::secret_key &privkey_g,
        const crypto::secret_key &privkey_t);

    bool try_sign_fcmp_spend_proof_v1(const crypto::hash &txid,
        const epee::span<const std::uint8_t> message,
        const std::vector<OutputOpeningHintVariant> &opening_hints,
        const std::vector<FcmpRerandomizedOutputCompressed> &rerandomized_outputs,
        crypto::hash &prefix_hash_out,
        knowledge_proof_device::signed_input_set_t &signed_inputs_out
    ) const override;

    bool try_sign_fcmp_reserve_proof_v1(const rct::xmr_amount threshold_amount,
        const std::vector<OutputOpeningHintVariant> &opening_hints,
        const std::vector<FcmpRerandomizedOutputCompressed> &rerandomized_outputs,
        crypto::hash &prefix_hash_out,
        knowledge_proof_device::signed_input_set_t &signed_inputs_out
    ) const override;
};
} //namespace carrot
