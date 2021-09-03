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

// Mockups for multisig unit tests.

#pragma once

//local headers
#include "crypto/crypto.h"
#include "cryptonote_basic/account_generators.h"
#include "multisig_account.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <unordered_map>
#include <vector>

//forward declarations


namespace multisig
{
namespace mocks
{

/**
* brief: make_multisig_mock_accounts - make accounts for a mock multisig group
* param: account_era - account era
* param: threshold - M
* param: num_signers - N
* outparam: accounts_out - mock accounts
*/
void make_multisig_mock_accounts(const cryptonote::account_generator_era account_era,
    const std::uint32_t threshold,
    const std::uint32_t num_signers,
    std::vector<multisig_account> &accounts_out);
/**
* brief: mock_convert_multisig_accounts - convert multisig accounts to a new account era
* param: new_era - account era to convert to
* inoutparam: accounts_inout - accounts to convert
*/
void mock_convert_multisig_accounts(const cryptonote::account_generator_era new_era,
    std::vector<multisig_account> &accounts_inout);
/**
* brief: mock_multisig_cn_key_image_recovery - perform multisig cryptonote key image recovery for a set of keys
* param: accounts - multisig group accounts
* param: saved_key_components - [ base key for key image : shared offset privkey material in base key ]
* outparam: recovered_key_images_out - the recovered key images mapped to their corresponding original keys
*/
void mock_multisig_cn_key_image_recovery(const std::vector<multisig_account> &accounts,
    // [ base key for key image : shared offset privkey material in base key ]
    const std::unordered_map<crypto::public_key, crypto::secret_key> &saved_key_components,
    std::unordered_map<crypto::public_key, crypto::key_image> &recovered_key_images_out);

} //namespace mocks
} //namespace multisig
