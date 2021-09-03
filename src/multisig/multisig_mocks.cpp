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
#include "multisig_mocks.h"

//local headers
#include "crypto/crypto.h"
#include "cryptonote_basic/account_generators.h"
#include "misc_log_ex.h"
#include "multisig.h"
#include "multisig_account.h"
#include "multisig_kex_msg.h"
#include "multisig_partial_cn_key_image_msg.h"
#include "multisig_signer_set_filter.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <unordered_map>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "multisig"

namespace multisig
{
namespace mocks
{
//-------------------------------------------------------------------------------------------------------------------
void make_multisig_mock_accounts(const cryptonote::account_generator_era account_era,
    const std::uint32_t threshold,
    const std::uint32_t num_signers,
    std::vector<multisig_account> &accounts_out)
{
    std::vector<crypto::public_key> signers;
    std::vector<multisig_kex_msg> current_round_msgs;
    std::vector<multisig_kex_msg> next_round_msgs;
    accounts_out.clear();
    accounts_out.reserve(num_signers);
    signers.reserve(num_signers);
    next_round_msgs.reserve(accounts_out.size());

    // create multisig accounts for each signer
    for (std::size_t account_index{0}; account_index < num_signers; ++account_index)
    {
        // create account [[ROUND 0]]
        accounts_out.emplace_back(account_era, rct::rct2sk(rct::skGen()), rct::rct2sk(rct::skGen()));

        // collect signer
        signers.emplace_back(accounts_out.back().get_base_pubkey());

        // collect account's first kex msg
        next_round_msgs.emplace_back(accounts_out.back().get_next_kex_round_msg());
    }

    // perform key exchange rounds until the accounts are ready
    while (accounts_out.size() && !accounts_out[0].multisig_is_ready())
    {
        current_round_msgs = std::move(next_round_msgs);
        next_round_msgs.clear();
        next_round_msgs.reserve(accounts_out.size());

        for (multisig_account &account : accounts_out)
        {
            // initialize or update account
            if (!account.account_is_active())
                account.initialize_kex(threshold, signers, current_round_msgs);  //[[ROUND 1]]
            else
                account.kex_update(current_round_msgs);  //[[ROUND 2+]]

            next_round_msgs.emplace_back(account.get_next_kex_round_msg());
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
void mock_convert_multisig_accounts(const cryptonote::account_generator_era new_era,
    std::vector<multisig_account> &accounts_inout)
{
    if (accounts_inout.size() == 0 || new_era == accounts_inout[0].get_era())
        return;

    // collect messages
    std::vector<multisig_account_era_conversion_msg> conversion_msgs;
    conversion_msgs.reserve(accounts_inout.size());

    for (const multisig_account &account : accounts_inout)
        conversion_msgs.emplace_back(account.get_account_era_conversion_msg(new_era));

    // convert accounts to 'new_era'
    for (multisig_account &account : accounts_inout)
        get_multisig_account_with_new_generator_era(account, new_era, conversion_msgs, account);
}
//-------------------------------------------------------------------------------------------------------------------
void mock_multisig_cn_key_image_recovery(const std::vector<multisig_account> &accounts,
    //[ base key for key image : shared offset privkey material in base key ]
    const std::unordered_map<crypto::public_key, crypto::secret_key> &saved_key_components,
    std::unordered_map<crypto::public_key, crypto::key_image> &recovered_key_images_out)
{
    // 1. prepare partial key image messages for the key image base keys from all multisig group members
    std::unordered_map<crypto::public_key,
        std::unordered_map<crypto::public_key, multisig_partial_cn_key_image_msg>> partial_ki_msgs;

    for (const multisig_account &account : accounts)
    {
        CHECK_AND_ASSERT_THROW_MES(account.get_era() == cryptonote::account_generator_era::cryptonote,
            "mock multisig cn key image recovery: account has unexpected account era.");

        for (const auto &saved_keys : saved_key_components)
        {
            partial_ki_msgs[saved_keys.first][account.get_base_pubkey()] =
                multisig_partial_cn_key_image_msg{
                        account.get_base_privkey(),
                        saved_keys.first,
                        account.get_multisig_privkeys()
                    };
        }
    }

    // 2. process the messages
    std::unordered_map<crypto::public_key, signer_set_filter> onetime_addresses_with_insufficient_partial_kis;
    std::unordered_map<crypto::public_key, signer_set_filter> onetime_addresses_with_invalid_partial_kis;
    std::unordered_map<crypto::public_key, crypto::public_key> recovered_key_image_cores;

    multisig_recover_cn_keyimage_cores(accounts[0].get_threshold(),
        accounts[0].get_signers(),
        accounts[0].get_multisig_pubkey(),
        partial_ki_msgs,
        onetime_addresses_with_insufficient_partial_kis,
        onetime_addresses_with_invalid_partial_kis,
        recovered_key_image_cores);

    CHECK_AND_ASSERT_THROW_MES(onetime_addresses_with_insufficient_partial_kis.size() == 0,
        "mock multisig cn key image recovery: failed to make partial kis for some onetime addresses.");
    CHECK_AND_ASSERT_THROW_MES(onetime_addresses_with_invalid_partial_kis.size() == 0,
        "mock multisig cn key image recovery: failed to make partial kis for some onetime addresses.");

    // 3. add the shared offset component to each key image core
    for (const auto &recovered_key_image_core : recovered_key_image_cores)
    {
        CHECK_AND_ASSERT_THROW_MES(saved_key_components.find(recovered_key_image_core.first) !=
                saved_key_components.end(),
            "mock multisig cn key image recovery: did not produce an expected key image core.");

        // KI_shared_piece = shared_offset * Hp(base key)
        crypto::key_image KI_shared_piece;
        crypto::generate_key_image(recovered_key_image_core.first,
            saved_key_components.at(recovered_key_image_core.first),
            KI_shared_piece);

        // KI = shared_offset * Hp(base key) + k_multisig * Hp(base key)
        recovered_key_images_out[recovered_key_image_core.first] =
            rct::rct2ki(rct::addKeys(rct::ki2rct(KI_shared_piece), rct::pk2rct(recovered_key_image_core.second)));
    }
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace mocks
} //namespace multisig
