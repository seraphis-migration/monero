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

// Utilities for obtaining legacy enote records.

#pragma once

//local headers
#include "crypto/crypto.h"
#include "cryptonote_basic/subaddress_index.h"
#include "device/device.hpp"
#include "enote_record_types.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/legacy_enote_types.h"

//third party headers

//standard headers
#include <unordered_map>

//forward declarations


namespace sp
{

/**
* brief: try_get_legacy_basic_enote_record - try to extract a legacy basic enote record from a legacy enote
* param: enote -
* param: enote_ephemeral_pubkey -
* param: tx_output_index -
* param: unlock_time -
* param: sender_receiver_DH_derivation -
* param: legacy_base_spend_pubkey -
* param: legacy_subaddress_map -
* inoutparam: hwdev -
* outparam: basic_record_out -
* return: true if an extraction succeeded
*/
bool try_get_legacy_basic_enote_record(const LegacyEnoteVariant &enote,
    const rct::key &enote_ephemeral_pubkey,
    const std::uint64_t tx_output_index,
    const std::uint64_t unlock_time,
    const crypto::key_derivation &sender_receiver_DH_derivation,
    const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    hw::device &hwdev,
    LegacyBasicEnoteRecord &basic_record_out);
bool try_get_legacy_basic_enote_record(const LegacyEnoteVariant &enote,
    const rct::key &enote_ephemeral_pubkey,
    const std::uint64_t tx_output_index,
    const std::uint64_t unlock_time,
    const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    hw::device &hwdev,
    LegacyBasicEnoteRecord &basic_record_out);
/**
* brief: try_get_legacy_intermediate_enote_record - try to extract a legacy intermediate enote record from a legacy enote
* param: enote -
* param: enote_ephemeral_pubkey -
* param: tx_output_index -
* param: unlock_time -
* param: legacy_base_spend_pubkey -
* param: legacy_subaddress_map -
* param: legacy_view_privkey -
* outparam: record_out -
* return: true if an extraction succeeded
*/
bool try_get_legacy_intermediate_enote_record(const LegacyEnoteVariant &enote,
    const rct::key &enote_ephemeral_pubkey,
    const std::uint64_t tx_output_index,
    const std::uint64_t unlock_time,
    const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    hw::device &hwdev,
    LegacyIntermediateEnoteRecord &record_out);
bool try_get_legacy_intermediate_enote_record(const LegacyBasicEnoteRecord &basic_record,
    const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_view_privkey,
    hw::device &hwdev,
    LegacyIntermediateEnoteRecord &record_out);
/**
* brief: try_get_legacy_enote_record - try to extract a legacy enote record from a legacy enote
* param: enote -
* param: enote_ephemeral_pubkey -
* param: tx_output_index -
* param: unlock_time -
* param: legacy_base_spend_pubkey -
* param: legacy_subaddress_map -
* param: legacy_spend_privkey -
* param: legacy_view_privkey -
* outparam: record_out -
* return: true if an extraction succeeded
*/
bool try_get_legacy_enote_record(const LegacyEnoteVariant &enote,
    const rct::key &enote_ephemeral_pubkey,
    const std::uint64_t tx_output_index,
    const std::uint64_t unlock_time,
    const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_spend_privkey,
    const crypto::secret_key &legacy_view_privkey,
    hw::device &hwdev,
    LegacyEnoteRecord &record_out);
bool try_get_legacy_enote_record(const LegacyBasicEnoteRecord &basic_record,
    const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_spend_privkey,
    const crypto::secret_key &legacy_view_privkey,
    hw::device &hwdev,
    LegacyEnoteRecord &record_out);
void get_legacy_enote_record(const LegacyIntermediateEnoteRecord &intermediate_record,
    const crypto::key_image &key_image,
    LegacyEnoteRecord &record_out);
void get_legacy_enote_record(const LegacyIntermediateEnoteRecord &intermediate_record,
    const crypto::secret_key &legacy_spend_privkey,
    hw::device &hwdev,
    LegacyEnoteRecord &record_out);

} //namespace sp
