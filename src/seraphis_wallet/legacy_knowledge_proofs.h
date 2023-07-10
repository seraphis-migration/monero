// Copyright (c) 2014-2023, The Monero Project
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
// 

#pragma once

#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "net/jsonrpc_structs.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "rpc/core_rpc_server_error_codes.h"
#include "seraphis_impl/enote_store.h"

using namespace sp;

#define THROW_ON_RPC_RESPONSE_ERROR(r, error, res, method, ...)                     \
    do                                                                              \
    {                                                                               \
        throw_on_rpc_response_error(r, error, res.status, method);                  \
        THROW_WALLET_EXCEPTION_IF(res.status != CORE_RPC_STATUS_OK, ##__VA_ARGS__); \
    }                                                                               \
    while (0)

#define THROW_ON_RPC_RESPONSE_ERROR_GENERIC(r, err, res, method) \
    THROW_ON_RPC_RESPONSE_ERROR(r, err, res, method, tools::error::wallet_generic_rpc_error, method, res.status)

//----------------------------------------------------------------------------------------------------

std::string generate_legacy_spend_proof(const std::string &message, const crypto::hash &txid,
                                        const crypto::secret_key &spend_key, const sp::SpEnoteStore &enote_store);

bool check_legacy_spend_proof(const crypto::hash &txid, const std::string &message, const std::string &sig_str);

//----------------------------------------------------------------------------------------------------

std::string generate_legacy_inproof(const crypto::hash &txid, const rct::key &spend_public_key,
                                    const rct::key &view_public_key, const crypto::secret_key &secret_view_key,
                                    bool is_subaddress, const std::string &message);

bool check_tx_proof(const cryptonote::transaction &tx, const cryptonote::account_public_address &address,
                    bool is_subaddress, const std::string &message, const std::string &sig_str, uint64_t &received);

bool check_tx_proof(const crypto::hash &txid, const cryptonote::account_public_address &address, bool is_subaddress,
                    const std::string &message, const std::string &sig_str, uint64_t &received, bool &in_pool,
                    uint64_t &confirmations);
//----------------------------------------------------------------------------------------------------

/// Auxiliary Functions
//----------------------------------------------------------------------------------------------------
bool get_pruned_tx(const cryptonote::COMMAND_RPC_GET_TRANSACTIONS::entry &entry, cryptonote::transaction &tx,
                   crypto::hash &tx_hash);

void check_tx_key_helper(const cryptonote::transaction &tx, const crypto::key_derivation &derivation,
                         const std::vector<crypto::key_derivation> &additional_derivations,
                         const cryptonote::account_public_address &address, uint64_t &received);

bool is_out_to_acc(const cryptonote::account_public_address &address, const crypto::public_key &out_key,
                   const crypto::key_derivation &derivation,
                   const std::vector<crypto::key_derivation> &additional_derivations, const size_t output_index,
                   const boost::optional<crypto::view_tag> &view_tag_opt, crypto::key_derivation &found_derivation);

void throw_on_rpc_response_error(bool r, const epee::json_rpc::error &error, const std::string &status,
                                 const char *method);
//----------------------------------------------------------------------------------------------------
