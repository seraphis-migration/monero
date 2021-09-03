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

// NOT FOR PRODUCTION

//paired header
#include "legacy_mock_keys.h"

//local headers
#include "crypto/crypto.h"
#include "cryptonote_basic/subaddress_index.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/legacy_core_utils.h"

//third party headers

//standard headers


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_mocks"

namespace sp
{
namespace mocks
{
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_mock_keys(legacy_mock_keys &keys_out)
{
    keys_out.k_s = rct::rct2sk(rct::skGen());
    keys_out.k_v = rct::rct2sk(rct::skGen());
    keys_out.Ks  = rct::scalarmultBase(rct::sk2rct(keys_out.k_s));
    keys_out.Kv  = rct::scalarmultBase(rct::sk2rct(keys_out.k_v));
}
//-------------------------------------------------------------------------------------------------------------------
void gen_legacy_subaddress(const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_view_privkey,
    rct::key &subaddr_spendkey_out,
    rct::key &subaddr_viewkey_out,
    cryptonote::subaddress_index &subaddr_index_out)
{
    // random subaddress index: i
    crypto::rand(sizeof(subaddr_index_out.minor), reinterpret_cast<unsigned char*>(&subaddr_index_out.minor));
    crypto::rand(sizeof(subaddr_index_out.major), reinterpret_cast<unsigned char*>(&subaddr_index_out.major));

    // subaddress spendkey: (Hn(k^v, i) + k^s) G
    make_legacy_subaddress_spendkey(legacy_base_spend_pubkey,
        legacy_view_privkey,
        subaddr_index_out,
        hw::get_device("default"),
        subaddr_spendkey_out);

    // subaddress viewkey: k^v * K^{s,i}
    rct::scalarmultKey(subaddr_viewkey_out, subaddr_spendkey_out, rct::sk2rct(legacy_view_privkey));
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace mocks
} //namespace sp
