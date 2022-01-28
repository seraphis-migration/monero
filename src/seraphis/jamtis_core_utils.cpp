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
#include "jamtis_address_utils.h"

//local headers
#include "crypto/crypto.h"
#include "jamtis_hash_functions.h"
#include "misc_log_ex.h"
#include "ringct/rctTypes.h"
#include "sp_crypto_utils.h"

//third party headers

//standard headers
#include <string>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
namespace jamtis
{
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_findreceived_key(const crypto::secret_key &k_view_balance,
    crypto::secret_key &findreceived_key_out)
{
    static const std::string domain_separator{config::HASH_KEY_JAMTIS_FINDRECEIVED_KEY};

    // k_fr = H_n(Pad136(k_vb))
    jamtis_derive_key(domain_separator, &k_view_balance, nullptr, 0, &findreceived_key_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_generateaddress_secret(const crypto::secret_key &k_view_balance,
    crypto::secret_key &generateaddress_secret_out)
{
    static const std::string domain_separator{config::HASH_KEY_JAMTIS_GENERATEADDRESS_SECRET};

    // s_ga = H_32(Pad136(k_vb))
    jamtis_derive_secret(domain_separator, &k_view_balance, nullptr, 0, &generateaddress_secret_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_ciphertag_secret(const crypto::secret_key &k_generate_address,
    crypto::secret_key &ciphertag_secret_out)
{
    static const std::string domain_separator{config::HASH_KEY_JAMTIS_CIPHERTAG_SECRET};

    // s_ct = H_32(Pad136(k_ga))
    jamtis_derive_secret(domain_separator, &k_generate_address, nullptr, 0, &ciphertag_secret_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_identifywallet_key(const crypto::secret_key &k_generate_address,
    crypto::secret_key &identifywallet_key_out)
{
    static const std::string domain_separator{config::HASH_KEY_JAMTIS_IDENTIFYWALLET_KEY};

    // k_id = H_n(Pad136(k_ga))
    jamtis_derive_key(domain_separator, &k_generate_address, nullptr, 0, &identifywallet_key_out);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp
