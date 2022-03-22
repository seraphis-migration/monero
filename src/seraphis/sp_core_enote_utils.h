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

// Seraphis enote and enote image component builders


#pragma once

//local headers
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "ringct/rctTypes.h"

//third party headers

//standard headers

//forward declarations
namespace sp { struct SpEnote; }

namespace sp
{

/**
* brief: make_seraphis_key_image - create a Seraphis key image from 'y' and spend key base 'zU'
*   KI = (1/y) * z U
* param: y - private key 'y' (e.g. created from private view key secrets)
* param: zU - pubkey z U (e.g. the base spend key 'ks U')
* outparam: key_image_out - KI
*/
void make_seraphis_key_image(const crypto::secret_key &y, const rct::key &zU, crypto::key_image &key_image_out);
/**
* brief: make_seraphis_key_image - create a Seraphis key image from private keys 'y' and 'z'
*   KI = (z/y)*U
*      = (k_{b, recipient} / (k_{a, sender} + k_{a, recipient}))*U
* param: y - private key '(k_{a, sender} + k_{a, recipient}))' (e.g. created from private view key secrets)
* param: z - private key 'k_{b, recipient}' (e.g. the private spend key 'ks')
* outparam: key_image_out - KI
*/
void make_seraphis_key_image(const crypto::secret_key &y, const crypto::secret_key &z, crypto::key_image &key_image_out);
/**
* brief: make_seraphis_key_image - create a Seraphis key image from sender/recipient pieces
*   KI = (k_{b. recipient} / (k_{a, sender} + k_{a, recipient})) * U
* param: k_a_sender - private key derived from sender (e.g. created from sender-recipient secret q_t)
* param: k_a_recipient - private key provided by recipient (e.g. based on the private view key)
* param: k_bU - recipient's spendbase pubkey (k_{b, recipient} * U)
* outparam: key_image_out - KI
*/
void make_seraphis_key_image(const crypto::secret_key &k_a_sender,
    const crypto::secret_key &k_a_recipient,
    const rct::key &k_bU,
    crypto::key_image &key_image_out);
/**
* brief: make_seraphis_spendbase - create the base part of a Seraphis spendkey
*   spendbase = k_{b, recipient} U
* param: spendbase_privkey - k_{b, recipient}
* outparam: spendbase_pubkey_out - k_{b, recipient} U
*/
void make_seraphis_spendbase(const crypto::secret_key &spendbase_privkey, rct::key &spendbase_pubkey_out);
/**
* brief: extend_seraphis_spendkey - extend/create a Seraphis spendkey (or onetime address)
*   K = k_a_extender X + K_original
* param: k_a_extender - extends the existing pubkey
* inoutparam: spendkey_inout - [in: K_original] [out: k_a_extender X + K_original]
*/
void extend_seraphis_spendkey(const crypto::secret_key &k_a_extender, rct::key &spendkey_inout);
/**
* brief: make_seraphis_spendkey - create a Seraphis spendkey (or onetime address)
*   K = k_a X + k_b U
* param: view_privkey - k_a
* param: spendbase_privkey - k_b
* outparam: spendkey_out - k_a X + k_b U
*/
void make_seraphis_spendkey(const crypto::secret_key &k_a, const crypto::secret_key &k_b, rct::key &spendkey_out);
/**
* brief: make_seraphis_squash_prefix - make the prefix for squashing an enote in the squashed enote model
*   H_n(Ko,C)
* param: onetime_address - Ko
* param: amount_commitment - C
* outparam: squash_prefix_out - H_n(Ko,C)
*/
void make_seraphis_squash_prefix(const rct::key &onetime_address,
    const rct::key &amount_commitment,
    crypto::secret_key &squash_prefix_out);
/**
* brief: make_seraphis_squashed_address_key - make a 'squashed' address in the squashed enote model
*   Ko^t = H_n(Ko,C) Ko
* param: onetime_address - Ko
* param: amount_commitment - C
* outparam: squashed_address_out - H(Ko,C) Ko
*/
void make_seraphis_squashed_address_key(const rct::key &onetime_address,
    const rct::key &amount_commitment,
    rct::key &squashed_address_out);
/**
* brief: make_seraphis_squashed_enote_Q - make a 'squashed' enote in the squashed enote model
*   Q = Ko^t + C^t = H_n(Ko,C) Ko + C
* param: onetime_address - Ko
* param: amount_commitment - C
* outparam: Q_out - Q
*/
void make_seraphis_squashed_enote_Q(const rct::key &onetime_address,
    const rct::key &amount_commitment,
    rct::key &Q_out);
/**
* brief: make_seraphis_enote_core - make a Seraphis ENote from a pre-made onetime address
* param: onetime_address -
* param: amount_blinding_factor -
* param: amount -
* outparam: enote_core_out -
*/
void make_seraphis_enote_core(const rct::key &onetime_address,
    const crypto::secret_key &amount_blinding_factor,
    const rct::xmr_amount amount,
    SpEnote &enote_core_out);
/**
* brief: make_seraphis_enote_core - make a Seraphis ENote by extending an existing address
* param: extension_privkey -
* param: initial_address -
* param: amount_blinding_factor -
* param: amount -
* outparam: enote_core_out -
*/
void make_seraphis_enote_core(const crypto::secret_key &extension_privkey,
    const rct::key &initial_address,
    const crypto::secret_key &amount_blinding_factor,
    const rct::xmr_amount amount,
    SpEnote &enote_core_out);
/**
* brief: make_seraphis_enote_core - make a Seraphis ENote when all secrets are known
* param: enote_view_privkey -
* param: spendbase_privkey -
* param: amount_blinding_factor -
* param: amount -
* outparam: enote_core_out -
*/
void make_seraphis_enote_core(const crypto::secret_key &enote_view_privkey,
    const crypto::secret_key &spendbase_privkey,
    const crypto::secret_key &amount_blinding_factor,
    const rct::xmr_amount amount,
    SpEnote &enote_core_out);


} //namespace sp
