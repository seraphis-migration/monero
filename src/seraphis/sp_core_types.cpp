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
#include "sp_core_types.h"

//local headers
#include "crypto/crypto.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_core_utils.h"
#include "sp_crypto_utils.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void SpEnote::make_base_with_onetime_address(const rct::key &onetime_address,
    const crypto::secret_key &amount_blinding_factor,
    const rct::xmr_amount amount)
{
    // Ko
    m_onetime_address = onetime_address;

    // C = x G + a H
    m_amount_commitment = rct::commit(amount, rct::sk2rct(amount_blinding_factor));
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnote::make_base_with_address_extension(const crypto::secret_key &extension_privkey,
        const rct::key &initial_address,
        const crypto::secret_key &amount_blinding_factor,
        const rct::xmr_amount amount)
{
    // Ko = k_address_extension X + K
    m_onetime_address = initial_address;
    extend_seraphis_spendkey(extension_privkey, m_onetime_address);

    // finish making enote base
    this->make_base_with_onetime_address(m_onetime_address, amount_blinding_factor, amount);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnote::make_base_with_privkeys(const crypto::secret_key &enote_view_privkey,
        const crypto::secret_key &spendbase_privkey,
        const crypto::secret_key &amount_blinding_factor,
        const rct::xmr_amount amount)
{
    // spendbase = k_{b, recipient} U
    rct::key spendbase;
    make_seraphis_spendbase(spendbase_privkey, spendbase);

    // finish making enote base
    this->make_base_with_address_extension(enote_view_privkey, spendbase, amount_blinding_factor, amount);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnote::gen()
{
    // all random
    m_onetime_address = rct::pkGen();
    m_amount_commitment = rct::pkGen();
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnote::append_to_string(std::string &str_inout) const
{
    // append all enote contents to the string
    // - assume the input string has enough capacity (or the caller doesn't care about allocations)
    str_inout.append((const char*) m_onetime_address.bytes, sizeof(rct::key));
    str_inout.append((const char*) m_amount_commitment.bytes, sizeof(rct::key));
}
//-------------------------------------------------------------------------------------------------------------------
void SpInputProposal::get_key_image(crypto::key_image &key_image_out) const
{
    // KI = k_a X + k_a U
    make_seraphis_key_image(m_enote_view_privkey, m_spendbase_privkey, key_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
void SpInputProposal::get_enote_base(SpEnote &enote_out) const
{
    enote_out.make_base_with_privkeys(m_enote_view_privkey, m_spendbase_privkey, m_amount_blinding_factor, m_amount);
}
//-------------------------------------------------------------------------------------------------------------------
void SpInputProposal::get_enote_image_squashed_base(SpEnoteImage &image_out) const
{
    // {Ko, C}
    SpEnote enote_temp;
    this->get_enote_base(enote_temp);

    // Ko' = t_k G + H(Ko,C) Ko
    squash_seraphis_address(enote_temp.m_onetime_address,
        enote_temp.m_amount_commitment,
        image_out.m_masked_address);  //H(Ko,C) Ko
    sp::mask_key(m_address_mask, image_out.m_masked_address, image_out.m_masked_address);  //t_k G + H(Ko,C) Ko

    // C' = t_c G + C
    sp::mask_key(m_commitment_mask, enote_temp.m_amount_commitment, image_out.m_masked_commitment);

    // KI = k_a X + k_b U
    this->get_key_image(image_out.m_key_image);
}
//-------------------------------------------------------------------------------------------------------------------
void SpInputProposal::gen(const rct::xmr_amount amount)
{
    m_enote_view_privkey = rct::rct2sk(rct::skGen());
    m_spendbase_privkey = rct::rct2sk(rct::skGen());
    m_amount_blinding_factor = rct::rct2sk(rct::skGen());
    m_amount = amount;
    m_address_mask = rct::rct2sk(rct::skGen());;
    m_commitment_mask = rct::rct2sk(rct::skGen());;
}
//-------------------------------------------------------------------------------------------------------------------
void SpOutputProposal::get_enote_base(SpEnote &enote_out) const
{
    enote_out.make_base_with_onetime_address(m_onetime_address, m_amount_blinding_factor, m_amount);
}
//-------------------------------------------------------------------------------------------------------------------
void SpOutputProposal::gen(const rct::xmr_amount amount)
{
    // all random except amount
    m_onetime_address = rct::pkGen();
    m_amount_blinding_factor = rct::rct2sk(rct::skGen());
    m_amount = amount;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
