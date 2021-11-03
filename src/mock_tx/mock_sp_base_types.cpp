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
#include "mock_sp_base_types.h"

//local headers
#include "crypto/crypto.h"
#include "misc_log_ex.h"
#include "mock_sp_core_utils.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_crypto_utils.h"

//third party headers

//standard headers
#include <vector>


namespace mock_tx
{
//-------------------------------------------------------------------------------------------------------------------
void MockENoteSp::make_base_from_privkeys(const crypto::secret_key &enote_view_privkey,
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
void MockENoteSp::make_base_with_address_extension(const crypto::secret_key &extension_privkey,
        const rct::key &initial_address,
        const crypto::secret_key &amount_blinding_factor,
        const rct::xmr_amount amount)
{
    // Ko = k_m_address_extension X + K
    m_onetime_address = initial_address;
    extend_seraphis_spendkey(extension_privkey, m_onetime_address);

    // C = x G + a H
    m_amount_commitment = rct::commit(amount, rct::sk2rct(amount_blinding_factor));
}
//-------------------------------------------------------------------------------------------------------------------
void MockENoteSp::gen_base()
{
    // all random
    m_onetime_address = rct::pkGen();
    m_amount_commitment = rct::pkGen();
}
//-------------------------------------------------------------------------------------------------------------------
void MockInputProposalSp::get_key_image(crypto::key_image &key_image_out) const
{
    // KI = k_a X + k_a U
    make_seraphis_key_image(m_enote_view_privkey, m_spendbase_privkey, key_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
void MockInputProposalSp::to_enote_image_base(const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    MockENoteImageSp &image_inout) const
{
    // Ko' = t_k G + Ko
    sp::mask_key(address_mask, get_enote_base().m_onetime_address, image_inout.m_masked_address);
    // C' = t_c G + C
    sp::mask_key(commitment_mask, get_enote_base().m_amount_commitment, image_inout.m_masked_commitment);
    // KI = k_a X + k_a U
    this->get_key_image(image_inout.m_key_image);
}
//-------------------------------------------------------------------------------------------------------------------
void MockInputProposalSp::to_enote_image_squashed_base(const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    MockENoteImageSp &image_inout) const
{
    // Ko' = t_k G + H(Ko,C) Ko
    squash_seraphis_address(get_enote_base().m_onetime_address,
        get_enote_base().m_amount_commitment,
        image_inout.m_masked_address);
    sp::mask_key(address_mask, image_inout.m_masked_address, image_inout.m_masked_address);
    // C' = t_c G + C
    sp::mask_key(commitment_mask, get_enote_base().m_amount_commitment, image_inout.m_masked_commitment);
    // KI = k_a X + k_a U
    this->get_key_image(image_inout.m_key_image);
}
//-------------------------------------------------------------------------------------------------------------------
void MockInputProposalSp::gen_base(const rct::xmr_amount amount)
{
    m_enote_view_privkey = rct::rct2sk(rct::skGen());
    m_spendbase_privkey = rct::rct2sk(rct::skGen());
    m_amount_blinding_factor = rct::rct2sk(rct::skGen());
    m_amount = amount;
}
//-------------------------------------------------------------------------------------------------------------------
void MockDestinationSp::gen_base(const rct::xmr_amount amount)
{
    // all random except amount
    m_recipient_DHkey = rct::pkGen();
    m_recipient_viewkey = rct::pkGen();
    m_recipient_spendkey = rct::pkGen();

    m_amount = amount;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace mock_tx
