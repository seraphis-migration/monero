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

// Mock tx: Seraphis base types
// NOT FOR PRODUCTION

#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace mock_tx
{

////
// MockENoteSp - Seraphis ENote base
///
struct MockENoteSp
{
    /// K = (k_{a, sender} + k_{a, recipient}) X + k_{b, recipient} U
    crypto::public_key m_onetime_address;
    /// C = x G + a H
    crypto::public_key m_amount_commitment;

    static std::size_t get_size_bytes_base() {return 32*2;}

    /**
    * brief: make_base_from_privkeys - make a Seraphis ENote when all secrets are known
    * param: enote_view_privkey -
    * param: spendbase_privkey -
    * param: amount_blinding_factor -
    * param: amount -
    */
    virtual void make_base_from_privkeys(const crypto::secret_key &enote_view_privkey,
        const crypto::secret_key &spendbase_privkey,
        const crypto::secret_key &amount_blinding_factor,
        const rct::xmr_amount amount) final;
    /**
    * brief: make_base_from_spendbase - make a Seraphis ENote from base public spend key
    * param: enote_view_privkey -
    * param: spendbase_pubkey -
    * param: amount_blinding_factor -
    * param: amount -
    */
    virtual void make_base_from_spendbase(const crypto::secret_key &enote_view_privkey,
        const crypto::public_key &spendbase_pubkey,
        const crypto::secret_key &amount_blinding_factor,
        const rct::xmr_amount amount) final;
    /**
    * brief: gen_base - generate a Seraphis ENote (all random)
    */
    virtual void gen_base() final;
};

////
// MockENoteImageSp - Seraphis ENote Image base
///
struct MockENoteImageSp
{
    /// K' = t_k G + (k_{a, sender} + k_{a, recipient}) X + k_{b, recipient} U
    crypto::public_key m_masked_address;
    /// C' = (t_c + x) G + a H
    crypto::public_key m_masked_commitment;
    /// KI = (k_{b, recipient} / (k_{a, sender} + k_{a, recipient})) U
    crypto::key_image m_key_image;

    static std::size_t get_size_bytes_base() {return 32*3;}
};

////
// MockInputSp - Seraphis Input base
// - inputs reference a set of enotes, so this is parameterized by the enote type
///
template <typename MockENoteType>
struct MockInputSp
{
    MockENoteType m_enote_to_spend;

    /// k_{a, sender} + k_{a, recipient}
    crypto::secret_key m_enote_view_privkey;
    /// k_{b, recipient} U
    crypto::public_key m_spendbase_pubkey;
    /// x
    crypto::secret_key m_amount_blinding_factor;
    /// a
    rct::xmr_amount m_amount;

    /**
    * brief: to_enote_image - convert this input to an enote image
    * param: address_mask - t_k
    * param: commitment_mask - t_c
    * inoutparam: image_inout -
    */
    virtual void to_enote_image_base(const crypto::secret_key &address_mask,
        const crypto::secret_key &commitment_mask,
        MockENoteImageSp &image_inout) const final;
};

////
// MockDestSp - Seraphis Destination base
// - for creating an e-note to send an amount to someone
///
struct MockDestSp
{
    crypto::public_key m_onetime_address;
    crypto::secret_key m_amount_blinding_factor;
    rct::xmr_amount m_amount;

    /// convert this destination into an e-note
    virtual void to_enote_sp_base(MockENoteSp &enote_inout) const final;

    /**
    * brief: gen_base - generate a Seraphis Destination (all random)
    * param: amount -
    */
    virtual void gen_base(const rct::xmr_amount amount) final;
};

} //namespace mock_tx
