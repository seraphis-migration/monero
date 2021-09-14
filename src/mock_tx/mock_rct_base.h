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

// Mock tx: plain RingCT base components (types/functions)
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
// MockENoteRct - RCT ENote
///
struct MockENoteRct
{
    crypto::public_key m_onetime_address;
    crypto::public_key m_amount_commitment;

    static std::size_t get_size_bytes_base() {return 32*2;}

    /**
    * brief: make_base - make an RCT ENote
    * param: onetime_privkey -
    * param: amount_blinding_factor -
    * param: amount -
    */
    virtual void make_base(const crypto::secret_key &onetime_privkey,
        const crypto::secret_key &amount_blinding_factor,
        const rct::xmr_amount amount) final;
    /**
    * brief: gen_base - generate an RCT ENote (all random)
    */
    virtual void gen_base() final;
};

////
// MockENoteImageRct - RCT ENote Image
///
struct MockENoteImageRct
{
    crypto::public_key m_pseudo_amount_commitment;
    crypto::key_image m_key_image;

    static std::size_t get_size_bytes_base() {return 32*2;}
};

////
// MockInputRct - RCT Input
// - inputs reference a set of enotes, so this is parameterized by the enote type
///
template <typename MockENoteType>
struct MockInputRct
{
    crypto::secret_key m_onetime_privkey;
    crypto::secret_key m_amount_blinding_factor;
    rct::xmr_amount m_amount;
    std::vector<MockENoteType> m_input_ref_set;
    std::size_t m_input_ref_set_real_index;
};

////
// MockDestRct - RCT Destination
///
struct MockDestRct
{
    /// destination (for creating an e-note to send an amount to someone)

    crypto::public_key m_onetime_address;
    crypto::secret_key m_amount_blinding_factor;
    rct::xmr_amount m_amount;

    /// convert this destination into an e-note
    virtual void to_enote_rct_base(MockENoteRct &enote_inout) const final;

    /**
    * brief: gen_base - generate an RCT Destination (all random)
    * param: amount -
    */
    virtual void gen_base(const rct::xmr_amount amount) final;
};

} //namespace mock_tx








