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

// Mock tx: plain RingCTT common types/functions
// NOT FOR PRODUCTION

#pragma once

//local headers
#include "crypto/crypto.h"
#include "mock_tx_interface.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace mock_tx
{

struct MockENoteRCT
{
    crypto::public_key m_onetime_address;
    crypto::public_key m_amount_commitment;

    // memo
    crypto::public_key m_enote_pubkey;
    rct::xmr_amount m_encoded_amount;

    static virtual std::size_t get_size_bytes() {return 32*3 + 8;}
};

struct MockENoteImageRCT
{
    crypto::public_key m_pseudo_amount_commitment;
    crypto::key_image m_key_image;

    static virtual std::size_t get_size_bytes() {return 32*2;}
};

template <typename MockTxType>
struct MockInputRCT
{
    crypto::secret_key m_onetime_privkey;
    crypto::secret_key m_amount_blinding_factor;
    rct::xmr_amount m_amount;
    std::vector<MockENote<MockTxType>> m_input_ref_set;
    std::size_t m_input_ref_set_real_index;
};

struct MockDestRCT
{
    // destination (for creating an e-note to send an amount to someone)

    crypto::public_key m_onetime_address;
    crypto::secret_key m_amount_blinding_factor;
    rct::xmr_amount m_amount;

    // for the memo
    crypto::public_key m_enote_pubkey;
    rct::xmr_amount m_encoded_amount;

    // convert this destination into an e-note
    void to_enote_rct(MockENoteRCT &enote_inout) const;
};

// create mock enote from known info
void make_mock_tx_enote_rct(const crypto::secret_key &onetime_privkey,
    const crypto::secret_key &amount_blinding_factor,
    const rct::xmr_amount amount,
    MockENoteRCT &enote_inout);

// create random mock enote
void gen_mock_tx_enote_rct(MockENoteRCT &enote_inout);

// create random destination
void gen_mock_tx_dest_rct(const rct::xmr_amount amount, MockDestRCT &dest_inout);


} //namespace mock_tx








