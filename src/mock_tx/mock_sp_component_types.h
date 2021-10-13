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

// Mock tx: Seraphis component types
// NOT FOR PRODUCTION

#pragma once

//local headers
#include "crypto/crypto.h"
#include "mock_sp_base.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers

//forward declarations


namespace mock_tx
{

////
// MockENoteSpV1 - v1 enote
///
struct MockENoteSpV1 final : public MockENoteSp
{
    /// enc(a)
    rct::xmr_amount m_encoded_amount;
    /// tag_t
    unsigned char m_view_tag;

    /**
    * brief: make - make a v1 enote
    * param: enote_privkey - r_t
    * param: recipient_DH_base - K^{DH}   [change in 2-out: other recipient's K^{DH}]
    * param: recipient_view_key - K^{vr}  [change in 2-out: k^{vr}_local * K^{DH}_other_recipient]
    * param: recipient_spend_key - K^s
    * param: amount - a
    * param: enote_index - t, index of the enote in its tx
    * outparam: enote_pubkey_out - the enote's pubkey
    */
    void make(const crypto::secret_key &enote_privkey,
        const rct::key &recipient_DH_base,
        const rct::key &recipient_view_key,
        const rct::key &recipient_spend_key,
        const rct::xmr_amount amount,
        const std::size_t enote_index,
        rct::key &enote_pubkey_out);
    /**
    * brief: get_hash - get a hash of the v1 enote
    * return: H(enote contents)
    */
    rct::key get_hash() const;

    /// generate a v1 enote (all random)
    void gen();

    static std::size_t get_size_bytes() { return get_size_bytes_base() + 8 + 1; }
};
#if 0
////
// MockENoteImageSpV1 - ENote Image V1
///
struct MockENoteImageSpV1 final : public MockENoteImageRct
{
    static std::size_t get_size_bytes() { return get_size_bytes_base(); }
};

////
// MockInputSpV1 - Input V1
///
struct MockInputSpV1 final : public MockInputRct<MockENoteSpV1>
{
    /// convert this input to an e-note-image (CryptoNote style)
    MockENoteImageSpV1 to_enote_image_v1(const crypto::secret_key &pseudo_blinding_factor) const;

    /// convert this input to an e-note-image (Triptych style)
    MockENoteImageSpV1 to_enote_image_v2(const crypto::secret_key &pseudo_blinding_factor) const;

    /**
    * brief: gen_v1 - generate a V1 Input (random)
    * param: amount -
    * param: ref_set_size -
    */
    void gen_v1(const rct::xmr_amount amount, const std::size_t ref_set_size);
};

////
// MockDestSpV1 - Destination V1
///
struct MockDestSpV1 final : public MockDestRct
{
    /// memo
    crypto::public_key m_enote_pubkey;
    rct::xmr_amount m_encoded_amount;

    /// convert this destination into a v1 enote
    MockENoteSpV1 to_enote_v1() const;

    /**
    * brief: gen_mock_tx_rct_dest_v1 - generate a V1 Destination (random)
    * param: amount -
    */
    void gen_v1(const rct::xmr_amount amount);
};

////
// MockRctProofV1 - Input Proof V1
// - CLSAG
///
struct MockRctProofV1 final
{
    /// a CLSAG proof
    rct::clsag m_clsag_proof;
    /// vector of pairs <Ko_i, C_i> for referenced enotes
    rct::ctkeyV m_referenced_enotes_converted;

    std::size_t get_size_bytes() const;
};

////
// MockRctProofV2 - Input Proof V2
// - Triptych
///
struct MockRctProofV2 final
{
    /// the Triptych proof
    rct::TriptychProof m_triptych_proof;
    /// onetime addresses Ko
    rct::keyV m_onetime_addresses;
    /// output commitments C
    rct::keyV m_commitments;
    /// pseudo-output commitment C'
    rct::key m_pseudo_amount_commitment;
    /// decomposition n^m
    std::size_t m_ref_set_decomp_n;
    std::size_t m_ref_set_decomp_m;

    std::size_t get_size_bytes() const;
};

////
// MockRctBalanceProofV1 - Balance Proof V1
// - balance proof: implicit [sum(inputs) == sum(outputs)]
// - range proof: Bulletproofs+
///
struct MockRctBalanceProofV1 final
{
    /// a set of BP+ proofs
    std::vector<rct::BulletproofPlus> m_bpp_proofs;

    std::size_t get_size_bytes() const;
};
#endif
} //namespace mock_tx
