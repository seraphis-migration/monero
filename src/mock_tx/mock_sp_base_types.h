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

//// Versioning

/// Transaction protocol generation: following CryptoNote (1) and RingCT (2)
const unsigned char TxGenerationSp = 3;

/// Transaction structure types
enum TxStructureVersionSp : unsigned char
{
    /// mining transaction (TODO)
    TxTypeSpMining = 0,
    /// concise grootle + separate composition proofs
    TxTypeSpConciseV1 = 1,
    /// concise grootle + merged composition proof
    TxTypeSpMergeV1 = 2,
    /// concise grootle in the squashed enote model + separate composition proof
    TxTypeSpSquashedV1 = 3
};


////
// MockENoteSp - Seraphis ENote base
///
struct MockENoteSp
{
    /// Ko = (k_{a, sender} + k_{a, recipient}) X + k_{b, recipient} U
    rct::key m_onetime_address;
    /// C = x G + a H
    rct::key m_amount_commitment;

    /// virtual destructor for non-final type
    virtual ~MockENoteSp() = default;

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
    * brief: make_base_with_address_extension - make a Seraphis ENote by extending an existing address
    * param: extension_privkey -
    * param: initial_address -
    * param: amount_blinding_factor -
    * param: amount -
    */
    virtual void make_base_with_address_extension(const crypto::secret_key &extension_privkey,
        const rct::key &initial_address,
        const crypto::secret_key &amount_blinding_factor,
        const rct::xmr_amount amount) final;
    /**
    * brief: gen_base - generate a Seraphis ENote (all random)
    */
    virtual void gen_base() final;

    /**
    * brief: append_to_string - convert enote to a string and append to existing string (for proof transcripts)
    * inoutparam: str_inout - enote contents concatenated to a string
    */
    virtual void append_to_string(std::string &str_inout) const = 0;

    static std::size_t get_size_bytes_base() {return 32*2;}
};

////
// MockENoteImageSp - Seraphis ENote Image base
///
struct MockENoteImageSp
{
    /// Ko' = t_k G + (k_{a, sender} + k_{a, recipient}) X + k_{b, recipient} U
    rct::key m_masked_address;
    /// C' = (t_c + x) G + a H
    rct::key m_masked_commitment;
    /// KI = (k_{b, recipient} / (k_{a, sender} + k_{a, recipient})) U
    crypto::key_image m_key_image;

    /// virtual destructor for non-final type
    virtual ~MockENoteImageSp() = default;

    static std::size_t get_size_bytes_base() {return 32*3;}
};

////
// MockInputProposalSp - Seraphis Input Proposal base
// - a tx input is an enote, so this is parameterized by the enote type
///
struct MockInputProposalSp
{
    /// k_{a, sender} + k_{a, recipient}
    crypto::secret_key m_enote_view_privkey;
    /// k_{b, recipient}
    crypto::secret_key m_spendbase_privkey;
    /// x
    crypto::secret_key m_amount_blinding_factor;
    /// a
    rct::xmr_amount m_amount;

    /// virtual destructor for non-final type
    virtual ~MockInputProposalSp() = default;

    /**
    * brief: get_key_image - get this input's key image
    * outparam: key_image_out - KI
    */
    virtual void get_key_image(crypto::key_image &key_image_out) const final;

    /**
    * brief: to_enote_image_base - convert this input to an enote image
    * param: address_mask - t_k
    * param: commitment_mask - t_c
    * inoutparam: image_inout -
    */
    virtual void to_enote_image_base(const crypto::secret_key &address_mask,
        const crypto::secret_key &commitment_mask,
        MockENoteImageSp &image_inout) const final;

    /**
    * brief: to_enote_image_squashed_base - convert this input to an enote image in the squashed enote model
    * param: address_mask - t_k
    * param: commitment_mask - t_c
    * inoutparam: image_inout -
    */
    virtual void to_enote_image_squashed_base(const crypto::secret_key &address_mask,
        const crypto::secret_key &commitment_mask,
        MockENoteImageSp &image_inout) const final;

    /**
    * brief: gen_base - generate a Seraphis Input (all random)
    * param: amount -
    */
    virtual void gen_base(const rct::xmr_amount amount) final;

protected:
    /// inheritor needs to store the enote this input is trying to spend, then pass it back up to the base class here
    virtual const MockENoteSp& get_enote_base() const = 0;
};

////
// MockDestinationSp - Seraphis Destination base
// - for creating an e-note to send an amount to someone
///
struct MockDestinationSp
{
    /// K^{DH}
    rct::key m_recipient_DHkey;
    /// K^{vr}
    rct::key m_recipient_viewkey;
    /// K^s
    rct::key m_recipient_spendkey;
    rct::xmr_amount m_amount;

    /// virtual destructor for non-final type
    virtual ~MockDestinationSp() = default;

    /**
    * brief: gen_base - generate a Seraphis Destination (all random)
    * param: amount -
    */
    virtual void gen_base(const rct::xmr_amount amount) final;
};

} //namespace mock_tx
