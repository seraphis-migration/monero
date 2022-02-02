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

// Seraphis base non-tx types
// NOT FOR PRODUCTION

#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace sp
{

//// Versioning

/// Transaction protocol era: following CryptoNote (1) and RingCT (2)
const unsigned char TxEraSp = 3;

/// Transaction structure types
enum TxStructureVersionSp : unsigned char
{
    /// mining transaction (TODO)
    TxTypeSpMining = 0,
    /// concise grootle in the squashed enote model + separate composition proofs
    TxTypeSpSquashedV1 = 1
};


////
// SpEnote
///
struct SpEnote final
{
    /// Ko = (k_{a, sender} + k_{a, recipient}) X + k_{b, recipient} U
    rct::key m_onetime_address;
    /// C = x G + a H
    rct::key m_amount_commitment;

    /**
    * brief: make_base_with_onetime_address - make a Seraphis ENote from a pre-made onetime address
    * param: onetime_address -
    * param: amount_blinding_factor -
    * param: amount -
    */
    void make_base_with_onetime_address(const rct::key &onetime_address,
        const crypto::secret_key &amount_blinding_factor,
        const rct::xmr_amount amount);

    /**
    * brief: make_base_with_address_extension - make a Seraphis ENote by extending an existing address
    * param: extension_privkey -
    * param: initial_address -
    * param: amount_blinding_factor -
    * param: amount -
    */
    void make_base_with_address_extension(const crypto::secret_key &extension_privkey,
        const rct::key &initial_address,
        const crypto::secret_key &amount_blinding_factor,
        const rct::xmr_amount amount);

    /**
    * brief: make_base_with_privkeys - make a Seraphis ENote when all secrets are known
    * param: enote_view_privkey -
    * param: spendbase_privkey -
    * param: amount_blinding_factor -
    * param: amount -
    */
    void make_base_with_privkeys(const crypto::secret_key &enote_view_privkey,
        const crypto::secret_key &spendbase_privkey,
        const crypto::secret_key &amount_blinding_factor,
        const rct::xmr_amount amount);

    /**
    * brief: gen_base - generate a Seraphis ENote (all random)
    */
    void gen_base();

    /**
    * brief: append_to_string - convert enote to a string and append to existing string (for proof transcripts)
    * inoutparam: str_inout - enote contents concatenated to a string
    */
    void append_to_string(std::string &str_inout) const;

    static std::size_t get_size_bytes() { return 32*2; }
};

////
// SpEnoteImage
///
struct SpEnoteImage final
{
    /// Ko' = t_k G + (k_{a, sender} + k_{a, recipient}) X + k_{b, recipient} U
    rct::key m_masked_address;
    /// C' = (t_c + x) G + a H
    rct::key m_masked_commitment;
    /// KI = (k_{b, recipient} / (k_{a, sender} + k_{a, recipient})) U
    crypto::key_image m_key_image;

    static std::size_t get_size_bytes() { return 32*3; }
};

////
// SpInputProposal
// - for spending an enote
///
struct SpInputProposal final
{
    /// k_{a, sender} + k_{a, recipient}
    crypto::secret_key m_enote_view_privkey;
    /// k_{b, recipient}
    crypto::secret_key m_spendbase_privkey;
    /// x
    crypto::secret_key m_amount_blinding_factor;
    /// a
    rct::xmr_amount m_amount;

    /// t_k
    crypto::secret_key m_address_mask;
    /// t_c
    crypto::secret_key m_commitment_mask;

    /**
    * brief: get_key_image - get this input's key image
    * outparam: key_image_out - KI
    */
    void get_key_image(crypto::key_image &key_image_out) const;

    /**
    * brief: get_enote_base - get the enote this input proposal represents
    * outparam: enote_out -
    */
    void get_enote_base(SpEnote &enote_out) const;

    /**
    * brief: get_enote_image_squashed_base - get this input's enote image in the squashed enote model
    * inoutparam: image_out -
    */
    void get_enote_image_squashed_base(SpEnoteImage &image_out) const;

    /**
    * brief: gen - generate random enote keys
    * param: amount -
    */
    void gen(const rct::xmr_amount amount);
};

////
// SpOutputProposal
// - for creating an e-note to send an amount to someone
///
struct SpOutputProposal final
{
    /// Ko
    rct::key m_onetime_address;
    /// y
    crypto::secret_key m_amount_blinding_factor;
    /// b
    rct::xmr_amount m_amount;

    /**
    * brief: get_enote_base - get the enote this input proposal represents
    * outparam: enote_out -
    */
    void get_enote_base(SpEnote &enote_out) const;

    /**
    * brief: gen - generate a random proposal
    * param: amount -
    */
    void gen(const rct::xmr_amount amount);
};

} //namespace sp
