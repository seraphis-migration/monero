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

// Seraphis core types.


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


////
// SpEnote
///
struct SpEnote final
{
    /// Ko = (k_{a, sender} + k_{a, recipient}) X + k_{b, recipient} U
    rct::key m_onetime_address;
    /// C = x G + a H
    rct::key m_amount_commitment;

    /// less-than operator for sorting
    bool operator<(const SpEnote &other_enote) const
    {
        return memcmp(&m_onetime_address, &other_enote.m_onetime_address, sizeof(rct::key)) < 0;
    }

    /// equality operator for direct comparisons
    bool operator==(const SpEnote &other_enote) const
    {
        return m_onetime_address == other_enote.m_onetime_address &&
            m_amount_commitment == m_amount_commitment;
    }

    /**
    * brief: onetime_address_is_canonical - check if the onetime address is canonical (prime subgroup)
    */
    bool onetime_address_is_canonical() const;

    /**
    * brief: append_to_string - convert enote to a string and append to existing string (for proof transcripts)
    *   str += Ko || C
    * inoutparam: str_inout - contents concatenated to a string
    */
    void append_to_string(std::string &str_inout) const;

    static std::size_t get_size_bytes() { return 32*2; }

    /**
    * brief: gen_base - generate a Seraphis ENote (all random)
    */
    void gen();
};

////
// SpEnoteImage
///
struct SpEnoteImage final
{
    /// K' = t_k G + H(Ko,C)*[(k_{a, sender} + k_{a, recipient}) X + k_{b, recipient} U]   (in the squashed enote model)
    rct::key m_masked_address;
    /// C' = (t_c + x) G + a H
    rct::key m_masked_commitment;
    /// KI = (k_{b, recipient} / (k_{a, sender} + k_{a, recipient})) U
    crypto::key_image m_key_image;

    /// less-than operator for sorting
    bool operator<(const SpEnoteImage &other_image) const
    {
        return m_key_image < other_image.m_key_image;
    }

    /**
    * brief: append_to_string - convert enote image to a string and append to existing string
    *   str += K' || C' || KI
    * inoutparam: str_inout - contents concatenated to a string
    */
    void append_to_string(std::string &str_inout) const;

    static std::size_t get_size_bytes() { return 32*3; }
};

////
// SpInputProposal
// - for spending an enote
///
struct SpInputProposal final
{
    /// core of the original enote
    SpEnote m_enote_core;
    /// the enote's key image
    crypto::key_image m_key_image;

    /// k_{a, sender} + k_{a, recipient}
    crypto::secret_key m_enote_view_privkey;
    /// x
    crypto::secret_key m_amount_blinding_factor;
    /// a
    rct::xmr_amount m_amount;

    /// t_k
    crypto::secret_key m_address_mask;
    /// t_c
    crypto::secret_key m_commitment_mask;

    /// less-than operator for sorting
    bool operator<(const SpInputProposal &other_proposal) const { return m_key_image < other_proposal.m_key_image; }

    /**
    * brief: get_key_image - get this input's key image
    * outparam: key_image_out - KI
    */
    void get_key_image(crypto::key_image &key_image_out) const { key_image_out = m_key_image; }

    /**
    * brief: get_enote_core - get the enote this input proposal represents
    * outparam: enote_out -
    */
    void get_enote_core(SpEnote &enote_out) const { enote_out = m_enote_core; }

    /**
    * brief: get_enote_image_core - get this input's enote image in the squashed enote model
    * outparam: image_out -
    */
    void get_enote_image_core(SpEnoteImage &image_out) const;

    /**
    * brief: gen - generate random enote keys
    * param: spendbase_privkey -
    * param: amount -
    */
    void gen(const crypto::secret_key &spendbase_privkey, const rct::xmr_amount amount);
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

    /// less-than operator for sorting
    bool operator<(const SpOutputProposal &other_proposal) const
    {
        return memcmp(&m_onetime_address, &other_proposal.m_onetime_address, sizeof(rct::key)) < 0;
    }

    /**
    * brief: onetime_address_is_canonical - check if the onetime address is canonical (prime subgroup)
    */
    bool onetime_address_is_canonical() const;

    /**
    * brief: get_enote_core - get the enote this input proposal represents
    * outparam: enote_out -
    */
    void get_enote_core(SpEnote &enote_out) const;

    /**
    * brief: gen - generate a random proposal
    * param: amount -
    */
    void gen(const rct::xmr_amount amount);
};

} //namespace sp
