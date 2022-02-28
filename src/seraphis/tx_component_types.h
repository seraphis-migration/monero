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

// Seraphis component types

#pragma once

//local headers
#include "crypto/crypto.h"
#include "concise_grootle.h"
#include "jamtis_support_types.h"
#include "ringct/rctTypes.h"
#include "sp_composition_proof.h"
#include "sp_core_types.h"
#include "tx_extra.h"

//third party headers

//standard headers

//forward declarations


namespace sp
{

////
// SpEnoteV1
///
struct SpEnoteV1 final
{
    /// enote core (one-time address, amount commitment)
    SpEnote m_core;

    /// enc(a)
    rct::xmr_amount m_encoded_amount;
    /// view_tag
    jamtis::view_tag_t m_view_tag;
    /// addr_tag_enc
    jamtis::encrypted_address_tag_t m_addr_tag_enc;

    /// less-than operator for sorting
    bool operator<(const SpEnoteV1 &other_enote) const
    {
        return m_core < other_enote.m_core;
    }

    /**
    * brief: append_to_string - convert enote to a string and append to existing string
    *   str += Ko || C || enc(a) || view_tag || addr_tag_enc
    * inoutparam: str_inout - enote contents concatenated to a string
    */
    void append_to_string(std::string &str_inout) const;

    /// generate a dummy v1 enote (all random; completely unspendable)
    void gen();

    static std::size_t get_size_bytes()
    {
        return SpEnote::get_size_bytes() +
            sizeof(rct::xmr_amount) +
            sizeof(jamtis::view_tag_t) +
            sizeof(jamtis::encrypted_address_tag_t);
    }
};

////
// SpEnoteImageV1
///
struct SpEnoteImageV1 final
{
    /// enote image core (masked address, masked amount commitment, key image)
    SpEnoteImage m_core;

    /// less-than operator for sorting
    bool operator<(const SpEnoteImageV1 &other_image) const
    {
        return m_core < other_image.m_core;
    }

    static std::size_t get_size_bytes() { return SpEnoteImage::get_size_bytes(); }
};

////
// SpMembershipProofV1
// - Concise Grootle
///
struct SpMembershipProofV1 final
{
    /// a concise grootle proof
    sp::ConciseGrootleProof m_concise_grootle_proof;
    /// ledger indices of enotes referenced by the proof
    std::vector<std::size_t> m_ledger_enote_indices;
    /// ref set size = n^m
    std::size_t m_ref_set_decomp_n;
    std::size_t m_ref_set_decomp_m;

    std::size_t get_size_bytes() const;
};

////
// SpImageProofV1
// - ownership and unspentness (legitimacy of key image)
// - Seraphis composition proof
///
struct SpImageProofV1 final
{
    /// a seraphis composition proof
    sp::SpCompositionProof m_composition_proof;

    static std::size_t get_size_bytes() { return 32*5; }
};

////
// SpBalanceProofV1
// - balance proof: implicit with a remainder blinding factor: [sum(inputs) == sum(outputs) + remainder_blinding_factor*G]
// - range proof: Bulletproofs+
///
struct SpBalanceProofV1 final
{
    /// an aggregate set of BP+ proofs
    rct::BulletproofPlus m_bpp_proof;
    /// the remainder blinding factor
    rct::key m_remainder_blinding_factor;

    std::size_t get_size_bytes(const bool include_commitments = false) const;
};

////
// SpTxSupplementV1
// - supplementary info about a tx
//   - enote ephemeral pubkeys: may not line up 1:1 with output enotes, so store in separate field
//   - tx memo
///
struct SpTxSupplementV1 final
{
    /// Ke: enote ephemeral pubkeys for outputs
    rct::keyV m_output_enote_ephemeral_pubkeys;
    /// tx memo
    TxExtra m_tx_extra;

    std::size_t get_size_bytes() const;
};

} //namespace sp
