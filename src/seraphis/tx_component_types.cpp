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
#include "tx_component_types.h"

//local headers
#include "crypto/crypto.h"
#include "int-util.h"
#include "jamtis_support_types.h"
#include "ringct/rctTypes.h"
#include "sp_transcript.h"
#include "tx_binned_reference_set.h"
#include "tx_misc_utils.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteV1::gen()
{
    // generate a dummy enote: random pieces, completely unspendable

    // gen base of enote
    m_core.gen();

    // memo
    m_encoded_amount = crypto::rand_idx(static_cast<rct::xmr_amount>(-1));
    m_view_tag = crypto::rand_idx(static_cast<jamtis::view_tag_t>(-1));
    crypto::rand(sizeof(jamtis::encrypted_address_tag_t), m_addr_tag_enc.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpEnoteV1 &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("core", container.m_core);
    const std::uint64_t le_encoded_amount{SWAP64LE(container.m_encoded_amount)};
    unsigned char encoded_amount[8];
    memcpy(encoded_amount, &le_encoded_amount, 8);  //encoded amounts are semantically 8-byte buffers
    transcript_inout.append("encoded_amount", encoded_amount);
    transcript_inout.append("addr_tag_enc", container.m_addr_tag_enc.bytes);
    transcript_inout.append("view_tag", container.m_view_tag);
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpEnoteImageV1 &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("core", container.m_core);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t SpMembershipProofV1::get_size_bytes(const std::size_t n, const std::size_t m, const std::size_t num_bin_members)
{
    const std::size_t ref_set_size{ref_set_size_from_decomp(n, m)};

    return sp::GrootleProof::get_size_bytes(n, m) + SpBinnedReferenceSetV1::get_size_bytes(ref_set_size / num_bin_members);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t SpMembershipProofV1::get_size_bytes() const
{
    return SpMembershipProofV1::get_size_bytes(m_ref_set_decomp_n,
        m_ref_set_decomp_m,
        m_binned_reference_set.m_bin_config.m_num_bin_members);
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpMembershipProofV1 &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("grootle_proof", container.m_grootle_proof);
    transcript_inout.append("binned_reference_set", container.m_binned_reference_set);
    transcript_inout.append("n", container.m_ref_set_decomp_n);
    transcript_inout.append("m", container.m_ref_set_decomp_m);
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpImageProofV1 &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("composition_proof", container.m_composition_proof);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t SpBalanceProofV1::get_size_bytes(const std::size_t num_inputs,
    const std::size_t num_outputs,
    const bool include_commitments /*=false*/)
{
    std::size_t size{0};

    // BP+ proof
    size += bpp_size_bytes(num_inputs + num_outputs, include_commitments);

    // remainder blinding factor
    size += 32;

    return size;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t SpBalanceProofV1::get_size_bytes(const bool include_commitments /*=false*/) const
{
    return SpBalanceProofV1::get_size_bytes(m_bpp2_proof.V.size(), 0, include_commitments);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t SpBalanceProofV1::get_weight(const std::size_t num_inputs,
    const std::size_t num_outputs,
    const bool include_commitments /*=false*/)
{
    std::size_t weight{0};

    // BP+ proof
    weight += bpp_weight(num_inputs + num_outputs, include_commitments);

    // remainder blinding factor
    weight += 32;

    return weight;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t SpBalanceProofV1::get_weight(const bool include_commitments /*=false*/) const
{
    return SpBalanceProofV1::get_weight(m_bpp2_proof.V.size(), 0, include_commitments);
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpBalanceProofV1 &container, SpTranscriptBuilder &transcript_inout)
{
    append_bpp2_to_transcript(container.m_bpp2_proof, transcript_inout);
    transcript_inout.append("remainder_blinding_factor", container.m_remainder_blinding_factor);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t SpTxSupplementV1::get_size_bytes(const std::size_t num_outputs, const TxExtra &tx_extra)
{
    std::size_t size{0};

    // enote ephemeral pubkeys (need to refactor if assumption about output count : enote ephemeral pubkey mapping changes)
    if (num_outputs == 2)
        size += 32;
    else
        size += 32 * num_outputs;

    // tx extra
    size += tx_extra.size();

    return size;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t SpTxSupplementV1::get_size_bytes() const
{
    return 32 * m_output_enote_ephemeral_pubkeys.size() + m_tx_extra.size();
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpTxSupplementV1 &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("output_K_e_keys", container.m_output_enote_ephemeral_pubkeys);
    transcript_inout.append("tx_extra", container.m_tx_extra);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
