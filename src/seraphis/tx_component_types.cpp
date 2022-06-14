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
#include "jamtis_support_types.h"
#include "ringct/rctTypes.h"
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
void SpEnoteV1::append_to_string(std::string &str_inout) const
{
    // append all enote contents to the string
    str_inout.reserve(str_inout.size() + get_size_bytes());

    m_core.append_to_string(str_inout);
    for (int i{0}; i < 8; ++i)
    {
        str_inout += static_cast<char>(m_encoded_amount >> i*8);
    }
    str_inout.append(reinterpret_cast<const char*>(m_addr_tag_enc.bytes), sizeof(jamtis::encrypted_address_tag_t));
    str_inout += static_cast<char>(m_view_tag);
}
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
void SpEnoteImageV1::append_to_string(std::string &str_inout) const
{
    // append all enote image contents to the string
    str_inout.reserve(str_inout.size() + get_size_bytes());

    m_core.append_to_string(str_inout);
}
//-------------------------------------------------------------------------------------------------------------------
void SpMembershipProofV1::append_to_string(std::string &str_inout) const
{
    // append all proof contents to the string
    str_inout.reserve(str_inout.size() + get_size_bytes());

    m_concise_grootle_proof.append_to_string(str_inout);
    m_binned_reference_set.append_to_string(str_inout);
    append_uint_to_string(m_ref_set_decomp_n, str_inout);
    append_uint_to_string(m_ref_set_decomp_m, str_inout);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t SpMembershipProofV1::get_size_bytes(const std::size_t n, const std::size_t m, const std::size_t num_bin_members)
{
    const std::size_t ref_set_size{ref_set_size_from_decomp(n, m)};

    return sp::ConciseGrootleProof::get_size_bytes(n, m) +
        SpBinnedReferenceSetV1::get_size_bytes(ref_set_size / num_bin_members);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t SpMembershipProofV1::get_size_bytes() const
{
    return SpMembershipProofV1::get_size_bytes(m_ref_set_decomp_n,
        m_ref_set_decomp_m,
        m_binned_reference_set.m_bin_config.m_num_bin_members);
}
//-------------------------------------------------------------------------------------------------------------------
void SpImageProofV1::append_to_string(std::string &str_inout) const
{
    // append all proof contents to the string
    str_inout.reserve(str_inout.size() + get_size_bytes());

    m_composition_proof.append_to_string(str_inout);
}
//-------------------------------------------------------------------------------------------------------------------
void SpBalanceProofV1::append_to_string(std::string &str_inout) const
{
    // append all proof contents to the string
    str_inout.reserve(str_inout.size() + get_size_bytes());

    append_bpp_to_string(m_bpp_proof, str_inout);
    str_inout.append(reinterpret_cast<const char *>(m_remainder_blinding_factor.bytes), sizeof(rct::key));
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
    return SpBalanceProofV1::get_size_bytes(m_bpp_proof.V.size(), 0, include_commitments);
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
    return SpBalanceProofV1::get_weight(m_bpp_proof.V.size(), 0, include_commitments);
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
} //namespace sp
