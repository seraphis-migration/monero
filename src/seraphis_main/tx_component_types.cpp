// Copyright (c) 2022, The Monero Project
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

//paired header
#include "tx_component_types.h"

//local headers
#include "common/variant.h"
#include "crypto/crypto.h"
#include "int-util.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/binned_reference_set.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_core/sp_core_types.h"
#include "seraphis_crypto/math_utils.h"
#include "seraphis_crypto/sp_legacy_proof_helpers.h"
#include "seraphis_crypto/sp_transcript.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpCoinbaseEnoteV1 &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("core", container.core);
    transcript_inout.append("addr_tag_enc", container.addr_tag_enc.bytes);
    transcript_inout.append("view_tag", container.view_tag);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_coinbase_enote_v1_size_bytes()
{
    return sp_coinbase_enote_core_size_bytes() +
        sizeof(jamtis::encrypted_address_tag_t) +
        sizeof(jamtis::view_tag_t);
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpEnoteV1 &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("core", container.core);
    transcript_inout.append("encoded_amount", container.encoded_amount.bytes);
    transcript_inout.append("addr_tag_enc", container.addr_tag_enc.bytes);
    transcript_inout.append("view_tag", container.view_tag);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_enote_v1_size_bytes()
{
    return sp_enote_core_size_bytes() +
        sizeof(jamtis::encoded_amount_t) +
        sizeof(jamtis::encrypted_address_tag_t) +
        sizeof(jamtis::view_tag_t);
}
//-------------------------------------------------------------------------------------------------------------------
SpEnoteCoreVariant core_ref(const SpEnoteVariant &variant)
{
    struct visitor final : public tools::variant_static_visitor<SpEnoteCoreVariant>
    {
        using variant_static_visitor::operator();  //for blank overload
        SpEnoteCoreVariant operator()(const SpCoinbaseEnoteV1 &enote) const { return enote.core; }
        SpEnoteCoreVariant operator()(const SpEnoteV1 &enote)         const { return enote.core; }
    };

    return variant.visit(visitor{});
}
//-------------------------------------------------------------------------------------------------------------------
const rct::key& onetime_address_ref(const SpEnoteVariant &variant)
{
    struct visitor final : public tools::variant_static_visitor<const rct::key&>
    {
        using variant_static_visitor::operator();  //for blank overload
        const rct::key& operator()(const SpCoinbaseEnoteV1 &enote) const { return enote.core.onetime_address; }
        const rct::key& operator()(const SpEnoteV1 &enote)         const { return enote.core.onetime_address; }
    };

    return variant.visit(visitor{});
}
//-------------------------------------------------------------------------------------------------------------------
rct::key amount_commitment_ref(const SpEnoteVariant &variant)
{
    struct visitor final : public tools::variant_static_visitor<rct::key>
    {
        using variant_static_visitor::operator();  //for blank overload
        rct::key operator()(const SpCoinbaseEnoteV1 &enote) const { return rct::zeroCommit(enote.core.amount); }
        rct::key operator()(const SpEnoteV1 &enote)         const { return enote.core.amount_commitment;       }
    };

    return variant.visit(visitor{});
}
//-------------------------------------------------------------------------------------------------------------------
const jamtis::encrypted_address_tag_t& addr_tag_enc_ref(const SpEnoteVariant &variant)
{
    struct visitor final : public tools::variant_static_visitor<const jamtis::encrypted_address_tag_t&>
    {
        using variant_static_visitor::operator();  //for blank overload
        const jamtis::encrypted_address_tag_t& operator()(const SpCoinbaseEnoteV1 &enote) const
        { return enote.addr_tag_enc; }
        const jamtis::encrypted_address_tag_t& operator()(const SpEnoteV1 &enote) const
        { return enote.addr_tag_enc; }
    };

    return variant.visit(visitor{});
}
//-------------------------------------------------------------------------------------------------------------------
jamtis::view_tag_t view_tag_ref(const SpEnoteVariant &variant)
{
    struct visitor final : public tools::variant_static_visitor<jamtis::view_tag_t>
    {
        using variant_static_visitor::operator();  //for blank overload
        jamtis::view_tag_t operator()(const SpCoinbaseEnoteV1 &enote) const { return enote.view_tag; }
        jamtis::view_tag_t operator()(const SpEnoteV1 &enote)         const { return enote.view_tag; }
    };

    return variant.visit(visitor{});
}
//-------------------------------------------------------------------------------------------------------------------
const crypto::key_image& key_image_ref(const SpEnoteImageV1 &enote_image)
{
    return enote_image.core.key_image;
}
//-------------------------------------------------------------------------------------------------------------------
const rct::key& masked_address_ref(const SpEnoteImageV1 &enote_image)
{
    return enote_image.core.masked_address;
}
//-------------------------------------------------------------------------------------------------------------------
const rct::key& masked_commitment_ref(const SpEnoteImageV1 &enote_image)
{
    return enote_image.core.masked_commitment;
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpEnoteImageV1 &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("core", container.core);
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpMembershipProofV1 &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("grootle_proof", container.grootle_proof);
    transcript_inout.append("binned_reference_set", container.binned_reference_set);
    transcript_inout.append("n", container.ref_set_decomp_n);
    transcript_inout.append("m", container.ref_set_decomp_m);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_membership_proof_v1_size_bytes(const std::size_t n,
    const std::size_t m,
    const std::size_t num_bin_members)
{
    const std::size_t ref_set_size{math::uint_pow(n, m)};

    return grootle_size_bytes(n, m) +
        (num_bin_members > 0
            ? sp_binned_ref_set_v1_size_bytes(ref_set_size / num_bin_members)
            : 0) +
        4 * 2;  //decomposition parameters (assume these fit in 4 bytes each)
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_membership_proof_v1_size_bytes_compact(const std::size_t n,
    const std::size_t m,
    const std::size_t num_bin_members)
{
    const std::size_t ref_set_size{math::uint_pow(n, m)};

    return grootle_size_bytes(n, m) +
        (num_bin_members > 0
            ? sp_binned_ref_set_v1_size_bytes_compact(ref_set_size / num_bin_members)  //compact binned ref set
            : 0);  //no decomposition parameters
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_membership_proof_v1_size_bytes(const SpMembershipProofV1 &proof)
{
    return sp_membership_proof_v1_size_bytes(proof.ref_set_decomp_n,
        proof.ref_set_decomp_m,
        proof.binned_reference_set.bin_config.num_bin_members);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_membership_proof_v1_size_bytes_compact(const SpMembershipProofV1 &proof)
{
    return sp_membership_proof_v1_size_bytes_compact(proof.ref_set_decomp_n,
        proof.ref_set_decomp_m,
        proof.binned_reference_set.bin_config.num_bin_members);
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpImageProofV1 &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("composition_proof", container.composition_proof);
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpBalanceProofV1 &container, SpTranscriptBuilder &transcript_inout)
{
    append_bpp2_to_transcript(container.bpp2_proof, transcript_inout);
    transcript_inout.append("remainder_blinding_factor", container.remainder_blinding_factor);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_balance_proof_v1_size_bytes(const std::size_t num_range_proofs)
{
    std::size_t size{0};

    // BP+ proof
    size += bpp_size_bytes(num_range_proofs, true);  //include commitments

    // remainder blinding factor
    size += 32;

    return size;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_balance_proof_v1_size_bytes(const SpBalanceProofV1 &proof)
{
    return sp_balance_proof_v1_size_bytes(proof.bpp2_proof.V.size());
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_balance_proof_v1_size_bytes_compact(const std::size_t num_range_proofs)
{
    // proof size minus cached amount commitments
    return sp_balance_proof_v1_size_bytes(num_range_proofs) - 32*(num_range_proofs);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_balance_proof_v1_size_bytes_compact(const SpBalanceProofV1 &proof)
{
    return sp_balance_proof_v1_size_bytes_compact(proof.bpp2_proof.V.size());
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_balance_proof_v1_weight(const std::size_t num_range_proofs)
{
    std::size_t weight{0};

    // BP+ proof
    weight += bpp_weight(num_range_proofs, false);  //weight without cached amount commitments

    // remainder blinding factor
    weight += 32;

    return weight;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_balance_proof_v1_weight(const SpBalanceProofV1 &proof)
{
    return sp_balance_proof_v1_weight(proof.bpp2_proof.V.size());
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpTxSupplementV1 &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("output_xK_e_keys", container.output_enote_ephemeral_pubkeys);
    transcript_inout.append("tx_extra", container.tx_extra);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_tx_supplement_v1_size_bytes(const std::size_t num_outputs,
    const std::size_t tx_extra_size,
    const bool use_shared_ephemeral_key_assumption)
{
    std::size_t size{0};

    // enote ephemeral pubkeys
    if (use_shared_ephemeral_key_assumption &&
            num_outputs == 2)
        size += 32;
    else
        size += 32 * num_outputs;

    // tx extra
    size += tx_extra_size;

    return size;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_tx_supplement_v1_size_bytes(const SpTxSupplementV1 &tx_supplement)
{
    return 32 * tx_supplement.output_enote_ephemeral_pubkeys.size() + tx_supplement.tx_extra.size();
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const SpCoinbaseEnoteV1 &a, const SpCoinbaseEnoteV1 &b)
{
    return a.core      == b.core &&
        a.addr_tag_enc == b.addr_tag_enc &&
        a.view_tag     == b.view_tag;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const SpEnoteV1 &a, const SpEnoteV1 &b)
{
    return a.core        == b.core &&
        a.encoded_amount == b.encoded_amount &&
        a.addr_tag_enc   == b.addr_tag_enc &&
        a.view_tag       == b.view_tag;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const SpEnoteVariant &variant1, const SpEnoteVariant &variant2)
{
    // check they have the same type
    if (!SpEnoteVariant::same_type(variant1, variant2))
        return false;

    // use a visitor to test equality
    struct visitor final : public tools::variant_static_visitor<bool>
    {
        visitor(const SpEnoteVariant &other_ref) : other{other_ref} {}
        const SpEnoteVariant &other;

        using variant_static_visitor::operator();  //for blank overload
        bool operator()(const SpCoinbaseEnoteV1 &enote) const { return enote == other.unwrap<SpCoinbaseEnoteV1>(); }
        bool operator()(const SpEnoteV1 &enote) const { return enote == other.unwrap<SpEnoteV1>(); }
    };

    return variant1.visit(visitor{variant2});
}
//-------------------------------------------------------------------------------------------------------------------
bool compare_Ko(const SpCoinbaseEnoteV1 &a, const SpCoinbaseEnoteV1 &b)
{
    return compare_Ko(a.core, b.core);
}
//-------------------------------------------------------------------------------------------------------------------
bool compare_Ko(const SpEnoteV1 &a, const SpEnoteV1 &b)
{
    return compare_Ko(a.core, b.core);
}
//-------------------------------------------------------------------------------------------------------------------
bool compare_KI(const SpEnoteImageV1 &a, const SpEnoteImageV1 &b)
{
    return compare_KI(a.core, b.core);
}
//-------------------------------------------------------------------------------------------------------------------
SpCoinbaseEnoteV1 gen_sp_coinbase_enote_v1()
{
    SpCoinbaseEnoteV1 temp;

    // gen base of enote
    temp.core = gen_sp_coinbase_enote_core();

    // extra pieces
    crypto::rand(sizeof(jamtis::encrypted_address_tag_t), temp.addr_tag_enc.bytes);
    temp.view_tag = crypto::rand_idx<jamtis::view_tag_t>(0);

    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
SpEnoteV1 gen_sp_enote_v1()
{
    SpEnoteV1 temp;

    // gen base of enote
    temp.core = gen_sp_enote_core();

    // extra pieces
    crypto::rand(sizeof(temp.encoded_amount), temp.encoded_amount.bytes);
    crypto::rand(sizeof(jamtis::encrypted_address_tag_t), temp.addr_tag_enc.bytes);
    temp.view_tag = crypto::rand_idx<jamtis::view_tag_t>(0);

    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
