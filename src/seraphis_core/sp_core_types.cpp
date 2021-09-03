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
#include "sp_core_types.h"

//local headers
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_crypto/sp_transcript.h"
#include "sp_core_enote_utils.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpCoinbaseEnoteCore &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("Ko", container.onetime_address);
    transcript_inout.append("a", container.amount);
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpEnoteCore &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("Ko", container.onetime_address);
    transcript_inout.append("C", container.amount_commitment);
}
//-------------------------------------------------------------------------------------------------------------------
const rct::key& onetime_address_ref(const SpEnoteCoreVariant &variant)
{
    struct visitor final : public tools::variant_static_visitor<const rct::key&>
    {
        using variant_static_visitor::operator();  //for blank overload
        const rct::key& operator()(const SpCoinbaseEnoteCore &enote) const { return enote.onetime_address; }
        const rct::key& operator()(const SpEnoteCore &enote)         const { return enote.onetime_address; }
    };

    return variant.visit(visitor{});
}
//-------------------------------------------------------------------------------------------------------------------
rct::key amount_commitment_ref(const SpEnoteCoreVariant &variant)
{
    struct visitor final : public tools::variant_static_visitor<rct::key>
    {
        using variant_static_visitor::operator();  //for blank overload
        rct::key operator()(const SpCoinbaseEnoteCore &enote) const { return rct::zeroCommit(enote.amount); }
        rct::key operator()(const SpEnoteCore &enote)         const { return enote.amount_commitment;       }
    };

    return variant.visit(visitor{});
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpEnoteImageCore &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("K_masked", container.masked_address);
    transcript_inout.append("C_masked", container.masked_commitment);
    transcript_inout.append("KI", container.key_image);
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const SpCoinbaseEnoteCore &a, const SpCoinbaseEnoteCore &b)
{
    return a.onetime_address == b.onetime_address &&
           a.amount          == b.amount;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const SpEnoteCore &a, const SpEnoteCore &b)
{
    return a.onetime_address   == b.onetime_address &&
           a.amount_commitment == b.amount_commitment;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const SpEnoteCoreVariant &variant1, const SpEnoteCoreVariant &variant2)
{
    // check they have the same type
    if (!SpEnoteCoreVariant::same_type(variant1, variant2))
        return false;

    // use a visitor to test equality with variant2
    struct visitor final : public tools::variant_static_visitor<bool>
    {
        visitor(const SpEnoteCoreVariant &other_ref) : other{other_ref} {}
        const SpEnoteCoreVariant &other;

        using variant_static_visitor::operator();  //for blank overload
        bool operator()(const SpCoinbaseEnoteCore &enote) const { return enote == other.unwrap<SpCoinbaseEnoteCore>(); }
        bool operator()(const SpEnoteCore &enote) const         { return enote == other.unwrap<SpEnoteCore>();         }
    };

    return variant1.visit(visitor{variant2});
}
//-------------------------------------------------------------------------------------------------------------------
bool compare_Ko(const SpCoinbaseEnoteCore &a, const SpCoinbaseEnoteCore &b)
{
    return memcmp(a.onetime_address.bytes, b.onetime_address.bytes, sizeof(rct::key)) < 0;
}
//-------------------------------------------------------------------------------------------------------------------
bool compare_Ko(const SpEnoteCore &a, const SpEnoteCore &b)
{
    return memcmp(a.onetime_address.bytes, b.onetime_address.bytes, sizeof(rct::key)) < 0;
}
//-------------------------------------------------------------------------------------------------------------------
bool compare_KI(const SpEnoteImageCore &a, const SpEnoteImageCore &b)
{
    return a.key_image < b.key_image;
}
//-------------------------------------------------------------------------------------------------------------------
bool compare_KI(const SpInputProposalCore &a, const SpInputProposalCore &b)
{
    return a.key_image < b.key_image;
}
//-------------------------------------------------------------------------------------------------------------------
bool compare_Ko(const SpOutputProposalCore &a, const SpOutputProposalCore &b)
{
    return memcmp(&a.onetime_address, &b.onetime_address, sizeof(rct::key)) < 0;
}
//-------------------------------------------------------------------------------------------------------------------
bool onetime_address_is_canonical(const SpCoinbaseEnoteCore &enote_core)
{
    return key_domain_is_prime_subgroup(enote_core.onetime_address);
}
//-------------------------------------------------------------------------------------------------------------------
bool onetime_address_is_canonical(const SpEnoteCore &enote_core)
{
    return key_domain_is_prime_subgroup(enote_core.onetime_address);
}
//-------------------------------------------------------------------------------------------------------------------
bool onetime_address_is_canonical(const SpOutputProposalCore &output_proposal)
{
    return key_domain_is_prime_subgroup(output_proposal.onetime_address);
}
//-------------------------------------------------------------------------------------------------------------------
void get_squash_prefix(const SpInputProposalCore &proposal, rct::key &squash_prefix_out)
{
    // H_n(Ko,C)
    make_seraphis_squash_prefix(onetime_address_ref(proposal.enote_core),
        amount_commitment_ref(proposal.enote_core),
        squash_prefix_out);
}
//-------------------------------------------------------------------------------------------------------------------
void get_enote_image_core(const SpInputProposalCore &proposal, SpEnoteImageCore &image_out)
{
    // K" = t_k G + H_n(Ko,C) Ko
    // C" = t_c G + C
    make_seraphis_enote_image_masked_keys(onetime_address_ref(proposal.enote_core),
        amount_commitment_ref(proposal.enote_core),
        proposal.address_mask,
        proposal.commitment_mask,
        image_out.masked_address,
        image_out.masked_commitment);

    // KI = ((k_u + k_m) / k_x) U
    image_out.key_image = proposal.key_image;
}
//-------------------------------------------------------------------------------------------------------------------
void get_enote_core(const SpOutputProposalCore &proposal, SpEnoteCore &enote_out)
{
    make_seraphis_enote_core(proposal.onetime_address, proposal.amount, proposal.amount_blinding_factor, enote_out);
}
//-------------------------------------------------------------------------------------------------------------------
SpCoinbaseEnoteCore gen_sp_coinbase_enote_core()
{
    SpCoinbaseEnoteCore temp;
    temp.onetime_address = rct::pkGen();
    crypto::rand(8, reinterpret_cast<unsigned char*>(&temp.amount));
    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
SpEnoteCore gen_sp_enote_core()
{
    SpEnoteCore temp;
    temp.onetime_address = rct::pkGen();
    temp.amount_commitment = rct::pkGen();
    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
SpInputProposalCore gen_sp_input_proposal_core(const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &sp_view_privkey,
    const rct::xmr_amount amount)
{
    SpInputProposalCore temp;

    temp.enote_view_extension_g = rct::rct2sk(rct::skGen());
    temp.enote_view_extension_x = rct::rct2sk(rct::skGen());
    temp.enote_view_extension_u = rct::rct2sk(rct::skGen());
    crypto::secret_key sp_spend_privkey_extended;
    sc_add(to_bytes(sp_spend_privkey_extended), to_bytes(temp.enote_view_extension_u), to_bytes(sp_spend_privkey));
    make_seraphis_key_image(add_secrets(temp.enote_view_extension_x, sp_view_privkey),
        sp_spend_privkey_extended,
        temp.key_image);
    temp.amount_blinding_factor = rct::rct2sk(rct::skGen());
    temp.amount                 = amount;
    SpEnoteCore enote_core_temp;
    make_seraphis_enote_core(temp.enote_view_extension_g,
        temp.enote_view_extension_x,
        temp.enote_view_extension_u,
        sp_spend_privkey,
        sp_view_privkey,
        temp.amount,
        temp.amount_blinding_factor,
        enote_core_temp);
    temp.enote_core      = enote_core_temp;
    temp.address_mask    = rct::rct2sk(rct::skGen());;
    temp.commitment_mask = rct::rct2sk(rct::skGen());;

    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
SpOutputProposalCore gen_sp_output_proposal_core(const rct::xmr_amount amount)
{
    SpOutputProposalCore temp;
    temp.onetime_address        = rct::pkGen();
    temp.amount_blinding_factor = rct::rct2sk(rct::skGen());
    temp.amount                 = amount;
    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
