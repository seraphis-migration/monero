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

// Seraphis core types.

#pragma once

//local headers
#include "common/variant.h"
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"

//third party headers
#include <boost/utility/string_ref.hpp>

//standard headers
#include <vector>

//forward declarations
namespace sp { class SpTranscriptBuilder; }

namespace sp
{

////
// SpCoinbaseEnoteCore
///
struct SpCoinbaseEnoteCore final
{
    //// Ko = k_g G + (k_x + k_a) X + (k_u + k_b) U
    rct::key onetime_address;
    /// a
    /// note: C = 1 G + a H  (implied)
    rct::xmr_amount amount;
};
inline const boost::string_ref container_name(const SpCoinbaseEnoteCore&) { return "SpCoinbaseEnoteCore"; }
void append_to_transcript(const SpCoinbaseEnoteCore &container, SpTranscriptBuilder &transcript_inout);

/// get size in bytes
inline std::size_t sp_coinbase_enote_core_size_bytes() { return 32 + 8; }

////
// SpEnoteCore
///
struct SpEnoteCore final
{
    /// Ko = k_g G + (k_x + k_a) X + (k_u + k_b) U
    rct::key onetime_address;
    /// C = x G + a H
    rct::key amount_commitment;
};
inline const boost::string_ref container_name(const SpEnoteCore&) { return "SpEnoteCore"; }
void append_to_transcript(const SpEnoteCore &container, SpTranscriptBuilder &transcript_inout);

/// get size in bytes
inline std::size_t sp_enote_core_size_bytes() { return 32*2; }

////
// SpEnoteCoreVariant
// - variant of all seraphis core enote types
//
// onetime_address_ref(): get the enote's onetime address
// amount_commitment_ref(): get the enote's amount commitment (this is a copy because coinbase enotes need to
//                          compute the commitment)
///
using SpEnoteCoreVariant = tools::variant<SpCoinbaseEnoteCore, SpEnoteCore>;
const rct::key& onetime_address_ref(const SpEnoteCoreVariant &variant);
rct::key amount_commitment_ref(const SpEnoteCoreVariant &variant);

////
// SpEnoteImageCore
///
struct SpEnoteImageCore final
{
    /// K" = t_k G + H_n(Ko,C)*Ko   (in the squashed enote model)
    rct::key masked_address;
    /// C" = (t_c + x) G + a H
    rct::key masked_commitment;
    /// KI = ((k_u + k_b) / (k_x + k_a)) U
    crypto::key_image key_image;
};
inline const boost::string_ref container_name(const SpEnoteImageCore&) { return "SpEnoteImageCore"; }
void append_to_transcript(const SpEnoteImageCore &container, SpTranscriptBuilder &transcript_inout);

/// get size in bytes
inline std::size_t sp_enote_image_core_size_bytes() { return 32*3; }

////
// SpInputProposalCore
// - for spending an enote
///
struct SpInputProposalCore final
{
    /// core of the original enote
    SpEnoteCoreVariant enote_core;
    /// the enote's key image
    crypto::key_image key_image;

    /// k_g = k_{g, sender} + k_{g, address}
    crypto::secret_key enote_view_extension_g;
    /// k_x = k_{x, sender} + k_{x, address}  (does not include k_a)
    crypto::secret_key enote_view_extension_x;
    /// k_u = k_{u, sender} + k_{u, address}  (does not include k_b)
    crypto::secret_key enote_view_extension_u;
    /// x
    crypto::secret_key amount_blinding_factor;
    /// a
    rct::xmr_amount amount;

    /// t_k
    crypto::secret_key address_mask;
    /// t_c
    crypto::secret_key commitment_mask;
};

////
// SpOutputProposalCore
// - for creating an enote to send an amount to someone
///
struct SpOutputProposalCore final
{
    /// Ko
    rct::key onetime_address;
    /// y
    crypto::secret_key amount_blinding_factor;
    /// b
    rct::xmr_amount amount;
};

/// equality operators for equivalence testing
bool operator==(const SpCoinbaseEnoteCore &a, const SpCoinbaseEnoteCore &b);
bool operator==(const SpEnoteCore &a, const SpEnoteCore &b);
bool operator==(const SpEnoteCoreVariant &variant1, const SpEnoteCoreVariant &variant2);
/// comparison methods for sorting: a.Ko < b.Ko
bool compare_Ko(const SpCoinbaseEnoteCore &a, const SpCoinbaseEnoteCore &b);
bool compare_Ko(const SpEnoteCore &a, const SpEnoteCore &b);
bool compare_Ko(const SpOutputProposalCore &a, const SpOutputProposalCore &b);
/// comparison methods for sorting: a.KI < b.KI
bool compare_KI(const SpEnoteImageCore &a, const SpEnoteImageCore &b);
bool compare_KI(const SpInputProposalCore &a, const SpInputProposalCore &b);
/// check if the type has a canonical onetime address
bool onetime_address_is_canonical(const SpCoinbaseEnoteCore &enote_core);
bool onetime_address_is_canonical(const SpEnoteCore &enote_core);
bool onetime_address_is_canonical(const SpOutputProposalCore &output_proposal);

/**
* brief: get_squash_prefix - get the input proposal's enote's squash prefix
* param: proposal -
* outparam: squash_prefix_out - H_n(Ko,C)
*/
void get_squash_prefix(const SpInputProposalCore &proposal, rct::key &squash_prefix_out);
/**
* brief: get_enote_image_core - get input proposal's enote image in the squashed enote model
* param: proposal -
* outparam: image_out -
*/
void get_enote_image_core(const SpInputProposalCore &proposal, SpEnoteImageCore &image_out);
/**
* brief: get_enote_core - get the output proposal's represented enote
* param: proposal -
* outparam: enote_out -
*/
void get_enote_core(const SpOutputProposalCore &proposal, SpEnoteCore &enote_out);
/**
* brief: gen() - generate a seraphis coinbase enote (all random)
* return: generated proposal
*/
SpCoinbaseEnoteCore gen_sp_coinbase_enote_core();
/**
* brief: gen() - generate a seraphis enote (all random)
* return: generated proposal
*/
SpEnoteCore gen_sp_enote_core();
/**
* brief: gen_sp_input_proposal_core - generate a random input proposal
* param: sp_spend_privkey -
* param: sp_view_privkey -
* param: amount -
* return: generated proposal
*/
SpInputProposalCore gen_sp_input_proposal_core(const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &sp_view_privkey,
    const rct::xmr_amount amount);
/**
* brief: gen - generate a random proposal
* param: amount -
* return: generated proposal
*/
SpOutputProposalCore gen_sp_output_proposal_core(const rct::xmr_amount amount);

} //namespace sp
