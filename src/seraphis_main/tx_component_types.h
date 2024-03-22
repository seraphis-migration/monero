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

// Seraphis transaction component types.

#pragma once

//local headers
#include "common/variant.h"
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/binned_reference_set.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_core/sp_core_types.h"
#include "seraphis_core/tx_extra.h"
#include "seraphis_crypto/bulletproofs_plus2.h"
#include "seraphis_crypto/grootle.h"
#include "seraphis_crypto/sp_composition_proof.h"

//third party headers
#include <boost/utility/string_ref.hpp>

//standard headers

//forward declarations
namespace sp { class SpTranscriptBuilder; }

namespace sp
{

////
// SpCoinbaseEnoteV1
///
struct SpCoinbaseEnoteV1 final
{
    /// enote core (onetime address, amount)
    SpCoinbaseEnoteCore core;

    /// addr_tag_enc
    jamtis::encrypted_address_tag_t addr_tag_enc;
    /// view_tag
    jamtis::view_tag_t view_tag;
};
inline const boost::string_ref container_name(const SpCoinbaseEnoteV1&) { return "SpCoinbaseEnoteV1"; }
void append_to_transcript(const SpCoinbaseEnoteV1 &container, SpTranscriptBuilder &transcript_inout);

/// get the size in bytes
std::size_t sp_coinbase_enote_v1_size_bytes();

////
// SpEnoteV1
///
struct SpEnoteV1 final
{
    /// enote core (onetime address, amount commitment)
    SpEnoteCore core;

    /// enc(a)
    jamtis::encoded_amount_t encoded_amount;
    /// addr_tag_enc
    jamtis::encrypted_address_tag_t addr_tag_enc;
    /// view_tag
    jamtis::view_tag_t view_tag;
};
inline const boost::string_ref container_name(const SpEnoteV1&) { return "SpEnoteV1"; }
void append_to_transcript(const SpEnoteV1 &container, SpTranscriptBuilder &transcript_inout);

/// get the size in bytes
std::size_t sp_enote_v1_size_bytes();

////
// SpEnoteVariant
// - variant of all seraphis enote types
//
// core_ref(): get a copy of the enote's core
// onetime_address_ref(): get the enote's onetime address
// amount_commitment_ref(): get the enote's amount commitment (this is a copy because coinbase enotes need to
//                          compute the commitment)
// addr_tag_enc_ref(): get the enote's encrypted address tag
// view_tag_ref(): get the enote's view tag (copies are cheap)
///
using SpEnoteVariant = tools::variant<SpCoinbaseEnoteV1, SpEnoteV1>;
SpEnoteCoreVariant core_ref(const SpEnoteVariant &variant);
const rct::key& onetime_address_ref(const SpEnoteVariant &variant);
rct::key amount_commitment_ref(const SpEnoteVariant &variant);
const jamtis::encrypted_address_tag_t& addr_tag_enc_ref(const SpEnoteVariant &variant);
jamtis::view_tag_t view_tag_ref(const SpEnoteVariant &variant);

////
// SpEnoteImageV1
///
struct SpEnoteImageV1 final
{
    /// enote image core (masked address, masked amount commitment, key image)
    SpEnoteImageCore core;
};
inline const boost::string_ref container_name(const SpEnoteImageV1&) { return "SpEnoteImageV1"; }
void append_to_transcript(const SpEnoteImageV1 &container, SpTranscriptBuilder &transcript_inout);

/// get size in bytes
inline std::size_t sp_enote_image_v1_size_bytes() { return sp_enote_image_core_size_bytes(); }

/// get the image components
const crypto::key_image& key_image_ref(const SpEnoteImageV1 &enote_image);
const rct::key& masked_address_ref(const SpEnoteImageV1 &enote_image);
const rct::key& masked_commitment_ref(const SpEnoteImageV1 &enote_image);

////
// SpMembershipProofV1
// - grootle proof
///
struct SpMembershipProofV1 final
{
    /// a grootle proof
    GrootleProof grootle_proof;
    /// binned representation of ledger indices of enotes referenced by the proof
    SpBinnedReferenceSetV1 binned_reference_set;
    /// ref set size = n^m
    std::size_t ref_set_decomp_n;
    std::size_t ref_set_decomp_m;
};
inline const boost::string_ref container_name(const SpMembershipProofV1&) { return "SpMembershipProofV1"; }
void append_to_transcript(const SpMembershipProofV1 &container, SpTranscriptBuilder &transcript_inout);

/// get size in bytes
/// - note: compact version excludes the decomposition parameters, and uses the compact size of the binned ref set
std::size_t sp_membership_proof_v1_size_bytes(const std::size_t n,
    const std::size_t m,
    const std::size_t num_bin_members);
std::size_t sp_membership_proof_v1_size_bytes_compact(const std::size_t n,
    const std::size_t m,
    const std::size_t num_bin_members);
std::size_t sp_membership_proof_v1_size_bytes(const SpMembershipProofV1 &proof);
std::size_t sp_membership_proof_v1_size_bytes_compact(const SpMembershipProofV1 &proof);

////
// SpImageProofV1
// - ownership and legitimacy of the key image
// - seraphis composition proof
///
struct SpImageProofV1 final
{
    /// a seraphis composition proof
    SpCompositionProof composition_proof;
};
inline const boost::string_ref container_name(const SpImageProofV1&) { return "SpImageProofV1"; }
void append_to_transcript(const SpImageProofV1 &container, SpTranscriptBuilder &transcript_inout);

/// get size in bytes
inline std::size_t sp_image_proof_v1_size_bytes() { return sp_composition_size_bytes(); }

////
// SpBalanceProofV1
// - balance proof: implicit with a remainder blinding factor: [sum(inputs) == sum(outputs) + remainder_blinding_factor*G]
// - range proofs: Bulletproofs+ v2
///
struct SpBalanceProofV1 final
{
    /// an aggregate set of BP+ proofs (does not contain V output commitment vector)
    BulletproofPlus2Proof bpp2_proof;
    /// the remainder blinding factor
    rct::key remainder_blinding_factor;
};
inline const boost::string_ref container_name(const SpBalanceProofV1&) { return "SpBalanceProofV1"; }
void append_to_transcript(const SpBalanceProofV1 &container, SpTranscriptBuilder &transcript_inout);

/// get the proof size in bytes (does not include commitment values)
std::size_t sp_balance_proof_v1_size_bytes(const std::size_t num_range_proofs);
std::size_t sp_balance_proof_v1_size_bytes(const SpBalanceProofV1 &proof);
/// get the proof weight
std::size_t sp_balance_proof_v1_weight(const std::size_t num_range_proofs);
std::size_t sp_balance_proof_v1_weight(const SpBalanceProofV1 &proof);

////
// SpTxSupplementV1
// - supplementary info about a tx
//   - enote ephemeral pubkeys (stored here instead of in enotes since enotes can share them)
//   - tx memo
///
struct SpTxSupplementV1 final
{
    /// xKe: enote ephemeral pubkeys for outputs
    std::vector<crypto::x25519_pubkey> output_enote_ephemeral_pubkeys;
    /// tx memo
    TxExtra tx_extra;
};
inline const boost::string_ref container_name(const SpTxSupplementV1&) { return "SpTxSupplementV1"; }
void append_to_transcript(const SpTxSupplementV1 &container, SpTranscriptBuilder &transcript_inout);

/// get the size in bytes
std::size_t sp_tx_supplement_v1_size_bytes(const std::size_t num_outputs,
    const std::size_t tx_extra_size,
    const bool use_shared_ephemeral_key_assumption);
std::size_t sp_tx_supplement_v1_size_bytes(const SpTxSupplementV1 &tx_supplement);

/// comparison operator for equivalence testing
bool operator==(const SpCoinbaseEnoteV1 &a, const SpCoinbaseEnoteV1 &b);
bool operator==(const SpEnoteV1 &a, const SpEnoteV1 &b);
bool operator==(const SpEnoteVariant &variant1, const SpEnoteVariant &variant2);
/// comparison method for sorting: a.Ko < b.Ko
bool compare_Ko(const SpCoinbaseEnoteV1 &a, const SpCoinbaseEnoteV1 &b);
bool compare_Ko(const SpEnoteV1 &a, const SpEnoteV1 &b);
/// comparison method for sorting: a.KI < b.KI
bool compare_KI(const SpEnoteImageV1 &a, const SpEnoteImageV1 &b);

/// generate a dummy v1 coinbase enote
SpCoinbaseEnoteV1 gen_sp_coinbase_enote_v1();
/// generate a dummy v1 enote
SpEnoteV1 gen_sp_enote_v1();

} //namespace sp
