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
// LegacyEnoteImageV1: not used in seraphis
// - key image only
///

////
// LegacyEnoteImageV2
// - masked commitment
// - key image
///
struct LegacyEnoteImageV2 final
{
    /// masked commitment (aka 'pseudo-output commitment')
    rct::key masked_commitment;
    /// legacy key image
    crypto::key_image key_image;
};
inline const boost::string_ref container_name(const LegacyEnoteImageV2&) { return "LegacyEnoteImageV2"; }
void append_to_transcript(const LegacyEnoteImageV2 &container, SpTranscriptBuilder &transcript_inout);

/// get the size in bytes
inline std::size_t legacy_enote_image_v2_size_bytes() { return 32 + 32; }

////
// LegacyRingSignatureV1: not used in seraphis
// - Cryptonote ring signature (using LegacyEnoteImageV1)
///

////
// LegacyRingSignatureV2: not used in seraphis
// - MLSAG combined inputs (using LegacyEnoteImageV2)
///

////
// LegacyRingSignatureV3: not used in seraphis
// - MLSAG split inputs (using LegacyEnoteImageV2)
///

////
// LegacyRingSignatureV4
// - CLSAG (using LegacyEnoteImageV2)
///
struct LegacyRingSignatureV4 final
{
    /// a clsag proof
    rct::clsag clsag_proof;
    /// on-chain indices of the proof's ring members
    std::vector<std::uint64_t> reference_set;
};
inline const boost::string_ref container_name(const LegacyRingSignatureV4&) { return "LegacyRingSignatureV4"; }
void append_to_transcript(const LegacyRingSignatureV4 &container, SpTranscriptBuilder &transcript_inout);

/// get the size in bytes
std::size_t legacy_ring_signature_v4_size_bytes(const std::size_t num_ring_members);
std::size_t legacy_ring_signature_v4_size_bytes(const LegacyRingSignatureV4 &ring_signature);

/// comparison method for sorting: a.KI < b.KI
bool compare_KI(const LegacyEnoteImageV2 &a, const LegacyEnoteImageV2 &b);

} //namespace sp
