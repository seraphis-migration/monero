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
#include "tx_component_types_legacy.h"

//local headers
#include "misc_log_ex.h"
#include "seraphis_crypto/sp_legacy_proof_helpers.h"
#include "seraphis_crypto/sp_transcript.h"

//third party headers

//standard headers


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const LegacyEnoteImageV2 &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("C_masked", container.masked_commitment);
    transcript_inout.append("KI", container.key_image);
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const LegacyRingSignatureV4 &container, SpTranscriptBuilder &transcript_inout)
{
    append_clsag_to_transcript(container.clsag_proof, transcript_inout);
    transcript_inout.append("reference_set", container.reference_set);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t legacy_ring_signature_v4_size_bytes(const std::size_t num_ring_members)
{
    return clsag_size_bytes(num_ring_members) + num_ring_members * 8;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t legacy_ring_signature_v4_size_bytes(const LegacyRingSignatureV4 &ring_signature)
{
    CHECK_AND_ASSERT_THROW_MES(ring_signature.clsag_proof.s.size() == ring_signature.reference_set.size(),
        "legacy ring signature v4 size: clsag proof doesn't match reference set size.");

    return legacy_ring_signature_v4_size_bytes(ring_signature.reference_set.size());
}
//-------------------------------------------------------------------------------------------------------------------
bool compare_KI(const LegacyEnoteImageV2 &a, const LegacyEnoteImageV2 &b)
{
    return a.key_image < b.key_image;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
