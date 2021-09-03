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

// Legacy transaction-builder helper types.

#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
#include "tx_component_types_legacy.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace sp
{

////
// LegacyInputProposalV1
///
struct LegacyInputProposalV1 final
{
    /// core of the original enote
    rct::key onetime_address;
    rct::key amount_commitment;
    /// the enote's key image
    crypto::key_image key_image;

    /// Hn(k_v R_t, t) + [subaddresses: Hn(k_v, i)]  (does not include legacy spend privkey k_s)
    crypto::secret_key enote_view_extension;
    /// x
    crypto::secret_key amount_blinding_factor;
    /// a
    rct::xmr_amount amount;

    /// mask
    crypto::secret_key commitment_mask;
};

/// get the proposal's amount
rct::xmr_amount amount_ref(const LegacyInputProposalV1 &proposal);

////
// LegacyRingSignaturePrepV1
// - data for producing a legacy ring signature
///
struct LegacyRingSignaturePrepV1 final
{
    /// tx proposal prefix (message to sign in the proof)
    rct::key tx_proposal_prefix;
    /// ledger indices of legacy enotes to be referenced by the proof
    std::vector<std::uint64_t> reference_set;
    /// the referenced enotes ({Ko, C}((legacy)) representation)
    rct::ctkeyV referenced_enotes;
    /// the index of the real enote being referenced within the reference set
    std::uint64_t real_reference_index;
    /// enote image of the real reference (useful for sorting)
    LegacyEnoteImageV2 reference_image;
    /// enote view privkey of the real reference's onetime address
    crypto::secret_key reference_view_privkey;
    /// commitment mask applied to the reference amount commitment to produce the image's masked commitment
    crypto::secret_key reference_commitment_mask;
};

////
// LegacyInputV1
// - legacy enote spent
// - legacy ring signature for the input
// - cached amount and masked amount commitment's blinding factor (for balance proof)
// - cached ring members (for validating the ring signature)
// - proposal prefix (spend proof msg) [for consistency checks when handling this object]
///
struct LegacyInputV1 final
{
    /// input's image
    LegacyEnoteImageV2 input_image;
    /// input's ring signature (demonstrates ownership and membership of the underlying enote, and that the enote image
    ///   is correct)
    LegacyRingSignatureV4 ring_signature;

    /// input amount
    rct::xmr_amount input_amount;
    /// input masked amount commitment's blinding factor; used for making the balance proof
    crypto::secret_key input_masked_commitment_blinding_factor;

    /// cached ring members of the ring signature; used for validating the ring signature
    rct::ctkeyV ring_members;

    /// tx proposal prefix (represents the inputs/outputs/fee/memo; signed by this input's ring signature)
    rct::key tx_proposal_prefix;
};

/// comparison method for sorting: a.KI < b.KI
bool compare_KI(const LegacyInputProposalV1 &a, const LegacyInputProposalV1 &b);
bool compare_KI(const LegacyRingSignaturePrepV1 &a, const LegacyRingSignaturePrepV1 &b);
bool compare_KI(const LegacyInputV1 &a, const LegacyInputV1 &b);

/**
* brief: get_enote_image_v2 - get this input's enote image
* outparam: image_out -
*/
void get_enote_image_v2(const LegacyInputProposalV1 &proposal, LegacyEnoteImageV2 &image_out);
/**
* brief: gen_legacy_input_proposal_v1 - generate a legacy input proposal
* param: legacy_spend_privkey -
* param: amount -
* return: random proposal
*/
LegacyInputProposalV1 gen_legacy_input_proposal_v1(const crypto::secret_key &legacy_spend_privkey,
    const rct::xmr_amount amount);

} //namespace sp
