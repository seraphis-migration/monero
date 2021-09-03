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
#include "tx_builder_types_legacy.h"

//local headers
#include "crypto/crypto.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/legacy_core_utils.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "tx_component_types_legacy.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount amount_ref(const LegacyInputProposalV1 &proposal)
{
    return proposal.amount;
}
//-------------------------------------------------------------------------------------------------------------------
bool compare_KI(const LegacyInputProposalV1 &a, const LegacyInputProposalV1 &b)
{
    return a.key_image < b.key_image;
}
//-------------------------------------------------------------------------------------------------------------------
bool compare_KI(const LegacyRingSignaturePrepV1 &a, const LegacyRingSignaturePrepV1 &b)
{
    return compare_KI(a.reference_image, b.reference_image);
}
//-------------------------------------------------------------------------------------------------------------------
bool compare_KI(const LegacyInputV1 &a, const LegacyInputV1 &b)
{
    return compare_KI(a.input_image, b.input_image);
}
//-------------------------------------------------------------------------------------------------------------------
void get_enote_image_v2(const LegacyInputProposalV1 &proposal, LegacyEnoteImageV2 &image_out)
{
    mask_key(proposal.commitment_mask, proposal.amount_commitment, image_out.masked_commitment);
    image_out.key_image = proposal.key_image;
}
//-------------------------------------------------------------------------------------------------------------------
LegacyInputProposalV1 gen_legacy_input_proposal_v1(const crypto::secret_key &legacy_spend_privkey,
    const rct::xmr_amount amount)
{
    LegacyInputProposalV1 temp;

    temp.enote_view_extension   = rct::rct2sk(rct::skGen());
    temp.amount_blinding_factor = rct::rct2sk(rct::skGen());
    temp.amount                 = amount;
    temp.commitment_mask        = rct::rct2sk(rct::skGen());
    temp.onetime_address        = rct::scalarmultBase(rct::sk2rct(legacy_spend_privkey));
    mask_key(temp.enote_view_extension, temp.onetime_address, temp.onetime_address);
    temp.amount_commitment      = rct::commit(temp.amount, rct::sk2rct(temp.amount_blinding_factor));
    make_legacy_key_image(temp.enote_view_extension,
        legacy_spend_privkey,
        temp.onetime_address,
        hw::get_device("default"),
        temp.key_image);

    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
