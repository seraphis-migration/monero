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
#include "legacy_enote_utils.h"

//local headers
#include "legacy_core_utils.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_enote_v1(const rct::key &destination_spendkey,
    const rct::key &destination_viewkey,
    const rct::xmr_amount amount,
    const std::uint64_t output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    LegacyEnoteV1 &enote_out)
{
    // onetime address (normal address): K^o = Hn(r K^v, t) G + K^s
    make_legacy_onetime_address(destination_spendkey,
        destination_viewkey,
        output_index,
        enote_ephemeral_privkey,
        enote_out.m_onetime_address);

    // amount: a
    enote_out.m_amount = amount;
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_enote_v2(const rct::key &destination_spendkey,
    const rct::key &destination_viewkey,
    const rct::xmr_amount amount,
    const std::uint64_t output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    LegacyEnoteV2 &enote_out)
{
    // onetime address (normal address): K^o = Hn(r K^v, t) G + K^s
    make_legacy_onetime_address(destination_spendkey,
        destination_viewkey,
        output_index,
        enote_ephemeral_privkey,
        enote_out.m_onetime_address);

    // amount commitment: x G + a H
    const crypto::secret_key amount_mask{rct::rct2sk(rct::skGen())};
    enote_out.m_amount_commitment = rct::commit(amount, rct::sk2rct(amount_mask));

    // encoded amount blinding factor: enc(x) = x + Hn(Hn(r K^v, t))
    // encoded amount: enc(a) = to_key(a) + Hn(Hn(Hn(r K^v, t)))
    make_legacy_encoded_amount_v1(destination_viewkey,
        output_index,
        enote_ephemeral_privkey,
        amount_mask,
        amount,
        enote_out.m_encoded_amount_blinding_factor,
        enote_out.m_encoded_amount);
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_enote_v3(const rct::key &destination_spendkey,
    const rct::key &destination_viewkey,
    const rct::xmr_amount amount,
    const std::uint64_t output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    LegacyEnoteV3 &enote_out)
{
    // onetime address (normal address): K^o = Hn(r K^v, t) G + K^s
    make_legacy_onetime_address(destination_spendkey,
        destination_viewkey,
        output_index,
        enote_ephemeral_privkey,
        enote_out.m_onetime_address);

    // amount commitment: Hn("commitment_mask", Hn(r K^v, t)) G + a H
    crypto::secret_key amount_mask;
    make_legacy_amount_blinding_factor_v2(destination_viewkey, output_index, enote_ephemeral_privkey, amount_mask);

    enote_out.m_amount_commitment = rct::commit(amount, rct::sk2rct(amount_mask));

    // encoded amount: enc(a) = a XOR_8 H32("amount", Hn(r K^v, t))
    make_legacy_encoded_amount_v2(destination_viewkey,
        output_index,
        enote_ephemeral_privkey,
        amount,
        enote_out.m_encoded_amount);
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_enote_v4(const rct::key &destination_spendkey,
    const rct::key &destination_viewkey,
    const rct::xmr_amount amount,
    const std::uint64_t output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    LegacyEnoteV4 &enote_out)
{
    // onetime address (normal address): K^o = Hn(r K^v, t) G + K^s
    make_legacy_onetime_address(destination_spendkey,
        destination_viewkey,
        output_index,
        enote_ephemeral_privkey,
        enote_out.m_onetime_address);

    // amount commitment: Hn("commitment_mask", Hn(r K^v, t)) G + a H
    crypto::secret_key amount_mask;
    make_legacy_amount_blinding_factor_v2(destination_viewkey, output_index, enote_ephemeral_privkey, amount_mask);

    enote_out.m_amount_commitment = rct::commit(amount, rct::sk2rct(amount_mask));

    // encoded amount: enc(a) = a XOR_8 H32("amount", Hn(r K^v, t))
    make_legacy_encoded_amount_v2(destination_viewkey,
        output_index,
        enote_ephemeral_privkey,
        amount,
        enote_out.m_encoded_amount);

    // view tag: 
    make_legacy_view_tag(destination_viewkey, output_index, enote_ephemeral_privkey, enote_out.m_view_tag);
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_ephemeral_pubkey_shared(const crypto::secret_key &enote_ephemeral_privkey,
    rct::key &enote_ephemeral_pubkey_out)
{
    // enote ephemeral pubkey (basic): r G
    rct::scalarmultBase(enote_ephemeral_pubkey_out, rct::sk2rct(enote_ephemeral_privkey));
}
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_ephemeral_pubkey_single(const rct::key &destination_spendkey,
    const crypto::secret_key &enote_ephemeral_privkey,
    rct::key &enote_ephemeral_pubkey_out)
{
    // enote ephemeral pubkey (for single enote): r K^s
    rct::scalarmultKey(enote_ephemeral_pubkey_out, destination_spendkey, rct::sk2rct(enote_ephemeral_privkey));
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
