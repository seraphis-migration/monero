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
#include "mock_sp_component_types.h"

//local headers
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "misc_log_ex.h"
#include "mock_sp_core.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <memory>
#include <vector>


namespace mock_tx
{
//-------------------------------------------------------------------------------------------------------------------
void MockENoteSpV1::make(const crypto::secret_key &enote_privkey,
    const rct::key &recipient_DH_base,
    const rct::key &recipient_view_key,
    const rct::key &recipient_spend_key,
    const rct::xmr_amount amount,
    const std::size_t enote_index,
    rct::key &enote_pubkey_out)
{
    // sender-receiver shared secret
    crypto::secret_key sender_receiver_secret;
    make_seraphis_sender_receiver_secret(enote_privkey, recipient_view_key, enote_index, sender_receiver_secret);

    // amount commitment mask (blinding factor)
    crypto::secret_key amount_mask;
    make_seraphis_amount_commitment_mask(sender_receiver_secret, amount_mask);

    // extension to add to user's spend key
    crypto::secret_key k_a_extender;
    make_seraphis_sender_address_extension(sender_receiver_secret, k_a_extender);

    // make the base of the enote
    this->make_base_with_address_extension(k_a_extender, recipient_spend_key, amount_mask, amount);

    // encoded amount
    m_encoded_amount = enc_dec_seraphis_amount(sender_receiver_secret, amount);

    // view tag
    m_view_tag = make_seraphis_view_tag(sender_receiver_secret);

    // enote pubkey to send back to caller
    make_seraphis_enote_pubkey(enote_privkey, recipient_DH_base, enote_pubkey_out);
}
//-------------------------------------------------------------------------------------------------------------------
void MockENoteSpV1::gen()
{
    // gen base of enote
    this->gen_base();

    // memo
    m_encoded_amount = rct::randXmrAmount(rct::xmr_amount{static_cast<rct::xmr_amount>(-1)});
    m_view_tag = 0;
}
#if 0
//-------------------------------------------------------------------------------------------------------------------
MockENoteImageRctV1 MockInputRctV1::to_enote_image_v1(const crypto::secret_key &pseudo_blinding_factor) const
{
    MockENoteImageRctV1 image;

    // C' = x' G + a H
    image.m_pseudo_amount_commitment = rct::rct2pk(rct::commit(m_amount, rct::sk2rct(pseudo_blinding_factor)));

    // KI = ko * Hp(Ko)
    crypto::public_key pubkey;
    CHECK_AND_ASSERT_THROW_MES(crypto::secret_key_to_public_key(m_onetime_privkey, pubkey), "Failed to derive public key");
    crypto::generate_key_image(pubkey, m_onetime_privkey, image.m_key_image);

    // KI_stored = (1/8)*KI
    // - for efficiently checking that the key image is in the prime subgroup during tx verification
    rct::key storable_ki;
    rct::scalarmultKey(storable_ki, rct::ki2rct(image.m_key_image), rct::INV_EIGHT);
    image.m_key_image = rct::rct2ki(storable_ki);

    return image;
}
MockENoteImageRctV1 MockInputRctV1::to_enote_image_v2(const crypto::secret_key &pseudo_blinding_factor) const
{
    MockENoteImageRctV1 image;

    // C' = x' G + a H
    image.m_pseudo_amount_commitment = rct::rct2pk(rct::commit(m_amount, rct::sk2rct(pseudo_blinding_factor)));

    // KI = 1/ko * U
    rct::key inv_ko{rct::invert(rct::sk2rct(m_onetime_privkey))};
    rct::key key_image{rct::scalarmultKey(rct::get_gen_U(), inv_ko)};

    // KI_stored = (1/8)*KI
    // - for efficiently checking that the key image is in the prime subgroup during tx verification
    rct::key storable_ki;
    rct::scalarmultKey(storable_ki, key_image, rct::INV_EIGHT);
    image.m_key_image = rct::rct2ki(storable_ki);

    return image;
}
//-------------------------------------------------------------------------------------------------------------------
void MockInputRctV1::gen_v1(const rct::xmr_amount amount, const std::size_t ref_set_size)
{
    // \pi = rand()
    m_input_ref_set_real_index = crypto::rand_idx(ref_set_size);

    // prep real input
    m_onetime_privkey = rct::rct2sk(rct::skGen());
    m_amount_blinding_factor = rct::rct2sk(rct::skGen());
    m_amount = amount;

    // construct reference set
    m_input_ref_set.resize(ref_set_size);

    for (std::size_t ref_index{0}; ref_index < ref_set_size; ++ref_index)
    {
        // insert real input at \pi
        if (ref_index == m_input_ref_set_real_index)
        {
            // make an enote at m_input_ref_set[ref_index]
            m_input_ref_set[ref_index].make_v1(m_onetime_privkey,
                    m_amount_blinding_factor,
                    m_amount);
        }
        // add random enote
        else
        {
            // generate a random enote at m_input_ref_set[ref_index]
            m_input_ref_set[ref_index].gen_v1();
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
MockENoteSpV1 MockDestRctV1::to_enote_v1() const
{
    MockENoteSpV1 enote;
    MockDestRct::to_enote_rct_base(enote);

    return enote;
}
//-------------------------------------------------------------------------------------------------------------------
void MockDestRctV1::gen_v1(const rct::xmr_amount amount)
{
    // gen base of dest
    this->gen_base(amount);

    // memo parts: random
    m_enote_pubkey = rct::rct2pk(rct::pkGen());
    m_encoded_amount = rct::randXmrAmount(rct::xmr_amount{static_cast<rct::xmr_amount>(-1)});
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t MockRctProofV1::get_size_bytes() const
{
    // note: ignore the key image stored in the clsag, it is double counted by the input's enote image struct
    return 32 * (2 + m_clsag_proof.s.size());
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t MockRctProofV2::get_size_bytes() const
{
    // note: ignore the key image stored in the Triptych proof, it is double counted by the input's enote image struct
    return 32 * (8 + m_triptych_proof.X.size() + m_triptych_proof.Y.size() + m_ref_set_decomp_n * m_ref_set_decomp_m);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t MockRctBalanceProofV1::get_size_bytes() const
{
    // note: ignore the amount commitment set stored in the range proofs, they are double counted by the output set
    std::size_t size{0};

    for (const auto &proof : m_bpp_proofs)
        size += 32 * (6 + proof.L.size() + proof.R.size());;

    return size;
}
#endif
//-------------------------------------------------------------------------------------------------------------------
} //namespace mock_tx
