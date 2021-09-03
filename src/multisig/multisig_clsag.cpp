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
#include "multisig_clsag.h"

//local headers
#include "common/container_helpers.h"
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "misc_language.h"
#include "misc_log_ex.h"
#include "multisig_clsag_context.h"
#include "multisig_nonce_cache.h"
#include "ringct/rctOps.h"
#include "ringct/rctSigs.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "multisig"

namespace multisig
{
//-------------------------------------------------------------------------------------------------------------------
// CLSAG proof response
// r = alpha - c * w
// r = alpha - c * (mu_K*k + mu_C*z)
//-------------------------------------------------------------------------------------------------------------------
static void compute_response(const rct::key &challenge,
    const rct::key &alpha,
    const crypto::secret_key &k,
    const crypto::secret_key &z,
    const rct::key &mu_K,
    const rct::key &mu_C,
    rct::key &r_out)
{
    // r = alpha - c * (mu_K*k + mu_C*z)
    sc_mul(r_out.bytes, mu_K.bytes, to_bytes(k));  //mu_K*k
    sc_muladd(r_out.bytes, mu_C.bytes, to_bytes(z), r_out.bytes);  //+ mu_C*z
    sc_mul(r_out.bytes, challenge.bytes, r_out.bytes);  //c * (...)
    sc_sub(r_out.bytes, alpha.bytes, r_out.bytes);  //alpha - c * (...)
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void signer_nonces_mul8(const MultisigPubNonces &signer_pub_nonce_pair, MultisigPubNonces &nonce_pair_mul8_out)
{
    nonce_pair_mul8_out.signature_nonce_1_pub = rct::scalarmult8(signer_pub_nonce_pair.signature_nonce_1_pub);
    nonce_pair_mul8_out.signature_nonce_2_pub = rct::scalarmult8(signer_pub_nonce_pair.signature_nonce_2_pub);

    CHECK_AND_ASSERT_THROW_MES(!(nonce_pair_mul8_out.signature_nonce_1_pub == rct::identity()),
        "clsag multisig: bad signer nonce (alpha_1 identity)!");
    CHECK_AND_ASSERT_THROW_MES(!(nonce_pair_mul8_out.signature_nonce_2_pub == rct::identity()),
        "clsag multisig: bad signer nonce (alpha_2 identity)!");
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static rct::keyV sum_together_multisig_pub_nonces(const std::vector<MultisigPubNonces> &pub_nonces)
{
    rct::keyV summed_nonces;
    summed_nonces.resize(2, rct::identity());

    for (const MultisigPubNonces &pub_nonce : pub_nonces)
    {
        rct::addKeys(summed_nonces[0], summed_nonces[0], pub_nonce.signature_nonce_1_pub);
        rct::addKeys(summed_nonces[1], summed_nonces[1], pub_nonce.signature_nonce_2_pub);
    }

    return summed_nonces;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
const rct::key& main_proof_key_ref(const CLSAGMultisigProposal &proposal)
{
    CHECK_AND_ASSERT_THROW_MES(proposal.l < proposal.ring_members.size(),
        "CLSAGMultisigProposal (get main proof key): l is out of range.");

    return proposal.ring_members[proposal.l].dest;
}
//-------------------------------------------------------------------------------------------------------------------
const rct::key& auxilliary_proof_key_ref(const CLSAGMultisigProposal &proposal)
{
    CHECK_AND_ASSERT_THROW_MES(proposal.l < proposal.ring_members.size(),
        "CLSAGMultisigProposal (get auxilliary proof key): l is out of range.");

    return proposal.ring_members[proposal.l].mask;
}
//-------------------------------------------------------------------------------------------------------------------
void make_clsag_multisig_proposal(const rct::key &message,
    rct::ctkeyV ring_members,
    const rct::key &masked_C,
    const crypto::key_image &KI,
    const crypto::key_image &D,
    const std::uint32_t l,
    CLSAGMultisigProposal &proposal_out)
{
    // checks
    const std::size_t num_ring_members{ring_members.size()};
    CHECK_AND_ASSERT_THROW_MES(l < num_ring_members, "make CLSAG multisig proposal: l is out of range.");

    // assemble proposal
    proposal_out.message          = message;
    proposal_out.ring_members     = std::move(ring_members);
    proposal_out.masked_C         = masked_C;
    proposal_out.KI               = KI;
    proposal_out.D                = D;
    proposal_out.decoy_responses  = rct::skvGen(num_ring_members);
    proposal_out.l                = l;
}
//-------------------------------------------------------------------------------------------------------------------
void make_clsag_multisig_partial_sig(const CLSAGMultisigProposal &proposal,
    const crypto::secret_key &k_e,
    const crypto::secret_key &z_e,
    const std::vector<MultisigPubNonces> &signer_pub_nonces_G,
    const std::vector<MultisigPubNonces> &signer_pub_nonces_Hp,
    const crypto::secret_key &local_nonce_1_priv,
    const crypto::secret_key &local_nonce_2_priv,
    CLSAGMultisigPartial &partial_sig_out)
{
    // check multisig proposal
    CHECK_AND_ASSERT_THROW_MES(!(main_proof_key_ref(proposal) == rct::identity()),
        "make CLSAG multisig partial sig: bad proof key (main key identity)!");
    CHECK_AND_ASSERT_THROW_MES(!(rct::ki2rct(proposal.KI) == rct::identity()), 
        "make CLSAG multisig partial sig: bad proof key (KI identity)!");

    for (const rct::key &decoy_response : proposal.decoy_responses)
    {
        CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(decoy_response.bytes),
            "make CLSAG multisig partial sig: bad private key (proposal decoy response zero)!");
        CHECK_AND_ASSERT_THROW_MES(sc_check(decoy_response.bytes) == 0,
            "make CLSAG multisig partial sig: bad private key (proposal decoy response)!");
    }

    const std::size_t num_ring_members{proposal.ring_members.size()};
    CHECK_AND_ASSERT_THROW_MES(proposal.decoy_responses.size() == num_ring_members,
        "make CLSAG multisig partial sig: inconsistent number of decoy responses!");
    CHECK_AND_ASSERT_THROW_MES(proposal.l < num_ring_members, "make CLSAG multisig partial sig: l is out of range.");

    // check other inputs
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(k_e)),
        "make CLSAG multisig partial sig: bad private key (proposal nonce k_e zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(k_e)) == 0,
        "make CLSAG multisig partial sig: bad private key (proposal nonce k_e)!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(z_e)),
        "make CLSAG multisig partial sig: bad private key (proposal nonce z_e zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(z_e)) == 0,
        "make CLSAG multisig partial sig: bad private key (proposal nonce z_e)!");

    const std::size_t num_signers{signer_pub_nonces_G.size()};
    CHECK_AND_ASSERT_THROW_MES(signer_pub_nonces_Hp.size() == num_signers,
        "make CLSAG multisig partial sig: inconsistent signer pub nonce set sizes!");

    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(local_nonce_1_priv)),
        "make CLSAG multisig partial sig: bad private key (local_nonce_1_priv zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(local_nonce_1_priv)) == 0,
        "make CLSAG multisig partial sig: bad private key (local_nonce_1_priv)!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(local_nonce_2_priv)),
        "make CLSAG multisig partial sig: bad private key (local_nonce_2_priv zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(local_nonce_2_priv)) == 0,
        "make CLSAG multisig partial sig: bad private key (local_nonce_2_priv)!");

    // prepare participant nonces
    std::vector<MultisigPubNonces> signer_pub_nonces_G_mul8;
    std::vector<MultisigPubNonces> signer_pub_nonces_Hp_mul8;
    signer_pub_nonces_G_mul8.reserve(num_signers);
    signer_pub_nonces_Hp_mul8.reserve(num_signers);

    for (const MultisigPubNonces &signer_pub_nonce_pair : signer_pub_nonces_G)
        signer_nonces_mul8(signer_pub_nonce_pair, tools::add_element(signer_pub_nonces_G_mul8));
    for (const MultisigPubNonces &signer_pub_nonce_pair : signer_pub_nonces_Hp)
        signer_nonces_mul8(signer_pub_nonce_pair, tools::add_element(signer_pub_nonces_Hp_mul8));

    // check that the local signer's signature opening is in the input set of opening nonces (for both G and Hp versions)
    MultisigPubNonces local_pub_nonces_G;
    rct::scalarmultBase(local_pub_nonces_G.signature_nonce_1_pub, rct::sk2rct(local_nonce_1_priv));
    rct::scalarmultBase(local_pub_nonces_G.signature_nonce_2_pub, rct::sk2rct(local_nonce_2_priv));

    crypto::key_image key_image_base;
    crypto::generate_key_image(rct::rct2pk(main_proof_key_ref(proposal)), rct::rct2sk(rct::I), key_image_base);  //Hp(K[l])

    MultisigPubNonces local_nonce_pubs_Hp;
    rct::scalarmultKey(local_nonce_pubs_Hp.signature_nonce_1_pub,
        rct::ki2rct(key_image_base),
        rct::sk2rct(local_nonce_1_priv));
    rct::scalarmultKey(local_nonce_pubs_Hp.signature_nonce_2_pub,
        rct::ki2rct(key_image_base),
        rct::sk2rct(local_nonce_2_priv));

    CHECK_AND_ASSERT_THROW_MES(
        std::find(signer_pub_nonces_G_mul8.begin(), signer_pub_nonces_G_mul8.end(), local_pub_nonces_G) !=
            signer_pub_nonces_G_mul8.end(),
        "make CLSAG multisig partial sig: local signer's opening nonces not in input set (G)!");
    CHECK_AND_ASSERT_THROW_MES(
        std::find(signer_pub_nonces_Hp_mul8.begin(), signer_pub_nonces_Hp_mul8.end(), local_nonce_pubs_Hp) !=
            signer_pub_nonces_Hp_mul8.end(),
        "make CLSAG multisig partial sig: local signer's opening nonces not in input set (Hp)!");

    // sum participant nonces to satisfy CLSAG_context_t, which pre-combines participant nonces before applying the
    //   multisig nonce merge factor
    const rct::keyV signer_nonce_pub_sum_G{
            sum_together_multisig_pub_nonces(signer_pub_nonces_G_mul8)
        };
    const rct::keyV signer_nonce_pub_sum_Hp{
            sum_together_multisig_pub_nonces(signer_pub_nonces_Hp_mul8)
        };

    // split the ring members
    rct::keyV nominal_proof_Ks;
    rct::keyV nominal_pedersen_Cs;
    nominal_proof_Ks.reserve(num_ring_members);
    nominal_pedersen_Cs.reserve(num_ring_members);

    for (const rct::ctkey &ring_member : proposal.ring_members)
    {
        nominal_proof_Ks.emplace_back(ring_member.dest);
        nominal_pedersen_Cs.emplace_back(ring_member.mask);
    }


    /// prepare CLSAG context
    signing::CLSAG_context_t multisig_CLSAG_context;

    multisig_CLSAG_context.init(nominal_proof_Ks,
        nominal_pedersen_Cs,
        proposal.masked_C,
        proposal.message,
        rct::ki2rct(proposal.KI),
        rct::ki2rct(proposal.D),
        proposal.l,
        proposal.decoy_responses,
        2);


    /// get the local signer's combined musig2-style private nonce and the CLSAG challenges (both the nominal challenge
    //    at index 0, and the challenge that is responded to by the signer at index l)
    rct::key combined_local_nonce_privkey;
    rct::key clsag_challenge_c_0;
    rct::key signer_challenge;

    CHECK_AND_ASSERT_THROW_MES(multisig_CLSAG_context.combine_alpha_and_compute_challenge(signer_nonce_pub_sum_G,
            signer_nonce_pub_sum_Hp,
            {rct::sk2rct(local_nonce_1_priv), rct::sk2rct(local_nonce_2_priv)},
            combined_local_nonce_privkey,
            clsag_challenge_c_0,
            signer_challenge),
        "make CLSAG multisig partial sig: failed to get combined local nonce privkey and CLSAG challenges.");


    /// compute the local signer's partial response

    // prepare the CLSAG merge factors that separate the main proof key and ancillary proof key components
    rct::key mu_K;
    rct::key mu_C;

    CHECK_AND_ASSERT_THROW_MES(multisig_CLSAG_context.get_mu(mu_K, mu_C),
        "make CLSAG multisig partial sig: failed to get CLSAG merge factors.");

    // compute the local signer's partial response
    rct::key partial_response;

    compute_response(signer_challenge,
        combined_local_nonce_privkey,
        k_e,
        z_e,
        mu_K,
        mu_C,
        partial_response);


    /// set the partial signature components
    partial_sig_out.message = proposal.message;
    partial_sig_out.main_proof_key_K = main_proof_key_ref(proposal);
    partial_sig_out.l = proposal.l;
    partial_sig_out.responses = proposal.decoy_responses;
    partial_sig_out.responses[proposal.l] = partial_response;  //inject partial response
    partial_sig_out.c_0 = clsag_challenge_c_0,
    partial_sig_out.KI = proposal.KI;
    partial_sig_out.D = proposal.D;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_make_clsag_multisig_partial_sig(const CLSAGMultisigProposal &proposal,
    const crypto::secret_key &k_e,
    const crypto::secret_key &z_e,
    const std::vector<MultisigPubNonces> &signer_pub_nonces_G,
    const std::vector<MultisigPubNonces> &signer_pub_nonces_Hp,
    const signer_set_filter filter,
    MultisigNonceCache &nonce_record_inout,
    CLSAGMultisigPartial &partial_sig_out)
{
    // get the nonce privkeys to sign with
    crypto::secret_key nonce_privkey_1;
    crypto::secret_key nonce_privkey_2;
    if (!nonce_record_inout.try_get_recorded_nonce_privkeys(proposal.message,
            main_proof_key_ref(proposal),
            filter,
            nonce_privkey_1,
            nonce_privkey_2))
        return false;

    // make the partial signature
    CLSAGMultisigPartial partial_sig_temp;
    make_clsag_multisig_partial_sig(proposal,
        k_e,
        z_e,
        signer_pub_nonces_G,
        signer_pub_nonces_Hp,
        nonce_privkey_1,
        nonce_privkey_2,
        partial_sig_temp);

    // clear the used nonces
    CHECK_AND_ASSERT_THROW_MES(nonce_record_inout.try_remove_record(proposal.message, main_proof_key_ref(proposal), filter),
        "try make clsag multisig partial sig: failed to clear nonces from nonce record (aborting partial signature)!");

    // set the output partial sig AFTER used nonces are cleared, in case of exception
    partial_sig_out = std::move(partial_sig_temp);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void finalize_clsag_multisig_proof(const std::vector<CLSAGMultisigPartial> &partial_sigs,
    const rct::ctkeyV &ring_members,
    const rct::key &masked_commitment,
    rct::clsag &proof_out)
{
    /// input checks
    CHECK_AND_ASSERT_THROW_MES(partial_sigs.size() > 0,
        "finalize clsag multisig proof: no partial signatures to make proof out of!");

    // common parts between partial signatures should match
    const std::size_t num_ring_members{partial_sigs[0].responses.size()};
    const std::size_t real_signing_index{partial_sigs[0].l};

    CHECK_AND_ASSERT_THROW_MES(real_signing_index < num_ring_members,
        "finalize clsag multisig proof: input partial sigs invalid l!");

    for (const CLSAGMultisigPartial &partial_sig : partial_sigs)
    {
        CHECK_AND_ASSERT_THROW_MES(partial_sig.message == partial_sigs[0].message,
            "finalize clsag multisig proof: input partial sigs don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sig.main_proof_key_K == partial_sigs[0].main_proof_key_K,
            "finalize clsag multisig proof: input partial sigs don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sig.l == real_signing_index,
            "finalize clsag multisig proof: input partial sigs don't match!");;

        CHECK_AND_ASSERT_THROW_MES(partial_sig.responses.size() == num_ring_members,
            "finalize clsag multisig proof: input partial sigs don't match!");;

        for (std::size_t ring_index{0}; ring_index < num_ring_members; ++ring_index)
        {
            // the response at the real signing index is for a partial signature, which is unique per signer, so it isn't
            //    checked here
            if (ring_index == real_signing_index)
                continue;

            CHECK_AND_ASSERT_THROW_MES(partial_sig.responses[ring_index] == partial_sigs[0].responses[ring_index],
                "finalize clsag multisig proof: input partial sigs don't match!");
        }

        CHECK_AND_ASSERT_THROW_MES(partial_sig.c_0 == partial_sigs[0].c_0,
            "finalize clsag multisig proof: input partial sigs don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sig.KI == partial_sigs[0].KI,
            "finalize clsag multisig proof: input partial sigs don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sig.D == partial_sigs[0].D,
            "finalize clsag multisig proof: input partial sigs don't match!");
    }

    // ring members should line up with the partial sigs
    CHECK_AND_ASSERT_THROW_MES(ring_members.size() == num_ring_members,
        "finalize clsag multisig proof: ring members are inconsistent with the partial sigs!");
    CHECK_AND_ASSERT_THROW_MES(ring_members[real_signing_index].dest == partial_sigs[0].main_proof_key_K,
        "finalize clsag multisig proof: ring members are inconsistent with the partial sigs!");


    /// assemble the final proof
    proof_out.s  = partial_sigs[0].responses;
    proof_out.c1 = partial_sigs[0].c_0;  //note: c_0 is correct notation according to the paper, c1 is a typo
    proof_out.I  = rct::ki2rct(partial_sigs[0].KI);
    proof_out.D  = rct::scalarmultKey(rct::ki2rct(partial_sigs[0].D), rct::INV_EIGHT);

    proof_out.s[real_signing_index] = rct::zero();
    for (const CLSAGMultisigPartial &partial_sig : partial_sigs)
    {
        // sum of responses from each multisig signer
        sc_add(proof_out.s[real_signing_index].bytes,
            proof_out.s[real_signing_index].bytes,
            partial_sig.responses[real_signing_index].bytes);
    }


    /// verify that proof assembly succeeded
    CHECK_AND_ASSERT_THROW_MES(rct::verRctCLSAGSimple(partial_sigs[0].message,
            proof_out,
            ring_members,
            masked_commitment),
        "Multisig CLSAG failed to verify on assembly!");
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace multisig
