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
#include "sp_composition_proof.h"

//local headers
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "crypto/generators.h"
#include "cryptonote_config.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_crypto_utils.h"
#include "sp_hash_functions.h"
#include "sp_transcript.h"

//third party headers
#include <boost/utility/string_ref.hpp>

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
namespace composition_proof_detail
{
//-------------------------------------------------------------------------------------------------------------------
// Fiat-Shamir challenge message
//
// challenge_message = H_32(X, U, m, K, KI, K_t1)
//-------------------------------------------------------------------------------------------------------------------
rct::key compute_challenge_message(const rct::key &message,
    const rct::key &K,
    const crypto::key_image &KI,
    const rct::key &K_t1)
{
    // collect challenge message hash data
    SpFSTranscript transcript{config::HASH_KEY_SP_COMPOSITION_PROOF_CHALLENGE_MESSAGE, 6*sizeof(rct::key)};
    transcript.append("X", crypto::get_X());
    transcript.append("U", crypto::get_U());
    transcript.append("message", message);
    transcript.append("K", K);
    transcript.append("KI", KI);
    transcript.append("K_t1", K_t1);

    // challenge_message
    rct::key challenge_message;
    sp_hash_to_32(transcript.data(), transcript.size(), challenge_message.bytes);
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(challenge_message.bytes), "Transcript challenge_message must be nonzero!");

    return challenge_message;
}
//-------------------------------------------------------------------------------------------------------------------
// Fiat-Shamir challenge: extend the challenge message
// c = H_n(challenge_message, [K_t1 proof key], [K_t2 proof key], [KI proof key])
//-------------------------------------------------------------------------------------------------------------------
rct::key compute_challenge(const rct::key &challenge_message,
    const rct::key &K_t1_proofkey,
    const rct::key &K_t2_proofkey,
    const rct::key &KI_proofkey)
{
    // collect challenge hash data
    SpFSTranscript transcript{config::HASH_KEY_SP_COMPOSITION_PROOF_CHALLENGE, 4*sizeof(rct::key)};
    transcript.append("challenge_message", challenge_message);
    transcript.append("K_t1_proofkey", K_t1_proofkey);
    transcript.append("K_t2_proofkey", K_t2_proofkey);
    transcript.append("KI_proofkey", KI_proofkey);

    rct::key challenge;
    sp_hash_to_scalar(transcript.data(), transcript.size(), challenge.bytes);
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(challenge.bytes), "Transcript challenge must be nonzero!");

    return challenge;
}
//-------------------------------------------------------------------------------------------------------------------
// Proof responses
// r_t1 = alpha_t1 - c * (1 / y)
// r_t2 = alpha_t2 - c * (x / y)
// r_ki = alpha_ki - c * (z / y)
//-------------------------------------------------------------------------------------------------------------------
void compute_responses(const rct::key &challenge,
    const rct::key &alpha_t1,
    const rct::key &alpha_t2,
    const rct::key &alpha_ki,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z,
    rct::key &r_t1_out,
    rct::key &r_t2_out,
    rct::key &r_ki_out)
{
    // r_t1 = alpha_t1 - c * (1 / y)
    r_t1_out = invert(rct::sk2rct(y));  // 1 / y
    sc_mulsub(r_t1_out.bytes, challenge.bytes, r_t1_out.bytes, alpha_t1.bytes);  // alpha_t1 - c * (1 / y)

    // r_t2 = alpha_t2 - c * (x / y)
    r_t2_out = invert(rct::sk2rct(y));  // 1 / y
    sc_mul(r_t2_out.bytes, to_bytes(x), r_t2_out.bytes);  // x / y
    sc_mulsub(r_t2_out.bytes, challenge.bytes, r_t2_out.bytes, alpha_t2.bytes);  // alpha_t2 - c * (x / y)

    // r_ki = alpha_ki - c * (z / y)
    r_ki_out = invert(rct::sk2rct(y));  // 1 / y
    sc_mul(r_ki_out.bytes, to_bytes(z), r_ki_out.bytes);  // z / y
    sc_mulsub(r_ki_out.bytes, challenge.bytes, r_ki_out.bytes, alpha_ki.bytes);  // alpha_ki - c * (z / y)
}
//-------------------------------------------------------------------------------------------------------------------
// Element 'K_t1' for a proof
//   - multiplied by (1/8) for storage (and for use in byte-aware contexts)
// K_t1 = (1/y) * K
// return: (1/8)*K_t1
//-------------------------------------------------------------------------------------------------------------------
void compute_K_t1_for_proof(const crypto::secret_key &y, const rct::key &K, rct::key &K_t1_out)
{
    rct::key inv_y{invert(rct::sk2rct(y))};
    sc_mul(inv_y.bytes, inv_y.bytes, rct::INV_EIGHT.bytes);
    rct::scalarmultKey(K_t1_out, K, inv_y);

    memwipe(inv_y.bytes, 32);  //try to clean up the lingering bytes
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace composition_proof_detail


//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpCompositionProof &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("c", container.c);
    transcript_inout.append("r_t1", container.r_t1);
    transcript_inout.append("r_t2", container.r_t2);
    transcript_inout.append("r_ki", container.r_ki);
    transcript_inout.append("K_t1", container.K_t1);
}
//-------------------------------------------------------------------------------------------------------------------
void make_sp_composition_proof(const rct::key &message,
    const rct::key &K,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z,
    SpCompositionProof &proof_out)
{
    /// input checks and initialization
    CHECK_AND_ASSERT_THROW_MES(!(K == rct::identity()), "make sp composition proof: bad proof key (K identity)!");

    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(x)), "make sp composition proof: bad private key (x zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(x)) == 0, "make sp composition proof: bad private key (x)!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(y)), "make sp composition proof: bad private key (y zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(y)) == 0, "make sp composition proof: bad private key (y)!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(z)), "make sp composition proof: bad private key (z zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(z)) == 0, "make sp composition proof: bad private key (z)!");

    // verify the input key matches the input private keys: K = x G + y X + z U
    rct::key reconstructed_K{
            rct::addKeys(
                    rct::scalarmultKey(rct::pk2rct(crypto::get_X()), rct::sk2rct(y)),
                    rct::scalarmultKey(rct::pk2rct(crypto::get_U()), rct::sk2rct(z))
                )
        };
    mask_key(x, reconstructed_K, reconstructed_K);

    CHECK_AND_ASSERT_THROW_MES(reconstructed_K == K,
        "make sp composition proof: bad proof key (K doesn't match privkeys)!");


    /// make K_t1 and KI

    // K_t1 = (1/8) * (1/y) * K
    composition_proof_detail::compute_K_t1_for_proof(y, K, proof_out.K_t1);

    // KI = (z / y) * U
    const crypto::key_image KI{
            rct::rct2ki(rct::scalarmultKey(
                    rct::scalarmultKey(rct::pk2rct(crypto::get_U()), rct::sk2rct(z)),  //z U
                    invert(rct::sk2rct(y))  //1/y
                ))
        };


    /// signature openers

    // alpha_t1 * K
    crypto::secret_key alpha_t1;
    rct::key alpha_t1_pub;
    generate_proof_nonce(K, alpha_t1, alpha_t1_pub);

    // alpha_t2 * G
    crypto::secret_key alpha_t2;
    rct::key alpha_t2_pub;
    generate_proof_nonce(rct::G, alpha_t2, alpha_t2_pub);

    // alpha_ki * U
    crypto::secret_key alpha_ki;
    rct::key alpha_ki_pub;
    generate_proof_nonce(rct::pk2rct(crypto::get_U()), alpha_ki, alpha_ki_pub);


    /// compute proof challenge
    const rct::key m{composition_proof_detail::compute_challenge_message(message, K, KI, proof_out.K_t1)};
    proof_out.c = composition_proof_detail::compute_challenge(m, alpha_t1_pub, alpha_t2_pub, alpha_ki_pub);


    /// responses
    composition_proof_detail::compute_responses(proof_out.c,
        rct::sk2rct(alpha_t1),
        rct::sk2rct(alpha_t2),
        rct::sk2rct(alpha_ki),
        x,
        y,
        z,
        proof_out.r_t1,
        proof_out.r_t2,
        proof_out.r_ki);
}
//-------------------------------------------------------------------------------------------------------------------
bool verify_sp_composition_proof(const SpCompositionProof &proof,
    const rct::key &message,
    const rct::key &K,
    const crypto::key_image &KI)
{
    /// input checks and initialization
    CHECK_AND_ASSERT_THROW_MES(sc_check(proof.r_t1.bytes) == 0, "verify sp composition proof: bad response (r_t1)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(proof.r_t2.bytes) == 0, "verify sp composition proof: bad response (r_t2)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(proof.r_ki.bytes) == 0, "verify sp composition proof: bad response (r_ki)!");

    CHECK_AND_ASSERT_THROW_MES(!(rct::ki2rct(KI) == rct::identity()), "verify sp composition proof: invalid key image!");


    /// challenge message
    const rct::key m{composition_proof_detail::compute_challenge_message(message, K, KI, proof.K_t1)};


    /// challenge pieces
    static const ge_p3 U_p3{crypto::get_U_p3()};
    static const ge_p3 X_p3{crypto::get_X_p3()};

    rct::key part_t1, part_t2, part_ki;
    ge_p3 K_p3, K_t1_p3, K_t2_p3, KI_p3;

    ge_cached temp_cache;
    ge_p1p1 temp_p1p1;
    ge_p2 temp_p2;
    ge_dsmp temp_dsmp;

    // get K
    CHECK_AND_ASSERT_THROW_MES(ge_frombytes_vartime(&K_p3, K.bytes) == 0, "ge_frombytes_vartime failed!");

    // get K_t1
    rct::scalarmult8(K_t1_p3, proof.K_t1);
    CHECK_AND_ASSERT_THROW_MES(!(ge_p3_is_point_at_infinity_vartime(&K_t1_p3)),
        "verify sp composition proof: invalid proof element K_t1!");

    // get KI
    CHECK_AND_ASSERT_THROW_MES(ge_frombytes_vartime(&KI_p3, rct::ki2rct(KI).bytes) == 0, "ge_frombytes_vartime failed!");

    // K_t2 = K_t1 - X - KI
    ge_p3_to_cached(&temp_cache, &X_p3);
    ge_sub(&temp_p1p1, &K_t1_p3, &temp_cache);  //K_t1 - X
    ge_p1p1_to_p3(&K_t2_p3, &temp_p1p1);
    ge_p3_to_cached(&temp_cache, &KI_p3);
    ge_sub(&temp_p1p1, &K_t2_p3, &temp_cache);  //(K_t1 - X) - KI
    ge_p1p1_to_p3(&K_t2_p3, &temp_p1p1);
    CHECK_AND_ASSERT_THROW_MES(!(ge_p3_is_point_at_infinity_vartime(&K_t2_p3)),
        "verify sp composition proof: invalid proof element K_t2!");

    // K_t1 part: [r_t1 * K + c * K_t1]
    ge_dsm_precomp(temp_dsmp, &K_t1_p3);
    ge_double_scalarmult_precomp_vartime(&temp_p2, proof.r_t1.bytes, &K_p3, proof.c.bytes, temp_dsmp);
    ge_tobytes(part_t1.bytes, &temp_p2);

    // K_t2 part: [r_t2 * G + c * K_t2]
    ge_double_scalarmult_base_vartime(&temp_p2, proof.c.bytes, &K_t2_p3, proof.r_t2.bytes);
    ge_tobytes(part_t2.bytes, &temp_p2);

    // KI part:   [r_ki * U + c * KI  ]
    ge_dsm_precomp(temp_dsmp, &KI_p3);
    ge_double_scalarmult_precomp_vartime(&temp_p2, proof.r_ki.bytes, &U_p3, proof.c.bytes, temp_dsmp);
    ge_tobytes(part_ki.bytes, &temp_p2);


    /// compute nominal challenge
    const rct::key challenge_nom{composition_proof_detail::compute_challenge(m, part_t1, part_t2, part_ki)};


    /// validate proof
    return challenge_nom == proof.c;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
