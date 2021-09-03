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
#include "grootle.h"

//local headers
#include "common/varint.h"
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "crypto/generators.h"
#include "cryptonote_config.h"
#include "misc_log_ex.h"
#include "ringct/multiexp.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_crypto_utils.h"
#include "sp_multiexp.h"
#include "sp_generator_factory.h"
#include "sp_hash_functions.h"
#include "sp_transcript.h"

//third party headers

//standard headers
#include <cmath>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "grootle"

namespace sp
{

// Useful scalar and group constants
static const rct::key ZERO = rct::zero();
static const rct::key ONE = rct::identity();
static const rct::key IDENTITY = rct::identity();
static const rct::key TWO = { {0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} };
static const rct::key MINUS_ONE = { {0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
    0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10} };

//-------------------------------------------------------------------------------------------------------------------
// commit to 2 matrices of equal size
// C = x G + {M_A}->Hi_A + {M_B}->Hi_B
// - mapping strategy: concatenate each 'row', e.g. {{1,2}, {3,4}} -> {1,2,3,4}; there are 'm' rows each of size 'n'
// - the generator vectors 'Hi_A' and 'Hi_B' are selected alternating from the generator factory
//-------------------------------------------------------------------------------------------------------------------
static void grootle_matrix_commitment(const rct::key &x,  //blinding factor
    const rct::keyM &M_priv_A,  //matrix A
    const rct::keyM &M_priv_B,  //matrix B
    std::vector<rct::MultiexpData> &data_out)
{
    const std::size_t m{M_priv_A.size()};
    CHECK_AND_ASSERT_THROW_MES(m > 0, "grootle proof matrix commitment: bad matrix size!");
    CHECK_AND_ASSERT_THROW_MES(m == M_priv_B.size(), "grootle proof matrix commitment: matrix size mismatch (m)!");
    const std::size_t n{M_priv_A[0].size()};
    CHECK_AND_ASSERT_THROW_MES(m*n <= GROOTLE_MAX_MN, "grootle proof matrix commitment: bad matrix commitment parameters!");

    data_out.resize(1 + 2*m*n);
    std::size_t offset;

    // mask: x G
    offset = 0;
    data_out[offset + 0] = {x, crypto::get_G_p3()};

    // map M_A onto Hi_A
    offset += 1;
    for (std::size_t j = 0; j < m; ++j)
    {
        CHECK_AND_ASSERT_THROW_MES(n == M_priv_A[j].size(), "grootle proof matrix commitment: matrix size mismatch (n)!");

        for (std::size_t i = 0; i < n; ++i)
            data_out[offset + j*n + i] = {M_priv_A[j][i], generator_factory::get_generator_at_index_p3(2*(j*n + i))};
    }

    // map M_B onto Hi_B
    offset += m*n;
    for (std::size_t j = 0; j < m; ++j)
    {
        CHECK_AND_ASSERT_THROW_MES(n == M_priv_B[j].size(), "grootle proof matrix commitment: matrix size mismatch (n)!");

        for (std::size_t i = 0; i < n; ++i)
            data_out[offset + j*n + i] = {M_priv_B[j][i], generator_factory::get_generator_at_index_p3(2*(j*n + i) + 1)};
    }
}
//-------------------------------------------------------------------------------------------------------------------
// Fiat-Shamir challenge
// c = H_n(message, n, m, {S}, C_offset, A, B, {X})
//
// note: c == xi
//-------------------------------------------------------------------------------------------------------------------
static rct::key compute_challenge(const rct::key &message,
    const std::size_t n,
    const std::size_t m,
    const rct::keyV &S,
    const rct::key &C_offset,
    const rct::key &A,
    const rct::key &B,
    const rct::keyV &X)
{
    // hash data
    SpFSTranscript transcript{config::HASH_KEY_GROOTLE_CHALLENGE, 2*4 + (S.size() + X.size() + 4)*sizeof(rct::key)};
    transcript.append("message", message);
    transcript.append("n", n);
    transcript.append("m", m);
    transcript.append("S", S);
    transcript.append("C_offset", C_offset);
    transcript.append("A", A);
    transcript.append("B", B);
    transcript.append("X", X);

    // challenge
    rct::key challenge;
    sp_hash_to_scalar(transcript.data(), transcript.size(), challenge.bytes);
    CHECK_AND_ASSERT_THROW_MES(!(challenge == ZERO), "grootle proof challenge: transcript challenge must be nonzero!");

    return challenge;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void build_verification_multiexps_for_proof(const GrootleProof &proof,
    const rct::key &message,
    const rct::keyV &S,
    const rct::key &proof_offset,
    const std::size_t n,
    const std::size_t m,
    const rct::key &weight1,
    const rct::key &weight2,
    SpMultiexpBuilder &builder1_inout,
    SpMultiexpBuilder &builder2_inout)
{
    CHECK_AND_ASSERT_THROW_MES(!(weight1 == rct::zero()), "grootle proof: invalid weigh1!");
    CHECK_AND_ASSERT_THROW_MES(!(weight2 == rct::zero()), "grootle proof: invalid weigh2!");

    // builer 1: A + xi*B == dual_matrix_commit(zA, f, f*(xi - f))
    // per-index storage:
    // 0                                  G                             (zA*G)
    // 1 .. 2*m*n                         alternate(Hi_A[i], Hi_B[i])   {f, f*(xi - f)}
    // ... other proof data: A, B

    // builer 2: sum_k( t_k*(S[k] - C_offset) ) - sum_j( xi^j*X[j] ) - z G == 0
    // per-index storage (builder 2):
    // 0                                  G                             (z*G)
    // 1                                  S[0]   + 1                    (f-coefficients)
    // ...
    // (N-1) + 1                          S[N-1] + 1
    // ... other proof data: C_offset, {X}
    const std::size_t N = std::pow(n, m);
    rct::key temp;

    // Transcript challenge
    const rct::key xi{compute_challenge(message, n, m, S, proof_offset, proof.A, proof.B, proof.X)};

    // Challenge powers (negated)
    const rct::keyV minus_xi_pow{powers_of_scalar(xi, m, true)};

    // Recover proof elements
    ge_p3 A_p3;
    ge_p3 B_p3;
    std::vector<ge_p3> X_p3;
    X_p3.resize(m);

    scalarmult8(A_p3, proof.A);
    scalarmult8(B_p3, proof.B);
    for (std::size_t j = 0; j < m; ++j)
    {
        scalarmult8(X_p3[j], proof.X[j]);
    }

    // Reconstruct the f-matrix
    rct::keyM f = rct::keyMInit(n, m);
    for (std::size_t j = 0; j < m; ++j)
    {
        // f[j][0] = xi - sum(f[j][i]) [from i = [1, n)]
        f[j][0] = xi;

        for (std::size_t i = 1; i < n; ++i)
        {
            // note: indexing between f-matrix and proof.f is off by 1 because
            //       'f[j][0] = xi - sum(f_{j,i})' is only implied by the proof, not recorded in it
            f[j][i] = proof.f[j][i - 1];
            sc_sub(f[j][0].bytes, f[j][0].bytes, f[j][i].bytes);
        }
        CHECK_AND_ASSERT_THROW_MES(!(f[j][0] == ZERO),
            "grootle proof verifying: proof matrix element should not be zero!");
    }

    // Signing index matrix commitments sub-proof
    //   weight1 * [ A + xi*B == dual_matrix_commit(zA, f, f*(xi - f))                                                 ]
    //   weight1 * [          == zA * G + ... f[j][i] * Hi_A[j][i] ... + ... f[j][i] * (xi - f[j][i]) * Hi_B[j][i] ... ]
    // G: weight1 * zA
    sc_mul(temp.bytes, weight1.bytes, proof.zA.bytes);
    builder1_inout.add_G_element(temp);

    // weight1 * [ ... f[j][i] * Hi_A[j][i] ... + ... f[j][i] * (xi - f[j][i]) * Hi_B[j][i] ... ]
    rct::key w1_f_temp;

    for (std::size_t j = 0; j < m; ++j)
    {
        for (std::size_t i = 0; i < n; ++i)
        {
            // weight1 * f[j][i]
            sc_mul(w1_f_temp.bytes, weight1.bytes, f[j][i].bytes);

            // Hi_A: weight1 * f[j][i]
            builder1_inout.add_element_at_generator_index(w1_f_temp, 2*(j*n + i));

            // Hi_B: weight1 * f[j][i]*(xi - f[j][i])
            sc_sub(temp.bytes, xi.bytes, f[j][i].bytes);      //xi - f[j][i]
            sc_mul(temp.bytes, w1_f_temp.bytes, temp.bytes);  //weight1 * f[j][i]*(xi - f[j][i])
            builder1_inout.add_element_at_generator_index(temp, 2*(j*n + i) + 1);
        }
    }

    // A, B
    // equality test:
    //   weight1 * [ dual_matrix_commit(zA, f, f*(xi - f)) - (A + xi*B) == 0 ]
    // A: weight1 * -A
    // B: weight1 * -xi * B
    rct::key w1_MINUS_ONE;
    sc_mul(w1_MINUS_ONE.bytes, weight1.bytes, MINUS_ONE.bytes);
    builder1_inout.add_element(w1_MINUS_ONE, A_p3);  //weight1 * -A

    sc_mul(temp.bytes, w1_MINUS_ONE.bytes, xi.bytes);
    builder1_inout.add_element(temp, B_p3);  //weight1 * -xi * B

    // One-of-many sub-proof
    //   t_k = mul_all_j(f[j][decomp_k[j]])
    //   weight2 * [ sum_k( t_k*(S[k] - C_offset) ) - sum_j( xi^j*X[j] ) - z G == 0  ]
    //
    // {S}
    //   weight2 * [ sum_k( t_k*S[k] ) - sum_k( t_k )*C_offset - [ sum(...) + z G ] == 0 ]
    // S[k]: weight2 * t_k
    std::vector<std::size_t> decomp_k;
    decomp_k.resize(m);
    rct::key w2_sum_t = ZERO;
    rct::key w2_t_k;
    for (std::size_t k = 0; k < N; ++k)
    {
        w2_t_k = weight2;
        decompose(k, n, m, decomp_k);

        for (std::size_t j = 0; j < m; ++j)
        {
            sc_mul(w2_t_k.bytes, w2_t_k.bytes, f[j][decomp_k[j]].bytes);  //weight2 * mul_all_j(f[j][decomp_k[j]])
        }

        sc_add(w2_sum_t.bytes, w2_sum_t.bytes, w2_t_k.bytes);  //weight2 * sum_k( t_k )
        builder2_inout.add_element(w2_t_k, S[k]);  //weight2 * t_k*S[k]
    }

    // C_offset
    //   weight2 * [ ... - sum_k( t_k )*C_offset ... ]
    // 
    // proof_offset: weight2 * -sum_t
    sc_mul(temp.bytes, MINUS_ONE.bytes, w2_sum_t.bytes);  //weight2 * -sum_t
    builder2_inout.add_element(temp, proof_offset);

    // {X}
    //   weight2 * [ ... - sum_j( xi^j*X[j] ) - z G == 0 ]
    for (std::size_t j = 0; j < m; ++j)
    {
        // weight2 * -xi^j
        sc_mul(temp.bytes, weight2.bytes, minus_xi_pow[j].bytes);

        // X[j]: weight2 * -xi^j
        builder2_inout.add_element(temp, X_p3[j]);
    }

    // G
    //   weight2 * [ ... - z G == 0 ]
    // G: weight2 * -z
    sc_mul(temp.bytes, weight2.bytes, MINUS_ONE.bytes);
    sc_mul(temp.bytes, temp.bytes, proof.z.bytes);
    builder2_inout.add_G_element(temp);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
std::size_t grootle_size_bytes(const std::size_t n, const std::size_t m)
{
    return 32 * (m + m*(n-1) + 4);  // X + f + {A, B, zA, z}
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t grootle_size_bytes(const GrootleProof &proof)
{
    const std::size_t n{proof.f.size() ? proof.f[0].size() : 0};
    const std::size_t m{proof.X.size()};

    return grootle_size_bytes(n, m);
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const GrootleProof &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("A", container.A);
    transcript_inout.append("B", container.B);
    transcript_inout.append("f", container.f);
    transcript_inout.append("X", container.X);
    transcript_inout.append("zA", container.zA);
    transcript_inout.append("z", container.z);
}
//-------------------------------------------------------------------------------------------------------------------
void make_grootle_proof(const rct::key &message,  // message to insert in Fiat-Shamir transform hash
    const rct::keyV &S,        // referenced commitments
    const std::size_t l,       // secret index into {S}
    const rct::key &C_offset,  // offset for commitment to zero at index l
    const crypto::secret_key &privkey,  // privkey of commitment to zero 'S[l] - C_offset'
    const std::size_t n,       // decomposition of the reference set size: n^m
    const std::size_t m,
    GrootleProof &proof_out)
{
    /// input checks and initialization
    CHECK_AND_ASSERT_THROW_MES(n > 1, "grootle proof proving: must have n > 1!");
    CHECK_AND_ASSERT_THROW_MES(m > 1, "grootle proof proving: must have m > 1!");
    CHECK_AND_ASSERT_THROW_MES(m*n <= GROOTLE_MAX_MN, "grootle proof proving: size parameters are too large!");

    // ref set size
    const std::size_t N = std::pow(n, m);

    CHECK_AND_ASSERT_THROW_MES(S.size() == N, "grootle proof proving: commitment column is wrong size!");

    // commitment to zero signing key position
    CHECK_AND_ASSERT_THROW_MES(l < N, "grootle proof proving: signing index out of bounds!");

    // verify: commitment to zero C_zero = S[l] - C_offset = privkey*G
    rct::key C_zero_reproduced;
    rct::subKeys(C_zero_reproduced, S[l], C_offset);
    CHECK_AND_ASSERT_THROW_MES(rct::scalarmultBase(rct::sk2rct(privkey)) == C_zero_reproduced,
        "grootle proof proving: bad signing private key!");


    /// Grootle proof
    GrootleProof proof;


    /// Decomposition sub-proof commitments: A, B
    std::vector<rct::MultiexpData> data;

    // Matrix masks
    rct::key rA{rct::skGen()};
    rct::key rB{rct::skGen()};

    // A: commit to zero-sum values: {a, -a^2}
    rct::keyM a = rct::keyMInit(n, m);
    rct::keyM a_sq = a;
    for (std::size_t j = 0; j < m; ++j)
    {
        a[j][0] = ZERO;
        for (std::size_t i = 1; i < n; ++i)
        {
            // a
            a[j][i] = rct::skGen();
            sc_sub(a[j][0].bytes, a[j][0].bytes, a[j][i].bytes);  //a[j][0] = - sum(a[1,..,n])

            // -a^2
            sc_mul(a_sq[j][i].bytes, a[j][i].bytes, a[j][i].bytes);
            sc_mul(a_sq[j][i].bytes, MINUS_ONE.bytes, a_sq[j][i].bytes);
        }

        // -(a[j][0])^2
        sc_mul(a_sq[j][0].bytes, a[j][0].bytes, a[j][0].bytes);
        sc_mul(a_sq[j][0].bytes, MINUS_ONE.bytes, a_sq[j][0].bytes);
    }
    grootle_matrix_commitment(rA, a, a_sq, data);  //A = dual_matrix_commit(r_A, a, -a^2)
    CHECK_AND_ASSERT_THROW_MES(data.size() == 1 + 2*m*n,
        "grootle proof proving: matrix commitment returned unexpected size (A data)!");
    proof.A = rct::straus(data);
    CHECK_AND_ASSERT_THROW_MES(!(proof.A == IDENTITY),
        "grootle proof proving: linear combination unexpectedly returned zero (A)!");

    // B: commit to decomposition bits: {sigma, a*(1-2*sigma)}
    std::vector<std::size_t> decomp_l;
    decomp_l.resize(m);
    decompose(l, n, m, decomp_l);

    rct::keyM sigma = rct::keyMInit(n, m);
    rct::keyM a_sigma = sigma;
    for (std::size_t j = 0; j < m; ++j)
    {
        for (std::size_t i = 0; i < n; ++i)
        {
            // sigma
            sigma[j][i] = kronecker_delta(decomp_l[j], i);

            // a*(1-2*sigma)
            sc_mulsub(a_sigma[j][i].bytes, TWO.bytes, sigma[j][i].bytes, ONE.bytes);  //1-2*sigma
            sc_mul(a_sigma[j][i].bytes, a_sigma[j][i].bytes, a[j][i].bytes);  //a*(1-2*sigma)
        }
    }
    grootle_matrix_commitment(rB, sigma, a_sigma, data);  //B = dual_matrix_commit(r_B, sigma, a*(1-2*sigma))
    CHECK_AND_ASSERT_THROW_MES(data.size() == 1 + 2*m*n,
        "grootle proof proving: matrix commitment returned unexpected size (B data)!");
    proof.B = rct::straus(data);
    CHECK_AND_ASSERT_THROW_MES(!(proof.B == IDENTITY),
        "grootle proof proving: linear combination unexpectedly returned zero (B)!");

    // done: store (1/8)*commitment
    proof.A = rct::scalarmultKey(proof.A, rct::INV_EIGHT);
    proof.B = rct::scalarmultKey(proof.B, rct::INV_EIGHT);


    /// one-of-many sub-proof: polynomial coefficients 'p'
    rct::keyM p = rct::keyMInit(m + 1, N);
    CHECK_AND_ASSERT_THROW_MES(p.size() == N, "grootle proof proving: bad matrix size (p)!");
    CHECK_AND_ASSERT_THROW_MES(p[0].size() == m + 1, "grootle proof proving: bad matrix size (p[])!");
    std::vector<std::size_t> decomp_k;
    rct::keyV pre_convolve_temp;
    decomp_k.resize(m);
    pre_convolve_temp.resize(2);
    for (std::size_t k = 0; k < N; ++k)
    {
        decompose(k, n, m, decomp_k);

        for (std::size_t j = 0; j < m+1; ++j)
        {
            p[k][j] = ZERO;
        }
        p[k][0] = a[0][decomp_k[0]];
        p[k][1] = kronecker_delta(decomp_l[0], decomp_k[0]);

        for (std::size_t j = 1; j < m; ++j)
        {
            pre_convolve_temp[0] = a[j][decomp_k[j]];
            pre_convolve_temp[1] = kronecker_delta(decomp_l[j], decomp_k[j]);

            p[k] = convolve(p[k], pre_convolve_temp, m);
        }
    }


    /// one-of-many sub-proof initial values: {rho}, {X}

    // {rho}: proof entropy
    rct::keyV rho;
    rho.reserve(m);
    for (std::size_t j = 0; j < m; ++j)
    {
        rho.push_back(rct::skGen());
    }

    // {X}: 'encodings' of [p] (i.e. of the real signing index 'l' in the referenced tuple set)
    proof.X = rct::keyV(m);
    rct::key C_zero_nominal_temp;
    for (std::size_t j = 0; j < m; ++j)
    {
        std::vector<rct::MultiexpData> data_X;
        data_X.reserve(N);

        for (std::size_t k = 0; k < N; ++k)
        {
            // X[j] += p[k][j] * (S[k] - C_offset)
            rct::subKeys(C_zero_nominal_temp, S[k], C_offset);  // S[k] - C_offset
            data_X.push_back({p[k][j], C_zero_nominal_temp});
        }

        // X[j] += rho[j]*G
        // note: addKeys1(X, rho, P) -> X = rho*G + P
        rct::addKeys1(proof.X[j], rho[j], rct::straus(data_X));
        CHECK_AND_ASSERT_THROW_MES(!(proof.X[j] == IDENTITY),
            "grootle proof proving: proof coefficient element should not be zero!");
    }

    // done: store (1/8)*X
    for (std::size_t j = 0; j < m; ++j)
    {
        rct::scalarmultKey(proof.X[j], proof.X[j], rct::INV_EIGHT);
    }
    CHECK_AND_ASSERT_THROW_MES(proof.X.size() == m, "grootle proof proving: proof coefficient vector is unexpected size!");


    /// one-of-many sub-proof challenges

    // xi: challenge
    const rct::key xi{compute_challenge(message, n, m, S, C_offset, proof.A, proof.B, proof.X)};

    // xi^j: challenge powers
    const rct::keyV xi_pow{powers_of_scalar(xi, m + 1)};


    /// grootle proof final components/responses

    // f-matrix: encapsulate index 'l'
    proof.f = rct::keyMInit(n - 1, m);
    for (std::size_t j = 0; j < m; ++j)
    {
        for (std::size_t i = 1; i < n; ++i)
        {
            sc_muladd(proof.f[j][i - 1].bytes, sigma[j][i].bytes, xi.bytes, a[j][i].bytes);
            CHECK_AND_ASSERT_THROW_MES(!(proof.f[j][i - 1] == ZERO),
                "grootle proof proving: proof matrix element should not be zero!");
        }
    }

    // z-terms: responses
    // zA = xi*rB + rA
    sc_muladd(proof.zA.bytes, xi.bytes, rB.bytes, rA.bytes);
    CHECK_AND_ASSERT_THROW_MES(!(proof.zA == ZERO), "grootle proof proving: proof scalar element should not be zero (zA)!");

    // z = privkey*xi^m - rho[0]*xi^0 - ... - rho[m - 1]*xi^(m - 1)
    proof.z = ZERO;
    sc_mul(proof.z.bytes, to_bytes(privkey), xi_pow[m].bytes);  //z = privkey*xi^m

    for (std::size_t j = 0; j < m; ++j)
    {
        sc_mulsub(proof.z.bytes, rho[j].bytes, xi_pow[j].bytes, proof.z.bytes);  //z -= rho[j]*xi^j
    }
    CHECK_AND_ASSERT_THROW_MES(!(proof.z == ZERO), "grootle proof proving: proof scalar element should not be zero (z)!");


    /// cleanup: clear secret prover data
    memwipe(&rA, sizeof(rct::key));
    memwipe(&rB, sizeof(rct::key));
    for (std::size_t j = 0; j < m; ++j)
    {
        memwipe(a[j].data(), a[j].size()*sizeof(rct::key));
    }
    memwipe(rho.data(), rho.size()*sizeof(rct::key));


    /// save result
    proof_out = std::move(proof);
}
//-------------------------------------------------------------------------------------------------------------------
void get_grootle_verification_data(const std::vector<const GrootleProof*> &proofs,
    const rct::keyV &messages,
    const std::vector<rct::keyV> &M,
    const rct::keyV &proof_offsets,
    const std::size_t n,
    const std::size_t m,
    std::list<SpMultiexpBuilder> &verification_data_out)
{
    /// Global checks
    const std::size_t num_proofs = proofs.size();

    CHECK_AND_ASSERT_THROW_MES(num_proofs > 0, "grootle proof verifying: must have at least one proof to verify!");

    CHECK_AND_ASSERT_THROW_MES(n > 1, "grootle proof verifying: must have n > 1!");
    CHECK_AND_ASSERT_THROW_MES(m > 1, "grootle proof verifying: must have m > 1!");
    CHECK_AND_ASSERT_THROW_MES(m*n <= GROOTLE_MAX_MN, "grootle proof verifying: size parameters are too large!");

    // reference set size
    const std::size_t N = std::pow(n, m);

    CHECK_AND_ASSERT_THROW_MES(M.size() == num_proofs,
        "grootle proof verifying: public key vectors don't line up with proofs!");
    for (const rct::keyV &proof_S : M)
    {
        CHECK_AND_ASSERT_THROW_MES(proof_S.size() == N,
            "grootle proof verifying: public key vector for a proof is wrong size!");
    }

    // inputs line up with proofs
    CHECK_AND_ASSERT_THROW_MES(messages.size() == num_proofs, "grootle proof verifying: incorrect number of messages!");
    CHECK_AND_ASSERT_THROW_MES(proof_offsets.size() == num_proofs,
        "grootle proof verifying: commitment offsets don't line up with input proofs!");


    /// Per-proof checks
    for (const GrootleProof *p: proofs)
    {
        CHECK_AND_ASSERT_THROW_MES(p, "grootle proof verifying: proof unexpectedly doesn't exist!");
        const GrootleProof &proof = *p;

        CHECK_AND_ASSERT_THROW_MES(proof.X.size() == m, "grootle proof verifying: bad proof vector size (X)!");
        CHECK_AND_ASSERT_THROW_MES(proof.f.size() == m, "grootle proof verifying: bad proof matrix size (f)!");
        for (std::size_t j = 0; j < m; ++j)
        {
            CHECK_AND_ASSERT_THROW_MES(proof.f[j].size() == n - 1,
                "grootle proof verifying: bad proof matrix size (f internal)!");
            for (std::size_t i = 0; i < n - 1; ++i)
            {
                CHECK_AND_ASSERT_THROW_MES(!(proof.f[j][i] == ZERO),
                    "grootle proof verifying: proof matrix element should not be zero (f internal)!");
                CHECK_AND_ASSERT_THROW_MES(sc_check(proof.f[j][i].bytes) == 0,
                    "grootle proof verifying: bad scalar element in proof (f internal)!");
            }
        }
        CHECK_AND_ASSERT_THROW_MES(!(proof.zA == ZERO),
            "grootle proof verifying: proof scalar element should not be zero (zA)!");
        CHECK_AND_ASSERT_THROW_MES(sc_check(proof.zA.bytes) == 0,
            "grootle proof verifying: bad scalar element in proof (zA)!");
        CHECK_AND_ASSERT_THROW_MES(!(proof.z == ZERO),
            "grootle proof verifying: proof scalar element should not be zero (z)!");
        CHECK_AND_ASSERT_THROW_MES(sc_check(proof.z.bytes) == 0,
            "grootle proof verifying: bad scalar element in proof (z)!");
    }


    /// per-proof data assembly
    std::list<SpMultiexpBuilder> builders;

    for (std::size_t proof_i{0}; proof_i < proofs.size(); ++proof_i)
    {
        // prepare two builders for this proof (for the index-encoding proof and the membership proof)
        // note: manually specify the weights for efficiency
        builders.emplace_back(rct::identity(), 2*m*n, 2);
        SpMultiexpBuilder &builder1 = builders.back();
        builders.emplace_back(rct::identity(), 0, N + m + 1);
        SpMultiexpBuilder &builder2 = builders.back();

        build_verification_multiexps_for_proof(*(proofs[proof_i]),
            messages[proof_i],
            M[proof_i],
            proof_offsets[proof_i],
            n,
            m,
            rct::skGen(),
            rct::skGen(),
            builder1,
            builder2);
    }


    /// return multiexp data for caller to deal with
    verification_data_out = builders;
}
//-------------------------------------------------------------------------------------------------------------------
bool verify_grootle_proofs(const std::vector<const GrootleProof*> &proofs,
    const rct::keyV &messages,
    const std::vector<rct::keyV> &M,
    const rct::keyV &proof_offsets,
    const std::size_t n,
    const std::size_t m)
{
    // build multiexp
    std::list<SpMultiexpBuilder> verification_data;
    get_grootle_verification_data(proofs, messages, M, proof_offsets, n, m, verification_data);

    // verify multiexp
    if (!SpMultiexp{verification_data}.evaluates_to_point_at_infinity())
    {
        MERROR("Grootle proof: verification failed!");
        return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
