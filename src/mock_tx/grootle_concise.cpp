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

//paired header
#include "grootle.h"

//local headers
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_config.h"
#include "misc_log_ex.h"
#include "multiexp.h"
#include "rctOps.h"
#include "rctTypes.h"
#include "seraphis_crypto_utils.h"
#include "triptych.h"

//third party headers
#include <boost/thread/lock_guard.hpp>
#include <boost/thread/mutex.hpp>

//standard headers
#include <cmath>


namespace sp
{

/// File-scope data

// generators
static ge_p3 Hi_p3[GROOTLE_MAX_MN];
static ge_p3 H_p3;
static ge_p3 G_p3;
static ge_p3 U_p3;
static key U;

// Useful scalar and group constants
static const rct::key ZERO = rct::zero();
static const rct::key ONE = rct::identity();
static const rct::key IDENTITY = rct::identity();
static const rct::key TWO = { {0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} };
static const rct::key MINUS_ONE = { {0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
    0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10} };

// misc
static std::shared_ptr<rct::pippenger_cached_data> cache;
static boost::mutex init_mutex;


/// Make generators, but only once
static void init_gens()
{
    boost::lock_guard<boost::mutex> lock(init_mutex);

    static bool init_done = false;
    if (init_done) return;

    // get Hi generators
    for (std::size_t i = 0; i < GROOTLE_MAX_MN; i++)
    {
        Hi_p3[i] = get_grootle_Hi_p3_gen(i);
    }

    // pippinger cache of Hi
    cache = get_grootle_Hi_pippinger_cache_init();

    // get H generator
    H_p3 = get_H_p3_gen();

    // get G
    G_p3 = get_G_p3_gen();

    // get U
    U = get_U_gen();
    U_p3 = get_U_p3_gen();

    init_done = true;
}

/// Initialize transcript
static void transcript_init(rct::key &transcript)
{
    std::string salt(config::HASH_KEY_CONCISE_GROOTLE_TRANSCRIPT);
    rct::hash_to_scalar(transcript, salt.data(), salt.size());
}

////
// Prefix for concise structure
// [[[TODO: extend parallel structure to arbitrary numbers of commitments to zero (need separate mu for each after first)]]]
// mu = H(H("domain-sep"), message, [M], [P], C_offset, J, K, A, B, C, D)
///
static rct::key compute_concise_prefix(const rct::key &message,
    const rct::keyV &M,
    const rct::keyV &P,
    const rct::key &C_offset,
    const rct::key &J,
    const rct::key &K,
    const rct::key &A,
    const rct::key &B,
    const rct::key &C,
    const rct::key &D)
{
    CHECK_AND_ASSERT_THROW_MES(M.size() == P.size(), "Transcript challenge inputs have incorrect size!");

    // initialize transcript message
    rct::key challenge;
    transcript_init(challenge);

    // collect challenge string
    std::string hash;
    hash.reserve((2*M.size() + 9)*sizeof(rct::key));
    hash = std::string((const char*) challenge.bytes, sizeof(challenge));
    hash += std::string((const char*) message.bytes, sizeof(message));
    for (std::size_t k = 0; k < M.size(); k++)
    {
        hash += std::string((const char*) M[k].bytes, sizeof(M[k]));
        hash += std::string((const char*) P[k].bytes, sizeof(P[k]));
    }
    hash += std::string((const char*) C_offset.bytes, sizeof(C_offset));
    hash += std::string((const char*) J.bytes, sizeof(J));
    hash += std::string((const char*) K.bytes, sizeof(K));
    hash += std::string((const char*) A.bytes, sizeof(A));
    hash += std::string((const char*) B.bytes, sizeof(B));
    hash += std::string((const char*) C.bytes, sizeof(C));
    hash += std::string((const char*) D.bytes, sizeof(D));
    CHECK_AND_ASSERT_THROW_MES(hash.size() > 1, "Bad hash input size!");

    // challenge
    rct::hash_to_scalar(challenge, hash.data(), hash.size());

    CHECK_AND_ASSERT_THROW_MES(!(challenge == ZERO), "Transcript challenge must be nonzero!");

    return challenge;
}

////
// Fiat-Shamir challenge
// c = H(message, [X], [Y])
//
// note: in practice, this extends the concise structure prefix (i.e. message = mu)
// note2: in Triptych notation, c == xi
///
static rct::key compute_challenge(const rct::key &message, const rct::keyV &X, const rct::keyV &Y)
{
    CHECK_AND_ASSERT_THROW_MES(X.size() == Y.size(), "Challenge inputs have incorrect size!");

    rct::key challenge;
    std::string hash;
    hash.reserve((X.size() + Y.size() + 1)*sizeof(rct::key));
    hash = std::string((const char*) message.bytes, sizeof(message));
    for (std::size_t j = 0; j < X.size(); j++)
    {
        hash += std::string((const char*) X[j].bytes, sizeof(X[j]));
        hash += std::string((const char*) Y[j].bytes, sizeof(Y[j]));
    }
    CHECK_AND_ASSERT_THROW_MES(hash.size() > 1, "Bad hash input size!");
    rct::hash_to_scalar(challenge, hash.data(), hash.size());

    CHECK_AND_ASSERT_THROW_MES(!(challenge == ZERO), "Transcript challenge must be nonzero!");

    return challenge;
}

/// Generate a concise Grootle proof
ConciseGrootleProof concise_grootle_prove(const rct::keyV &M,
    const rct::keyV &P,
    const rct::key &C_offset,
    const std::size_t l,
    const rct::key &r,
    const rct::key &s,
    const std::size_t n,
    const std::size_t m,
    const rct::key &message)
{
    /// input checks and initialization
    CHECK_AND_ASSERT_THROW_MES(n > 1, "Must have n > 1!");
    CHECK_AND_ASSERT_THROW_MES(m > 1, "Must have m > 1!");
    CHECK_AND_ASSERT_THROW_MES(m*n <= GROOTLE_MAX_MN, "Size parameters are too large!");

    const std::size_t N = std::pow(n, m);

    CHECK_AND_ASSERT_THROW_MES(M.size() == N, "Public key vector is wrong size!");
    CHECK_AND_ASSERT_THROW_MES(P.size() == N, "Commitment vector is wrong size!");
    CHECK_AND_ASSERT_THROW_MES(l < M.size(), "Signing index out of bounds!");
    CHECK_AND_ASSERT_THROW_MES(rct::scalarmultBase(r) == M[l], "Bad signing key!");

    // verify: commitment to zero C_zero = P[l] - C_offset = s*G
    rct::key C_zero;
    rct::subKeys(C_zero, P[l], C_offset);
    CHECK_AND_ASSERT_THROW_MES(rct::scalarmultBase(s) == C_zero, "Bad commitment key!");

    // statically initialize Grootle proof generators
    init_gens();


    /// Concise Grootle proof
    ConciseGrootleProof proof;


    // Compute key images [[[TODO: remove]]]
    // J = (1/r)*U
    // K = s*J
    // note: don't store (1/8)*J because domain-check with l*J is done by caller (tx protocol-level check)
    proof.J = rct::scalarmultKey(U, invert(r));
    proof.K = rct::scalarmultKey(proof.J, s);
    proof.K = rct::scalarmultKey(proof.K, INV_EIGHT);   //store (1/8)*K


    /// Decomposition sub-proof commitments: A, B, C, D
    std::vector<rct::MultiexpData> data;
    data.resize(m*n + 1);

    // Matrix masks
    rct::key rA = rct::skGen();
    rct::key rB = rct::skGen();
    rct::key rC = rct::skGen();
    rct::key rD = rct::skGen();

    // A: commit to zero-sum values
    rct::keyM a = rct::keyMInit(n, m);
    CHECK_AND_ASSERT_THROW_MES(a.size() == m, "Bad matrix size!");
    CHECK_AND_ASSERT_THROW_MES(a[0].size() == n, "Bad matrix size!");
    for (std::size_t j = 0; j < m; j++)
    {
        a[j][0] = ZERO;
        for (std::size_t i = 1; i < n; i++)
        {
            a[j][i] = rct::skGen();
            sc_sub(a[j][0].bytes, a[j][0].bytes, a[j][i].bytes);
        }
    }
    com_matrix(data, a, rA);
    CHECK_AND_ASSERT_THROW_MES(data.size() == m*n + 1, "Matrix commitment returned unexpected size!");
    proof.A = rct::straus(data);
    CHECK_AND_ASSERT_THROW_MES(!(proof.A == IDENTITY), "Linear combination unexpectedly returned zero!");

    // B: commit to decomposition bits
    std::vector<std::size_t> decomp_l;
    decomp_l.resize(m);
    decompose(decomp_l, l, n, m);

    rct::keyM sigma = rct::keyMInit(n, m);
    CHECK_AND_ASSERT_THROW_MES(sigma.size() == m, "Bad matrix size!");
    CHECK_AND_ASSERT_THROW_MES(sigma[0].size() == n, "Bad matrix size!");
    for (std::size_t j = 0; j < m; j++)
    {
        for (std::size_t i = 0; i < n; i++)
        {
            sigma[j][i] = delta(decomp_l[j], i);
        }
    }
    com_matrix(data, sigma, rB);
    CHECK_AND_ASSERT_THROW_MES(data.size() == m*n + 1, "Matrix commitment returned unexpected size!");
    proof.B = rct::straus(data);
    CHECK_AND_ASSERT_THROW_MES(!(proof.B == IDENTITY), "Linear combination unexpectedly returned zero!");

    // C: commit to a/sigma relationships
    rct::keyM a_sigma = rct::keyMInit(n, m);
    CHECK_AND_ASSERT_THROW_MES(a_sigma.size() == m, "Bad matrix size!");
    CHECK_AND_ASSERT_THROW_MES(a_sigma[0].size() == n, "Bad matrix size!");
    for (std::size_t j = 0; j < m; j++)
    {
        for (std::size_t i = 0; i < n; i++)
        {
            // a_sigma[j][i] = a[j][i]*(ONE - TWO*sigma[j][i])
            sc_mulsub(a_sigma[j][i].bytes, TWO.bytes, sigma[j][i].bytes, ONE.bytes);
            sc_mul(a_sigma[j][i].bytes, a_sigma[j][i].bytes, a[j][i].bytes);
        }
    }
    com_matrix(data, a_sigma, rC);
    CHECK_AND_ASSERT_THROW_MES(data.size() == m*n + 1, "Matrix commitment returned unexpected size!");
    proof.C = rct::straus(data);
    CHECK_AND_ASSERT_THROW_MES(!(proof.C == IDENTITY), "Linear combination unexpectedly returned zero!");

    // D: commit to squared a-values
    rct::keyM a_sq = rct::keyMInit(n, m);
    for (std::size_t j = 0; j < m; j++)
    {
        for (std::size_t i = 0; i < n; i++)
        {
            sc_mul(a_sq[j][i].bytes, a[j][i].bytes, a[j][i].bytes);
            sc_mul(a_sq[j][i].bytes, MINUS_ONE.bytes, a_sq[j][i].bytes);
        }
    }
    com_matrix(data, a_sq, rD);
    CHECK_AND_ASSERT_THROW_MES(data.size() == m*n + 1, "Matrix commitment returned unexpected size!");
    proof.D = rct::straus(data);
    CHECK_AND_ASSERT_THROW_MES(!(proof.D == IDENTITY), "Linear combination unexpectedly returned zero!");

    // done: store (1/8)*commitment
    proof.A = rct::scalarmultKey(proof.A, INV_EIGHT);
    proof.B = rct::scalarmultKey(proof.B, INV_EIGHT);
    proof.C = rct::scalarmultKey(proof.C, INV_EIGHT);
    proof.D = rct::scalarmultKey(proof.D, INV_EIGHT);


    /// one-of-many sub-proof: polynomial 'p' coefficients
    rct::keyM p = rct::keyMInit(m + 1, N);
    CHECK_AND_ASSERT_THROW_MES(p.size() == N, "Bad matrix size!");
    CHECK_AND_ASSERT_THROW_MES(p[0].size() == m + 1, "Bad matrix size!");
    for (std::size_t k = 0; k < N; k++)
    {
        std::vector<std::size_t> decomp_k;
        decomp_k.resize(m);
        decompose(decomp_k, k, n, m);

        for (std::size_t j = 0; j < m+1; j++)
        {
            p[k][j] = ZERO;
        }
        p[k][0] = a[0][decomp_k[0]];
        p[k][1] = delta(decomp_l[0], decomp_k[0]);

        for (std::size_t j = 1; j < m; j++)
        {
            rct::keyV temp;
            temp.resize(2);
            temp[0] = a[j][decomp_k[j]];
            temp[1] = delta(decomp_l[j], decomp_k[j]);

            p[k] = convolve(p[k], temp, m);
        }
    }


    /// one-of-many sub-proof initial values: [rho], mu, [X], [Y]

    // rho elements: proof entropy
    rct::keyV rho;
    rho.reserve(m);
    for (std::size_t j = 0; j < m; j++)
    {
        rho.push_back(rct::skGen());
    }

    // mu: challenge
    const rct::key mu{
            compute_concise_prefix(message, M, P, C_offset, proof.J, proof.K, proof.A, proof.B, proof.C, proof.D)
        };

    // X, Y: 'encodings' of [p] (i.e. of the real signing index)
    proof.X = rct::keyV(m);
    proof.Y = rct::keyV(m);
    rct::key U_aggregate_prefix;
    rct::key c_zero_nominal_prefix_temp;
    rct::key C_zero_nominal_temp;
    for (std::size_t j = 0; j < m; j++)
    {
        std::vector<rct::MultiexpData> data_X;
        data_X.reserve(2*N);
        
        U_aggregate_prefix = ZERO;

        for (std::size_t k = 0; k < N; k++)
        {
            // X[j] += p[k][j]*(M[k] + mu*(P[k] - C_offset)) ->
            //         p[k][j]*M[k] + p[k][j]*mu*(P[k] - C_offset)
            data_X.push_back({p[k][j], M[k]});

            sc_mul(c_zero_nominal_prefix_temp.bytes, mu.bytes, p[k][j].bytes);
            rct::subKeys(C_zero_nominal_temp, P[k], C_offset);
            data_X.push_back({c_zero_nominal_prefix_temp, C_zero_nominal_temp});

            // Y[j] += p[k][j]*U
            sc_add(U_aggregate_prefix.bytes, U_aggregate_prefix.bytes, p[k][j].bytes);
        }

        // X[j] += rho[j]*G
        // note: addKeys1(X, rho, P) -> X = rho*G + P
        addKeys1(proof.X[j], rho[j], rct::straus(data_X));
        CHECK_AND_ASSERT_THROW_MES(!(proof.X[j] == IDENTITY), "Proof coefficient element should not be zero!");

        // Y[j] += rho[j]*J
        // (and the U_aggregate_prefix collected)
        proof.Y[j] = rct::scalarmultKey(U, U_aggregate_prefix);
        rct::key rho_J = rct::scalarmultKey(proof.J, rho[j]);
        addKeys(proof.Y[j], proof.Y[j], rho_J);
        CHECK_AND_ASSERT_THROW_MES(!(proof.Y[j] == IDENTITY), "Proof coefficient element should not be zero!");
    }

    // done: store (1/8)*P
    for (std::size_t j = 0; j < m; j++)
    {
        proof.X[j] = rct::scalarmultKey(proof.X[j], INV_EIGHT);
        proof.Y[j] = rct::scalarmultKey(proof.Y[j], INV_EIGHT);
    }
    CHECK_AND_ASSERT_THROW_MES(proof.X.size() == m, "Proof coefficient vector is unexpected size!");
    CHECK_AND_ASSERT_THROW_MES(proof.Y.size() == m, "Proof coefficient vector is unexpected size!");


    /// one-of-many sub-proof challenges

    // xi: challenge
    const rct::key xi{compute_challenge(mu, proof.X, proof.Y)};

    // xi^j: challenge powers
    rct::keyV x_pow;
    x_pow.resize(m + 1);
    x_pow[0] = ONE;
    for (std::size_t j = 1; j < m+1; j++)
    {
        sc_mul(x_pow[j].bytes, x_pow[j-1].bytes, xi.bytes);
    }


    /// concise grootle proof final components/responses

    // f-matrix
    proof.f = rct::keyMInit(n-1, m);
    for (std::size_t j = 0; j < m; j++)
    {
        for (std::size_t i = 1; i < n; i++)
        {
            sc_muladd(proof.f[j][i-1].bytes, sigma[j][i].bytes, xi.bytes, a[j][i].bytes);
            CHECK_AND_ASSERT_THROW_MES(!(proof.f[j][i-1] == ZERO), "Proof matrix element should not be zero!");
        }
    }

    // z-terms: responses
    // zA = rB*xi + rA
    sc_muladd(proof.zA.bytes, rB.bytes, xi.bytes, rA.bytes);
    CHECK_AND_ASSERT_THROW_MES(!(proof.zA == ZERO), "Proof scalar element should not be zero!");

    // zC = rC*xi + rD
    sc_muladd(proof.zC.bytes, rC.bytes, xi.bytes, rD.bytes);
    CHECK_AND_ASSERT_THROW_MES(!(proof.zC == ZERO), "Proof scalar element should not be zero!");

    // z = (r + mu*s)*xi**m - rho[0]*xi**0 - ... - rho[m-1]*xi**(m-1)
    sc_muladd(proof.z.bytes, mu.bytes, s.bytes, r.bytes);
    sc_mul(proof.z.bytes, proof.z.bytes, x_pow[m].bytes);

    for (std::size_t j = 0; j < m; j++)
    {
        sc_mulsub(proof.z.bytes, rho[j].bytes, x_pow[j].bytes, proof.z.bytes);
    }
    CHECK_AND_ASSERT_THROW_MES(!(proof.z == ZERO), "Proof scalar element should not be zero!");


    /// cleanup: clear secret prover data
    memwipe(&rA, sizeof(rct::key));
    memwipe(&rB, sizeof(rct::key));
    memwipe(&rC, sizeof(rct::key));
    memwipe(&rD, sizeof(rct::key));
    for (std::size_t j = 0; j < m; j++)
    {
        memwipe(a[j].data(), a[j].size()*sizeof(rct::key));
    }
    memwipe(rho.data(), rho.size()*sizeof(rct::key));

    return proof;
}

/// Verify a batch of concise Grootle proofs with common input keys
bool concise_grootle_verify(const std::vector<const ConciseGrootleProof*> &proofs,
    const rct::keyV &M,
    const rct::keyV &P,
    const rct::keyV &C_offsets,
    const std::size_t n,
    const std::size_t m,
    const rct::keyV &messages)
{
    /// Global checks
    CHECK_AND_ASSERT_THROW_MES(n > 1, "Must have n > 1!");
    CHECK_AND_ASSERT_THROW_MES(m > 1, "Must have m > 1!");
    CHECK_AND_ASSERT_THROW_MES(m*n <= GROOTLE_MAX_MN, "Size parameters are too large!");

    const std::size_t N = std::pow(n, m); // anonymity set size

    CHECK_AND_ASSERT_THROW_MES(M.size() == N, "Public key vector is wrong size!");
    CHECK_AND_ASSERT_THROW_MES(P.size() == N, "Commitment vector is wrong size!");

    const std::size_t N_proofs = proofs.size(); // number of proofs in batch

    CHECK_AND_ASSERT_THROW_MES(C_offsets.size() == N_proofs, "Incorrect number of commitment offsets!");
    CHECK_AND_ASSERT_THROW_MES(messages.size() == N_proofs, "Incorrect number of messages!");


    /// Per-proof checks
    for (const ConciseGrootleProof *p: proofs)
    {
        CHECK_AND_ASSERT_THROW_MES(p, "Proof unexpectedly doesn't exist!");
        const ConciseGrootleProof &proof = *p;

        CHECK_AND_ASSERT_THROW_MES(!(proof.J == IDENTITY), "Proof group element should not be zero!");
        CHECK_AND_ASSERT_THROW_MES(proof.X.size() == m, "Bad proof vector size!");
        CHECK_AND_ASSERT_THROW_MES(proof.Y.size() == m, "Bad proof vector size!");
        CHECK_AND_ASSERT_THROW_MES(proof.f.size() == m, "Bad proof matrix size!");
        for (std::size_t j = 0; j < m; j++)
        {
            CHECK_AND_ASSERT_THROW_MES(proof.f[j].size() == n - 1, "Bad proof matrix size!");
            for (std::size_t i = 0; i < n - 1; i++)
            {
                CHECK_AND_ASSERT_THROW_MES(sc_check(proof.f[j][i].bytes) == 0, "Bad scalar element in proof!");
            }
        }
        CHECK_AND_ASSERT_THROW_MES(sc_check(proof.zA.bytes) == 0, "Bad scalar element in proof!");
        CHECK_AND_ASSERT_THROW_MES(!(proof.zA == ZERO), "Proof scalar element should not be zero!");
        CHECK_AND_ASSERT_THROW_MES(sc_check(proof.zC.bytes) == 0, "Bad scalar element in proof!");
        CHECK_AND_ASSERT_THROW_MES(!(proof.zC == ZERO), "Proof scalar element should not be zero!");
        CHECK_AND_ASSERT_THROW_MES(sc_check(proof.z.bytes) == 0, "Bad scalar element in proof!");
        CHECK_AND_ASSERT_THROW_MES(!(proof.z == ZERO), "Proof scalar element should not be zero!");
    }

    init_gens();
    rct::key temp;

    // 'data': for aggregate multi-exponentiation computation across all proofs
    //
    // per-index storage:
    // 0            m*n-1       Hi[i]
    // m*n                      H
    // m*n+1        m*n+N       M[i]
    // m*n+N+1      m*n+2*N     P[i]
    // m*n+2*N+1                U
    // m*n+2*N+2                G
    // ... then per-proof data
    std::vector<rct::MultiexpData> data;
    data.reserve((m*n + 1) + (2*N + 2) + N_proofs*(2*m + 7));
    data.resize((m*n + 1) + (2*N + 2)); // set up for all common elements

    // Data for {Hi}, H
    for (std::size_t i = 0; i < m*n; i++)
    {
        data[i] = {ZERO, Hi_p3[i]};
    }
    data[m*n] = {ZERO, G_p3};

    // Data for {M}, {P}
    for (std::size_t k = 0; k < N; k++)
    {
        data[m*n+1+k] = {ZERO, M[k]};
        data[m*n+N+1+k] = {ZERO, P[k]};
    }

    // Data for U
    data[m*n+2*N+1] = {ZERO, U_p3};

    // Data for G
    data[m*n+2*N+2] = {ZERO, G_p3};

    // Start per-proof data assembly
    for (std::size_t i_proofs = 0; i_proofs < N_proofs; i_proofs++)
    {
        const ConciseGrootleProof &proof = *proofs[i_proofs];

        // Per-proof random weights
        rct::key w1 = ZERO;
        rct::key w2 = ZERO;
        rct::key w3 = ZERO;
        rct::key w4 = ZERO;
        while (w1 == ZERO || w2 == ZERO || w3 == ZERO || w4 == ZERO)
        {
            w1 = rct::skGen();
            w2 = rct::skGen();
            w3 = rct::skGen();
            w4 = rct::skGen();
        }

        // Transcript challenges
        const rct::key mu{
                compute_concise_prefix(messages[i_proofs],
                    M,
                    P,
                    C_offsets[i_proofs],
                    proof.J,
                    proof.K,
                    proof.A,
                    proof.B,
                    proof.C,
                    proof.D)
            };
        const rct::key x{compute_challenge(mu, proof.X, proof.Y)};

        // Recover proof elements
        ge_p3 K_p3;
        ge_p3 A_p3;
        ge_p3 B_p3;
        ge_p3 C_p3;
        ge_p3 D_p3;
        std::vector<ge_p3> X_p3;
        std::vector<ge_p3> Y_p3;
        X_p3.resize(m);
        Y_p3.resize(m);
        scalarmult8(K_p3, proof.K);
        scalarmult8(A_p3, proof.A);
        scalarmult8(B_p3, proof.B);
        scalarmult8(C_p3, proof.C);
        scalarmult8(D_p3, proof.D);
        for (std::size_t j = 0; j < m; j++)
        {
            scalarmult8(X_p3[j], proof.X[j]);
            scalarmult8(Y_p3[j], proof.Y[j]);
        }

        // Challenge powers (negated)
        rct::keyV minus_x;
        minus_x.resize(m);
        minus_x[0] = MINUS_ONE;
        for (std::size_t j = 1; j < m; j++)
        {
            sc_mul(minus_x[j].bytes, minus_x[j-1].bytes, x.bytes);
        }

        // Reconstruct the f-matrix
        rct::keyM f = rct::keyMInit(n, m);
        for (std::size_t j = 0; j < m; j++)
        {
            f[j][0] = x;
            for (std::size_t i = 1; i < n; i++)
            {
                CHECK_AND_ASSERT_THROW_MES(!(proof.f[j][i-1] == ZERO), "Proof matrix element should not be zero!");
                f[j][i] = proof.f[j][i-1];
                sc_sub(f[j][0].bytes, f[j][0].bytes, f[j][i].bytes);
            }
            CHECK_AND_ASSERT_THROW_MES(!(f[j][0] == ZERO), "Proof matrix element should not be zero!");
        }

        // Matrix generators
        for (std::size_t j = 0; j < m; j++)
        {
            for (std::size_t i = 0; i < n; i++)
            {
                // Hi: w1*f + w2*f*(x-f) = w1*f + w2*f*x - w2*f*f
                rct::key Hi_scalar;
                sc_mul(Hi_scalar.bytes, w1.bytes, f[j][i].bytes);

                sc_mul(temp.bytes, w2.bytes, f[j][i].bytes);
                sc_mul(temp.bytes, temp.bytes, x.bytes);
                sc_add(Hi_scalar.bytes, Hi_scalar.bytes, temp.bytes);

                sc_mul(temp.bytes, MINUS_ONE.bytes, w2.bytes);
                sc_mul(temp.bytes, temp.bytes, f[j][i].bytes);
                sc_mul(temp.bytes, temp.bytes, f[j][i].bytes);
                sc_add(Hi_scalar.bytes, Hi_scalar.bytes, temp.bytes);

                sc_add(data[j*n + i].scalar.bytes, data[j*n + i].scalar.bytes, Hi_scalar.bytes);
            }
        }

        // H: w1*zA + w2*zC
        sc_muladd(data[m*n].scalar.bytes, w1.bytes, proof.zA.bytes, data[m*n].scalar.bytes);
        sc_muladd(data[m*n].scalar.bytes, w2.bytes, proof.zC.bytes, data[m*n].scalar.bytes);

        // A, B, C, D
        // A: -w1
        // B: -w1*x
        // C: -w2*x
        // D: -w2
        sc_mul(temp.bytes, MINUS_ONE.bytes, w1.bytes);
        data.push_back({temp, A_p3});

        sc_mul(temp.bytes, temp.bytes, x.bytes);
        data.push_back({temp, B_p3});

        sc_mul(temp.bytes, MINUS_ONE.bytes, w2.bytes);
        data.push_back({temp, D_p3});

        sc_mul(temp.bytes, temp.bytes, x.bytes);
        data.push_back({temp, C_p3});

        // M, P
        // M[k]: w3*t
        // P[k]: w3*t*mu
        rct::key sum_t = ZERO;
        for (std::size_t k = 0; k < N; k++)
        {
            rct::key t = ONE;
            std::vector<std::size_t> decomp_k;
            decomp_k.resize(m);
            decompose(decomp_k, k, n, m);

            for (std::size_t j = 0; j < m; j++)
            {
                sc_mul(t.bytes, t.bytes, f[j][decomp_k[j]].bytes);
            }

            sc_mul(temp.bytes, w3.bytes, t.bytes);
            sc_add(data[m*n+1+k].scalar.bytes, data[m*n+1+k].scalar.bytes, temp.bytes);

            sc_mul(temp.bytes, temp.bytes, mu.bytes);
            sc_add(data[m*n+N+1+k].scalar.bytes, data[m*n+N+1+k].scalar.bytes, temp.bytes);

            sc_add(sum_t.bytes, sum_t.bytes, t.bytes);
        }

        // C_offsets[i_proofs]: -w3*mu*sum_t
        sc_mul(temp.bytes, MINUS_ONE.bytes, w3.bytes);
        sc_mul(temp.bytes, temp.bytes, mu.bytes);
        sc_mul(temp.bytes, temp.bytes, sum_t.bytes);
        data.push_back({temp, C_offsets[i_proofs]});

        // U: w4*sum_t
        sc_mul(temp.bytes, w4.bytes, sum_t.bytes);
        sc_add(data[m*n+2*N+1].scalar.bytes, data[m*n+2*N+1].scalar.bytes, temp.bytes);

        // K: w4*sum_t*mu
        sc_mul(temp.bytes, temp.bytes, mu.bytes);
        data.push_back({temp, K_p3});

        for (std::size_t j = 0; j < m; j++)
        {
            // X[j]: -w3*x**j
            sc_mul(temp.bytes, w3.bytes, minus_x[j].bytes);
            data.push_back({temp, X_p3[j]});

            // Y[j]: -w4*x**j
            sc_mul(temp.bytes, w4.bytes, minus_x[j].bytes);
            data.push_back({temp, Y_p3[j]});
        }

        // G: -w3*z
        sc_mul(temp.bytes, MINUS_ONE.bytes, proof.z.bytes);
        sc_mul(temp.bytes, temp.bytes, w3.bytes);
        sc_add(data[m*n+2*N+2].scalar.bytes, data[m*n+2*N+2].scalar.bytes, temp.bytes);

        // J: -w4*z
        sc_mul(temp.bytes, MINUS_ONE.bytes, proof.z.bytes);
        sc_mul(temp.bytes, temp.bytes, w4.bytes);
        data.push_back({temp, proof.J});
    }

    // Final check
    CHECK_AND_ASSERT_THROW_MES(data.size() == (m*n + 1) + (2*N + 2) + N_proofs*(2*m + 7),
        "Final proof data is incorrect size!");
    if (!(rct::pippenger(data, cache, m*n, rct::get_pippenger_c(data.size())) == IDENTITY))
    {
        MERROR("Concise Grootle proof: verification failed!");
        return false;
    }

    return true;
}

} //namespace sp
