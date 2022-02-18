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
#include "grootle.h"

//local headers
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_config.h"
#include "misc_log_ex.h"
#include "mock_tx_utils.h"
#include "ringct/multiexp.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_crypto_utils.h"

//third party headers

//standard headers
#include <cmath>
#include <mutex>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "concise_grootle"

namespace sp
{

/// File-scope data

// config (todo: move to config file)
const char HASH_KEY_GROOTLE_Hi_A[] = "grootle Hi A";
const char HASH_KEY_GROOTLE_Hi_B[] = "grootle Hi B";

// generators
static ge_p3 Hi_A_p3[GROOTLE_MAX_MN];
static ge_p3 Hi_B_p3[GROOTLE_MAX_MN];
static ge_p3 G_p3;

// Useful scalar and group constants
static const rct::key ZERO = rct::zero();
static const rct::key ONE = rct::identity();
static const rct::key IDENTITY = rct::identity();
static const rct::key TWO = { {0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} };

// misc
static std::shared_ptr<rct::pippenger_cached_data> generator_cache;
static std::mutex init_mutex;


//-------------------------------------------------------------------------------------------------------------------
// Make generators, but only once
//-------------------------------------------------------------------------------------------------------------------
static void init_gens()
{
    std::lock_guard<std::mutex> lock(init_mutex);

    static bool init_done = false;
    if (init_done) return;

    // Build Hi generators
    // H_i = keccak_to_pt("grootle Hi", i)
    const std::string Hi_A_salt(HASH_KEY_GROOTLE_Hi_A);
    for (std::size_t i = 0; i < GROOTLE_MAX_MN; ++i)
    {
        std::string hash = Hi_A_salt + tools::get_varint_data(i);
        hash_to_p3(Hi_A_p3[i], rct::hash2rct(crypto::cn_fast_hash(hash.data(), hash.size())));
    }

    const std::string Hi_B_salt(HASH_KEY_GROOTLE_Hi_B);
    for (std::size_t i = 0; i < GROOTLE_MAX_MN; ++i)
    {
        std::string hash = Hi_B_salt + tools::get_varint_data(i);
        hash_to_p3(Hi_B_p3[i], rct::hash2rct(crypto::cn_fast_hash(hash.data(), hash.size())));
    }

    // get G
    G_p3 = get_G_p3_gen();

    init_done = true;
}
//-------------------------------------------------------------------------------------------------------------------
// Initialize cache for fixed generators: Hi_A, Hi_B, G
//TODO: A/B optimization
// - The cache pre-converts ge_p3 points to ge_cached, for the first N terms in a pippinger multiexponentiation.
// - When doing the multiexp, you specify how many of those N terms are actually used (i.e. 'cache_size').
// - Here: alternate Hi_A, Hi_B to allow variable m*n (the number of Hi_A gens used always equals number of Hi_B gens used).
// cached: G, Hi_A[0], Hi_B[0], Hi_A[1], Hi_B[1], ..., Hi_A[GROOTLE_MAX_MN], Hi_B[GROOTLE_MAX_MN]
//-------------------------------------------------------------------------------------------------------------------
static std::shared_ptr<rct::pippenger_cached_data> get_pippinger_cache_init()
{
    init_gens();

    std::vector<rct::MultiexpData> data;
    data.reserve(1 + 2*GROOTLE_MAX_MN);

    // G
    data.push_back({ZERO, G_p3});

    // alternate Hi_A, Hi_B
    for (std::size_t i = 0; i < GROOTLE_MAX_MN; ++i)
    {
        data.push_back({ZERO, Hi_A_p3[i]});
        data.push_back({ZERO, Hi_B_p3[i]});
    }
    CHECK_AND_ASSERT_THROW_MES(data.size() == 1 + 2*GROOTLE_MAX_MN, "Bad generator vector size!");

    // initialize multiexponentiation cache
    return rct::pippenger_init_cache(data, 0, 0);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void init_static()
{
    init_gens();

    // pippinger cache of stable generators
    generator_cache = get_pippinger_cache_init();
}
//-------------------------------------------------------------------------------------------------------------------
// commit to 2 matrices of equal size
// C = x G + {M_A}->Hi_A + {M_B}->Hi_B
// - mapping strategy: concatenate each 'row', e.g. {{1,2}, {3,4}} -> {1,2,3,4}; there are 'm' rows each of size 'n'
//-------------------------------------------------------------------------------------------------------------------
static void grootle_matrix_commitment(const rct::key &x,  //blinding factor
    const rct::keyM &M_priv_A,  //matrix A
    const rct::keyM &M_priv_B,  //matrix B
    std::vector<rct::MultiexpData> &data_out)
{
    const std::size_t m = M_priv_A.size();
    CHECK_AND_ASSERT_THROW_MES(m > 0, "Bad matrix size!");
    CHECK_AND_ASSERT_THROW_MES(m == M_priv_B.size(), "Matrix size mismatch!");
    const std::size_t n = M_priv_A[0].size();
    CHECK_AND_ASSERT_THROW_MES(n == M_priv_B[0].size(), "Matrix size mismatch!");
    CHECK_AND_ASSERT_THROW_MES(m*n <= GROOTLE_MAX_MN, "Bad matrix commitment parameters!");

    data_out.resize(1 + 2*m*n);
    std::size_t offset;

    // mask: x G
    offset = 0;
    data_out[offset + 0] = {x, G_p3};

    // map M_A onto Hi_A
    offset += 1;
    for (std::size_t j = 0; j < m; ++j)
    {
        for (std::size_t i = 0; i < n; ++i)
        {
            data_out[offset + j*n + i] = {M_priv_A[j][i], Hi_A_p3[j*n + i]};
        }
    }

    // map M_B onto Hi_B
    offset += m*n;
    for (std::size_t j = 0; j < m; ++j)
    {
        for (std::size_t i = 0; i < n; ++i)
        {
            data_out[offset + j*n + i] = {M_priv_B[j][i], Hi_B_p3[j*n + i]};
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
// Initialize transcript
//-------------------------------------------------------------------------------------------------------------------
static void transcript_init(rct::key &transcript)
{
    std::string salt(config::HASH_KEY_GROOTLE_TRANSCRIPT);
    rct::hash_to_scalar(transcript, salt.data(), salt.size());
}
//-------------------------------------------------------------------------------------------------------------------
// Fiat-Shamir challenge
// c = H(H("domain-sep"), message, {{M}}, {C_offsets}, A, B, {{X}})
//
// note: in Triptych notation, c == xi
//-------------------------------------------------------------------------------------------------------------------
static rct::key compute_challenge(const rct::key &message,
    const rct::keyM &M,
    const rct::keyV &C_offsets,
    const rct::key &A,
    const rct::key &B,
    const rct::keyM &X)
{
    for (const auto &tuple : M)
        CHECK_AND_ASSERT_THROW_MES(tuple.size() == C_offsets.size(), "Transcript challenge inputs have incorrect size!");

    // initialize transcript message
    rct::key challenge;
    transcript_init(challenge);

    // collect challenge string
    std::string hash;

    std::size_t m{0};
    if (X.size())
        m = X[0].size();

    hash.reserve(((M.size() + 1)*C_offsets.size() + m*X.size() + 4)*sizeof(rct::key));
    hash = std::string((const char*) challenge.bytes, sizeof(challenge));
    hash += std::string((const char*) message.bytes, sizeof(message));
    for (const auto &tuple : M)
    {
        for (const auto &key : tuple)
            hash += std::string((const char*) key.bytes, sizeof(key));
    }
    for (const auto &offset : C_offsets)
    {
        hash += std::string((const char*) offset.bytes, sizeof(offset));
    }
    hash += std::string((const char*) A.bytes, sizeof(A));
    hash += std::string((const char*) B.bytes, sizeof(B));
    for (std::size_t alpha = 0; alpha < X.size(); ++alpha)
    {
        for (std::size_t j = 0; j < m; ++j)
        {
            hash += std::string((const char*) X[alpha][j].bytes, sizeof(X[alpha][j]));
        }
    }
    CHECK_AND_ASSERT_THROW_MES(hash.size() > 1, "Bad hash input size!");
    rct::hash_to_scalar(challenge, hash.data(), hash.size());

    CHECK_AND_ASSERT_THROW_MES(!(challenge == ZERO), "Transcript challenge must be nonzero!");

    return challenge;
}
//-------------------------------------------------------------------------------------------------------------------
GrootleProof grootle_prove(const rct::keyM &M, // [vec<tuple of commitments>]
    const std::size_t l,        // secret index into {{M}}
    const rct::keyV &C_offsets,  // offsets for commitment to zero at index l
    const std::vector<crypto::secret_key> &privkeys,  // privkeys of commitments to zero in 'M[l] - C_offsets'
    const std::size_t n,        // decomp input set: n^m
    const std::size_t m,
    const rct::key &message)    // message to insert in Fiat-Shamir transform hash
{
    /// input checks and initialization
    CHECK_AND_ASSERT_THROW_MES(n > 1, "Must have n > 1!");
    CHECK_AND_ASSERT_THROW_MES(m > 1, "Must have m > 1!");
    CHECK_AND_ASSERT_THROW_MES(m*n <= GROOTLE_MAX_MN, "Size parameters are too large!");

    // ref set size
    const std::size_t N = std::pow(n, m);

    CHECK_AND_ASSERT_THROW_MES(M.size() == N, "Ref set vector is wrong size!");

    // number of parallel commitments to zero
    const std::size_t num_keys = C_offsets.size();

    CHECK_AND_ASSERT_THROW_MES(privkeys.size() == num_keys, "Private key vector is wrong size!");

    for (const auto &tuple : M)
        CHECK_AND_ASSERT_THROW_MES(tuple.size() == num_keys, "Commitment tuple is wrong size!");

    // commitment to zero signing keys
    CHECK_AND_ASSERT_THROW_MES(l < M.size(), "Signing index out of bounds!");

    for (std::size_t alpha = 0; alpha < num_keys; ++alpha)
    {
        // verify: commitment to zero C_zero = M - C_offset = k*G
        rct::key C_zero_temp;
        rct::subKeys(C_zero_temp, M[l][alpha], C_offsets[alpha]);
        CHECK_AND_ASSERT_THROW_MES(rct::scalarmultBase(rct::sk2rct(privkeys[alpha])) == C_zero_temp, "Bad commitment key!");
    }

    // statically initialize Grootle proof generators
    init_static();


    /// Grootle proof
    GrootleProof proof;


    /// Decomposition sub-proof commitments: A, B
    std::vector<rct::MultiexpData> data;

    // Matrix masks
    rct::key rA = rct::skGen();
    rct::key rB = rct::skGen();

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
    CHECK_AND_ASSERT_THROW_MES(data.size() == 1 + 2*m*n, "Matrix commitment returned unexpected size!");
    proof.A = rct::straus(data);
    CHECK_AND_ASSERT_THROW_MES(!(proof.A == IDENTITY), "Linear combination unexpectedly returned zero!");

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
    CHECK_AND_ASSERT_THROW_MES(data.size() == 1 + 2*m*n, "Matrix commitment returned unexpected size!");
    proof.B = rct::straus(data);
    CHECK_AND_ASSERT_THROW_MES(!(proof.B == IDENTITY), "Linear combination unexpectedly returned zero!");

    // done: store (1/8)*commitment
    proof.A = rct::scalarmultKey(proof.A, rct::INV_EIGHT);
    proof.B = rct::scalarmultKey(proof.B, rct::INV_EIGHT);


    /// one-of-many sub-proof: polynomial 'p' coefficients
    rct::keyM p = rct::keyMInit(m + 1, N);
    CHECK_AND_ASSERT_THROW_MES(p.size() == N, "Bad matrix size!");
    CHECK_AND_ASSERT_THROW_MES(p[0].size() == m + 1, "Bad matrix size!");
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


    /// one-of-many sub-proof initial values: {{rho}}, {{X}}

    // {{rho}}: proof entropy
    rct::keyM rho;
    rho.resize(num_keys);
    for (std::size_t alpha = 0; alpha < num_keys; ++alpha)
    {
        rho[alpha].reserve(m);

        for (std::size_t j = 0; j < m; ++j)
        {
            rho[alpha].push_back(rct::skGen());
        }
    }

    // {{X}}: 'encodings' of [p] (i.e. of the real signing index 'l' in the referenced tuple set)
    proof.X.resize(num_keys, rct::keyV(m));
    ge_p3 C_zero_nominal_temp_p3;
    for (std::size_t alpha = 0; alpha < num_keys; ++alpha)
    {
        for (std::size_t j = 0; j < m; ++j)
        {
            std::vector<rct::MultiexpData> data_X;
            data_X.reserve(N*num_keys);

            for (std::size_t k = 0; k < N; ++k)
            {
                // X[alpha][j] += p[k][j] * ( M[k][alpha] - C_offset[alpha] )
                sp::sub_keys_p3(M[k][alpha], C_offsets[alpha], C_zero_nominal_temp_p3);
                data_X.push_back({p[k][j], C_zero_nominal_temp_p3});
            }

            // X[alpha][j] += rho[alpha][j]*G
            // note: addKeys1(X, rho, P) -> X = rho*G + P
            addKeys1(proof.X[alpha][j], rho[alpha][j], rct::straus(data_X));
            CHECK_AND_ASSERT_THROW_MES(!(proof.X[alpha][j] == IDENTITY), "Proof coefficient element should not be zero!");
        }
    }

    // done: store (1/8)*X
    for (std::size_t alpha = 0; alpha < num_keys; ++alpha)
    {
        for (std::size_t j = 0; j < m; ++j)
        {
            rct::scalarmultKey(proof.X[alpha][j], proof.X[alpha][j], rct::INV_EIGHT);
        }
        CHECK_AND_ASSERT_THROW_MES(proof.X[alpha].size() == m, "Proof coefficient vector is unexpected size!");
    }
    CHECK_AND_ASSERT_THROW_MES(proof.X.size() == num_keys, "Proof coefficient vector is unexpected size!");


    /// one-of-many sub-proof challenges

    // xi: challenge
    const rct::key xi{compute_challenge(message, M, C_offsets, proof.A, proof.B, proof.X)};

    // xi^j: challenge powers
    rct::keyV xi_pow = powers_of_scalar(xi, m + 1);


    /// grootle proof final components/responses

    // f-matrix
    proof.f = rct::keyMInit(n - 1, m);
    for (std::size_t j = 0; j < m; ++j)
    {
        for (std::size_t i = 1; i < n; ++i)
        {
            sc_muladd(proof.f[j][i - 1].bytes, sigma[j][i].bytes, xi.bytes, a[j][i].bytes);
            CHECK_AND_ASSERT_THROW_MES(!(proof.f[j][i - 1] == ZERO), "Proof matrix element should not be zero!");
        }
    }

    // z-terms: responses
    // zA = rB*xi + rA
    sc_muladd(proof.zA.bytes, rB.bytes, xi.bytes, rA.bytes);
    CHECK_AND_ASSERT_THROW_MES(!(proof.zA == ZERO), "Proof scalar element should not be zero!");

    // z[alpha] = privkeys[alpha]*xi^m -
    //            rho[alpha][0]*xi^0 - ... - rho[alpha][m - 1]*xi^(m - 1)
    proof.z.resize(num_keys);
    for (std::size_t alpha = 0; alpha < num_keys; ++alpha)
    {
        sc_mul(proof.z[alpha].bytes, &(privkeys[alpha]), xi_pow[m].bytes);  //z = privkeys[alpha]*xi^m

        for (std::size_t j = 0; j < m; ++j)
        {
            sc_mulsub(proof.z[alpha].bytes, rho[alpha][j].bytes, xi_pow[j].bytes, proof.z[alpha].bytes);  //z -= rho[alpha][j]*xi^j
        }
        CHECK_AND_ASSERT_THROW_MES(!(proof.z[alpha] == ZERO), "Proof scalar element should not be zero!");
    }


    /// cleanup: clear secret prover data
    memwipe(&rA, sizeof(rct::key));
    memwipe(&rB, sizeof(rct::key));
    for (std::size_t j = 0; j < m; ++j)
    {
        memwipe(a[j].data(), a[j].size()*sizeof(rct::key));
    }
    for (std::size_t alpha = 0; alpha < num_keys; ++alpha)
    {
        memwipe(rho[alpha].data(), rho[alpha].size()*sizeof(rct::key));
    }

    return proof;
}
//-------------------------------------------------------------------------------------------------------------------
bool grootle_verify(const std::vector<const GrootleProof*> &proofs,
    const std::vector<rct::keyM> &M,
    const rct::keyM &proof_offsets,
    const std::size_t n,
    const std::size_t m,
    const rct::keyV &messages,
    const std::size_t small_weighting_size)
{
    /// Global checks
    const std::size_t N_proofs = proofs.size();

    CHECK_AND_ASSERT_THROW_MES(N_proofs > 0, "Must have at least one proof to verify!");

    CHECK_AND_ASSERT_THROW_MES(n > 1, "Must have n > 1!");
    CHECK_AND_ASSERT_THROW_MES(m > 1, "Must have m > 1!");
    CHECK_AND_ASSERT_THROW_MES(m*n <= GROOTLE_MAX_MN, "Size parameters are too large!");

    CHECK_AND_ASSERT_THROW_MES(small_weighting_size >= 1, "Small weight variable size too small!");

    // anonymity set size
    const std::size_t N = std::pow(n, m);

    CHECK_AND_ASSERT_THROW_MES(M.size() == N_proofs, "Public key vector is wrong size!");
    for (const rct::keyM &proof_M : M)
        CHECK_AND_ASSERT_THROW_MES(proof_M.size() == N, "Public key vector is wrong size!");

    // inputs line up with proofs
    CHECK_AND_ASSERT_THROW_MES(proof_offsets.size() == N_proofs, "Commitment offsets don't match with input proofs!");
    CHECK_AND_ASSERT_THROW_MES(messages.size() == N_proofs, "Incorrect number of messages!");

    // commitment offsets must line up with input set
    const std::size_t num_keys = proof_offsets[0].size();
    CHECK_AND_ASSERT_THROW_MES(num_keys > 0, "Unsufficient signing keys in proof!");

    for (const auto &C_offsets : proof_offsets)
        CHECK_AND_ASSERT_THROW_MES(C_offsets.size() == num_keys, "Incorrect number of commitment offsets!");

    for (const rct::keyM &proof_M : M)
        for (const rct::keyV &tuple : proof_M)
            CHECK_AND_ASSERT_THROW_MES(tuple.size() == num_keys, "Incorrect number of input keys!");


    /// Per-proof checks
    for (const GrootleProof *p: proofs)
    {
        CHECK_AND_ASSERT_THROW_MES(p, "Proof unexpectedly doesn't exist!");
        const GrootleProof &proof = *p;

        CHECK_AND_ASSERT_THROW_MES(proof.X.size() == num_keys, "Bad proof vector size (X)!");
        for (std::size_t alpha = 0; alpha < num_keys; ++alpha)
        {
            CHECK_AND_ASSERT_THROW_MES(proof.X[alpha].size() == m, "Bad proof vector size (X internal)!");
        }
        CHECK_AND_ASSERT_THROW_MES(proof.f.size() == m, "Bad proof matrix size (f)!");
        for (std::size_t j = 0; j < m; ++j)
        {
            CHECK_AND_ASSERT_THROW_MES(proof.f[j].size() == n - 1, "Bad proof matrix size (f internal)!");
            for (std::size_t i = 0; i < n - 1; ++i)
            {
                CHECK_AND_ASSERT_THROW_MES(sc_check(proof.f[j][i].bytes) == 0, "Bad scalar element in proof (f internal 2)!");
            }
        }
        CHECK_AND_ASSERT_THROW_MES(sc_check(proof.zA.bytes) == 0, "Bad scalar element in proof (zA)!");
        CHECK_AND_ASSERT_THROW_MES(!(proof.zA == ZERO), "Proof scalar element should not be zero (zA)!");

        CHECK_AND_ASSERT_THROW_MES(proof.z.size() == num_keys, "Bad proof vector size (z)!");
        for (std::size_t alpha = 0; alpha < num_keys; ++alpha)
        {
            CHECK_AND_ASSERT_THROW_MES(sc_check(proof.z[alpha].bytes) == 0, "Bad scalar element in proof (z)!");
            CHECK_AND_ASSERT_THROW_MES(!(proof.z[alpha] == ZERO), "Proof scalar element should not be zero (z)!");
        }
    }

    init_static();
    rct::key temp;  //common variable shuttle so only one needs to be allocated


    /// setup 'data': for aggregate multi-exponentiation computation across all proofs

    // per-index storage:
    // 0                                  G                             (zA*G, z*G)
    // 1                  2*m*n           alternate(Hi_A[i], Hi_B[i])   {f, f*(xi - f)}
    //    <per-proof, start at 2*m*n + 1>
    // 0                  N-1             {M_agg}                       (f-coefficients)
    // ... then per-proof data (A, B, {C_offsets_agg}, {{X}})
    std::vector<rct::MultiexpData> data;
    std::size_t max_size{(1 + 2*m*n) + N_proofs*(N + 3 + num_keys*m)};
    data.reserve(max_size);
    data.resize(1 + 2*m*n); // set up for all common elements
    std::size_t offset{0};

    // prep terms: G, {Hi_A, Hi_B}
    data[0] = {ZERO, G_p3};
    offset = 1;
    for (std::size_t i = 0; i < m*n; ++i)
    {
        data[offset + 2*i    ] = {ZERO, Hi_A_p3[i]};
        data[offset + 2*i + 1] = {ZERO, Hi_B_p3[i]};
    }


    /// per-proof data assembly
    std::size_t skipped_offset_sets{0};

    for (std::size_t i_proofs = 0; i_proofs < N_proofs; ++i_proofs)
    {
        const GrootleProof &proof = *(proofs[i_proofs]);

        // small weight scalars: {sw}
        // - set first to one since all other indices will be separated from it by their own weights
        rct::keyV sw;
        sw.resize(num_keys);
        sw[0] = ONE;

        for (std::size_t alpha = 1; alpha < num_keys; ++alpha)
            sw[alpha] = small_scalar_gen(small_weighting_size);

        // random weights
        // - to allow verifiying batches of proofs, must weight each proof's components randomly so an adversary doesn't
        //   gain an advantage if >1 of their proofs are being validated in a batch
        rct::key w1 = ZERO;  // decomp:          w1*[ A + xi*B == dual_matrix_commit(zA, f, f*(xi - f)) ]
        rct::key w2 = ZERO;  // main stuff:      w2*[ sum_alpha( sw[alpha]*( ... - z[alpha]G == 0 ) ) ]
        rct::keyV w2_sw;
        w2_sw.resize(num_keys);
        while (w1 == ZERO || w2 == ZERO)
        {
            w1 = small_scalar_gen(32);
            w2 = small_scalar_gen(32);

            for (std::size_t alpha = 0; alpha < num_keys; ++alpha)
            {
                // w2_sw[alpha] = w2 * sw[alpha]
                sc_mul(w2_sw[alpha].bytes, w2.bytes, sw[alpha].bytes);
                if (w2_sw[alpha] == ZERO)
                {
                    // try again
                    w2 = ZERO;
                    break;
                }
            }
        }

        // Transcript challenge
        const rct::key xi{
                compute_challenge(messages[i_proofs],
                    M[i_proofs],
                    proof_offsets[i_proofs],
                    proof.A,
                    proof.B,
                    proof.X)
            };

        // Challenge powers (negated)
        rct::keyV minus_xi_pow = powers_of_scalar(xi, m, true);

        // Recover proof elements
        ge_p3 A_p3;
        ge_p3 B_p3;
        std::vector<std::vector<ge_p3>> X_p3;
        X_p3.resize(num_keys, std::vector<ge_p3>(m));

        scalarmult8(A_p3, proof.A);
        scalarmult8(B_p3, proof.B);
        for (std::size_t alpha = 0; alpha < num_keys; ++alpha)
        {
            for (std::size_t j = 0; j < m; ++j)
            {
                scalarmult8(X_p3[alpha][j], proof.X[alpha][j]);
            }
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
                CHECK_AND_ASSERT_THROW_MES(!(proof.f[j][i - 1] == ZERO), "Proof matrix element should not be zero!");
                f[j][i] = proof.f[j][i - 1];
                sc_sub(f[j][0].bytes, f[j][0].bytes, f[j][i].bytes);
            }
            CHECK_AND_ASSERT_THROW_MES(!(f[j][0] == ZERO), "Proof matrix element should not be zero!");
        }

        // Matrix commitment
        //   w1* [ A + xi*B == zA * G + ... f[j][i] * Hi_A[j][i] ... + ... f[j][i] * (xi - f[j][i]) * Hi_B[j][i] ... ]
        //       [          == dual_matrix_commit(zA, f, f*(xi - f))                                                 ]
        // G: w1*zA
        sc_muladd(data[0].scalar.bytes, w1.bytes, proof.zA.bytes, data[0].scalar.bytes);  // w1*zA
        offset = 1;

        rct::key Hi_temp;
        for (std::size_t j = 0; j < m; ++j)
        {
            for (std::size_t i = 0; i < n; ++i)
            {
                // Hi_A: w1*f[j][i]
                sc_mul(Hi_temp.bytes, w1.bytes, f[j][i].bytes);  // w1*f[j][i]
                sc_add(data[offset + 2*(j*n + i)].scalar.bytes, data[offset + 2*(j*n + i)].scalar.bytes, Hi_temp.bytes);

                // Hi_B: w1*f[j][i]*(xi - f[j][i]) -> w1*xi*f[j][i] - w1*f[j][i]*f[j][i]
                sc_mul(temp.bytes, xi.bytes, Hi_temp.bytes);  //w1*xi*f[j][i]
                sc_mul(Hi_temp.bytes, f[j][i].bytes, Hi_temp.bytes);  //w1*f[j][i]*f[j][i]
                sc_sub(temp.bytes, temp.bytes, Hi_temp.bytes);  //[] - []
                sc_add(data[offset + 2*(j*n + i) + 1].scalar.bytes, data[offset + 2*(j*n + i) + 1].scalar.bytes, temp.bytes);
            }
        }

        // A, B
        // equality test:
        //   w1*[ dual_matrix_commit(zA, f, f*(xi - f)) - (A + xi*B) ] == 0
        // A: -w1    * A
        // B: -w1*xi * B
        sc_mul(temp.bytes, MINUS_ONE.bytes, w1.bytes);
        data.push_back({temp, A_p3});  // -w1 * A

        sc_mul(temp.bytes, temp.bytes, xi.bytes);
        data.push_back({temp, B_p3});  // -w1*xi * B

        // {M_agg}
        //   t_k = mul_all_j(f[j][decomp_k[j]])
        //   w2*[ sum_k( t_k * sum_{alpha}(M_agg[k] - sw[alpha]*C_offsets[alpha])) ) -  ]
        //      [ sum_{alpha}( sw[alpha]*sum(...) ) -                                   ]
        //      [ sum_{alpha}( sw[alpha]*z[alpha] G )                                   ] == 0
        //
        //   sum_k( w2*t_k*M_agg[k] ) -
        //      w2*sum_k( t_k )*sum_{alpha}(sw[alpha]*C_offsets[alpha]) -
        //      w2*[ ... ] == 0
        // M_agg[k]: w2*t_k
        ge_p3 Key_agg_temp;
        //std::vector<rct::MultiexpData> Magg_data;  //aggregate with strauss
        //Magg_data.resize(num_keys);
        rct::key sum_t = ZERO;
        rct::key t_k;
        for (std::size_t k = 0; k < N; ++k)
        {
            // aggregate the keys at this layer
            for (std::size_t alpha = 0; alpha < num_keys; ++alpha)
            {
                //Magg_data[alpha] = {sw[alpha], M[i_proof][k][alpha]};
            }
            multi_exp_vartime_p3(sw, M[i_proofs][k], Key_agg_temp);  //aggregate with custom multiexp function

            // compute the coefficient
            t_k = ONE;
            std::vector<std::size_t> decomp_k;
            decomp_k.resize(m);
            decompose(k, n, m, decomp_k);

            for (std::size_t j = 0; j < m; ++j)
            {
                sc_mul(t_k.bytes, t_k.bytes, f[j][decomp_k[j]].bytes);  // mul_all_j(f[j][decomp_k[j]])
            }

            sc_mul(temp.bytes, w2.bytes, t_k.bytes);  // w2*t_k
            sc_add(sum_t.bytes, sum_t.bytes, t_k.bytes);  // sum_k( t_k )

            // add the element
            //data.push_back({temp, rct::straus_p3(Magg_data)});
            data.push_back({temp, Key_agg_temp});  //w2*t_k*M_agg[k]
        }

        // {C_offsets}
        //   ... - w2*sum_k( t_k )*sum_{alpha}(sw[alpha]*C_offsets[alpha]) ...
        // 
        // proof_offsets[i_proofs]_agg = sum_{alpha}(sw[alpha]*C_offsets[alpha])
        // proof_offsets[i_proofs]_agg: -sum_t*w2
        std::size_t skippable_offsets{0};
        for (std::size_t alpha = 0; alpha < num_keys; ++alpha)
        {
            // optimization: skip if offset == identity
            if (proof_offsets[i_proofs][alpha] == rct::identity())
                ++skippable_offsets;
        }

        if (skippable_offsets < num_keys)
        {
            rct::keyV temp_sw, temp_offsets;
            temp_sw.reserve(sw.size() - skippable_offsets);
            temp_offsets.reserve(sw.size() - skippable_offsets);

            for (std::size_t alpha = 0; alpha < num_keys; ++alpha)
            {
                // optimization: skip if offset == identity
                if (proof_offsets[i_proofs][alpha] == rct::identity())
                    continue;

                temp_sw.push_back(sw[alpha]);
                temp_offsets.push_back(proof_offsets[i_proofs][alpha]);
            }

            sc_mul(temp.bytes, MINUS_ONE.bytes, sum_t.bytes);  //-sum_t
            sc_mul(temp.bytes, temp.bytes, w2.bytes);  //-sum_t*w2

            // optimization: only call multi_exp if there are multiple offsets to combine
            if (temp_sw.size() == 1)
            {
                sc_mul(temp.bytes, temp.bytes, temp_sw[0].bytes);  //-sum_t*w2*sw[whatever it is]
                data.push_back({temp, temp_offsets[0]});
            }
            else
            {
                multi_exp_vartime_p3(temp_sw, temp_offsets, Key_agg_temp);
                data.push_back({temp, Key_agg_temp});
            }
        }
        else if (skippable_offsets > 0)
            ++skipped_offset_sets;

        // {{X}}
        //   w2*[ ... - sum_{alpha}( sw[alpha]*( sum_j( xi^j*X[alpha][j] ) - z[alpha] G ) ) ] == 0
        for (std::size_t alpha = 0; alpha < num_keys; ++alpha)
        {
            for (std::size_t j = 0; j < m; ++j)
            {
                // X[alpha][j]: -w2_sw[alpha]*xi^j
                sc_mul(temp.bytes, w2_sw[alpha].bytes, minus_xi_pow[j].bytes);
                data.push_back({temp, X_p3[alpha][j]});
            }
        }

        // G
        //   w2*[ ... - sum_{alpha}( sw[alpha]*z[alpha] G ) ] == 0
        // G: -w2_sw[alpha]*z[alpha]
        for (std::size_t alpha = 0; alpha < num_keys; ++alpha)
        {
            sc_mul(temp.bytes, MINUS_ONE.bytes, proof.z[alpha].bytes);
            sc_mul(temp.bytes, temp.bytes, w2_sw[alpha].bytes);
            sc_add(data[0].scalar.bytes, data[0].scalar.bytes, temp.bytes);
        }
    }


    /// Final check
    CHECK_AND_ASSERT_THROW_MES(data.size() == max_size - skipped_offset_sets, "Final proof data is incorrect size!");


    /// Verify all elements sum to zero
    ge_p3 result = rct::pippenger_p3(data, generator_cache, 1 + 2*m*n, rct::get_pippenger_c(data.size()));
    if (ge_p3_is_point_at_infinity_vartime(&result) == 0)
    {
        MERROR("Grootle proof: verification failed!");
        return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
