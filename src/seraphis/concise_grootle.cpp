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
#include "concise_grootle.h"

//local headers
#include "common/varint.h"
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_config.h"
#include "seraphis_config_temp.h"
#include "misc_log_ex.h"
#include "ringct/multiexp.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_crypto_utils.h"

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
static std::once_flag init_gens_once_flag, init_static_once_flag;


//-------------------------------------------------------------------------------------------------------------------
// Make generators, but only once
//-------------------------------------------------------------------------------------------------------------------
static void init_gens()
{
    std::call_once(init_gens_once_flag,
        [&](){

        // Build Hi generators
        // H_i = keccak_to_pt("grootle Hi", i)
        const std::string Hi_A_salt(config::HASH_KEY_GROOTLE_Hi_A);
        for (std::size_t i = 0; i < GROOTLE_MAX_MN; ++i)
        {
            std::string hash = Hi_A_salt + tools::get_varint_data(i);
            hash_to_p3(Hi_A_p3[i], rct::hash2rct(crypto::cn_fast_hash(hash.data(), hash.size())));
        }

        const std::string Hi_B_salt(config::HASH_KEY_GROOTLE_Hi_B);
        for (std::size_t i = 0; i < GROOTLE_MAX_MN; ++i)
        {
            std::string hash = Hi_B_salt + tools::get_varint_data(i);
            hash_to_p3(Hi_B_p3[i], rct::hash2rct(crypto::cn_fast_hash(hash.data(), hash.size())));
        }

        // get G
        G_p3 = get_G_p3_gen();

    });
}
//-------------------------------------------------------------------------------------------------------------------
// Initialize cache for fixed generators: Hi_A, Hi_B, G
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
    data.emplace_back(ZERO, G_p3);

    // alternate Hi_A, Hi_B
    for (std::size_t i = 0; i < GROOTLE_MAX_MN; ++i)
    {
        data.emplace_back(ZERO, Hi_A_p3[i]);
        data.emplace_back(ZERO, Hi_B_p3[i]);
    }
    CHECK_AND_ASSERT_THROW_MES(data.size() == 1 + 2*GROOTLE_MAX_MN, "Bad generator vector size!");

    // initialize multiexponentiation cache
    return rct::pippenger_init_cache(data, 0, 0);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void init_static()
{
    std::call_once(init_static_once_flag,
        [&](){

        init_gens();

        // pippinger cache of stable generators
        generator_cache = get_pippinger_cache_init();

    });
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
static void transcript_init(rct::key &transcript_out)
{
    std::string salt(config::HASH_KEY_CONCISE_GROOTLE_TRANSCRIPT);
    rct::cn_fast_hash(transcript_out, salt.data(), salt.size());
}
//-------------------------------------------------------------------------------------------------------------------
// Base aggregation coefficient for concise structure
// mu = H_n(H("domain-sep"), message, n, m, {{M}}, {C_offsets}, A, B)
//-------------------------------------------------------------------------------------------------------------------
static rct::key compute_base_aggregation_coefficient(const rct::key &message,
    const std::size_t n,
    const std::size_t m,
    const rct::keyM &M,
    const rct::keyV &C_offsets,
    const rct::key &A,
    const rct::key &B)
{
    for (const rct::keyV &tuple : M)
        CHECK_AND_ASSERT_THROW_MES(tuple.size() == C_offsets.size(), "Transcript challenge inputs have incorrect size!");

    // initialize transcript message
    rct::key challenge;
    transcript_init(challenge);

    // collect challenge string
    std::string hash;
    hash.reserve(2*4 + ((M.size() + 1)*C_offsets.size() + 4)*sizeof(rct::key));
    hash = std::string(reinterpret_cast<const char*>(challenge.bytes), sizeof(challenge));
    hash.append(reinterpret_cast<const char*>(message.bytes), sizeof(message));
    {
        unsigned char v_variable[(sizeof(std::size_t) * 8 + 6) / 7];
        unsigned char *v_variable_end = v_variable;

        // n
        tools::write_varint(v_variable_end, n);
        assert(v_variable_end <= v_variable + sizeof(v_variable));
        hash.append(reinterpret_cast<const char*>(v_variable), v_variable_end - v_variable);

        // m
        v_variable_end = v_variable;
        tools::write_varint(v_variable_end, m);
        assert(v_variable_end <= v_variable + sizeof(v_variable));
        hash.append(reinterpret_cast<const char*>(v_variable), v_variable_end - v_variable);
    }
    for (const rct::keyV &tuple : M)
    {
        for (const rct::key &key : tuple)
            hash.append(reinterpret_cast<const char*>(key.bytes), sizeof(key));
    }
    for (const rct::key &offset : C_offsets)
    {
        hash.append(reinterpret_cast<const char*>(offset.bytes), sizeof(offset));
    }
    hash.append(reinterpret_cast<const char*>(A.bytes), sizeof(A));
    hash.append(reinterpret_cast<const char*>(B.bytes), sizeof(B));
    CHECK_AND_ASSERT_THROW_MES(hash.size() > 1, "Bad hash input size!");

    // challenge
    rct::hash_to_scalar(challenge, hash.data(), hash.size());

    CHECK_AND_ASSERT_THROW_MES(!(challenge == ZERO), "Transcript challenge must be nonzero!");

    return challenge;
}
//-------------------------------------------------------------------------------------------------------------------
// Fiat-Shamir challenge
// c = H_n(message, {X})
//
// note: in practice, this extends the concise structure's aggregation coefficient (i.e. message = mu)
// note2: in Triptych notation, c == xi
//-------------------------------------------------------------------------------------------------------------------
static rct::key compute_challenge(const rct::key &message, const rct::keyV &X)
{
    rct::key challenge;
    std::string hash;
    hash.reserve((X.size() + 1)*sizeof(rct::key));
    hash = std::string(reinterpret_cast<const char*>(message.bytes), sizeof(message));
    for (const rct::key &x : X)
    {
        hash.append(reinterpret_cast<const char*>(x.bytes), sizeof(x));
    }
    CHECK_AND_ASSERT_THROW_MES(hash.size() > 1, "Bad hash input size!");
    rct::hash_to_scalar(challenge, hash.data(), hash.size());

    CHECK_AND_ASSERT_THROW_MES(!(challenge == ZERO), "Transcript challenge must be nonzero!");

    return challenge;
}
//-------------------------------------------------------------------------------------------------------------------
ConciseGrootleProof concise_grootle_prove(const rct::keyM &M, // [vec<tuple of commitments>]
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

    for (const rct::keyV &tuple : M)
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
    init_gens();


    /// Concise Grootle proof
    ConciseGrootleProof proof;


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


    /// one-of-many sub-proof initial values: {rho}, mu, {X}

    // {rho}: proof entropy
    rct::keyV rho;
    rho.reserve(m);
    for (std::size_t j = 0; j < m; ++j)
    {
        rho.push_back(rct::skGen());
    }

    // mu: base aggregation coefficient
    const rct::key mu{
            compute_base_aggregation_coefficient(message, n, m, M, C_offsets, proof.A, proof.B)
        };

    // mu^alpha: powers of the aggregation coefficient
    rct::keyV mu_pow = powers_of_scalar(mu, num_keys);

    // {X}: 'encodings' of [p] (i.e. of the real signing index 'l' in the referenced tuple set)
    proof.X = rct::keyV(m);
    rct::key c_zero_nominal_prefix_temp;
    rct::key C_zero_nominal_temp;
    for (std::size_t j = 0; j < m; ++j)
    {
        std::vector<rct::MultiexpData> data_X;
        data_X.reserve(N*num_keys);

        for (std::size_t k = 0; k < N; ++k)
        {
            // X[j] += p[k][j] * sum_{alpha}( mu^alpha * (M[k][alpha] - C_offset[alpha]) )
            for (std::size_t alpha = 0; alpha < num_keys; ++alpha)
            {
                sc_mul(c_zero_nominal_prefix_temp.bytes, mu_pow[alpha].bytes, p[k][j].bytes);  // p[k][j] * mu^alpha
                rct::subKeys(C_zero_nominal_temp, M[k][alpha], C_offsets[alpha]);  // M[k][alpha] - C_offset[alpha]
                data_X.push_back({c_zero_nominal_prefix_temp, C_zero_nominal_temp});
            }
        }

        // X[j] += rho[j]*G
        // note: addKeys1(X, rho, P) -> X = rho*G + P
        rct::addKeys1(proof.X[j], rho[j], rct::straus(data_X));
        CHECK_AND_ASSERT_THROW_MES(!(proof.X[j] == IDENTITY), "Proof coefficient element should not be zero!");
    }

    // done: store (1/8)*X
    for (std::size_t j = 0; j < m; ++j)
    {
        rct::scalarmultKey(proof.X[j], proof.X[j], rct::INV_EIGHT);
    }
    CHECK_AND_ASSERT_THROW_MES(proof.X.size() == m, "Proof coefficient vector is unexpected size!");


    /// one-of-many sub-proof challenges

    // xi: challenge
    const rct::key xi{compute_challenge(mu, proof.X)};

    // xi^j: challenge powers
    rct::keyV xi_pow = powers_of_scalar(xi, m + 1);


    /// concise grootle proof final components/responses

    // f-matrix: encapsulate index 'l'
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

    // z = (sum_{alpha}( mu^{alpha}*privkey[alpha] ))*xi^m -
    //     rho[0]*xi^0 - ... - rho[m - 1]*xi^(m - 1)
    proof.z = ZERO;
    for (std::size_t alpha = 0; alpha < num_keys; ++alpha)
    {
        sc_muladd(proof.z.bytes, mu_pow[alpha].bytes, to_bytes(privkeys[alpha]), proof.z.bytes);  //z += mu^alpha*privkey[alpha]
    }
    sc_mul(proof.z.bytes, proof.z.bytes, xi_pow[m].bytes);  //z *= xi^m

    for (std::size_t j = 0; j < m; ++j)
    {
        sc_mulsub(proof.z.bytes, rho[j].bytes, xi_pow[j].bytes, proof.z.bytes);  //z -= rho[j]*xi^j
    }
    CHECK_AND_ASSERT_THROW_MES(!(proof.z == ZERO), "Proof scalar element should not be zero!");


    /// cleanup: clear secret prover data
    memwipe(&rA, sizeof(rct::key));
    memwipe(&rB, sizeof(rct::key));
    for (std::size_t j = 0; j < m; ++j)
    {
        memwipe(a[j].data(), a[j].size()*sizeof(rct::key));
    }
    memwipe(rho.data(), rho.size()*sizeof(rct::key));

    return proof;
}
//-------------------------------------------------------------------------------------------------------------------
rct::pippenger_prep_data get_concise_grootle_verification_data(const std::vector<const ConciseGrootleProof*> &proofs,
    const std::vector<rct::keyM> &M,
    const rct::keyM &proof_offsets,
    const std::size_t n,
    const std::size_t m,
    const rct::keyV &messages)
{
    /// Global checks
    const std::size_t N_proofs = proofs.size();

    CHECK_AND_ASSERT_THROW_MES(N_proofs > 0, "Must have at least one proof to verify!");

    CHECK_AND_ASSERT_THROW_MES(n > 1, "Must have n > 1!");
    CHECK_AND_ASSERT_THROW_MES(m > 1, "Must have m > 1!");
    CHECK_AND_ASSERT_THROW_MES(m*n <= GROOTLE_MAX_MN, "Size parameters are too large!");

    // anonymity set size
    const std::size_t N = std::pow(n, m);

    CHECK_AND_ASSERT_THROW_MES(M.size() == N_proofs, "Public key vector is wrong size!");
    for (const rct::keyM &proof_M : M)
        CHECK_AND_ASSERT_THROW_MES(proof_M.size() == N, "Public key vector is wrong size!");

    // inputs line up with proofs
    CHECK_AND_ASSERT_THROW_MES(proof_offsets.size() == N_proofs, "Commitment offsets don't match with input proofs!");
    CHECK_AND_ASSERT_THROW_MES(messages.size() == N_proofs, "Incorrect number of messages!");

    // commitment offsets must line up with input sets
    const std::size_t num_keys = proof_offsets[0].size();

    for (const rct::keyV &C_offsets : proof_offsets)
        CHECK_AND_ASSERT_THROW_MES(C_offsets.size() == num_keys, "Incorrect number of commitment offsets!");

    for (const rct::keyM &proof_M : M)
        for (const rct::keyV &tuple : proof_M)
            CHECK_AND_ASSERT_THROW_MES(tuple.size() == num_keys, "Incorrect number of input keys!");


    /// Per-proof checks
    for (const ConciseGrootleProof *p: proofs)
    {
        CHECK_AND_ASSERT_THROW_MES(p, "Proof unexpectedly doesn't exist!");
        const ConciseGrootleProof &proof = *p;

        CHECK_AND_ASSERT_THROW_MES(proof.X.size() == m, "Bad proof vector size (X)!");
        CHECK_AND_ASSERT_THROW_MES(proof.f.size() == m, "Bad proof matrix size (f)!");
        for (std::size_t j = 0; j < m; ++j)
        {
            CHECK_AND_ASSERT_THROW_MES(proof.f[j].size() == n - 1, "Bad proof matrix size (f internal)!");
            for (std::size_t i = 0; i < n - 1; ++i)
            {
                CHECK_AND_ASSERT_THROW_MES(sc_check(proof.f[j][i].bytes) == 0, "Bad scalar element in proof (f internal)!");
            }
        }
        CHECK_AND_ASSERT_THROW_MES(sc_check(proof.zA.bytes) == 0, "Bad scalar element in proof (zA)!");
        CHECK_AND_ASSERT_THROW_MES(!(proof.zA == ZERO), "Proof scalar element should not be zero (zA)!");
        CHECK_AND_ASSERT_THROW_MES(sc_check(proof.z.bytes) == 0, "Bad scalar element in proof (z)!");
        CHECK_AND_ASSERT_THROW_MES(!(proof.z == ZERO), "Proof scalar element should not be zero (z)!");
    }

    // prepare context
    init_static();
    rct::key temp;  //common variable shuttle so only one needs to be allocated


    /// setup 'data': for aggregate multi-exponentiation computation across all proofs

    // per-index storage:
    // 0                                  G                             (zA*G, z*G)
    // 1                  2*m*n           alternate(Hi_A[i], Hi_B[i])   {f, f*(xi - f)}
    //    <per-proof, start at 2*m*n + 1>
    // 0                  num_keys-1      M[0][alpha]                   (f-coefficients)
    // ...
    // (N-1)*num_keys     N*num_keys-1    M[N-1][alpha]
    // ... other proof data: A, B, {C_offsets}, {X}
    std::vector<rct::MultiexpData> data;
    std::size_t max_size{(1 + 2*m*n) + N_proofs*(N*num_keys + 2 + num_keys + m)};
    data.reserve(max_size);
    data.resize(1 + 2*m*n); // start with common/batched elements
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
    std::size_t skipped_offsets{0};

    for (std::size_t proof_i = 0; proof_i < N_proofs; ++proof_i)
    {
        const ConciseGrootleProof &proof = *(proofs[proof_i]);
        const rct::keyM &proof_M = M[proof_i];

        // random weights
        // - to allow verifiying batches of proofs, must weight each proof's components randomly so an adversary doesn't
        //   gain an advantage if >1 of their proofs are being validated in a batch
        rct::key w1{rct::skGen()};  // decomp:        w1*[ A + xi*B == dual_matrix_commit(zA, f, f*(xi - f)) ]
        rct::key w2{rct::skGen()};  // main stuff:    w2*[ ... - zG == 0 ]

        // Transcript challenges
        const rct::key mu{
                compute_base_aggregation_coefficient(messages[proof_i],
                    n,
                    m,
                    proof_M,
                    proof_offsets[proof_i],
                    proof.A,
                    proof.B)
            };
        const rct::key xi{compute_challenge(mu, proof.X)};

        // Aggregation coefficient powers
        rct::keyV mu_pow = powers_of_scalar(mu, num_keys);

        // Challenge powers (negated)
        rct::keyV minus_xi_pow = powers_of_scalar(xi, m, true);

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
        data.emplace_back(temp, A_p3);  // -w1 * A

        sc_mul(temp.bytes, temp.bytes, xi.bytes);
        data.emplace_back(temp, B_p3);  // -w1*xi * B

        // {{M}}
        //   t_k = mul_all_j(f[j][decomp_k[j]])
        //   w2*[ sum_k( t_k * sum_{alpha}(mu^alpha * (M[k][alpha] - C_offsets[alpha])) ) - sum(...) - z G ] == 0
        //
        //   sum_k( w2*t_k*sum_{alpha}(mu^alpha*M[k][alpha]) ) -
        //      w2*sum_k( t_k )*sum_{alpha}(mu^alpha*C_offsets[alpha]) -
        //      w2*[ sum(...) + z G ] == 0
        // M[k][alpha]: w2*t_k*mu^alpha
        rct::key sum_t = ZERO;
        rct::key t_k;
        for (std::size_t k = 0; k < N; ++k)
        {
            t_k = ONE;
            std::vector<std::size_t> decomp_k;
            decomp_k.resize(m);
            decompose(k, n, m, decomp_k);

            for (std::size_t j = 0; j < m; ++j)
            {
                sc_mul(t_k.bytes, t_k.bytes, f[j][decomp_k[j]].bytes);  // mul_all_j(f[j][decomp_k[j]])
            }

            sc_add(sum_t.bytes, sum_t.bytes, t_k.bytes);  // sum_k( t_k )

            // borrow the t_k variable...
            sc_mul(t_k.bytes, w2.bytes, t_k.bytes);  // w2*t_k

            for (std::size_t alpha = 0; alpha < num_keys; ++alpha)
            {
                sc_mul(temp.bytes, t_k.bytes, mu_pow[alpha].bytes);  // w2*t_k*mu^alpha
                data.emplace_back(temp, proof_M[k][alpha]);
            }
        }

        // {C_offsets}
        //   ... - w2*sum_k( t_k )*sum_{alpha}(mu^alpha*C_offsets[alpha]) ...
        // 
        // proof_offsets[proof_i][alpha]: -w2*sum_t*mu^alpha
        sc_mul(temp.bytes, MINUS_ONE.bytes, w2.bytes);
        sc_mul(temp.bytes, temp.bytes, sum_t.bytes);  //-w2*sum_t
        rct::key shuttle;

        for (std::size_t alpha = 0; alpha < num_keys; ++alpha)
        {
            // optimization: skip if offset == identity
            if (proof_offsets[proof_i][alpha] == rct::identity())
            {
                ++skipped_offsets;
                continue;
            }

            sc_mul(shuttle.bytes, temp.bytes, mu_pow[alpha].bytes);  //-w2*sum_t*mu^alpha
            data.emplace_back(shuttle, proof_offsets[proof_i][alpha]);
        }

        // {X}
        //   w2*[ ... - sum_j( xi^j*X[j] ) - z G ] == 0
        for (std::size_t j = 0; j < m; ++j)
        {
            // X[j]: -w2*xi^j
            sc_mul(temp.bytes, w2.bytes, minus_xi_pow[j].bytes);
            data.emplace_back(temp, X_p3[j]);
        }

        // G
        //   w2*[ ... - z G ] == 0
        // G: -w2*z
        sc_mul(temp.bytes, MINUS_ONE.bytes, proof.z.bytes);
        sc_mul(temp.bytes, temp.bytes, w2.bytes);
        sc_add(data[0].scalar.bytes, data[0].scalar.bytes, temp.bytes);
    }


    /// Final check
    CHECK_AND_ASSERT_THROW_MES(data.size() == max_size - skipped_offsets, "Final proof data is incorrect size!");


    /// return multiexp data for caller to deal with
    return rct::pippenger_prep_data{std::move(data), generator_cache, 1 + 2*m*n};
}
//-------------------------------------------------------------------------------------------------------------------
bool concise_grootle_verify(const std::vector<const ConciseGrootleProof*> &proofs,
    const std::vector<rct::keyM> &M,
    const rct::keyM &proof_offsets,
    const std::size_t n,
    const std::size_t m,
    const rct::keyV &messages)
{
    // build and verify multiexp
    if (!multiexp_is_identity(get_concise_grootle_verification_data(proofs, M, proof_offsets, n, m, messages)))
    {
        MERROR("Concise Grootle proof: verification failed!");
        return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
