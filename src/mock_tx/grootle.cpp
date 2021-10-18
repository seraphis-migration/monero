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
#include <boost/thread/lock_guard.hpp>
#include <boost/thread/mutex.hpp>

//standard headers
#include <cmath>
#include <vector>


namespace sp
{

/// File-scope data

// generators
static ge_p3 Hi_p3[GROOTLE_MAX_MN];
static ge_p3 G_p3;

// Useful scalar and group constants
static const rct::key ZERO = rct::zero();
static const rct::key ONE = rct::identity();
static const rct::key IDENTITY = rct::identity();
static const rct::key TWO = { {0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} };

// misc
static std::shared_ptr<rct::pippenger_cached_data> cache;
static boost::mutex init_mutex;


//-------------------------------------------------------------------------------------------------------------------
// Make generators, but only once
//-------------------------------------------------------------------------------------------------------------------
static void init_gens()
{
    boost::lock_guard<boost::mutex> lock(init_mutex);

    static bool init_done = false;
    if (init_done) return;

    // get Hi generators
    for (std::size_t i = 0; i < GROOTLE_MAX_MN; ++i)
    {
        Hi_p3[i] = get_grootle_Hi_p3_gen(i);
    }

    // pippinger cache of Hi
    cache = get_grootle_Hi_pippinger_cache_init();

    // get G
    G_p3 = get_G_p3_gen();

    init_done = true;
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
// c = H(H("domain-sep"), message, {{M}}, {C_offsets}, A, B, C, D, {{X}})
//
// note: in Triptych notation, c == xi
//-------------------------------------------------------------------------------------------------------------------
static rct::key compute_challenge(const rct::key &message,
    const rct::keyM &M,
    const rct::keyV &C_offsets,
    const rct::key &A,
    const rct::key &B,
    const rct::key &C,
    const rct::key &D,
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

    hash.reserve(((M.size() + 1)*C_offsets.size() + m*X.size() + 6)*sizeof(rct::key));
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
    hash += std::string((const char*) C.bytes, sizeof(C));
    hash += std::string((const char*) D.bytes, sizeof(D));
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
    init_gens();


    /// Grootle proof
    GrootleProof proof;


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
    for (std::size_t j = 0; j < m; ++j)
    {
        a[j][0] = ZERO;
        for (std::size_t i = 1; i < n; ++i)
        {
            a[j][i] = rct::skGen();
            sc_sub(a[j][0].bytes, a[j][0].bytes, a[j][i].bytes);
        }
    }
    com_matrix(a, rA, data);
    CHECK_AND_ASSERT_THROW_MES(data.size() == m*n + 1, "Matrix commitment returned unexpected size!");
    proof.A = rct::straus(data);
    CHECK_AND_ASSERT_THROW_MES(!(proof.A == IDENTITY), "Linear combination unexpectedly returned zero!");

    // B: commit to decomposition bits
    std::vector<std::size_t> decomp_l;
    decomp_l.resize(m);
    decompose(l, n, m, decomp_l);

    rct::keyM sigma = rct::keyMInit(n, m);
    CHECK_AND_ASSERT_THROW_MES(sigma.size() == m, "Bad matrix size!");
    CHECK_AND_ASSERT_THROW_MES(sigma[0].size() == n, "Bad matrix size!");
    for (std::size_t j = 0; j < m; ++j)
    {
        for (std::size_t i = 0; i < n; ++i)
        {
            sigma[j][i] = kronecker_delta(decomp_l[j], i);
        }
    }
    com_matrix(sigma, rB, data);
    CHECK_AND_ASSERT_THROW_MES(data.size() == m*n + 1, "Matrix commitment returned unexpected size!");
    proof.B = rct::straus(data);
    CHECK_AND_ASSERT_THROW_MES(!(proof.B == IDENTITY), "Linear combination unexpectedly returned zero!");

    // C: commit to a/sigma relationships
    rct::keyM a_sigma = rct::keyMInit(n, m);
    CHECK_AND_ASSERT_THROW_MES(a_sigma.size() == m, "Bad matrix size!");
    CHECK_AND_ASSERT_THROW_MES(a_sigma[0].size() == n, "Bad matrix size!");
    for (std::size_t j = 0; j < m; ++j)
    {
        for (std::size_t i = 0; i < n; ++i)
        {
            // a_sigma[j][i] = a[j][i]*(ONE - TWO*sigma[j][i])
            sc_mulsub(a_sigma[j][i].bytes, TWO.bytes, sigma[j][i].bytes, ONE.bytes);
            sc_mul(a_sigma[j][i].bytes, a_sigma[j][i].bytes, a[j][i].bytes);
        }
    }
    com_matrix(a_sigma, rC, data);
    CHECK_AND_ASSERT_THROW_MES(data.size() == m*n + 1, "Matrix commitment returned unexpected size!");
    proof.C = rct::straus(data);
    CHECK_AND_ASSERT_THROW_MES(!(proof.C == IDENTITY), "Linear combination unexpectedly returned zero!");

    // D: commit to squared a-values
    rct::keyM a_sq = rct::keyMInit(n, m);
    for (std::size_t j = 0; j < m; ++j)
    {
        for (std::size_t i = 0; i < n; ++i)
        {
            sc_mul(a_sq[j][i].bytes, a[j][i].bytes, a[j][i].bytes);
            sc_mul(a_sq[j][i].bytes, MINUS_ONE.bytes, a_sq[j][i].bytes);
        }
    }
    com_matrix(a_sq, rD, data);
    CHECK_AND_ASSERT_THROW_MES(data.size() == m*n + 1, "Matrix commitment returned unexpected size!");
    proof.D = rct::straus(data);
    CHECK_AND_ASSERT_THROW_MES(!(proof.D == IDENTITY), "Linear combination unexpectedly returned zero!");

    // done: store (1/8)*commitment
    proof.A = rct::scalarmultKey(proof.A, rct::INV_EIGHT);
    proof.B = rct::scalarmultKey(proof.B, rct::INV_EIGHT);
    proof.C = rct::scalarmultKey(proof.C, rct::INV_EIGHT);
    proof.D = rct::scalarmultKey(proof.D, rct::INV_EIGHT);


    /// one-of-many sub-proof: polynomial 'p' coefficients
    rct::keyM p = rct::keyMInit(m + 1, N);
    CHECK_AND_ASSERT_THROW_MES(p.size() == N, "Bad matrix size!");
    CHECK_AND_ASSERT_THROW_MES(p[0].size() == m + 1, "Bad matrix size!");
    for (std::size_t k = 0; k < N; ++k)
    {
        std::vector<std::size_t> decomp_k;
        decomp_k.resize(m);
        decompose(k, n, m, decomp_k);

        for (std::size_t j = 0; j < m+1; ++j)
        {
            p[k][j] = ZERO;
        }
        p[k][0] = a[0][decomp_k[0]];
        p[k][1] = kronecker_delta(decomp_l[0], decomp_k[0]);

        for (std::size_t j = 1; j < m; ++j)
        {
            rct::keyV temp;
            temp.resize(2);
            temp[0] = a[j][decomp_k[j]];
            temp[1] = kronecker_delta(decomp_l[j], decomp_k[j]);

            p[k] = convolve(p[k], temp, m);
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
    rct::key C_zero_nominal_temp;
    for (std::size_t alpha = 0; alpha < num_keys; ++alpha)
    {
        for (std::size_t j = 0; j < m; ++j)
        {
            std::vector<rct::MultiexpData> data_X;
            data_X.reserve(N*num_keys);

            for (std::size_t k = 0; k < N; ++k)
            {
                // X[alpha][j] += p[k][j] * ( M[k][alpha] - C_offset[alpha] )
                rct::subKeys(C_zero_nominal_temp, M[k][alpha], C_offsets[alpha]);
                data_X.push_back({p[k][j], C_zero_nominal_temp});
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
            proof.X[alpha][j] = rct::scalarmultKey(proof.X[alpha][j], rct::INV_EIGHT);
        }
        CHECK_AND_ASSERT_THROW_MES(proof.X[alpha].size() == m, "Proof coefficient vector is unexpected size!");
    }
    CHECK_AND_ASSERT_THROW_MES(proof.X.size() == num_keys, "Proof coefficient vector is unexpected size!");


    /// one-of-many sub-proof challenges

    // xi: challenge
    const rct::key xi{compute_challenge(message, M, C_offsets, proof.A, proof.B, proof.C, proof.D, proof.X)};

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

    // zC = rC*xi + rD
    sc_muladd(proof.zC.bytes, rC.bytes, xi.bytes, rD.bytes);
    CHECK_AND_ASSERT_THROW_MES(!(proof.zC == ZERO), "Proof scalar element should not be zero!");

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
    memwipe(&rC, sizeof(rct::key));
    memwipe(&rD, sizeof(rct::key));
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
    const rct::keyM &M,
    const std::vector<rct::keyV> &proof_offsets,
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

    CHECK_AND_ASSERT_THROW_MES(small_weighting_size >= 3, "Small weight variable size too small!");  //heuristic

    // anonymity set size
    const std::size_t N = std::pow(n, m);

    CHECK_AND_ASSERT_THROW_MES(M.size() == N, "Public key vector is wrong size!");

    // inputs line up with proofs
    CHECK_AND_ASSERT_THROW_MES(proof_offsets.size() == N_proofs, "Commitment offsets don't match with input proofs!");
    CHECK_AND_ASSERT_THROW_MES(messages.size() == N_proofs, "Incorrect number of messages!");

    // commitment offsets must line up with input set
    const std::size_t num_keys = proof_offsets[0].size();
    CHECK_AND_ASSERT_THROW_MES(num_keys > 0, "Unsufficient signing keys in proof!");

    for (const auto &C_offsets : proof_offsets)
        CHECK_AND_ASSERT_THROW_MES(C_offsets.size() == num_keys, "Incorrect number of commitment offsets!");

    for (const auto &tuple : M)
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
        CHECK_AND_ASSERT_THROW_MES(sc_check(proof.zC.bytes) == 0, "Bad scalar element in proof (zC)!");
        CHECK_AND_ASSERT_THROW_MES(!(proof.zC == ZERO), "Proof scalar element should not be zero (zC)!");

        CHECK_AND_ASSERT_THROW_MES(proof.z.size() == num_keys, "Bad proof vector size (z)!");
        for (std::size_t alpha = 0; alpha < num_keys; ++alpha)
        {
            CHECK_AND_ASSERT_THROW_MES(sc_check(proof.z[alpha].bytes) == 0, "Bad scalar element in proof (z)!");
            CHECK_AND_ASSERT_THROW_MES(!(proof.z[alpha] == ZERO), "Proof scalar element should not be zero (z)!");
        }
    }

    init_gens();
    rct::key temp;  //common variable shuttle so only one needs to be allocated


    /// setup 'data': for aggregate multi-exponentiation computation across all proofs

    // per-index storage:
    // 0            m*n-1    Hi[i]
    // m*n          G        (zA*G, zC*G, {z}*G)
    // m*n+1        m*n+N    {M_agg}
    // ... then per-proof data (A, B, C, D, {C_offsets_agg}, {{X}})
    std::vector<rct::MultiexpData> data;
    data.reserve((m*n + 1) + N + N_proofs*(num_keys*m + 5));
    data.resize((m*n + 1) + N); // set up for all common elements

    // prep terms: {Hi}, G
    for (std::size_t i = 0; i < m*n; ++i)
    {
        data[i] = {ZERO, Hi_p3[i]};
    }
    data[m*n] = {ZERO, G_p3};

    // small weight scalars: {sw}
    // - set first to zero since all other indices will be separated from it by their own weights
    rct::keyV sw;
    sw.resize(num_keys, ZERO);
    sw[0] = ONE;

    for (std::size_t alpha = 1; alpha < num_keys; ++alpha)
    {
        while (sw[alpha] == ZERO)
            sw[alpha] = small_scalar_gen(small_weighting_size);
    }

    // prep terms: {M_agg}
    // M_agg[k] = sum_{alpha}( sw[alpha]*M[k][alpha] )
    // - with 'small weight' aggregation of M-keys at each row of the matrix (for faster verification)
    ge_p3 Key_agg_temp;
    std::vector<rct::MultiexpData> Magg_data;
    Magg_data.resize(num_keys);

    for (std::size_t k = 0; k < N; ++k)
    {
        for (std::size_t alpha = 0; alpha < num_keys; ++alpha)
        {
            //Magg_data[alpha] = {sw[alpha], M[k][alpha]};
        }
        multi_exp_vartime_p3(sw, M[k], Key_agg_temp);

        //data[m*n + (1 + k)] = {ZERO, rct::straus_p3(Magg_data)};
        data[m*n + (1 + k)] = {ZERO, Key_agg_temp};
    }


    /// per-proof data assembly
    std::size_t skipped_offset_sets{0};

    for (std::size_t i_proofs = 0; i_proofs < N_proofs; ++i_proofs)
    {
        const GrootleProof &proof = *(proofs[i_proofs]);

        // random weights
        // - to allow verifiying batches of proofs, must weight each proof's components randomly so an adversary doesn't
        //   gain an advantage if >1 of their proofs are being validated in a batch
        rct::key w1 = ZERO;  // decomp part 1:   w1*[ A + xi*B == com_matrix(f, zA) ]
        rct::key w2 = ZERO;  // decomp part 2:   w2*[ xi*C + D == com_matrix(f(xi - f), zC) ]
        rct::key w3 = ZERO;  // main stuff:      w3*[ sum_alpha( sw[alpha]*( ... - z[alpha]G == 0 ) ) ]
        rct::keyV w3_sw;
        w3_sw.resize(num_keys);
        while (w1 == ZERO || w2 == ZERO || w3 == ZERO)
        {
            w1 = small_scalar_gen(32);
            w2 = small_scalar_gen(32);
            w3 = small_scalar_gen(32);

            for (std::size_t alpha = 0; alpha < num_keys; ++alpha)
            {
                // w3_sw[alpha] = w3 * sw[alpha]
                sc_mul(w3_sw[alpha].bytes, w3.bytes, sw[alpha].bytes);
                if (w3_sw[alpha] == ZERO)
                {
                    // try again
                    w3 = ZERO;
                    break;
                }
            }
        }

        // Transcript challenge
        const rct::key xi{
                compute_challenge(messages[i_proofs],
                    M,
                    proof_offsets[i_proofs],
                    proof.A,
                    proof.B,
                    proof.C,
                    proof.D,
                    proof.X)
            };

        // Challenge powers (negated)
        rct::keyV minus_xi_pow = powers_of_scalar(xi, m, true);

        // Recover proof elements
        ge_p3 A_p3;
        ge_p3 B_p3;
        ge_p3 C_p3;
        ge_p3 D_p3;
        std::vector<std::vector<ge_p3>> X_p3;
        X_p3.resize(num_keys, std::vector<ge_p3>(m));

        scalarmult8(A_p3, proof.A);
        scalarmult8(B_p3, proof.B);
        scalarmult8(C_p3, proof.C);
        scalarmult8(D_p3, proof.D);
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

        // Matrix generators
        //   w1* [ A + xi*B == ... f[j][i]                  * Hi[j][i] ... + zA * G ]
        //       [          == com_matrix(f, zA)                                    ]
        //   w2* [ xi*C + D == ... f[j][i] * (xi - f[j][i]) * Hi[j][i] ... + zC * G ]
        //       [          == com_matrix(f(xi - f), zC)                            ]
        for (std::size_t j = 0; j < m; ++j)
        {
            for (std::size_t i = 0; i < n; ++i)
            {
                // Hi: w1*f[j][i] + w2*f[j][i]*(xi - f[j][i]) ->
                //     w1*f[j][i] + w2*xi*f[j][i] - w2*f[j][i]^2
                rct::key Hi_scalar;
                sc_mul(Hi_scalar.bytes, w1.bytes, f[j][i].bytes);  // w1*f[j][i]

                sc_mul(temp.bytes, w2.bytes, f[j][i].bytes);
                sc_mul(temp.bytes, temp.bytes, xi.bytes);
                sc_add(Hi_scalar.bytes, Hi_scalar.bytes, temp.bytes);  // + w2*xi*f[j][i]

                sc_mul(temp.bytes, MINUS_ONE.bytes, w2.bytes);
                sc_mul(temp.bytes, temp.bytes, f[j][i].bytes);
                sc_mul(temp.bytes, temp.bytes, f[j][i].bytes);
                sc_add(Hi_scalar.bytes, Hi_scalar.bytes, temp.bytes);  // - w2*f[j][i]^2

                sc_add(data[j*n + i].scalar.bytes, data[j*n + i].scalar.bytes, Hi_scalar.bytes); // stack on existing data
            }
        }

        // G: w1*zA + w2*zC
        sc_muladd(data[m*n].scalar.bytes, w1.bytes, proof.zA.bytes, data[m*n].scalar.bytes);  // w1*zA
        sc_muladd(data[m*n].scalar.bytes, w2.bytes, proof.zC.bytes, data[m*n].scalar.bytes);  // w2*zC

        // A, B, C, D
        // equality tests:
        //   w1*[ com_matrix(f, zA)         - (A + xi*B) ] == 0
        //   w2*[ com_matrix(f(xi - f), zC) - (xi*C + D) ] == 0
        // A: -w1    * A
        // B: -w1*xi * B
        // C: -w2*xi * C
        // D: -w2    * D
        sc_mul(temp.bytes, MINUS_ONE.bytes, w1.bytes);
        data.push_back({temp, A_p3});  // -w1 * A

        sc_mul(temp.bytes, temp.bytes, xi.bytes);
        data.push_back({temp, B_p3});  // -w1*xi * B

        sc_mul(temp.bytes, MINUS_ONE.bytes, w2.bytes);
        data.push_back({temp, D_p3});  // -w2 * D

        sc_mul(temp.bytes, temp.bytes, xi.bytes);
        data.push_back({temp, C_p3});  // -w2*xi * C

        // {M_agg}
        //   t_k = mul_all_j(f[j][decomp_k[j]])
        //   w3*[ sum_k( t_k * sum_{alpha}(M_agg[k] - sw[alpha]*C_offsets[alpha])) ) -  ]
        //      [ sum_{alpha}( sw[alpha]*sum(...) ) -                                   ]
        //      [ sum_{alpha}( sw[alpha]*z[alpha] G )                                   ] == 0
        //
        //   sum_k( w3*t_k*M_agg[k] ) -
        //      w3*sum_k( t_k )*sum_{alpha}(sw[alpha]*C_offsets[alpha]) -
        //      w3*[ ... ] == 0
        // M_agg[k]: w3*t_k
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

            sc_mul(temp.bytes, w3.bytes, t_k.bytes);  // w3*t_k
            sc_add(data[m*n + 1 + k].scalar.bytes, data[m*n + 1 + k].scalar.bytes, temp.bytes);  // w3*t_k*M_agg[k]

            sc_add(sum_t.bytes, sum_t.bytes, t_k.bytes);  // sum_k( t_k )
        }

        // {C_offsets}
        //   ... - w3*sum_k( t_k )*sum_{alpha}(sw[alpha]*C_offsets[alpha]) ...
        // 
        // proof_offsets[i_proofs]_agg = sum_{alpha}(sw[alpha]*C_offsets[alpha])
        // proof_offsets[i_proofs]_agg: -sum_t*w3
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
            sc_mul(temp.bytes, temp.bytes, w3.bytes);  //-sum_t*w3

            // optimization: only call multi_exp if there are multiple offsets to combine
            if (temp_sw.size() == 1)
            {
                sc_mul(temp.bytes, temp.bytes, temp_sw[0].bytes);  //-sum_t*w3*sw[whatever it is]
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
        //   w3*[ ... - sum_{alpha}( sw[alpha]*( sum_j( xi^j*X[alpha][j] ) - z[alpha] G ) ) ] == 0
        for (std::size_t alpha = 0; alpha < num_keys; ++alpha)
        {
            for (std::size_t j = 0; j < m; ++j)
            {
                // X[alpha][j]: -w3_sw[alpha]*xi^j
                sc_mul(temp.bytes, w3_sw[alpha].bytes, minus_xi_pow[j].bytes);
                data.push_back({temp, X_p3[alpha][j]});
            }
        }

        // G
        //   w3*[ ... - sum_{alpha}( sw[alpha]*z[alpha] G ) ] == 0
        // G: -w3_sw[alpha]*z[alpha]
        for (std::size_t alpha = 0; alpha < num_keys; ++alpha)
        {
            sc_mul(temp.bytes, MINUS_ONE.bytes, proof.z[alpha].bytes);
            sc_mul(temp.bytes, temp.bytes, w3_sw[alpha].bytes);
            sc_add(data[m*n].scalar.bytes, data[m*n].scalar.bytes, temp.bytes);
        }
    }


    /// Final check
    CHECK_AND_ASSERT_THROW_MES(data.size() == (m*n + 1) + N + N_proofs*(num_keys*m + 5) - skipped_offset_sets,
        "Final proof data is incorrect size!");


    /// Verify all elements sum to zero
    ge_p3 result = rct::pippenger_p3(data, cache, m*n, rct::get_pippenger_c(data.size()));
    if (ge_p3_is_point_at_infinity(&result) == 0)
    {
        MERROR("Grootle proof: verification failed!");
        return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
