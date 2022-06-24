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

#pragma once

#include "crypto/crypto.h"
#include "seraphis/grootle.h"
#include "seraphis/sp_crypto_utils.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

#include <vector>


using namespace rct;

template<std::size_t a_n,
    std::size_t a_m,
    std::size_t num_proofsV,
    bool with_ident_offset>
class test_grootle
{
    public:
        static const std::size_t loop_count = 1000;
        static const std::size_t n = a_n;
        static const std::size_t m = a_m;
        static const std::size_t N_proofs = num_proofsV;
        static const bool use_ident_offset = with_ident_offset;

        bool init()
        {
            // anonymity set size
            const std::size_t N = std::pow(n, m);

            // Build key vectors
            M.resize(N_proofs, keyV(N));
            std::vector<crypto::secret_key> proof_privkeys;// privkey per-proof (at secret indices in M)
            proof_privkeys.resize(N_proofs);
            proof_messages = keyV(N_proofs);  // message per-proof
            proof_offsets.resize(N_proofs);

            // Random keys
            key temp;
            for (std::size_t proof_i = 0; proof_i < N_proofs; proof_i++)
            {
                for (std::size_t k = 0; k < N; k++)
                {
                    skpkGen(temp, M[proof_i][k]);
                }
            }

            // Signing keys, proof_messages, and commitment offsets
            key privkey, offset_privkey;
            for (std::size_t proof_i = 0; proof_i < N_proofs; proof_i++)
            {
                // set real-signer index = proof index (kludge)
                skpkGen(privkey, M[proof_i][proof_i]);  //m_l * G
                proof_messages[proof_i] = skGen();

                if (use_ident_offset)
                {
                    proof_offsets[proof_i] = identity();
                    proof_privkeys[proof_i] = rct::rct2sk(privkey);
                }
                else
                {
                    skpkGen(offset_privkey, proof_offsets[proof_i]);  //c * G
                    sc_sub(to_bytes(proof_privkeys[proof_i]), privkey.bytes, offset_privkey.bytes); //m - c [commitment to zero]
                }
            }

            proofs.reserve(N_proofs);
            proof_ptrs.reserve(N_proofs);

            try
            {
                for (std::size_t proof_i = 0; proof_i < N_proofs; proof_i++)
                {
                    proofs.push_back(
                        sp::grootle_prove(M[proof_i],
                            proof_i,
                            proof_offsets[proof_i],
                            proof_privkeys[proof_i],
                            n,
                            m,
                            proof_messages[proof_i])
                        );
                }
            }
            catch (...)
            {
                return false;
            }

            for (sp::GrootleProof &proof: proofs)
            {
                proof_ptrs.push_back(&proof);
            }

            return true;
        }

        bool test()
        {
            // Verify batch
            try
            {
                if (!sp::grootle_verify(proof_ptrs, M, proof_offsets, n, m, proof_messages))
                    return false;
            }
            catch (...)
            {
                return false;
            }

            return true;
        }

    private:
        std::vector<rct::keyV> M;   // reference set
        keyV proof_offsets;         // commitment offset per-proof
        keyV proof_messages;        // message per-proof
        std::vector<sp::GrootleProof> proofs;
        std::vector<const sp::GrootleProof *> proof_ptrs;
};
