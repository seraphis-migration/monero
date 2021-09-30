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
#include "seraphis_composition_proof.h"

//local headers
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_crypto_utils.h"

//third party headers

//standard headers
#include <vector>


namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
SpCompositionProof sp_composition_prove(const rct::keyV &K,
    const rct::keyV &x,
    const rct::keyV &y,
    const rct::keyV &z,
    const rct::key &message)
{
    CHECK_AND_ASSERT_THROW_MES(K.size() > 0, "Not enough keys to make a proof!");
    CHECK_AND_ASSERT_THROW_MES(K.size() == x.size(), "Input key sets not the same size (K ?= x)!");
    CHECK_AND_ASSERT_THROW_MES(K.size() == y.size(), "Input key sets not the same size (K ?= y)!");
    CHECK_AND_ASSERT_THROW_MES(K.size() == z.size(), "Input key sets not the same size (K ?= z)!");

    for (std::size_t i{0}; i < K.size(); ++i)
    {
        CHECK_AND_ASSERT_THROW_MES(K[i] != rct::identity(), "Bad proof key (K[i] identity)!");

        CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(x[i].bytes) == 0, "Bad private key (x[i] zero)!");
        CHECK_AND_ASSERT_THROW_MES(sc_check(x[i].bytes) == 0, "Bad private key (x[i])!");
        CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(y[i].bytes) == 0, "Bad private key (y[i] zero)!");
        CHECK_AND_ASSERT_THROW_MES(sc_check(y[i].bytes) == 0, "Bad private key (y[i])!");
        CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(z[i].bytes) == 0, "Bad private key (z[i] zero)!");
        CHECK_AND_ASSERT_THROW_MES(sc_check(z[i].bytes) == 0, "Bad private key (z[i])!");
    }
}
//-------------------------------------------------------------------------------------------------------------------
bool sp_composition_verify(const SpCompositionProof &proof,
    const rct::keyV &K,
    const rct::keyV &KI,
    const rct::key &message)
{

}
//-------------------------------------------------------------------------------------------------------------------
SpCompositionProofMultisigProposal sp_composition_multisig_proposal(const rct::keyV &KI,
    const rct::keyV &K,
    const rct::key &message)
{

}
//-------------------------------------------------------------------------------------------------------------------
SpCompositionProofMultisigPrep sp_composition_multisig_init()
{

}
//-------------------------------------------------------------------------------------------------------------------
SpCompositionProofMultisigPartial sp_composition_multisig_response(const SpCompositionProofMultisigProposal &proposal,
    const rct::keyV &x,
    const rct::keyV &y,
    const rct::keyV &z_e,
    const rct::keyV &signer_openings,
    const rct::key &local_opening_priv,
    const rct::key &message)
{

}
//-------------------------------------------------------------------------------------------------------------------
SpCompositionProof sp_composition_prove_multisig_final(const std::vector<SpCompositionProofMultisigPartial> &partial_sigs)
{

}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
