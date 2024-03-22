// Copyright (c) 2017-2022, The Monero Project
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

// Adapted from ringct/bulletproofs_plus.h/.cpp to use the seraphis generator factory and transcript utilities.

#pragma once

//local headers
#include "ringct/rctTypes.h"
#include "sp_multiexp.h"

//third party headers

//standard headers
#include <list>
#include <vector>

//forward declarations


namespace sp
{

struct BulletproofPlus2Proof
{
    rct::key A, A1, B;
    rct::key r1, s1, d1;
    rct::keyV L, R;
};

struct BulletproofPlus2
{
    rct::keyV V; //! @brief Pederson commitment points multiplied by (1/8)
    BulletproofPlus2Proof proof;
};

BulletproofPlus2 bulletproof_plus2_PROVE(const rct::key &v, const rct::key &gamma);
BulletproofPlus2 bulletproof_plus2_PROVE(uint64_t v, const rct::key &gamma);
BulletproofPlus2 bulletproof_plus2_PROVE(const rct::keyV &v, const rct::keyV &gamma);
BulletproofPlus2 bulletproof_plus2_PROVE(const std::vector<uint64_t> &v, const rct::keyV &gamma);
bool try_get_bulletproof_plus2_verification_data(const std::vector<const rct::keyV*> &Vs,
    const std::vector<const BulletproofPlus2Proof*> &proofs,
    std::list<SpMultiexpBuilder> &prep_data_out);
bool bulletproof_plus2_VERIFY(const BulletproofPlus2 &proof);
bool bulletproof_plus2_VERIFY(const std::vector<const rct::keyV*> &Vs,
    const std::vector<const BulletproofPlus2Proof*> &proofs);
bool bulletproof_plus2_VERIFY(const std::vector<BulletproofPlus2> &proofs);

} //namespace sp
