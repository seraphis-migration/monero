// Copyright (c) 2026, The Monero Project
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

//local headers
#include "fcmp_pp/fcmp_pp_types.h"

//third party headers

//standard headers
#include <variant>

//forward declarations

namespace carrot
{
/**
 * @brief An FCMP++ SA/L proof, its re-reandomized input, and the O~ opening can be used to prove OTA<->KI association
 */
struct FcmpPpTxKeyImageProofV1
{
    crypto::hash signable_tx_hash;
    FcmpInputCompressed input;
    fcmp_pp::FcmpPpSalProof sal;
    crypto::secret_key r_o; // r_o s.t. O~ = O + r_o T
};

/**
 * @brief Variation between any key image association proof
 */
using KeyImageProofVariant = std::variant<
        crypto::signature,       // prove L = x Hp(O), s.t. O = x G
        fcmp_pp::FcmpPpSalProof, // prove L = x Hp(O), s.t. O = x G + y T
        FcmpPpTxKeyImageProofV1  // like previous, but with user-provided prefix and rerandomized input
        //! @TODO: variant which allows k_gi proving without knowledge of k_ps
    >;
} //namespace carrot
