// Copyright (c) 2023, The Monero Project
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

// Seraphis knowledge proof types.

#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_crypto/matrix_proof.h"
#include "seraphis_crypto/sp_composition_proof.h"
#include "seraphis_main/enote_record_types.h"
#include "seraphis_main/tx_builder_types.h"
#include "seraphis_main/tx_component_types.h"
#include "seraphis_main/tx_validation_context.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace sp
{
namespace knowledge_proofs
{

////
// AddressOwnershipProofV1
// - proof that an address K is constructed in the seraphis address style and is owned by the prover
// - {K = K_1}  OR  {K = K_s = k_vb X + k_m U}
//
// - INTERACTIVE PROOF: verifier must give a custom message to the prover, otherwise the prover can just copy-paste
//   a pre-computed proof that he got from who-knows-where
//
// - VERIFIER: validate the seraphis composition proof on K
///
struct AddressOwnershipProofV1
{
    rct::key message;
    rct::key K;
    crypto::key_image addr_key_image;  //'key image' of the address used in this proof
    SpCompositionProof composition_proof;
};

////
// AddressIndexProofV1
// - proof that a jamtis address with spendkey K_1 was constructed from an index j from base spend key K_s
//
// - VERIFIER: recompute K_1 ?= [G/X/U spendkey extensions from {j, generator, K_s}] + K_s
///
struct AddressIndexProofV1
{
    rct::key K_s;
    jamtis::address_index_t j;
    rct::key generator;
    rct::key K_1;
};

////
// EnoteOwnershipProofV1
// - proof an enote with onetime adress Ko is owned by an address K_1
// - disclaimer: this does not prove that the owner of address K_1 can actually spend the enote; q could be computed in
//   violation of the jamtis spec, in which case the owner of K_1 may never recover the enote and so the funds are
//   effectively burned
//
// - VERIFIER: recompute Ko ?= [G/X/U sender extensions from {K_1, q, C}] + K_1
///
struct EnoteOwnershipProofV1
{
    rct::key K_1;
    rct::key q;
    rct::key C;
    rct::key Ko;
}; 

////
// EnoteAmountProofV1
// - proof an enote with amount commitment C has a particular amount a
//
// - VERIFIER: recompute C ?= x G + a H
///
struct EnoteAmountProofV1
{
    rct::xmr_amount a;
    rct::key x;
    rct::key C;
};

////
// EnoteKeyImageProofV1
// - proof a key image KI corresponds to a particular onetime address Ko
//
// - VERIFIER:
//   - check that KI is in the prime-order subgroup
//   - validate the seraphis composition proof on the provided {Ko, KI}
///
struct EnoteKeyImageProofV1
{
    rct::key Ko;
    crypto::key_image KI;
    SpCompositionProof composition_proof;
};

////
// EnoteUnspentProofV1
// - proof an enote with onetime address Ko was NOT spent by a tx input with key image test_KI
//
// pubkeys stored in the matrix proofs:
//   Ko_g = k_g G
//   Ko_x = (k_x + k_vb) X
//   Ko_u = (k_u + k_m) U
//
// - VERIFIER:
//   - recompute Ko ?= Ko_g + Ko_x + Ko_u
//   - validate:
//     - g_component_proof on base key G
//     - x_component_transform_proof on base keys {X, test_KI}
//     - u_component_proof on base key U
//   - check:
//     - if [x_component_transform_proof second proof key] == Ko_u then test_KI is the key image of Ko, otherwise
//       it is not
//
// TODO: a more efficient version of this would make a proof on multiple test_KI at once
///
struct EnoteUnspentProofV1
{
    rct::key Ko;
    crypto::key_image test_KI;
    MatrixProof g_component_proof;            //Ko_g                          on  G
    MatrixProof x_component_transform_proof;  //{Ko_x, (k_x + k_vb)*test_KI}  on  {X, test_KI}
    MatrixProof u_component_proof;            //Ko_u                          on  U
};

////
// TxFundedProofV1
// - proof that the prover owns the enote that was spent in a tx input with key image KI
// - this proof does not expose the enote, it just demonstrates that the prover can reproduce KI
// - note that this proof does not expose the input amount; if the prover cached the mask t_c in the original tx input,
//   then they can make an EnoteAmountProofV1 on the input's masked amount commitment; otherwise they need an
//   EnoteAmountProofV1 on the input enote's original amount commitment (which will expose which enote was spent by the tx)
//
// - INTERACTIVE PROOF: verifier must give a custom message to the prover
//
// - VERIFIER: validate the seraphis composition proof on the provided {K", KI}
///
struct TxFundedProofV1
{
    rct::key message;
    rct::key masked_address;  //K" = t_k G + Ko  (using a different mask t_k than was used in the tx)
    crypto::key_image KI;
    SpCompositionProof composition_proof;
};

////
// EnoteSentProofV1
// - proof that an enote with amount a and onetime address Ko was sent to an address K_1
//
// - VERIFIER: validate the EnoteOwnershipProofV1 and EnoteAmountProofV1
///
struct EnoteSentProofV1
{
    EnoteOwnershipProofV1 enote_ownership_proof;
    EnoteAmountProofV1 amount_proof;
};

////
// ReservedEnoteProofV1
// - proof that an enote with onetime address Ko is owned by address K_1, has amount a, has key image KI, is onchain, and
//   is unspent
//
// - VERIFIER:
//   - validate the EnoteOwnershipProofV1, EnoteAmountProofV1, and EnoteKeyImageProofV1 proofs
//   - verify that {C, Ko} corresponds to an onchain enote using enote_ledger_index
//   - verify the KI doesn't exist on-chain
///
struct ReservedEnoteProofV1
{
    EnoteOwnershipProofV1 enote_ownership_proof;
    EnoteAmountProofV1 amount_proof;
    EnoteKeyImageProofV1 KI_proof;
    std::uint64_t enote_ledger_index;
};

////
// ReserveProofV1
// - proof that the prover has at least v = sum(a) unspent funds onchain
//
// - INTERACTIVE PROOF: verifier must give a custom message to the prover
//
// - VERIFIER:
//   - validate the AddressOwnershipProofV1 proofs
//   - check that the owning address K_1 in each of the reserved enote proofs corresponds to an address owned by the prover
//   - check that the enotes referenced by the reserved enote proofs exist in the ledger
//   - check that the key images in the reserved enote proofs do not exist in the ledger
//   - validate the ReservedEnoteProofV1 proofs
//
// - OUTPUT: v = sum(amounts in the proofs)
///
struct ReserveProofV1
{
    std::vector<AddressOwnershipProofV1> address_ownership_proofs;
    std::vector<ReservedEnoteProofV1> reserved_enote_proofs;
};

} //namespace knowledge_proofs
} //namespace sp
