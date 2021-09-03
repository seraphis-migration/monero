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

// Multisig signing helper types.

#pragma once

//local headers
#include "common/variant.h"
#include "crypto/crypto.h"
#include "multisig_clsag.h"
#include "multisig_nonce_cache.h"
#include "multisig_signer_set_filter.h"
#include "multisig_sp_composition_proof.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <unordered_map>
#include <vector>

//forward declarations


namespace multisig
{

////
// MultisigProofInitSetV1
// - this signer initializes a proof to be signed by a multisig group
// - the init set initializes a proof attempt for every signer subgroup this signer is a member of in the specified
//   aggregate signer set filter
///
struct MultisigProofInitSetV1 final
{
    /// all multisig signers who should participate in attempting to make these multisig proofs (get this from e.g. a
    ///   multisig proof proposal)
    signer_set_filter aggregate_signer_set_filter;
    /// id of signer who made this proof initializer set
    crypto::public_key signer_id;
    /// message to be signed by the multisig proofs
    rct::key proof_message;
    /// main proof key to be signed by the multisig proofs (any additional/auxilliary proof keys aren't recorded here,
    ///   since they are assumed to be implicitly tied to the main proof key)
    rct::key proof_key;

    /// proof initializers
    // - for each signer set in permutations of the aggregate signer set that includes the specified signer id, record a
    //   vector of pub nonces where each element aligns to a set of nonce base keys across which the multisig signature will
    //   be made (for example: CLSAG signs across both G and Hp(Ko), where Ko = ko*G is the proof key recorded here)
    // - note that permutations of signers depend on the threshold and list of multisig signers, which are not recorded here
    //   - WARNING: ordering is dependent on the signer set filter permutation generator
    // {  { {pub nonces: filter 0 and proof base key 0},  {pub nonces: filter 0 and proof base key 1 } },  ... }
    std::vector<               //filter permutations
        std::vector<           //proof base keys
            MultisigPubNonces  //nonces
        >
    > inits;
};

////
// MultisigPartialSigVariant
// - variant of multisig partial signatures
// 
// proof_key_ref(): get the main proof key used in the partial signature (there may be additional auxilliary proof keys)
// message_ref(): get the message signed by the partial signature
///
using MultisigPartialSigVariant = tools::variant<CLSAGMultisigPartial, SpCompositionProofMultisigPartial>;
const rct::key& proof_key_ref(const MultisigPartialSigVariant &variant);
const rct::key& message_ref(const MultisigPartialSigVariant &variant);

////
// MultisigPartialSigSetV1
// - set of multisig partial signatures for different proof keys; combine partial signatures to complete a proof
///
struct MultisigPartialSigSetV1 final
{
    /// multisig signer subgroup these partial signatures were created for
    multisig::signer_set_filter signer_set_filter;
    /// id of signer who made these partial signatures
    crypto::public_key signer_id;

    /// [ proof key : partial signatures ] partial signatures mapped to their internally cached proof keys
    std::unordered_map<rct::key, MultisigPartialSigVariant> partial_signatures;
};

/// get set of nonces from an init set for a given filter (returns false if the location doesn't exist)
bool try_get_nonces(const MultisigProofInitSetV1 &init_set,
    const std::size_t filter_index,
    std::vector<MultisigPubNonces> &nonces_out);

} //namespace multisig
