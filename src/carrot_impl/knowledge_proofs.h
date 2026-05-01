// Copyright (c) 2025, The Monero Project
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
#include "address_device.h"
#include "crypto/crypto.h"
#include "key_image_device.h"
#include "fcmp_pp/fcmp_pp_types.h"
#include "mx25519.h"
#include "output_opening_types.h"
#include "ringct/rctTypes.h"
#include "serialization/serialization.h"

//third party headers

//standard headers
#include <memory>
#include <optional>

//forward declarations

namespace carrot
{
struct knowledge_proof_device: virtual public key_image_device
{
    // maps KI -> (OTA, SA/L) in consensus ordering
    using signed_input_set_t = std::map<crypto::key_image,
        std::pair<crypto::public_key, fcmp_pp::FcmpPpSalProof>,
        std::greater<crypto::key_image>>;

    virtual bool try_sign_fcmp_spend_proof_v1(const crypto::hash &txid,
        const epee::span<const std::uint8_t> message,
        const std::vector<OutputOpeningHintVariant> &opening_hints,
        const std::vector<FcmpRerandomizedOutputCompressed> &rerandomized_outputs,
        crypto::hash &prefix_hash_out,
        signed_input_set_t &signed_inputs_out
    ) const = 0;

    virtual bool try_sign_fcmp_reserve_proof_v1(const rct::xmr_amount threshold_amount,
        const std::vector<OutputOpeningHintVariant> &opening_hints,
        const std::vector<FcmpRerandomizedOutputCompressed> &rerandomized_outputs,
        crypto::hash &prefix_hash_out,
        signed_input_set_t &signed_inputs_out
    ) const = 0;
};

struct FcmpPpProofExtended
{
    std::vector<crypto::ec_point> rerandomized_amount_commitments;
    std::uint64_t reference_block;
    std::uint8_t n_tree_layers;
    fcmp_pp::FcmpPpProof fcmp_pp;
};
/**
 * brief: A reserve proof of at least `threshold_amount` which uses FCMP++s and BP+s to preseve privacy
 *
 * This reserve proof has unique privacy properties compared to previous reserve proofs in the following ways:
 *   - The total amount sum of the input set is not necessarily revealed
 *   - The amount per input is not revealed
 *   - The association between key images and one-time addresses is not revealed, preserving sender privacy
 *
 * The threshold amount is the minimum amount the given set of inputs contains, if the proof
 * verifies. The rerandomized outputs here do not have to equal rerandomized outputs in spending
 * txs, which is nice for the holder since they don't have to store rerandomizations. `inputs`
 * should be sorted in key image consensus order.`reference_block` and `n_tree_layers` are the same
 * as if we were making a new transaction spending these enotes. The FCMP++ proof is also
 * effectively the same as a real transaction, except that the signed message is a reserve-proof
 * specific message, and can't be used for Monero consensus. The BP+ range proof is a range proof
 * over C_rem = C_sum - a H, where `a` is `threshold_amount` and `C_sum` is the sum of all C~ in
 * `inputs`. If `threshold_amount` was greater than the sum of the amounts bound to in
 * `rerandomized_amount_commitments`, then the opening against `H` would be a scalar much, much
 * greater than 2^64 and a valid range proof could not be created.
 */
struct FcmpReserveProof
{
    FcmpPpProofExtended fcmp_pp;
    rct::BulletproofPlus bpp;
};

/**
 * brief: Generate a PoK of `r` s.t. `D = r ConvertPointE(A)` and (`R = r G` or `R = r ConvertPointE(B)`)
 *            where G is the X25519 base point, and ConvertPointE() is the Ed25519->X25519 conversion function
 * param: prefix_hash - challenge message
 * param: A - A [Ed25519]
 * param: B - B [Ed25519] [Optional]
 * param: r - r in scalar field (mod l)
 * outparam: sig_out - Schnorr proof of knowledge of discrete log `r`
 *
 * This handles use cases for both standard addresses and subaddresses.
 * Generates only proofs for InProofV2 and OutProofV2.
*/
void generate_carrot_tx_proof_normal(const crypto::hash &prefix_hash,
    const crypto::public_key &A,
    const std::optional<crypto::public_key> &B,
    crypto::secret_key r,
    crypto::signature &sig_out);
/**
 * @TODO: doc
 */
bool check_carrot_tx_proof_normal(const crypto::hash &prefix_hash,
    const mx25519_pubkey &R,
    const crypto::public_key &A,
    const std::optional<crypto::public_key> &B,
    const mx25519_pubkey &D,
    const crypto::signature &sig);
/**
 * brief: Generate a PoK of `a` s.t. `D = a R` and (`A = a G_ed` or `A = a B`)
 *            where G_ed is the *Ed25519* base point
 * param: prefix_hash - challenge message
 * param: R - R [X25519]
 * param: B - B [Ed25519] [Optional]
 * param: a - a in scalar field (mod l)
 * outparam: sig_out - Schnorr proof of knowledge of discrete log `a`
 *
 * This handles use cases for both standard addresses and subaddresses.
 * Generates only proofs for InProofV2 and OutProofV2.
*/
void generate_carrot_tx_proof_receiver(const crypto::hash &prefix_hash,
    const mx25519_pubkey &R,
    const std::optional<crypto::public_key> &B,
    crypto::secret_key a,
    crypto::signature &sig_out);
/**
 * @TODO: doc
 */
bool check_carrot_tx_proof_receiver(const crypto::hash &prefix_hash,
    const mx25519_pubkey &R,
    const crypto::public_key &A,
    const std::optional<crypto::public_key> &B,
    const mx25519_pubkey &D,
    const crypto::signature &sig);
/**
 * @TODO: doc
 */
crypto::hash make_fcmp_spend_proof_prefix_hash(
    const crypto::hash &txid,
    const epee::span<const std::uint8_t> message,
    const std::vector<crypto::key_image> &signing_key_images);
/**
 * @TODO: doc
 */
void generate_fcmp_spend_proof(const crypto::hash &txid,
    const epee::span<const std::uint8_t> message,
    std::vector<OutputOpeningHintVariant> opening_hints,
    std::vector<fcmp_pp::Path> input_paths,
    const std::uint64_t reference_block,
    const std::uint8_t n_tree_layers,
    const knowledge_proof_device &knowledge_proof_dev,
    std::vector<crypto::key_image> &key_images_out,
    FcmpPpProofExtended &spend_proof_out);
/**
 * @TODO: doc
 */
bool check_fcmp_spend_proof(const crypto::hash &txid,
    const epee::span<const std::uint8_t> message,
    const std::vector<crypto::key_image> &key_images,
    const FcmpPpProofExtended &fcmp_pp,
    const fcmp_pp::TreeRootShared &fcmp_tree_root);
/**
 * @TODO: doc
 */
crypto::hash make_fcmp_reserve_proof_prefix_hash(
    rct::xmr_amount threshold_amount,
    const std::vector<crypto::key_image> &signing_key_images);
/**
 * @TODO: doc
 */
void generate_fcmp_reserve_proof(const rct::xmr_amount threshold_amount,
    std::vector<OutputOpeningHintVariant> opening_hints,
    std::vector<fcmp_pp::Path> input_paths,
    const std::uint64_t reference_block,
    const std::uint8_t n_tree_layers,
    std::shared_ptr<view_incoming_key_device> k_view_incoming_dev,
    std::shared_ptr<view_balance_secret_device> s_view_balance_dev,
    const epee::span<const crypto::public_key> main_address_spend_pubkeys,
    const knowledge_proof_device &knowledge_proof_dev,
    std::vector<crypto::key_image> &key_images_out,
    FcmpReserveProof &reserve_proof_out);
/**
 * @TODO: doc
 *
 * Does not check key image exclusion nor that `n_tree_layers` is correct for `reference_block`
 */
bool check_fcmp_reserve_proof(const rct::xmr_amount threshold_amount,
    const std::vector<crypto::key_image> &key_images,
    const FcmpReserveProof &reserve_proof,
    const fcmp_pp::TreeRootShared &fcmp_tree_root);

DECLARE_SERIALIZE_OBJECT(FcmpPpProofExtended)
DECLARE_SERIALIZE_OBJECT(FcmpReserveProof)
} //namespace carrot
