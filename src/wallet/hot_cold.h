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
#include "carrot_impl/address_device_hierarchies.h"
#include "carrot_impl/key_image_device.h"
#include "carrot_impl/spend_device.h"
#include "carrot_impl/subaddress_index.h"
#include "tx_builder.h"
#include "wallet2_basic/wallet2_types.h"

//third party headers

//standard headers
#include <unordered_map>
#include <variant>
#include <vector>

//forward declarations

namespace tools
{
namespace wallet
{
namespace cold
{
struct exported_pre_carrot_transfer_details
{
    crypto::public_key m_pubkey;
    uint64_t m_internal_output_index;
    uint64_t m_global_output_index;
    crypto::public_key m_tx_pubkey;
    union
    {
        struct
        {
            uint8_t m_spent: 1;
            uint8_t m_frozen: 1;
            uint8_t m_rct: 1;
            uint8_t m_key_image_known: 1;
            uint8_t m_key_image_request: 1; // view wallets: we want to request it; cold wallets: it was requested
            uint8_t m_key_image_partial: 1;
        };
        uint8_t flags;
    } m_flags;
    uint64_t m_amount;
    std::vector<crypto::public_key> m_additional_tx_keys;
    uint32_t m_subaddr_index_major;
    uint32_t m_subaddr_index_minor;
};
bool operator==(const exported_pre_carrot_transfer_details&, const exported_pre_carrot_transfer_details&);

struct exported_carrot_transfer_details
{
    // K^j_s can be derived on the cold side given j and derive_type. For normal enotes, d_e can
    // be computed from anchor_norm, input_context, K^j_s, and pid. Furthermore, D_e can be
    // recomputed with d_e and K^j_s. For selfsend enote, D_e is passed explicitly. s_sr can be
    // recomputed with D_e and private view key. s^ctx_sr can be recomputed with s_sr, D_e, and
    // input_context. k_a can be recomputed with s^ctx_sr, a, K^j_s, and given enote_type. C_a be
    // be recomputed with a and k_a. Sender extensions k^g_o and k^t_o can be recomputed with
    // s^ctx_sr and C_a. K_o can be recomputed with K^j_s, k^g_o, and k^t_o. For normal enotes,
    // the act of recomputing D_e from d_e and K^j_s prevents Janus attacks. For special enotes,
    // anchor_sp is explicitly provided, which can be checked. As for burning bugs, K_o is
    // recomputed as a function of k^g_o and k^t_o, which are functions of C_a and input_context.
    //
    // This struct is designed to provide just enough information so that a malicious hot wallet
    // or other unprivileged communicator passing an arbitrary packet will not be able to get the
    // cold wallet to sign a SA/L proof for a valid existing enote and perform either a Janus
    // attack or a burning bug attack.

    union
    {
        struct
        {
            uint64_t m_spent: 1;
            uint64_t m_key_image_known: 1;
            uint64_t m_key_image_request: 1; // view wallets: we want to request it; cold wallets: it was requested
            uint64_t m_selfsend: 1;
            uint64_t m_enote_type_change: 1; // true iff enote_type is "change"
            uint64_t m_carrot_derived_addr: 1; // true iff derive_type for receiving addr is AddressDeriveType::Carrot
            uint64_t m_internal: 1;
            uint64_t m_coinbase: 1;
            uint64_t m_has_pid: 1;
            uint64_t m_frozen: 1;
            uint64_t m_key_image_partial: 1;
        };
        uint64_t flags;
    } flags;

    std::uint64_t block_index;
    crypto::key_image tx_first_key_image;
    carrot::subaddress_index subaddr_index;
    carrot::payment_id_t payment_id;
    rct::xmr_amount amount;
    carrot::janus_anchor_t janus_anchor;
    mx25519_pubkey selfsend_enote_ephemeral_pubkey;
};
bool operator==(const exported_carrot_transfer_details&, const exported_carrot_transfer_details&);

using exported_transfer_details_variant = std::variant<
        exported_pre_carrot_transfer_details,
        exported_carrot_transfer_details
    >;

// The term "Unsigned tx" is not really a tx since it's not signed yet.
// It doesnt have tx hash, key and the integrated address is not separated into addr + payment id.
struct UnsignedPreCarrotTransactionSet
{
    std::vector<PreCarrotTransactionProposal> txes;
    std::tuple<uint64_t, uint64_t, wallet2_basic::transfer_container> transfers;
    std::tuple<uint64_t, uint64_t, std::vector<exported_pre_carrot_transfer_details>> new_transfers;
};

using HotColdSeed = crypto::hash;

struct HotColdCarrotPaymentProposalV1
{
    /// user address
    carrot::CarrotDestinationV1 destination;
    /// b
    rct::xmr_amount amount;

    // janus anchor randomness is derived from the hot/cold seed
};

struct HotColdCarrotPaymentProposalVerifiableSelfSendV1
{
    /// j for K^j_s (derive_type is implied)
    carrot::subaddress_index subaddr_index;
    /// a
    rct::xmr_amount amount;
    /// enote_type
    carrot::CarrotEnoteType enote_type;

    // enote ephemeral pubkey D_e is derived from hot/cold seed

    // internal anchor message isn't used for V1
};

struct HotColdCarrotTransactionProposalV1
{
    /// 32-byte randomness for deterministically deriving rerandomizations and other random components
    HotColdSeed hot_cold_seed;

    /// Spent enote onetime addresses per input
    std::vector<crypto::public_key> input_onetime_addresses;

    /// Payment proposals to be converted into output enotes (the order is very important for consistency)
    std::vector<HotColdCarrotPaymentProposalV1> normal_payment_proposals;
    std::vector<HotColdCarrotPaymentProposalVerifiableSelfSendV1> selfsend_payment_proposals;
    carrot::AddressDeriveType addr_derive_type;

    // dummy_encrypted_payment_id is derived from the hot/cold seed

    /// Fee to miner
    rct::xmr_amount fee;

    /// This field is truly "extra". It should contain only tx.extra fields that aren't present in a
    /// normal Carrot transaction, i.e. NOT ephemeral pubkeys nor encrypted PIDs
    std::vector<std::uint8_t> extra;
};

struct UnsignedCarrotTransactionSetV1
{
    std::vector<HotColdCarrotTransactionProposalV1> tx_proposals;

    std::vector<exported_transfer_details_variant> new_transfers;
    std::uint64_t starting_transfer_index;

    /// Signal to the cold wallet whether you want the above tx proposals sent back with the signed
    /// transactio info. This allows the hot wallet to "forget" about unsigned transaction sets it
    /// has passed to the cold wallet but still verify all of the transaction information. Set to
    /// `false` for the most compact messages.
    bool resend_tx_proposals;
};

using UnsignedTransactionSetVariant = std::variant<
        UnsignedPreCarrotTransactionSet,
        UnsignedCarrotTransactionSetV1
    >;
std::size_t num_unsigned_txs_ref(const UnsignedTransactionSetVariant&);
std::size_t num_new_outputs_ref(const UnsignedTransactionSetVariant&);

struct SignedFullTransactionSet
{
    std::vector<pending_tx> ptx;
    std::vector<crypto::key_image> key_images;
    std::unordered_map<crypto::public_key, crypto::key_image> tx_key_images;
};

struct SignedCarrotTransactionSetV1
{
    std::vector<HotColdCarrotTransactionProposalV1> tx_proposals;
    std::unordered_map<crypto::public_key, carrot::InputProposalV1> tx_input_proposals;

    carrot::spend_device::signed_input_set_t signed_inputs;

    std::unordered_map<crypto::public_key, crypto::key_image> other_key_images;
};

using SignedTransactionSetVariant = std::variant<
        SignedFullTransactionSet,
        SignedCarrotTransactionSetV1
    >;

using KeyImageProofVariant = std::variant<
        crypto::signature,       // allows proving L = x Hp(O), s.t. O = x G
        fcmp_pp::FcmpPpSalProof  // allows proving L = x Hp(O), s.t. O = x G + y T
        //! @TODO: variant which allows k_gi proving without knowledge of k_ps
    >;

exported_pre_carrot_transfer_details export_cold_pre_carrot_output(const wallet2_basic::transfer_details &td);

exported_carrot_transfer_details export_cold_carrot_output(const wallet2_basic::transfer_details &td,
    const carrot::cryptonote_hierarchy_address_device &addr_dev);

exported_transfer_details_variant export_cold_output(const wallet2_basic::transfer_details &td,
    const carrot::cryptonote_hierarchy_address_device &addr_dev);

wallet2_basic::transfer_details import_cold_pre_carrot_output(const exported_pre_carrot_transfer_details &etd,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    const carrot::key_image_device &key_image_dev);

wallet2_basic::transfer_details import_cold_carrot_output(const exported_carrot_transfer_details &etd,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    const carrot::key_image_device &key_image_dev);

wallet2_basic::transfer_details import_cold_output(const exported_transfer_details_variant &etd,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    const carrot::key_image_device &key_image_dev);

HotColdCarrotTransactionProposalV1 compress_carrot_transaction_proposal_lossy(
    const carrot::CarrotTransactionProposalV1 &tx_proposal,
    const HotColdSeed &hot_cold_seed);

std::function<carrot::InputProposalV1(const crypto::public_key&)> make_supplemental_input_proposals_fetcher(
    const wallet2_basic::transfer_container &transfers);

void expand_carrot_transaction_proposal(const HotColdCarrotTransactionProposalV1 &tx_proposal,
    const std::function<carrot::InputProposalV1(const crypto::public_key&)> &supplemental_input_proposals,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    carrot::CarrotTransactionProposalV1 &tx_proposal_out);

void expand_carrot_transaction_proposals(const UnsignedCarrotTransactionSetV1 &unsigned_txs,
    const std::function<carrot::InputProposalV1(const crypto::public_key&)> &supplemental_input_proposals,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    std::vector<carrot::CarrotTransactionProposalV1> &tx_proposals_out);

void expand_carrot_transaction_proposal_and_rerandomized_outputs(
    const HotColdCarrotTransactionProposalV1 &tx_proposal,
    const std::function<carrot::InputProposalV1(const crypto::public_key&)> &supplemental_input_proposals,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    const carrot::key_image_device &key_image_dev,
    carrot::CarrotTransactionProposalV1 &tx_proposal_out,
    std::vector<crypto::key_image> &input_key_images_out,
    std::vector<FcmpRerandomizedOutputCompressed> &rerandomized_outputs_out);

UnsignedTransactionSetVariant generate_unsigned_tx_set_from_pending_txs(
    const std::vector<pending_tx> &ptxs,
    const wallet2_basic::transfer_container &transfers,
    const bool resend_tx_proposals,
    const carrot::cryptonote_hierarchy_address_device &addr_dev);

std::vector<tx_reconstruct_variant_t> get_transaction_proposals_from_unsigned_tx_set(
    const UnsignedTransactionSetVariant &unsigned_txs,
    const std::function<carrot::InputProposalV1(const crypto::public_key&)> &supplemental_input_proposals,
    const carrot::cryptonote_hierarchy_address_device &addr_dev);

/**
 * brief: sign_pre_carrot_tx_set - cold sign an unsigned pre-Carrot transaction set
 * param: unsigned_txs - 
 * param: acc_keys -
 * param: subaddress_map -
 * param: nettype - Monero network type, used solely for debug messages
 * outparam: signed_txs_out - signed pre-Carrot transaction set
 * outparam: tx_keys_out - main ephemeral tx privkeys, indexed by TXID
 * outparam: additional_tx_keys_out - additional ephemeral tx privkeys, indexed by TXID
 *
 * `signed_txs_out` does not contain nether main nor additional ephemeral tx privkeys in its
 * pending transaction list, to prevent the hot wallet from knowing them. It's `key_images`
 * field is also not populated, which should contain key images for the whole cold wallet
 * transfers list.
 */
void sign_pre_carrot_tx_set(const UnsignedPreCarrotTransactionSet &unsigned_txs,
    const cryptonote::account_keys &acc_keys,
    const std::unordered_map<crypto::public_key, cryptonote::subaddress_index> &subaddress_map,
    const cryptonote::network_type nettype,
    SignedFullTransactionSet &signed_txs_out,
    std::unordered_map<crypto::hash, crypto::secret_key> &tx_keys_out,
    std::unordered_map<crypto::hash, std::vector<crypto::secret_key>> &additional_tx_keys_out);
/**
 * brief: sign_carrot_tx_set_v1 - cold sign an unsigned Carrot transaction set
 * param: unsigned_txs -
 * param: supplemental_opening_hints - callback to retrieve opening hints by OTA that aren't present in `unsigned_txs`
 * param: addr_dev -
 * param: spend_dev - device representing k_s
 * outparam: signed_txs_out -
 * outparam: ephemeral_tx_privkeys_out - list of s_sr for tx in enote order, indexed by signable tx hash
 */
void sign_carrot_tx_set_v1(const UnsignedCarrotTransactionSetV1 &unsigned_txs,
    const std::function<carrot::InputProposalV1(const crypto::public_key&)> &supplemental_opening_hints,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    const carrot::spend_device &spend_dev,
    SignedCarrotTransactionSetV1 &signed_txs_out,
    std::unordered_map<crypto::hash, std::vector<crypto::secret_key>> &ephemeral_tx_privkeys_out);
/**
 * brief: finalize_proofs_for_signed_carrot_tx_set_v1 - construct FCMPs and range proofs for signed Carrot/FCMP++ txs
 * param: signed_txs -
 * param: supplemental_tx_proposals -
 * param: supplemental_input_proposals -
 * param: addr_dev -
 * param: tree_cache -
 * param: curve_trees -
 * outparam: expanded_tx_proposals_out -
 * outparam: txs_out -
 */
void finalize_proofs_for_signed_carrot_tx_set_v1(const SignedCarrotTransactionSetV1 &signed_txs,
    const std::function<HotColdCarrotTransactionProposalV1(const crypto::public_key&)> &supplemental_tx_proposals,
    const std::function<carrot::InputProposalV1(const crypto::public_key&)> &supplemental_input_proposals,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    const fcmp_pp::curve_trees::TreeCacheV1 &tree_cache,
    const fcmp_pp::curve_trees::CurveTreesV1 &curve_trees,
    std::vector<carrot::CarrotTransactionProposalV1> &expanded_tx_proposals_out,
    std::vector<cryptonote::transaction> &txs_out);
/**
 * brief: finalize_signed_carrot_tx_set_v1_into_full_set - construct FCMPs and range proofs for signed Carrot/FCMP++ txs
 * param: signed_txs -
 * param: supplemental_tx_proposals -
 * param: supplemental_input_proposals -
 * param: addr_dev -
 * param: tree_cache -
 * param: curve_trees -
 * return: Signed full transaction set with proven Carrot/FCMP++ txs and given SA/Ls
 */
SignedFullTransactionSet finalize_signed_carrot_tx_set_v1_into_full_set(
    const SignedCarrotTransactionSetV1 &signed_txs,
    const std::function<HotColdCarrotTransactionProposalV1(const crypto::public_key&)> &supplemental_tx_proposals,
    const std::function<carrot::InputProposalV1(const crypto::public_key&)> &supplemental_input_proposals,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    const fcmp_pp::curve_trees::TreeCacheV1 &tree_cache,
    const fcmp_pp::curve_trees::CurveTreesV1 &curve_trees);

void prove_key_image_proof(const carrot::OutputOpeningHintVariant &opening_hint,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    const crypto::secret_key &k_spend,
    KeyImageProofVariant &ki_proof_out,
    crypto::key_image &key_image_out);

bool validate_ring_signature_key_image_proof(const crypto::public_key &onetime_address,
    const crypto::key_image &key_image,
    const crypto::signature &ki_proof);

bool validate_fcmp_pp_sal_key_image_proof(const crypto::public_key &onetime_address,
    const crypto::key_image &key_image,
    const fcmp_pp::FcmpPpSalProof &ki_proof);

bool validate_key_image_proof(const crypto::public_key &onetime_address,
    const crypto::key_image &key_image,
    const KeyImageProofVariant &ki_proof);

void encrypt_exported_outputs(const std::uint64_t transfers_offset,
    const std::uint64_t transfers_size,
    const std::vector<exported_transfer_details_variant> &outputs,
    const crypto::public_key &account_spend_pubkey,
    const crypto::secret_key &k_view,
    const std::uint64_t kdf_rounds,
    std::string &payload_out);

void decrypt_exported_outputs(const std::string &payload,
    const crypto::public_key &account_spend_pubkey,
    const crypto::secret_key &k_view,
    const std::uint64_t kdf_rounds,
    std::uint64_t &transfers_offset_out,
    std::uint64_t &transfers_size_out,
    std::vector<exported_transfer_details_variant> &outputs_out);

void encrypt_key_images(const std::uint64_t offset,
    const std::vector<std::pair<crypto::key_image, KeyImageProofVariant>> &key_images,
    const crypto::public_key &account_spend_pubkey,
    const crypto::secret_key &k_view,
    const std::uint64_t kdf_rounds,
    std::string &payload_out);

void decrypt_key_images(const std::string &payload,
    const crypto::public_key &account_spend_pubkey,
    const crypto::secret_key &k_view,
    const std::uint64_t kdf_rounds,
    std::uint64_t &offset_out,
    std::vector<std::pair<crypto::key_image, KeyImageProofVariant>> &key_images_out);

void encrypt_unsigned_tx_set(const UnsignedTransactionSetVariant &unsigned_txs,
    const crypto::secret_key &k_view,
    const std::uint64_t kdf_rounds,
    std::string &payload_out);

void decrypt_unsigned_tx_set(const std::string payload,
    const crypto::secret_key &k_view,
    const std::uint64_t kdf_rounds,
    UnsignedTransactionSetVariant &unsigned_txs_out);

void encrypt_signed_tx_set(const SignedTransactionSetVariant &signed_txs,
    const crypto::secret_key &k_view,
    const std::uint64_t kdf_rounds,
    std::string &payload_out);

void decrypt_signed_tx_set(const std::string payload,
    const crypto::secret_key &k_view,
    const std::uint64_t kdf_rounds,
    SignedTransactionSetVariant &signed_txs_out);

/**
 * brief: perform lexical casts to/from key image proofs
 */
std::string key_image_proof_to_readable_string(const KeyImageProofVariant &ki_proof);
bool try_key_image_proof_from_readable_string(const std::string &str, KeyImageProofVariant &ki_proof_out);

} //namespace cold
} //namespace wallet
} //namespace tools
