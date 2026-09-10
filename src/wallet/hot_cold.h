// Copyright (c) 2025-2026, The Monero Project
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
/**
 * @brief Represents data required to export pre-Carrot UTXOs from hot wallet to cold wallet
 *
 * Previously known as `wallet2::exported_transfer_details`
 */
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

/**
 * @brief Represents data required to export post-Carrot UTXOs from hot wallet to cold wallet
 */
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

/**
 * @brief Variation between any exported UTXO from a hot wallet to a cold wallet
 */
using exported_transfer_details_variant = std::variant<
        exported_pre_carrot_transfer_details,
        exported_carrot_transfer_details
    >;

/**
 * @brief Set of unsigned pre-Carrot transaction intents, as well as UTXOs to import
 *
 * Previously known as `wallet2::unsigned_tx_set`
 */
struct UnsignedPreCarrotTransactionSet
{
    std::vector<PreCarrotTransactionProposal> txes;
    std::tuple<uint64_t, uint64_t, wallet2_basic::transfer_container> transfers;
    std::tuple<uint64_t, uint64_t, std::vector<exported_pre_carrot_transfer_details>> new_transfers;
};

/**
 * @brief Seed of randomness for all random values in a Carrot hot-cold transaction proposal
 */
using HotColdSeed = crypto::hash;

/**
 * @brief Effectively a CarrotPaymentProposalV1, w/o randomness
 */
struct HotColdCarrotPaymentProposalV1
{
    /// user address
    carrot::CarrotDestinationV1 destination;
    /// b
    rct::xmr_amount amount;

    // janus anchor randomness is derived from the hot/cold seed
};

/**
 * @brief Effectively a CarrotPaymentProposalVerifiableSelfSendV1, w/o randomness nor derive type
 */
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

/**
 * @brief Effectively a CarrotTransactionProposalV1, w/ compressed randomness
 */
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

/**
 * @brief Set of unsigned post-Carrot transaction intents, as well as UTXOs to import
 */
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

/**
 * @brief Variation between any set of unsigned transaction intents
 */
using UnsignedTransactionSetVariant = std::variant<
        UnsignedPreCarrotTransactionSet,
        UnsignedCarrotTransactionSetV1
    >;
std::size_t num_unsigned_txs_ref(const UnsignedTransactionSetVariant&);
std::size_t num_new_outputs_ref(const UnsignedTransactionSetVariant&);

/**
 * @brief Set of fully-proved (incl. membership) transactions and key images to import
 */
struct SignedFullTransactionSet
{
    std::vector<pending_tx> ptx;
    std::vector<crypto::key_image> key_images;
    std::unordered_map<crypto::public_key, crypto::key_image> tx_key_images;
};

/**
 * @brief Set of FCMP++ SA/L signatures for given post-Carrot tx intents, and key images to import
 */
struct SignedCarrotTransactionSetV1
{
    std::vector<HotColdCarrotTransactionProposalV1> tx_proposals;

    carrot::spend_device::signed_input_set_t signed_inputs;

    std::unordered_map<crypto::public_key, std::pair<crypto::key_image, carrot::KeyImageProofVariant>> other_key_images;
};

/**
 * @brief Variation between any set of signed (fully or not) tx intents, and key images to import
 */
using SignedTransactionSetVariant = std::variant<
        SignedFullTransactionSet,
        SignedCarrotTransactionSetV1
    >;

/**
 * @brief Convert transfer details for pre-Carrot UTXO into compressed export form
 * @param td transfer details entry representing pre-Carrot UTXO
 * @return compressed pre-Carrot exported output
 */
exported_pre_carrot_transfer_details export_cold_pre_carrot_output(const wallet2_basic::transfer_details &td);
/**
 * @brief Convert transfer details for post-Carrot UTXO into compressed export form
 * @param td transfer details entry representing post-Carrot UTXO
 * @return compressed post-Carrot exported output
 */
exported_carrot_transfer_details export_cold_carrot_output(const wallet2_basic::transfer_details &td,
    const carrot::cryptonote_hierarchy_address_device &addr_dev);
/**
 * @brief Convert transfer details for any type UTXO into compressed export form
 * @param td transfer details entry
 * @return compressed exported output
 */
exported_transfer_details_variant export_cold_output(const wallet2_basic::transfer_details &td,
    const carrot::cryptonote_hierarchy_address_device &addr_dev);
/**
 * @brief Convert compressed pre-Carrot exported output into expanded transfer details, and calculate key image
 * @param etd compressed pre-Carrot exported output
 * @param addr_dev address device
 * @param key_image_dev key image device (optional)
 * @return expanded transfer details, with key image filled in
 */
wallet2_basic::transfer_details import_cold_pre_carrot_output(const exported_pre_carrot_transfer_details &etd,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    const carrot::key_image_device *key_image_dev);
/**
 * @brief Convert compressed post-Carrot exported output into expanded transfer details, and calculate key image
 * @param etd compressed post-Carrot exported output
 * @param addr_dev address device
 * @param key_image_dev key image device (optional)
 * @return expanded transfer details, with key image filled in
 */
wallet2_basic::transfer_details import_cold_carrot_output(const exported_carrot_transfer_details &etd,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    const carrot::key_image_device *key_image_dev);
/**
 * @brief Convert compressed any type exported output into expanded transfer details, and calculate key image
 * @param etd compressed exported output
 * @param addr_dev address device
 * @param key_image_dev key image device (optional)
 * @return expanded transfer details, with key image filled in
 */
wallet2_basic::transfer_details import_cold_output(const exported_transfer_details_variant &etd,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    const carrot::key_image_device *key_image_dev);
/**
 * @brief Convert Carrot transaction intent into compressed hot-cold form, losing random fields
 * @param tx_proposal
 * @param hot_cold_seed Hot-Cold seed to be used for returned Hot-Cold proposal
 * @return compressed Hot-Cold transaction intent w/ `hot_cold_seed` as randomness
 */
HotColdCarrotTransactionProposalV1 compress_carrot_transaction_proposal_lossy(
    const carrot::CarrotTransactionProposalV1 &tx_proposal,
    const HotColdSeed &hot_cold_seed);
/**
 * @brief Make fetcher which looks up input proposals by one-time address, from existing list of transfer details
 */
std::function<carrot::InputProposalV1(const crypto::public_key&)> make_supplemental_input_proposals_fetcher(
    const wallet2_basic::transfer_container &transfers);
/**
 * @brief Convert Hot-Cold Carrot transaction intent into expanded Carrot transaction intent
 * @param tx_proposal compressed Hot-Cold transaction intent
 * @param supplemental_input_proposals fetcher of one-time address -> input proposal
 * @param addr_dev address device
 * @param tx_proposal_out expanded Carrot transaction intent
 */
void expand_carrot_transaction_proposal(const HotColdCarrotTransactionProposalV1 &tx_proposal,
    const std::function<carrot::InputProposalV1(const crypto::public_key&)> &supplemental_input_proposals,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    carrot::CarrotTransactionProposalV1 &tx_proposal_out);
/**
 * @brief Convert all Hot-Cold Carrot transaction intents in unsigned tx set into expanded Carrot transaction intents
 * @param unsigned_txs set of unsigned Hot-Cold Carrot transaction intents
 * @param supplemental_input_proposals fetcher of one-time address -> input proposal
 * @param addr_dev address device
 * @param tx_proposals_out expanded Carrot transaction intents
 */
void expand_carrot_transaction_proposals(const UnsignedCarrotTransactionSetV1 &unsigned_txs,
    const std::function<carrot::InputProposalV1(const crypto::public_key&)> &supplemental_input_proposals,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    std::vector<carrot::CarrotTransactionProposalV1> &tx_proposals_out);
/**
 * @brief Expand Hot-Cold Carrot transaction intents, and calculate key images and rerandomized outputs
 * @param tx_proposal compressed Hot-Cold transaction intent
 * @param supplemental_input_proposals fetcher of one-time address -> input proposal
 * @param addr_dev address device
 * @param key_image_dev key image device for known one-time addresses (see below)
 *
 * @see expand_carrot_transaction_proposal()
 *
 * The key image device will only be called for opening hints corresponding to one-time addresses
 * in `tx_proposal`. On the hot side, this means that the hot wallet can pass a
 * `carrot::key_image_device_precompted` device since it should know the one-time address -> key
 * image association after receiving the signed tx set.
 */
void expand_carrot_transaction_proposal_and_rerandomized_outputs(
    const HotColdCarrotTransactionProposalV1 &tx_proposal,
    const std::function<carrot::InputProposalV1(const crypto::public_key&)> &supplemental_input_proposals,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    const carrot::key_image_device &key_image_dev,
    carrot::CarrotTransactionProposalV1 &tx_proposal_out,
    std::vector<crypto::key_image> &input_key_images_out,
    std::vector<FcmpRerandomizedOutputCompressed> &rerandomized_outputs_out);
/**
 * @brief Generate a set of unsigned transaction intents from a lis of `pending_tx` entries
 * @param ptxs pending tx entries, returned from e.g. `make_pending_carrot_tx()`
 * @param transfers existing list of transfer detail entries
 * @param resend_tx_proposals sets `resend_tx_proposals` field of unsigned tx set, if applicable
 * @param addr_dev address device
 * @return set of unsigned transaction intents contained in `ptxs`, and outputs to export
 */
UnsignedTransactionSetVariant generate_unsigned_tx_set_from_pending_txs(
    const std::vector<pending_tx> &ptxs,
    const wallet2_basic::transfer_container &transfers,
    const bool resend_tx_proposals,
    const carrot::cryptonote_hierarchy_address_device &addr_dev);
/**
 * @brief Extracts transaction intent varations from variation of set of unsigned txs
 * @param unsigned_txs variation of set of unsigned txs
 * @param supplemental_input_proposals fetcher of one-time address -> input proposal
 * @param addr_dev address device
 * @return list of variations of transaction intents
 *
 * Useful for enumerating human-meaningful details of unsigned tx set before signing.
 */
std::vector<tx_reconstruct_variant_t> get_transaction_proposals_from_unsigned_tx_set(
    const UnsignedTransactionSetVariant &unsigned_txs,
    const std::function<carrot::InputProposalV1(const crypto::public_key&)> &supplemental_input_proposals,
    const carrot::cryptonote_hierarchy_address_device &addr_dev);
/**
 * @brief Cold sign an unsigned pre-Carrot transaction set
 * @param unsigned_txs -
 * @param acc_keys -
 * @param subaddress_map -
 * @param nettype - Monero network type, used solely for debug messages
 * @param[out] signed_txs_out - signed pre-Carrot transaction set
 * @param[out] tx_keys_out - main ephemeral tx privkeys, indexed by TXID
 * @param[out] additional_tx_keys_out - additional ephemeral tx privkeys, indexed by TXID
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
 * @brief Cold sign an unsigned Carrot transaction set
 * @param unsigned_txs -
 * @param supplemental_opening_hints - callback to retrieve opening hints by OTA that aren't present in `unsigned_txs`
 * @param addr_dev -
 * @param spend_dev - device representing k_s
 * @param[out] signed_txs_out -
 * @param[out] ephemeral_tx_privkeys_out - list of s_sr for tx in enote order, indexed by signable tx hash
 */
void sign_carrot_tx_set_v1(const UnsignedCarrotTransactionSetV1 &unsigned_txs,
    const std::function<carrot::InputProposalV1(const crypto::public_key&)> &supplemental_opening_hints,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    const carrot::spend_device &spend_dev,
    SignedCarrotTransactionSetV1 &signed_txs_out,
    std::unordered_map<crypto::hash, std::vector<crypto::secret_key>> &ephemeral_tx_privkeys_out);
/**
 * @brief Construct FCMPs and range proofs for signed Carrot/FCMP++ txs
 * @param signed_txs -
 * @param supplemental_tx_proposals fetcher of one-time address -> tx proposal
 * @param supplemental_input_proposals fetcher of one-time address -> input proposal
 * @param addr_dev -
 * @param tree_cache -
 * @param curve_trees -
 * @param[out] expanded_tx_proposals_out -
 * @param[out] rerandomized_outputs_out -
 * @param[out] txs_out -
 */
void finalize_proofs_for_signed_carrot_tx_set_v1(const SignedCarrotTransactionSetV1 &signed_txs,
    const std::function<HotColdCarrotTransactionProposalV1(const crypto::public_key&)> &supplemental_tx_proposals,
    const std::function<carrot::InputProposalV1(const crypto::public_key&)> &supplemental_input_proposals,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    const fcmp_pp::curve_trees::TreeCacheV1 &tree_cache,
    const fcmp_pp::curve_trees::CurveTreesV1 &curve_trees,
    std::vector<carrot::CarrotTransactionProposalV1> &expanded_tx_proposals_out,
    std::vector<std::vector<FcmpRerandomizedOutputCompressed>> &rerandomized_outputs_out,
    std::vector<cryptonote::transaction> &txs_out);
/**
 * @brief Construct FCMPs and range proofs for signed Carrot/FCMP++ txs
 * @param signed_txs -
 * @param supplemental_tx_proposals -
 * @param supplemental_input_proposals -
 * @param addr_dev -
 * @param tree_cache -
 * @param curve_trees -
 * @param[out] ki_proofs_out explicit key image proofs from the signed tx set, as well as signed inputs
 * @return Signed full transaction set with proven Carrot/FCMP++ txs and given SA/Ls
 */
SignedFullTransactionSet finalize_signed_carrot_tx_set_v1_into_full_set(
    const SignedCarrotTransactionSetV1 &signed_txs,
    const std::function<HotColdCarrotTransactionProposalV1(const crypto::public_key&)> &supplemental_tx_proposals,
    const std::function<carrot::InputProposalV1(const crypto::public_key&)> &supplemental_input_proposals,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    const fcmp_pp::curve_trees::TreeCacheV1 &tree_cache,
    const fcmp_pp::curve_trees::CurveTreesV1 &curve_trees,
    std::unordered_map<crypto::public_key, std::pair<crypto::key_image, carrot::KeyImageProofVariant>> &ki_proofs_out);
/**
 * @brief Encode and encrypt (to k_v) exported output information
 * @param transfers_offset index into transfers list that export starts at
 * @param transfers_size size of local transfers list
 * @param outputs exported outputs
 * @param account_spend_pubkey K_s
 * @param k_view k_v
 * @param kdf_rounds KDF rounds for encryption key (standard is 1)
 * @param[out] payload_out encrypted message containing `transfers_offset`, `transfers_size`, `outputs`, and K_s
 */
void encrypt_exported_outputs(const std::uint64_t transfers_offset,
    const std::uint64_t transfers_size,
    const std::vector<exported_transfer_details_variant> &outputs,
    const crypto::public_key &account_spend_pubkey,
    const crypto::secret_key &k_view,
    const std::uint64_t kdf_rounds,
    std::string &payload_out);
/**
 * @brief Decrypt (to k_v) and decode exported output information
 * @param payload encrypted message containing `transfers_offset`, `transfers_size`, `outputs`, and K_s
 * @param account_spend_pubkey K_s (for verification)
 * @param k_view k_v
 * @param kdf_rounds KDF rounds for encryption key (standard is 1)
 * @param[out] transfers_offset_out index into transfers list that export starts at
 * @param[out] transfers_size_out size of local transfers list
 * @param[out] outputs_out exported outputs
 *
 * Backwards compatible with v4 outputs format
 */
void decrypt_exported_outputs(const std::string &payload,
    const crypto::public_key &account_spend_pubkey,
    const crypto::secret_key &k_view,
    const std::uint64_t kdf_rounds,
    std::uint64_t &transfers_offset_out,
    std::uint64_t &transfers_size_out,
    std::vector<exported_transfer_details_variant> &outputs_out);
/**
 * @brief Encode and encrypt (to k_v) key image association proofs
 * @param offset index into some transfer details list that the key image list starts at [OPTIONAL]
 * @param key_image_proofs list of key images and their one-time address association proofs
 * @param account_spend_pubkey K_s
 * @param k_view k_v
 * @param kdf_rounds KDF rounds for encryption key (standard is 1)
 * @param[out] payload_out encrypted message containing `key_image_proofs`, and K_s
 */
void encrypt_key_image_proofs(const std::uint64_t offset,
    const std::vector<std::pair<crypto::key_image, carrot::KeyImageProofVariant>> &key_image_proofs,
    const crypto::public_key &account_spend_pubkey,
    const crypto::secret_key &k_view,
    const std::uint64_t kdf_rounds,
    std::string &payload_out);
/**
 * @brief Decrypt (to k_v) and decode key image association proofs
 * @param payload encrypted message containing `key_image_proofs`, and K_s
 * @param account_spend_pubkey K_s (for verification)
 * @param k_view k_v
 * @param kdf_rounds KDF rounds for encryption key (standard is 1)
 * @param[out] offset_out index into some transfer details list that the key image list starts at
 * @param[out] key_image_proofs_out list of key images and their one-time address association proofs
 *
 * Backwards compatible with v3 key image format
 */
void decrypt_key_image_proofs(const std::string &payload,
    const crypto::public_key &account_spend_pubkey,
    const crypto::secret_key &k_view,
    const std::uint64_t kdf_rounds,
    std::uint64_t &offset_out,
    std::vector<std::pair<crypto::key_image, carrot::KeyImageProofVariant>> &key_image_proofs_out);
/**
 * @brief Encode and encrypt (to k_v) unsigned transaction set
 * @param unsigned_txs
 * @param k_view k_v
 * @param kdf_rounds KDF rounds for encryption key (standard is 1)
 * @param[out] payload_out encrypted message containing `unsigned_txs`
 */
void encrypt_unsigned_tx_set(const UnsignedTransactionSetVariant &unsigned_txs,
    const crypto::secret_key &k_view,
    const std::uint64_t kdf_rounds,
    std::string &payload_out);
/**
 * @brief Decrypt (to k_v) and decode unsigned transaction set
 * @param payload encrypted message containing `unsigned_txs`
 * @param k_view k_v
 * @param kdf_rounds KDF rounds for encryption key (standard is 1)
 * @param[out] unsigned_txs_out
 *
 * Backwards compatible with v2 unsigned transaction set format
 */
void decrypt_unsigned_tx_set(const std::string payload,
    const crypto::secret_key &k_view,
    const std::uint64_t kdf_rounds,
    UnsignedTransactionSetVariant &unsigned_txs_out);
/**
 * @brief Encode and encrypt (to k_v) signed transaction set
 * @param signed_txs
 * @param k_view k_v
 * @param kdf_rounds KDF rounds for encryption key (standard is 1)
 * @param[out] payload_out encrypted message containing `signed_txs`
 */
void encrypt_signed_tx_set(const SignedTransactionSetVariant &signed_txs,
    const crypto::secret_key &k_view,
    const std::uint64_t kdf_rounds,
    std::string &payload_out);
/**
 * @brief Decrypt (to k_v) and decode signed transaction set
 * @param payload encrypted message containing `signed_txs`
 * @param k_view k_v
 * @param kdf_rounds KDF rounds for encryption key (standard is 1)
 * @param[out] signed_txs_out
 *
 * Backwards compatible with v0 signed transaction set format
 */
void decrypt_signed_tx_set(const std::string payload,
    const crypto::secret_key &k_view,
    const std::uint64_t kdf_rounds,
    SignedTransactionSetVariant &signed_txs_out);

} //namespace cold
} //namespace wallet
} //namespace tools
