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

//paired header
#include "hot_cold.h"

//local headers
#include "carrot_core/config.h"
#include "carrot_core/core_types.h"
#include "carrot_core/enote_utils.h"
#include "carrot_core/exceptions.h"
#include "carrot_core/hash_functions.h"
#include "carrot_core/scan.h"
#include "carrot_core/scan_unsafe.h"
#include "carrot_core/transcript_fixed.h"
#include "carrot_impl/address_device_ram_borrowed.h"
#include "carrot_impl/address_utils.h"
#include "carrot_impl/carrot_offchain_serialization.h"
#include "carrot_impl/format_utils.h"
#include "carrot_impl/key_image_device_composed.h"
#include "carrot_impl/key_image_device_precomputed.h"
#include "carrot_impl/output_opening_types.h"
#include "carrot_impl/tx_builder_inputs.h"
#include "carrot_impl/tx_builder_outputs.h"
#include "carrot_impl/tx_proposal.h"
#include "common/apply_permutation.h"
#include "common/va_args.h"
#include "crypto/crypto.h"
#include "crypto/generators.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "fcmp_pp/fcmp_pp_types.h"
#include "fcmp_pp/prove.h"
#include "hot_cold_serialization.h"
#include "misc_wallet_utils.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "serialization/binary_utils.h"
#include "scanning_tools.h"
#include "wallet_errors.h"

//third party headers

//standard headers
#include <string_view>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.hot_cold"

namespace tools
{
namespace wallet
{
namespace cold
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static constexpr std::string_view OUTPUT_EXPORT_FILE_MAGIC = "Monero output export";
static constexpr std::string_view KEY_IMAGE_EXPORT_FILE_MAGIC = "Monero key image export";
static constexpr std::string_view UNSIGNED_TX_PREFIX = "Monero unsigned tx set";
static constexpr std::string_view SIGNED_TX_PREFIX = "Monero signed tx set";
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static crypto::hash make_contextualized_sender_receiver_secret(
    const carrot::view_incoming_key_device &k_view_incoming_dev,
    const mx25519_pubkey &enote_ephemeral_pubkey,
    const carrot::input_context_t &input_context)
{
    // s_sr = k_v D_e
    mx25519_pubkey s_sender_receiver;
    CARROT_CHECK_AND_THROW(carrot::try_make_carrot_shared_key_receiver(k_view_incoming_dev,
            enote_ephemeral_pubkey,
            s_sender_receiver),
        carrot::invalid_point, "Could not make receiver-side ECDH");

    // s^ctx_sr = H_32(s_sr, D_e, input_context)
    crypto::hash s_sender_receiver_ctx;
    carrot::make_carrot_contextualized_sender_receiver_secret(s_sender_receiver.data,
        enote_ephemeral_pubkey,
        input_context,
        s_sender_receiver_ctx);

    return s_sender_receiver_ctx;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool decrypt_and_test_anchor(const carrot::encrypted_janus_anchor_t &encrypted_janus_anchor,
    const crypto::hash &s_sender_receiver,
    const crypto::public_key &onetime_address,
    const mx25519_pubkey &enote_ephemeral_pubkey,
    const crypto::key_image &tx_first_key_image,
    const carrot::view_incoming_key_device &k_view_incoming_dev,
    carrot::janus_anchor_t &janus_anchor_out)
{
    // decrypt janus anchor and test if enote is a special enote

    // anchor = anchor_enc XOR m_anchor
    janus_anchor_out = carrot::decrypt_carrot_anchor(encrypted_janus_anchor, s_sender_receiver, onetime_address);

    return carrot::verify_carrot_special_janus_protection(tx_first_key_image,
        enote_ephemeral_pubkey,
        onetime_address,
        k_view_incoming_dev,
        janus_anchor_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static HotColdCarrotPaymentProposalV1 compress_carrot_normal_payment_proposal_lossy(
    const carrot::CarrotPaymentProposalV1 &payment_proposal)
{
    return HotColdCarrotPaymentProposalV1{
        .destination = payment_proposal.destination,
        .amount = payment_proposal.amount
    };
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static HotColdCarrotPaymentProposalVerifiableSelfSendV1 compress_carrot_selfsend_payment_proposal_lossy(
    const carrot::CarrotPaymentProposalVerifiableSelfSendV1 &payment_proposal)
{
    return HotColdCarrotPaymentProposalVerifiableSelfSendV1{
        .subaddr_index = payment_proposal.subaddr_index.index,
        .amount = payment_proposal.proposal.amount,
        .enote_type = payment_proposal.proposal.enote_type
    };
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static carrot::CarrotPaymentProposalV1 expand_carrot_normal_payment_proposal(
    const HotColdCarrotPaymentProposalV1 &payment_proposal,
    const HotColdSeed &hot_cold_seed,
    const std::uint8_t payment_proposal_idx)
{
    // anchor_norm = DeriveBytes16(seed, i)
    const auto anchor_transcript = carrot::make_fixed_transcript<carrot::HOT_COLD_DOMAIN_SEP_NORMAL_JANUS_ANCHOR>(
        payment_proposal_idx);
    carrot::janus_anchor_t anchor_randomness;
    carrot::derive_bytes_16(anchor_transcript.data(), anchor_transcript.size(), &hot_cold_seed, &anchor_randomness);

    return carrot::CarrotPaymentProposalV1{
        .destination = payment_proposal.destination,
        .amount = payment_proposal.amount,
        .randomness = anchor_randomness
    };
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static carrot::CarrotPaymentProposalVerifiableSelfSendV1 expand_carrot_selfsend_payment_proposal(
    const HotColdCarrotPaymentProposalVerifiableSelfSendV1 &payment_proposal,
    const HotColdSeed &hot_cold_seed,
    const std::uint8_t payment_proposal_idx,
    const carrot::AddressDeriveType addr_derive_type,
    const carrot::cryptonote_hierarchy_address_device &addr_dev)
{
    // d_e = DeriveScalar(seed, i)
    const auto ephemeral_pubkey_transcript = carrot::make_fixed_transcript<carrot::HOT_COLD_DOMAIN_SEP_SPECIAL_EPHEM>(
        payment_proposal_idx);
    crypto::secret_key ephemeral_privkey;
    carrot::derive_scalar(ephemeral_pubkey_transcript.data(),
        ephemeral_pubkey_transcript.size(),
        &hot_cold_seed,
        &ephemeral_privkey);

    // D_e = d_e B
    mx25519_pubkey enote_ephemeral_pubkey;
    carrot::make_carrot_enote_ephemeral_pubkey_cryptonote(ephemeral_privkey, enote_ephemeral_pubkey);

    // K^j_s = K_s + k^j_subext G
    crypto::public_key address_spend_pubkey;
    addr_dev.get_address_spend_pubkey({payment_proposal.subaddr_index}, address_spend_pubkey);

    return carrot::CarrotPaymentProposalVerifiableSelfSendV1{
        .proposal = carrot::CarrotPaymentProposalSelfSendV1{
            .destination_address_spend_pubkey = address_spend_pubkey,
            .amount = payment_proposal.amount,
            .enote_type = payment_proposal.enote_type,
            .enote_ephemeral_pubkey = enote_ephemeral_pubkey
        },
        .subaddr_index = carrot::subaddress_index_extended{
            .index = payment_proposal.subaddr_index,
            .derive_type = addr_derive_type
        }
    };
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static carrot::encrypted_payment_id_t expand_dummy_encrypted_payment_id(const HotColdSeed &hot_cold_seed)
{
    // pid_enc = DeriveBytes8(seed)
    const auto enc_pid_transcript = carrot::make_fixed_transcript<carrot::HOT_COLD_DOMAIN_SEP_DUMMY_PID>();
    carrot::encrypted_payment_id_t dummy_encrypted_payment_id;
    carrot::derive_bytes_8(enc_pid_transcript.data(),
        enc_pid_transcript.size(),
        &hot_cold_seed,
        &dummy_encrypted_payment_id);
    return dummy_encrypted_payment_id;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static carrot::CarrotTransactionProposalV1 expand_carrot_transaction_proposal(
    const HotColdCarrotTransactionProposalV1 &tx_proposal,
    std::vector<carrot::InputProposalV1> &&input_proposals,
    const carrot::cryptonote_hierarchy_address_device &addr_dev)
{
    const HotColdSeed &hot_cold_seed = tx_proposal.hot_cold_seed;

    const std::size_t n_inputs = tx_proposal.input_onetime_addresses.size();
    CARROT_CHECK_AND_THROW(input_proposals.size() == n_inputs,
        carrot::component_out_of_order, "wrong number of input proposals for tx input one-time addresses");

    // check OTAs of input proposals
    for (std::size_t input_idx = 0; input_idx < n_inputs; ++input_idx)
    {
        const bool same_ota = onetime_address_ref(input_proposals.at(input_idx))
            == tx_proposal.input_onetime_addresses.at(input_idx);
        CARROT_CHECK_AND_THROW(same_ota,
            carrot::component_out_of_order, "mismatched one-time address in provided input proposals");
    }

    std::vector<carrot::CarrotPaymentProposalV1> normal_payment_proposals;
    normal_payment_proposals.reserve(tx_proposal.normal_payment_proposals.size());
    for (std::size_t payment_idx = 0; payment_idx < tx_proposal.normal_payment_proposals.size(); ++payment_idx)
    {
        const HotColdCarrotPaymentProposalV1 &p = tx_proposal.normal_payment_proposals.at(payment_idx);
        normal_payment_proposals.push_back(expand_carrot_normal_payment_proposal(p, hot_cold_seed, payment_idx));
    }

    std::vector<carrot::CarrotPaymentProposalVerifiableSelfSendV1> selfsend_payment_proposals;
    selfsend_payment_proposals.reserve(tx_proposal.selfsend_payment_proposals.size());
    for (std::size_t payment_idx = 0; payment_idx < tx_proposal.selfsend_payment_proposals.size(); ++payment_idx)
    {
        selfsend_payment_proposals.push_back(expand_carrot_selfsend_payment_proposal(
            tx_proposal.selfsend_payment_proposals.at(payment_idx),
            hot_cold_seed,
            payment_idx,
            tx_proposal.addr_derive_type,
            addr_dev));
    }

    // erase the random D_e for the last selfsend in a 2-out tx
    const std::size_t n_outputs = normal_payment_proposals.size() + selfsend_payment_proposals.size();
    CARROT_CHECK_AND_THROW(!selfsend_payment_proposals.empty(),
        carrot::too_few_outputs, "hot/cold transaction proposal doesn't contain any selfsend proposals");
    if (n_outputs == 2)
        selfsend_payment_proposals.back().proposal.enote_ephemeral_pubkey.reset();

    const carrot::encrypted_payment_id_t dummy_encrypted_payment_id = expand_dummy_encrypted_payment_id(hot_cold_seed);

    return carrot::CarrotTransactionProposalV1{
        .input_proposals = std::move(input_proposals),
        .normal_payment_proposals = std::move(normal_payment_proposals),
        .selfsend_payment_proposals = std::move(selfsend_payment_proposals),
        .dummy_encrypted_payment_id = dummy_encrypted_payment_id,
        .fee = tx_proposal.fee,
        .extra = tx_proposal.extra
    };
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static rct::key expand_rerandomization_scalar(const HotColdSeed &hot_cold_seed,
    const std::uint16_t input_idx,
    const unsigned char type)
{
    const auto transcript = carrot::make_fixed_transcript<carrot::HOT_COLD_DOMAIN_SEP_RERANDOMIZATION>(input_idx, type);
    rct::key rerandomization_scalar;
    carrot::derive_scalar(transcript.data(), transcript.size(), &hot_cold_seed, &rerandomization_scalar);
    return rerandomization_scalar;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
struct RerandomizationScalars
{
    rct::key r_o;
    rct::key r_i;
    rct::key r_r_i;
    rct::key r_c;
};
static std::vector<RerandomizationScalars> expand_rerandomization_scalars(const HotColdSeed &hot_cold_seed,
    const std::size_t n_inputs)
{
    enum rerandomization_type: char { r_o = 'o', r_i = 'i', r_r_i = 'r', r_c = 'c' };
    std::vector<RerandomizationScalars> rerandomizations(n_inputs);
    for (std::uint16_t input_idx = 0; input_idx < rerandomizations.size(); ++input_idx)
    {
        RerandomizationScalars &rerandomization = rerandomizations[input_idx];
        rerandomization.r_o   = expand_rerandomization_scalar(hot_cold_seed, input_idx, r_o);
        rerandomization.r_i   = expand_rerandomization_scalar(hot_cold_seed, input_idx, r_i);
        rerandomization.r_r_i = expand_rerandomization_scalar(hot_cold_seed, input_idx, r_r_i);
        rerandomization.r_c   = expand_rerandomization_scalar(hot_cold_seed, input_idx, r_c);
    }
    return rerandomizations;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::function<carrot::InputProposalV1(const crypto::public_key&)> extend_supplemental_input_proposals_fetcher(
    const std::function<carrot::InputProposalV1(const crypto::public_key&)> &supplemental_input_proposals,
    const UnsignedCarrotTransactionSetV1 &unsigned_txs,
    const carrot::cryptonote_hierarchy_address_device &addr_dev)
{
    // fake key image device
    struct dummy_key_image_device final: public carrot::key_image_device
    {
        crypto::key_image derive_key_image(const carrot::OutputOpeningHintVariant&) const final
        { return {}; }
        crypto::key_image derive_key_image_prescanned(const crypto::secret_key &,
            const crypto::public_key &,
            const carrot::subaddress_index_extended &,
            const bool) const final
        { return {}; }
    };

    // collect new in-set transfers by one-time address (w/o correct key images)
    std::unordered_map<crypto::public_key, carrot::InputProposalV1> inset_input_proposals;
    for (const exported_transfer_details_variant &etd : unsigned_txs.new_transfers)
    {
        const wallet2_basic::transfer_details td = import_cold_output(etd, addr_dev, dummy_key_image_device());
        inset_input_proposals.emplace(td.get_public_key(), make_sal_opening_hint_from_transfer_details(td));
    }

    // try to find in-set first, then use backup supplemental callback
    return [&, inset_input_proposals](const crypto::public_key &ota) -> carrot::InputProposalV1
    {
        const auto inset_it = inset_input_proposals.find(ota);
        if (inset_it != inset_input_proposals.cend())
            return inset_it->second;
        return supplemental_input_proposals(ota);
    };
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static crypto::hash ki2hash(const crypto::key_image &ki)
{
    return carrot::raw_byte_convert<crypto::hash>(ki);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static FcmpRerandomizedOutputCompressed ota_to_ki_proof_rerand_out(const crypto::public_key &onetime_address,
    const bool use_biased_hash_to_point)
{
    // I = Hp(O)
    crypto::ec_point I;
    crypto::derive_key_image_generator(onetime_address, use_biased_hash_to_point, I);

    // r_o = r_i = r_r_i = r_c = 0
    FcmpRerandomizedOutputCompressed o{};
    // O~ = O
    memcpy(o.input.O_tilde, onetime_address.data, sizeof(o.input.O_tilde));
    // I~ = I
    memcpy(o.input.I_tilde, I.data, sizeof(o.input.I_tilde));
    // R = 0
    memcpy(o.input.R, rct::I.bytes, sizeof(o.input.R));
    // C~ = 0
    memcpy(o.input.C_tilde, rct::I.bytes, sizeof(o.input.C_tilde));
    return o;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void prove_ring_signature_key_image_proof(const crypto::secret_key &x,
    crypto::signature &ki_proof_out,
    crypto::key_image &key_image_out)
{
    // O = x G
    crypto::public_key onetime_address;
    crypto::secret_key_to_public_key(x, onetime_address);

    // L = x Hp(O)
    crypto::generate_key_image(onetime_address, x, key_image_out);

    crypto::generate_ring_signature(ki2hash(key_image_out), key_image_out, {&onetime_address}, x, 0, &ki_proof_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void prove_fcmp_sal_key_image_proof(const crypto::secret_key &x,
    const crypto::secret_key &y,
    const bool use_biased_hash_to_point,
    fcmp_pp::FcmpPpSalProof &ki_proof_out,
    crypto::key_image &key_image_out)
{
    // O = x G + y T
    crypto::public_key onetime_address;
    crypto::secret_key_to_public_key(x, onetime_address);
    onetime_address = rct::rct2pk(rct::addKeys(rct::pk2rct(onetime_address),
        rct::scalarmultKey(rct::pk2rct(crypto::get_T()), rct::sk2rct(y))));

    // L = x Hp(O)
    crypto::derive_key_image_generator(onetime_address, use_biased_hash_to_point, key_image_out);
    key_image_out = rct::rct2ki(rct::scalarmultKey(rct::pt2rct(key_image_out), rct::sk2rct(x)));

    std::tie(ki_proof_out, key_image_out) = fcmp_pp::prove_sal(ki2hash(key_image_out),
        x, y, ota_to_ki_proof_rerand_out(onetime_address, use_biased_hash_to_point));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const exported_pre_carrot_transfer_details &a, const exported_pre_carrot_transfer_details &b)
{
    return a.m_pubkey                == b.m_pubkey
        && a.m_internal_output_index == b.m_internal_output_index
        && a.m_global_output_index   == b.m_global_output_index
        && a.m_flags.flags           == b.m_flags.flags
        && a.m_amount                == b.m_amount
        && a.m_additional_tx_keys    == b.m_additional_tx_keys
        && a.m_subaddr_index_major   == b.m_subaddr_index_major
        && a.m_subaddr_index_minor   == b.m_subaddr_index_minor;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const exported_carrot_transfer_details &a, const exported_carrot_transfer_details &b)
{
    return a.flags.flags        == b.flags.flags
        && a.block_index        == b.block_index
        && a.tx_first_key_image == b.tx_first_key_image
        && a.subaddr_index      == b.subaddr_index
        && a.payment_id         == b.payment_id
        && a.amount             == b.amount
        && a.janus_anchor       == b.janus_anchor
        && memcmp(&a.selfsend_enote_ephemeral_pubkey, &b.selfsend_enote_ephemeral_pubkey, sizeof(mx25519_pubkey)) == 0;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t num_unsigned_txs_ref(const UnsignedTransactionSetVariant &v)
{
    struct num_unsigned_txs_ref_visitor
    {
        std::size_t operator()(const UnsignedPreCarrotTransactionSet &x) const { return x.txes.size(); }
        std::size_t operator()(const UnsignedCarrotTransactionSetV1 &x) const { return x.tx_proposals.size(); }
    };

    return std::visit(num_unsigned_txs_ref_visitor{}, v);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t num_new_outputs_ref(const UnsignedTransactionSetVariant &v)
{
    struct num_new_outputs_ref_visitor
    {
        std::size_t operator()(const UnsignedPreCarrotTransactionSet &x) const {
            return std::get<2>(x.transfers).size() + std::get<2>(x.new_transfers).size(); }
        std::size_t operator()(const UnsignedCarrotTransactionSetV1 &x) const { return x.new_transfers.size(); }
    };

    return std::visit(num_new_outputs_ref_visitor{}, v);
}
//-------------------------------------------------------------------------------------------------------------------
exported_pre_carrot_transfer_details export_cold_pre_carrot_output(const wallet2_basic::transfer_details &td)
{
    CARROT_CHECK_AND_THROW(!carrot::is_carrot_transaction_v1(td.m_tx),
        carrot::component_out_of_order, "Cannot export carrot output as pre-carrot output");
    exported_pre_carrot_transfer_details etd{};
    etd.m_pubkey = td.get_public_key();
    etd.m_tx_pubkey = cryptonote::get_tx_pub_key_from_extra(td.m_tx, td.m_pk_index);
    etd.m_internal_output_index = td.m_internal_output_index;
    etd.m_global_output_index = td.m_global_output_index;
    etd.m_flags.flags = 0;
    etd.m_flags.m_spent = td.m_spent;
    etd.m_flags.m_frozen = td.m_frozen;
    etd.m_flags.m_rct = td.m_rct;
    etd.m_flags.m_key_image_known = td.m_key_image_known;
    etd.m_flags.m_key_image_request = td.m_key_image_request;
    etd.m_flags.m_key_image_partial = td.m_key_image_partial;
    etd.m_amount = td.m_amount;
    etd.m_additional_tx_keys = cryptonote::get_additional_tx_pub_keys_from_extra(td.m_tx);
    etd.m_subaddr_index_major = td.m_subaddr_index.major;
    etd.m_subaddr_index_minor = td.m_subaddr_index.minor;
    return etd;
}
//-------------------------------------------------------------------------------------------------------------------
exported_carrot_transfer_details export_cold_carrot_output(const wallet2_basic::transfer_details &td,
    const carrot::cryptonote_hierarchy_address_device &addr_dev)
{
    CARROT_CHECK_AND_THROW(carrot::is_carrot_transaction_v1(td.m_tx),
        carrot::component_out_of_order, "Cannot export pre-carrot output as carrot output");

    // 1. easy flags
    exported_carrot_transfer_details etd{};
    etd.flags.flags = 0;
    etd.flags.m_spent = td.m_spent;
    etd.flags.m_key_image_known = td.m_key_image_known;
    etd.flags.m_key_image_request = td.m_key_image_request;
    //etd.flags.m_selfsend = ...
    //etd.flags.m_enote_type_change = ...
    etd.flags.m_carrot_derived_addr = 0; //! @TODO: carrot hierarchy
    etd.flags.m_internal = 0;
    etd.flags.m_coinbase = cryptonote::is_coinbase(td.m_tx);
    //etd.flags.m_has_pid = ...
    etd.flags.m_frozen = td.m_frozen;
    etd.flags.m_key_image_partial = td.m_key_image_partial;

    // 2. other easy fields
    if (etd.flags.m_coinbase)
    {
        etd.block_index = etd.flags.m_coinbase ? td.m_block_height : 0;
        etd.tx_first_key_image = crypto::key_image{};
    }
    else // non-coinbase
    {
        etd.block_index = 0;
        const cryptonote::txin_to_key *in_to_key = boost::strict_get<cryptonote::txin_to_key>(&td.m_tx.vin.at(0));
        CHECK_AND_ASSERT_THROW_MES(nullptr != in_to_key,
            "cannot export transfer details: failed to get key image from transaction");
        etd.tx_first_key_image = in_to_key->k_image;
    }
    etd.subaddr_index = {td.m_subaddr_index.major, td.m_subaddr_index.minor};
    etd.amount = td.amount();

    // 3. parse carrot from tx.extra
    std::vector<mx25519_pubkey> enote_ephemeral_pubkeys;
    std::optional<carrot::encrypted_payment_id_t> encrypted_payment_id;
    CHECK_AND_ASSERT_THROW_MES(
        carrot::try_load_carrot_extra_v1(td.m_tx.extra,
            enote_ephemeral_pubkeys,
            encrypted_payment_id),
        "cannot export transfer details: failed to parse Carrot tx extra");
    const std::size_t ephemeral_pubkey_idx = enote_ephemeral_pubkeys.size() == 1 ? 0 : td.m_internal_output_index;
    CHECK_AND_ASSERT_THROW_MES(ephemeral_pubkey_idx < enote_ephemeral_pubkeys.size(),
        "cannot export transfer details: wrong number of ephemeral pubkeys");
    const mx25519_pubkey &enote_ephemeral_pubkey = enote_ephemeral_pubkeys.at(ephemeral_pubkey_idx);

    // 4. input_context
    carrot::input_context_t input_context;
    CHECK_AND_ASSERT_THROW_MES(carrot::parse_carrot_input_context(td.m_tx, input_context),
        "cannot export transfer details: failed to parse input context");

    // 5. s^ctx_sr = H_32(s_sr, D_e, input_context)
    const crypto::hash s_sender_receiver_ctx = make_contextualized_sender_receiver_secret(addr_dev,
        enote_ephemeral_pubkey, input_context);

    // 6. get encrypted janus anchor: anchor_enc
    CHECK_AND_ASSERT_THROW_MES(td.m_internal_output_index < td.m_tx.vout.size(),
        "cannot export transfer details: wrong number of transaction outputs");
    const cryptonote::txout_target_v &o_target = td.m_tx.vout.at(td.m_internal_output_index).target;
    const cryptonote::txout_to_carrot_v1 *o_carrot = boost::strict_get<cryptonote::txout_to_carrot_v1>(&o_target);
    CHECK_AND_ASSERT_THROW_MES(nullptr != o_carrot, "cannot export transfer details: output isn't carrot");
    const carrot::encrypted_janus_anchor_t &encrypted_janus_anchor = o_carrot->encrypted_janus_anchor;
    const crypto::public_key &onetime_address = o_carrot->key;

    // 8. anchor = m_anchor XOR anchor_enc
    etd.janus_anchor = carrot::decrypt_carrot_anchor(encrypted_janus_anchor, s_sender_receiver_ctx, onetime_address);

    // 8. decrypt anchor and treat as selfsend iff special janus check passes
    etd.flags.m_selfsend = decrypt_and_test_anchor(encrypted_janus_anchor,
        s_sender_receiver_ctx,
        onetime_address,
        enote_ephemeral_pubkey,
        etd.tx_first_key_image,
        addr_dev,
        etd.janus_anchor);
    if (etd.flags.m_selfsend)
        etd.selfsend_enote_ephemeral_pubkey = enote_ephemeral_pubkey;

    // 9. C_a = k_a G + a H
    const rct::key amount_commitment = rct::commit(td.amount(), td.m_mask);

    // K^j_s, enote_type
    crypto::public_key address_spend_pubkey;
    addr_dev.get_address_spend_pubkey({etd.subaddr_index}, address_spend_pubkey);
    crypto::secret_key amount_blinding_factor;
    etd.flags.m_enote_type_change = carrot::try_recompute_carrot_amount_commitment(s_sender_receiver_ctx,
        td.amount(), address_spend_pubkey, carrot::CarrotEnoteType::CHANGE,
        amount_commitment, amount_blinding_factor); 

    // 10. pid decrypting and setting flag
    if (encrypted_payment_id && !etd.flags.m_selfsend)
    {
        // pid = m_pid XOR pid_enc
        etd.payment_id = carrot::decrypt_legacy_payment_id(*encrypted_payment_id,
            s_sender_receiver_ctx,
            onetime_address);

        // do normal janus verification and reset PID if d_e is null-bound
        const bool is_subaddress = !td.m_subaddr_index.is_zero();
        //! @TODO: verify that is_subaddress matches where nominal address spend pubkey is main
        CHECK_AND_ASSERT_THROW_MES(
            carrot::verify_carrot_normal_janus_protection(input_context,
                address_spend_pubkey,
                is_subaddress,
                enote_ephemeral_pubkey,
                etd.janus_anchor,
                etd.payment_id),
            "cannot export transfer details: normal janus check failed");

        etd.flags.m_has_pid = etd.payment_id != carrot::null_payment_id;
    }
    else // no encrypted payment ID in tx or is selfsend
    {
        etd.flags.m_has_pid = false;
        etd.payment_id = carrot::null_payment_id;
    }

    return etd;
}
//-------------------------------------------------------------------------------------------------------------------
exported_transfer_details_variant export_cold_output(const wallet2_basic::transfer_details &td,
    const carrot::cryptonote_hierarchy_address_device &addr_dev)
{
    exported_transfer_details_variant etd_v;
    if (carrot::is_carrot_transaction_v1(td.m_tx))
        etd_v = export_cold_carrot_output(td, addr_dev);
    else // not carrot
        etd_v = export_cold_pre_carrot_output(td);

    return etd_v;
}
//-------------------------------------------------------------------------------------------------------------------
wallet2_basic::transfer_details import_cold_pre_carrot_output(const exported_pre_carrot_transfer_details &etd,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    const carrot::key_image_device &key_image_dev)
{
    wallet2_basic::transfer_details td{};

    // setup td with "cheap" loaded data
    td.m_block_height = 0;
    td.m_txid = crypto::null_hash;
    td.m_global_output_index = etd.m_global_output_index;
    td.m_spent = etd.m_flags.m_spent;
    td.m_frozen = etd.m_flags.m_frozen;
    td.m_spent_height = 0;
    td.m_amount = etd.m_amount;
    td.m_rct = etd.m_flags.m_rct;
    td.m_key_image_known = etd.m_flags.m_key_image_known;
    td.m_key_image_request = etd.m_flags.m_key_image_request;
    td.m_key_image_partial = false;
    td.m_subaddr_index.major = etd.m_subaddr_index_major;
    td.m_subaddr_index.minor = etd.m_subaddr_index_minor;

    // construct a synthetic tx prefix that has the info we'll need: the output with its pubkey, the tx pubkey in extra
    td.m_tx = {};

    THROW_WALLET_EXCEPTION_IF(etd.m_internal_output_index >= 65536, error::wallet_internal_error, "internal output index seems outrageously high, rejecting");
    td.m_internal_output_index = etd.m_internal_output_index;
    cryptonote::txout_to_key tk;
    tk.key = etd.m_pubkey;
    cryptonote::tx_out out;
    out.amount = etd.m_amount;
    out.target = tk;
    td.m_tx.vout.resize(etd.m_internal_output_index);
    td.m_tx.vout.push_back(out);

    td.m_pk_index = 0;
    cryptonote::add_tx_pub_key_to_extra(td.m_tx, etd.m_tx_pubkey);
    if (!etd.m_additional_tx_keys.empty())
      cryptonote::add_additional_tx_pub_keys_to_extra(td.m_tx.extra, etd.m_additional_tx_keys);

    const crypto::public_key tx_pubkey_mul8 = rct::rct2pk(rct::scalarmult8(rct::pk2rct(etd.m_tx_pubkey)));
    crypto::public_key kd_pk;
    CHECK_AND_ASSERT_THROW_MES(addr_dev.view_key_scalar_mult_ed25519(tx_pubkey_mul8, kd_pk),
        "could not import transfer details: view-incoming key multiplication failed");
    crypto::key_derivation kd;
    memcpy(&kd, &kd_pk, sizeof(kd));

    crypto::secret_key derivation_scalar;
    crypto::derivation_to_scalar(kd, td.m_internal_output_index, derivation_scalar);

    // get amount blinding factor if RingCT
    if (td.m_rct)
    {
        td.m_mask = rct::genCommitmentMask(rct::sk2rct(derivation_scalar));
    }
    else
    {
        td.m_mask = rct::I;
    }

    const carrot::LegacyOutputOpeningHintV1 opening_hint{
        .onetime_address = etd.m_pubkey,
        .ephemeral_tx_pubkey = etd.m_tx_pubkey,
        .subaddr_index = {etd.m_subaddr_index_major, etd.m_subaddr_index_minor},
        .amount = etd.m_amount,
        .amount_blinding_factor = td.m_mask,
        .local_output_index = static_cast<std::size_t>(etd.m_internal_output_index)
    };
    td.m_key_image = key_image_dev.derive_key_image(opening_hint);
    td.m_key_image_known = true;
    td.m_key_image_request = true;
    td.m_key_image_partial = false;

    return td;
}
//-------------------------------------------------------------------------------------------------------------------
wallet2_basic::transfer_details import_cold_carrot_output(const exported_carrot_transfer_details &etd,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    const carrot::key_image_device &key_image_dev)
{
    wallet2_basic::transfer_details td{};

    td.m_block_height = 0;
    td.m_tx.set_null();
    td.m_txid = crypto::null_hash;
    td.m_internal_output_index = 0;
    td.m_global_output_index = 0;
    td.m_spent = etd.flags.m_spent;
    td.m_frozen = etd.flags.m_frozen;
    td.m_spent_height = 0;
    td.m_amount = etd.amount;
    td.m_rct = true;
    td.m_pk_index = 0;
    td.m_subaddr_index.major = etd.subaddr_index.major;
    td.m_subaddr_index.minor = etd.subaddr_index.minor;
    td.m_multisig_k.clear();
    td.m_multisig_info.clear();
    td.m_uses.clear();

    // get receive subaddress
    const carrot::AddressDeriveType derive_type = etd.flags.m_carrot_derived_addr
        ? carrot::AddressDeriveType::Carrot : carrot::AddressDeriveType::PreCarrot;
    CHECK_AND_ASSERT_THROW_MES(derive_type == carrot::AddressDeriveType::PreCarrot,
        "cannot import transfer details: carrot key hierarchy addresses are not yet supported"); //! @TODO
    const carrot::subaddress_index_extended subaddr_index{
        .index = etd.subaddr_index,
        .derive_type = derive_type
    };
    carrot::CarrotDestinationV1 destination{
        .address_spend_pubkey = {},
        .address_view_pubkey = {},
        .is_subaddress = !td.m_subaddr_index.is_zero(),
        .payment_id = etd.flags.m_has_pid ? etd.payment_id : carrot::null_payment_id
    };
    addr_dev.get_address_pubkeys(subaddr_index,
        destination.address_spend_pubkey,
        destination.address_view_pubkey);

    // Use exported_carrot_transfer_details to make payment proposals to ourselves,
    // then construct transaction outputs & opening hints and set amount blinding factor
    carrot::OutputOpeningHintVariant opening_hint;
    if (etd.flags.m_coinbase)
    {
        const carrot::CarrotPaymentProposalV1 payment_proposal{
            .destination = destination,
            .amount = td.amount(),
            .randomness = etd.janus_anchor
        };

        carrot::CarrotCoinbaseEnoteV1 enote;
        carrot::get_coinbase_enote_v1(payment_proposal, etd.block_index, enote);
        td.m_tx = carrot::store_carrot_to_coinbase_transaction_v1({enote}, {});
        td.m_mask = rct::I;
        opening_hint = carrot::CarrotCoinbaseOutputOpeningHintV1{
            .source_enote = enote,
            .derive_type = derive_type
        };
    }
    else // non-coinbase
    {
        carrot::RCTOutputEnoteProposal output_enote_proposal;
        std::optional<carrot::encrypted_payment_id_t> encrypted_payment_id;
        if (etd.flags.m_selfsend)
        {
            CHECK_AND_ASSERT_THROW_MES(!etd.flags.m_internal,
                "cannot import transfer details: internal enotes are not yet supported"); //! @TODO");

            const carrot::CarrotEnoteType enote_type = etd.flags.m_enote_type_change
                ? carrot::CarrotEnoteType::CHANGE : carrot::CarrotEnoteType::PAYMENT;

            const carrot::CarrotPaymentProposalSelfSendV1 payment_proposal{
                .destination_address_spend_pubkey = destination.address_spend_pubkey,
                .amount = td.amount(),
                .enote_type = enote_type,
                .enote_ephemeral_pubkey = etd.selfsend_enote_ephemeral_pubkey,
                .internal_message = etd.flags.m_internal
                    ? std::optional<carrot::janus_anchor_t>(etd.janus_anchor) : std::optional<carrot::janus_anchor_t>()
            };

            // construct enote
            carrot::get_output_proposal_special_v1(payment_proposal,
                addr_dev,
                etd.tx_first_key_image,
                etd.selfsend_enote_ephemeral_pubkey,
                output_enote_proposal);
        }
        else // normal non-coinbase
        {
            const carrot::CarrotPaymentProposalV1 payment_proposal{
                .destination = destination,
                .amount = td.amount(),
                .randomness = etd.janus_anchor
            };

            carrot::get_output_proposal_normal_v1(payment_proposal,
                etd.tx_first_key_image,
                output_enote_proposal,
                encrypted_payment_id.emplace());
        }

        td.m_tx = carrot::store_carrot_to_transaction_v1({output_enote_proposal.enote},
            {etd.tx_first_key_image},
            /*fee=*/0,
            encrypted_payment_id.value_or(carrot::encrypted_payment_id_t{}));
        td.m_mask = rct::sk2rct(output_enote_proposal.amount_blinding_factor);
        opening_hint = carrot::CarrotOutputOpeningHintV1{
            .source_enote = output_enote_proposal.enote,
            .encrypted_payment_id = encrypted_payment_id,
            .subaddr_index = subaddr_index
        };
    }

    td.m_key_image = key_image_dev.derive_key_image(opening_hint);
    td.m_key_image_known = true;
    td.m_key_image_request = true;
    td.m_key_image_partial = false;

    return td;
}
//-------------------------------------------------------------------------------------------------------------------
wallet2_basic::transfer_details import_cold_output(const exported_transfer_details_variant &etd,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    const carrot::key_image_device &key_image_dev)
{
    struct import_cold_output_visitor
    {
        wallet2_basic::transfer_details operator()(const exported_pre_carrot_transfer_details &etd) const
        {
           return import_cold_pre_carrot_output(etd, addr_dev, key_image_dev);
        }

        wallet2_basic::transfer_details operator()(const exported_carrot_transfer_details &etd) const
        {
           return import_cold_carrot_output(etd, addr_dev, key_image_dev);
        }

        const carrot::cryptonote_hierarchy_address_device &addr_dev;
        const carrot::key_image_device &key_image_dev;
    };

    return std::visit(import_cold_output_visitor{addr_dev, key_image_dev}, etd);
}
//-------------------------------------------------------------------------------------------------------------------
HotColdCarrotTransactionProposalV1 compress_carrot_transaction_proposal_lossy(
    const carrot::CarrotTransactionProposalV1 &tx_proposal,
    const HotColdSeed &hot_cold_seed)
{
    std::vector<crypto::public_key> input_onetime_addresses;
    input_onetime_addresses.reserve(tx_proposal.input_proposals.size());
    for (const carrot::InputProposalV1 &p : tx_proposal.input_proposals)
        input_onetime_addresses.push_back(onetime_address_ref(p));

    std::vector<HotColdCarrotPaymentProposalV1> normal_payment_proposals;
    normal_payment_proposals.reserve(tx_proposal.normal_payment_proposals.size());
    for (const carrot::CarrotPaymentProposalV1 &p : tx_proposal.normal_payment_proposals)
        normal_payment_proposals.push_back(compress_carrot_normal_payment_proposal_lossy(p));

    std::vector<HotColdCarrotPaymentProposalVerifiableSelfSendV1> selfsend_payment_proposals;
    carrot::AddressDeriveType addr_derive_type = carrot::AddressDeriveType::Auto;
    selfsend_payment_proposals.reserve(tx_proposal.selfsend_payment_proposals.size());
    for (const carrot::CarrotPaymentProposalVerifiableSelfSendV1 &p : tx_proposal.selfsend_payment_proposals)
    {
        selfsend_payment_proposals.push_back(compress_carrot_selfsend_payment_proposal_lossy(p));
        addr_derive_type = p.subaddr_index.derive_type;
    }

    return HotColdCarrotTransactionProposalV1{
        .hot_cold_seed = hot_cold_seed,
        .input_onetime_addresses = std::move(input_onetime_addresses),
        .normal_payment_proposals = std::move(normal_payment_proposals),
        .selfsend_payment_proposals = std::move(selfsend_payment_proposals),
        .addr_derive_type = addr_derive_type,
        .fee = tx_proposal.fee,
        .extra = tx_proposal.extra,
    };
}
//-------------------------------------------------------------------------------------------------------------------
std::function<carrot::InputProposalV1(const crypto::public_key&)> make_supplemental_input_proposals_fetcher(
    const wallet2_basic::transfer_container &transfers)
{
    const auto best_transfer_by_ota = collect_non_burned_transfers_by_onetime_address(transfers);

    return [transfers, best_transfer_by_ota](const crypto::public_key &ota) -> carrot::InputProposalV1
    {
        const auto it = best_transfer_by_ota.find(ota);
        CARROT_CHECK_AND_THROW(it != best_transfer_by_ota.cend(),
            carrot::missing_components, "cannot cold-sign tx set: missing transfer info for given one-time address");
        return make_sal_opening_hint_from_transfer_details(transfers.at(it->second));
    };
}
//-------------------------------------------------------------------------------------------------------------------
void expand_carrot_transaction_proposal(const HotColdCarrotTransactionProposalV1 &tx_proposal,
    const std::function<carrot::InputProposalV1(const crypto::public_key&)> &supplemental_input_proposals,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    carrot::CarrotTransactionProposalV1 &tx_proposal_out)
{
    // collect input proposals
    const std::size_t n_inputs = tx_proposal.input_onetime_addresses.size();
    std::vector<carrot::InputProposalV1> tx_input_proposals;
    tx_input_proposals.reserve(n_inputs);
    for (const crypto::public_key &input_onetime_address : tx_proposal.input_onetime_addresses)
        tx_input_proposals.push_back(supplemental_input_proposals(input_onetime_address));

    // expand tx proposal
    tx_proposal_out = expand_carrot_transaction_proposal(tx_proposal, std::move(tx_input_proposals), addr_dev);
}
//-------------------------------------------------------------------------------------------------------------------
void expand_carrot_transaction_proposals(const UnsignedCarrotTransactionSetV1 &unsigned_txs,
    const std::function<carrot::InputProposalV1(const crypto::public_key&)> &supplemental_input_proposals,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    std::vector<carrot::CarrotTransactionProposalV1> &tx_proposals_out)
{
    tx_proposals_out.clear();
    tx_proposals_out.reserve(unsigned_txs.tx_proposals.size());

    const auto supplemental_and_inset_input_proposals = extend_supplemental_input_proposals_fetcher(
        supplemental_input_proposals, unsigned_txs, addr_dev);

    for (const HotColdCarrotTransactionProposalV1 &cold_tx_proposal : unsigned_txs.tx_proposals)
    {
        expand_carrot_transaction_proposal(cold_tx_proposal,
            supplemental_and_inset_input_proposals,
            addr_dev,
            tx_proposals_out.emplace_back());
    }
}
//-------------------------------------------------------------------------------------------------------------------
void expand_carrot_transaction_proposal_and_rerandomized_outputs(
    const HotColdCarrotTransactionProposalV1 &tx_proposal,
    const std::function<carrot::InputProposalV1(const crypto::public_key&)> &supplemental_input_proposals,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    const carrot::key_image_device &key_image_dev,
    carrot::CarrotTransactionProposalV1 &tx_proposal_out,
    std::vector<crypto::key_image> &input_key_images_out,
    std::vector<FcmpRerandomizedOutputCompressed> &rerandomized_outputs_out)
{
    // expand tx proposal
    expand_carrot_transaction_proposal(tx_proposal, supplemental_input_proposals, addr_dev, tx_proposal_out);

    // n_inputs number of (r_o, r_i, r_r_i, r_c) tuples
    const std::size_t n_inputs = tx_proposal.input_onetime_addresses.size();
    CARROT_CHECK_AND_THROW(n_inputs, carrot::too_few_inputs, "no inputs in hot/cold transaction proposal");
    std::vector<RerandomizationScalars> rerandomizations = expand_rerandomization_scalars(tx_proposal.hot_cold_seed,
        n_inputs);
    CARROT_CHECK_AND_THROW(rerandomizations.size() == n_inputs,
        carrot::component_out_of_order, "incorrect number of generated hot/cold rerandomizations");

    const std::size_t n_outputs = tx_proposal.normal_payment_proposals.size()
        + tx_proposal.selfsend_payment_proposals.size();

    rct::key r_c;
    sc_0(r_c.bytes);

    // get sorted input key images from tx proposal
    std::vector<std::size_t> key_image_order;
    carrot::get_sorted_input_key_images_from_proposal_v1(tx_proposal_out,
        key_image_dev,
        input_key_images_out,
        &key_image_order);
    const crypto::key_image &tx_first_key_image = input_key_images_out.at(0);

    // finalize enotes of transaction proposal to add output enote amount blinding factors
    std::vector<carrot::RCTOutputEnoteProposal> output_enote_proposals;
    carrot::encrypted_payment_id_t encrypted_payment_id;
    output_enote_proposals.reserve(n_outputs);
    carrot::get_output_enote_proposals_from_proposal_v1(tx_proposal_out,
        /*s_view_balance=*/nullptr,
        &addr_dev,
        tx_first_key_image,
        output_enote_proposals,
        encrypted_payment_id);
    for (const carrot::RCTOutputEnoteProposal &output_enote_proposal : output_enote_proposals)
        sc_add(r_c.bytes, r_c.bytes, to_bytes(output_enote_proposal.amount_blinding_factor));

    // scan all opening hints to subtract input enote amount blinding factors
    crypto::public_key main_address_spend_pubkey;
    addr_dev.get_address_spend_pubkey({}, main_address_spend_pubkey);
    for (const carrot::InputProposalV1 &input_proposal : tx_proposal_out.input_proposals)
    {
        rct::xmr_amount amount;
        rct::key amount_blinding_factor;
        CARROT_CHECK_AND_THROW(carrot::try_scan_opening_hint_amount(input_proposal,
                {&main_address_spend_pubkey, 1}, &addr_dev, nullptr, amount, amount_blinding_factor),
            carrot::unexpected_scan_failure, "could not scan tx input proposal for amount");
        sc_sub(r_c.bytes, r_c.bytes, amount_blinding_factor.bytes);
    }

    // subtract the other non-last r_c
    for (std::size_t input_idx = 0; input_idx < n_inputs - 1; ++input_idx)
        sc_sub(r_c.bytes, r_c.bytes, rerandomizations.at(input_idx).r_c.bytes);

    // update last r_c
    rerandomizations.back().r_c = r_c;

    // calculate rerandomized outputs from rerandomizations
    rerandomized_outputs_out.clear();
    rerandomized_outputs_out.reserve(n_inputs);
    for (std::size_t sorted_input_idx : key_image_order)
    {
        const carrot::InputProposalV1 &input_proposal = tx_proposal_out.input_proposals.at(sorted_input_idx);
        const RerandomizationScalars &rerandomization = rerandomizations.at(sorted_input_idx);

        FcmpRerandomizedOutputCompressed &rerandomized_output = rerandomized_outputs_out.emplace_back();
        rerandomized_output.input = fcmp_pp::calculate_fcmp_input_for_rerandomizations(
            onetime_address_ref(input_proposal),
            rct::rct2pt(amount_commitment_ref(input_proposal)),
            use_biased_hash_to_point(input_proposal),
            rct::rct2sk(rerandomization.r_o),
            rct::rct2sk(rerandomization.r_i),
            rct::rct2sk(rerandomization.r_r_i),
            rct::rct2sk(rerandomization.r_c));
        memcpy(&rerandomized_output.r_o, &rerandomization.r_o, 32);
        memcpy(&rerandomized_output.r_i, &rerandomization.r_i, 32);
        memcpy(&rerandomized_output.r_r_i, &rerandomization.r_r_i, 32);
        memcpy(&rerandomized_output.r_c, &rerandomization.r_c, 32);
    }

    // re-order tx proposal inputs to match rerandomized outputs
    tools::apply_permutation(key_image_order, tx_proposal_out.input_proposals);
}
//-------------------------------------------------------------------------------------------------------------------
UnsignedTransactionSetVariant generate_unsigned_tx_set_from_pending_txs(
    const std::vector<pending_tx> &ptxs,
    const wallet2_basic::transfer_container &transfers,
    const bool resend_tx_proposals,
    const carrot::cryptonote_hierarchy_address_device &addr_dev)
{
    // check there is at least one tx
    CARROT_CHECK_AND_THROW(!ptxs.empty(), carrot::missing_components, "cannot make unsigned tx set with no txs");

    // check that all pending txs are of same type
    for (const pending_tx &ptx : ptxs)
    {
        CARROT_CHECK_AND_THROW(ptx.construction_data.index() == ptxs.at(0).construction_data.index(),
            carrot::component_out_of_order, "cannot make unsigned tx set with pending txs of mixed type");
    }

    const tx_reconstruct_variant_t &first_ctx_data = ptxs.at(0).construction_data;

    // determine pending txs type
    const bool is_pending_carrot_v1 = std::holds_alternative<carrot::CarrotTransactionProposalV1>(first_ctx_data);
    const bool is_pending_pre_carrot = std::holds_alternative<PreCarrotTransactionProposal>(first_ctx_data);

    // determine whether we have received a Carrot tx yet
    bool yet_received_first_carrot_tx = false;
    for (const wallet2_basic::transfer_details &td : transfers)
        if (carrot::is_carrot_transaction_v1(td.m_tx))
            yet_received_first_carrot_tx = true;

    // disallow pre-Carrot txs if we have already received a Carrot enote
    CARROT_CHECK_AND_THROW(is_pending_carrot_v1 || !yet_received_first_carrot_tx,
        carrot::component_out_of_order, "pre-Carrot unsigned tx sets not allowed after first Carrot enote received");

    // determine offset of first key image to request
    std::size_t ki_request_start = 0;
    while (ki_request_start < transfers.size())
    {
        const wallet2_basic::transfer_details &td = transfers.at(ki_request_start);
        if (!td.m_key_image_known || td.m_key_image_request)
            break;
        ++ki_request_start;
    }

    UnsignedTransactionSetVariant unsigned_tx_set_v;

    // compress pending txs into hot/cold tx proposals and export transfer details after `ki_request_start`
    if (is_pending_carrot_v1)
    {
        UnsignedCarrotTransactionSetV1 unsigned_tx_set;
        unsigned_tx_set.tx_proposals.reserve(ptxs.size());
        unsigned_tx_set.new_transfers.reserve(transfers.size() - ki_request_start);
        for (const pending_tx &ptx : ptxs)
        {
            const HotColdSeed hot_cold_seed = crypto::rand<HotColdSeed>();
            const auto &tx_proposal = std::get<carrot::CarrotTransactionProposalV1>(ptx.construction_data);
            HotColdCarrotTransactionProposalV1 &hot_cold_tx_proposal = unsigned_tx_set.tx_proposals.emplace_back();
            hot_cold_tx_proposal = compress_carrot_transaction_proposal_lossy(tx_proposal, hot_cold_seed);
        }
        for (std::size_t td_idx = ki_request_start; td_idx < transfers.size(); ++td_idx)
        {
            const wallet2_basic::transfer_details &td = transfers.at(td_idx);
            exported_transfer_details_variant &etd = unsigned_tx_set.new_transfers.emplace_back();
            etd = export_cold_output(td, addr_dev);
        }
        unsigned_tx_set.starting_transfer_index = ki_request_start;
        unsigned_tx_set.resend_tx_proposals = resend_tx_proposals;
        unsigned_tx_set_v = std::move(unsigned_tx_set);
    }
    else if (is_pending_pre_carrot)
    {
        UnsignedPreCarrotTransactionSet unsigned_tx_set;
        unsigned_tx_set.txes.reserve(ptxs.size());
        unsigned_tx_set.new_transfers = {ki_request_start, transfers.size(), {}};
        auto &exported_transfer_details = std::get<2>(unsigned_tx_set.new_transfers);
        exported_transfer_details.reserve(transfers.size() - ki_request_start);
        for (const pending_tx &ptx : ptxs)
            unsigned_tx_set.txes.push_back(std::get<PreCarrotTransactionProposal>(ptx.construction_data));
        for (std::size_t td_idx = ki_request_start; td_idx < transfers.size(); ++td_idx)
        {
            const wallet2_basic::transfer_details &td = transfers.at(td_idx);
            exported_pre_carrot_transfer_details &etd = exported_transfer_details.emplace_back();
            etd = export_cold_pre_carrot_output(td);
        }
        unsigned_tx_set_v = std::move(unsigned_tx_set);
    }
    else
    {
        CARROT_CHECK_AND_THROW(false,
            carrot::component_out_of_order, "cannot make unsigned tx set with pending txs of unrecognized type");
    }

    return unsigned_tx_set_v;
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<tx_reconstruct_variant_t> get_transaction_proposals_from_unsigned_tx_set(
    const UnsignedTransactionSetVariant &unsigned_txs,
    const std::function<carrot::InputProposalV1(const crypto::public_key&)> &supplemental_input_proposals,
    const carrot::cryptonote_hierarchy_address_device &addr_dev)
{
    struct get_transaction_proposals_from_unsigned_tx_set_visitor
    {
        std::vector<tx_reconstruct_variant_t> operator()(const UnsignedPreCarrotTransactionSet &u) const
        {
            std::vector<tx_reconstruct_variant_t> res;
            res.reserve(u.txes.size());
            for (const PreCarrotTransactionProposal &tx_proposal : u.txes)
                res.emplace_back(tx_proposal);
            return res;
        }

        std::vector<tx_reconstruct_variant_t> operator()(const UnsignedCarrotTransactionSetV1 &u) const
        {
            std::vector<carrot::CarrotTransactionProposalV1> carrot_tx_proposals;
            expand_carrot_transaction_proposals(u, supplemental_input_proposals, addr_dev, carrot_tx_proposals);
            std::vector<tx_reconstruct_variant_t> res;
            res.reserve(carrot_tx_proposals.size());
            for (const carrot::CarrotTransactionProposalV1 &carrot_tx_proposal : carrot_tx_proposals)
                res.emplace_back(carrot_tx_proposal);
            return res;
        }

        const std::function<carrot::InputProposalV1(const crypto::public_key&)> &supplemental_input_proposals;
        const carrot::cryptonote_hierarchy_address_device &addr_dev;
    };
    return std::visit(get_transaction_proposals_from_unsigned_tx_set_visitor{supplemental_input_proposals, addr_dev},
        unsigned_txs);
}
//-------------------------------------------------------------------------------------------------------------------
void sign_pre_carrot_tx_set(const UnsignedPreCarrotTransactionSet &unsigned_txs,
    const cryptonote::account_keys &acc_keys,
    const std::unordered_map<crypto::public_key, cryptonote::subaddress_index> &subaddress_map,
    const cryptonote::network_type nettype,
    SignedFullTransactionSet &signed_txs_out,
    std::unordered_map<crypto::hash, crypto::secret_key> &tx_keys_out,
    std::unordered_map<crypto::hash, std::vector<crypto::secret_key>> &additional_tx_keys_out)
{
    tx_keys_out.clear();
    additional_tx_keys_out.clear();

    for (size_t n = 0; n < unsigned_txs.txes.size(); ++n)
    {
        PreCarrotTransactionProposal sd = unsigned_txs.txes[n];
        THROW_WALLET_EXCEPTION_IF(sd.sources.empty(), error::wallet_internal_error, "Empty sources");
        THROW_WALLET_EXCEPTION_IF(sd.unlock_time, error::nonzero_unlock_time);
        LOG_PRINT_L1(" " << (n+1) << ": " << sd.sources.size()
            << " inputs, ring size " << sd.sources.at(0).outputs.size());
        pending_tx &ptx = signed_txs_out.ptx.emplace_back();
        rct::RCTConfig rct_config = sd.rct_config;
        crypto::secret_key tx_key;
        std::vector<crypto::secret_key> additional_tx_keys;
        bool r = cryptonote::construct_tx_and_get_tx_key(acc_keys, subaddress_map, sd.sources, sd.splitted_dsts,
                sd.change_dts.addr, sd.extra, ptx.tx, tx_key, additional_tx_keys, sd.use_rct, rct_config,
                sd.use_view_tags);
        THROW_WALLET_EXCEPTION_IF(!r, error::tx_not_constructed, sd.sources, sd.splitted_dsts, nettype);
        // we don't test tx size, because we don't know the current limit, due to not having a blockchain,
        // and it's a bit pointless to fail there anyway, since it'd be a (good) guess only. We sign anyway,
        // and if we really go over limit, the daemon will reject when it gets submitted. Chances are it's
        // OK anyway since it was generated in the first place, and rerolling should be within a few bytes.

        // normally, the tx keys are saved in commit_tx, when the tx is actually sent to the daemon.
        // we can't do that here since the tx will be sent from the compromised wallet, which we don't want
        // to see that info, so we save it here
        if (tx_key != crypto::null_skey)
        {
            const crypto::hash txid = get_transaction_hash(ptx.tx);
            tx_keys_out[txid] = tx_key;
            additional_tx_keys_out[txid] = additional_tx_keys;
        }

        std::string key_images;
        const bool all_are_txin_to_key = std::all_of(ptx.tx.vin.begin(), ptx.tx.vin.end(),
            [&](const cryptonote::txin_v& s_e) -> bool
            {
                CHECKED_GET_SPECIFIC_VARIANT(s_e, const cryptonote::txin_to_key, in, false);
                key_images += epee::string_tools::pod_to_hex(in.k_image) + " ";
                return true;
            });
        THROW_WALLET_EXCEPTION_IF(!all_are_txin_to_key, error::unexpected_txin_type, ptx.tx);

        ptx.key_images = key_images;
        ptx.fee = 0;
        for (const auto &i: sd.sources) ptx.fee += i.amount;
            for (const auto &i: sd.splitted_dsts) ptx.fee -= i.amount;
                ptx.dust = 0;
        ptx.dust_added_to_fee = false;
        ptx.change_dts = sd.change_dts;
        ptx.tx_key = rct::rct2sk(rct::identity()); // don't send it back to the untrusted view wallet
        ptx.dests = sd.dests;
        ptx.construction_data = sd;
    }

    // add key image mapping for these txes
    hw::device &hwdev = acc_keys.get_device();
    for (size_t n = 0; n < unsigned_txs.txes.size(); ++n)
    {
        const cryptonote::transaction &tx = signed_txs_out.ptx[n].tx;
        const crypto::hash txid = cryptonote::get_transaction_hash(tx);

        crypto::key_derivation derivation;
        std::vector<crypto::key_derivation> additional_derivations;

        const crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(tx);
        std::vector<crypto::public_key> additional_tx_pub_keys;
        for (const crypto::secret_key &skey: additional_tx_keys_out.at(txid))
        {
            additional_tx_pub_keys.resize(additional_tx_pub_keys.size() + 1);
            crypto::secret_key_to_public_key(skey, additional_tx_pub_keys.back());
        }

        // compute derivations
        hwdev.set_mode(hw::device::TRANSACTION_PARSE);
        if (!hwdev.generate_key_derivation(tx_pub_key, acc_keys.m_view_secret_key, derivation))
        {
            MWARNING("Failed to generate key derivation from tx pubkey in " << txid << ", skipping");
            static_assert(sizeof(derivation) == sizeof(rct::key), "Mismatched sizes of key_derivation and rct::key");
            memcpy(&derivation, rct::identity().bytes, sizeof(derivation));
        }
        for (size_t i = 0; i < additional_tx_pub_keys.size(); ++i)
        {
            additional_derivations.push_back({});
            if (!hwdev.generate_key_derivation(additional_tx_pub_keys[i],
                acc_keys.m_view_secret_key,
                additional_derivations.back()))
            {
                MWARNING("Failed to generate key derivation from additional tx pubkey in " << txid << ", skipping");
                memcpy(&additional_derivations.back(), rct::identity().bytes, sizeof(crypto::key_derivation));
            }
        }

        for (size_t i = 0; i < tx.vout.size(); ++i)
        {
            crypto::public_key output_public_key;
            if (!cryptonote::get_output_public_key(tx.vout[i], output_public_key))
                continue;

            // if this output is back to this wallet, we can calculate its key image already
            if (!cryptonote::is_out_to_acc_precomp(subaddress_map,
                    output_public_key,
                    derivation,
                    additional_derivations,
                    i,
                    hwdev,
                    cryptonote::get_output_view_tag(tx.vout[i])))
                continue;
            crypto::key_image ki;
            cryptonote::keypair in_ephemeral;
            if (cryptonote::generate_key_image_helper(acc_keys,
                    subaddress_map,
                    output_public_key,
                    tx_pub_key,
                    additional_tx_pub_keys,
                    i,
                    in_ephemeral,
                    ki,
                    hwdev))
                signed_txs_out.tx_key_images[output_public_key] = ki;
            else
                MERROR("Failed to calculate key image");
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
void sign_carrot_tx_set_v1(const UnsignedCarrotTransactionSetV1 &unsigned_txs,
    const std::function<carrot::InputProposalV1(const crypto::public_key&)> &supplemental_opening_hints,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    const carrot::spend_device &spend_dev,
    SignedCarrotTransactionSetV1 &signed_txs_out,
    std::unordered_map<crypto::hash, std::vector<crypto::secret_key>> &ephemeral_tx_privkeys_out)
{
    if (unsigned_txs.resend_tx_proposals)
        signed_txs_out.tx_proposals = unsigned_txs.tx_proposals;
    else
        signed_txs_out.tx_proposals.clear();

    signed_txs_out.signed_inputs.clear();

    ephemeral_tx_privkeys_out.clear();

    // fetcher of input proposals / opening hints which tries provided in-set first
    const auto supplemental_and_inset_input_proposals = extend_supplemental_input_proposals_fetcher(
        supplemental_opening_hints, unsigned_txs, addr_dev);

    // for each hot/cold tx proposal...
    for (const HotColdCarrotTransactionProposalV1 &tx_proposal : unsigned_txs.tx_proposals)
    {
        // expand tx proposal, input key images, and rerandomized outputs, with sorted inputs
        carrot::CarrotTransactionProposalV1 expanded_tx_proposal;
        std::vector<crypto::key_image> input_key_images;
        std::vector<FcmpRerandomizedOutputCompressed> rerandomized_outputs;
        expand_carrot_transaction_proposal_and_rerandomized_outputs(tx_proposal,
            supplemental_and_inset_input_proposals,
            addr_dev,
            spend_dev,
            expanded_tx_proposal,
            input_key_images,
            rerandomized_outputs);
        const std::size_t n_inputs = expanded_tx_proposal.input_proposals.size();
        CARROT_CHECK_AND_THROW(input_key_images.size() == n_inputs, carrot::component_out_of_order,
            "wrong number of key images in expanded tx proposal compared to spent OTAs");
        CARROT_CHECK_AND_THROW(rerandomized_outputs.size() == n_inputs, carrot::component_out_of_order,
            "wrong number of rerandomized outputs in expanded tx proposal compared to spent OTAs");

        // calculate signable tx hash
        crypto::hash signable_tx_hash;
        carrot::make_signable_tx_hash_from_proposal_v1(expanded_tx_proposal,
            nullptr, &addr_dev, input_key_images, signable_tx_hash);

        // collect rerandomized outputs and key imagess by onetime-address of spent input
        std::unordered_map<crypto::public_key, FcmpRerandomizedOutputCompressed> rerandomized_output_by_ota;
        std::unordered_map<crypto::public_key, crypto::key_image> key_image_by_ota;
        for (std::size_t input_idx = 0; input_idx < n_inputs; ++input_idx)
        {
            const crypto::public_key ota = onetime_address_ref(expanded_tx_proposal.input_proposals.at(input_idx));
            rerandomized_output_by_ota.emplace(ota, rerandomized_outputs.at(input_idx));
            key_image_by_ota.emplace(ota, input_key_images.at(input_idx));
        }

        // sign SA/L for each input and push to `signed_txs_out.signed_inputs`
        crypto::hash device_signable_tx_hash;
        carrot::spend_device::signed_input_set_t tx_signed_inputs;
        const bool sign_success = spend_dev.try_sign_carrot_transaction_proposal_v1(expanded_tx_proposal,
            rerandomized_output_by_ota,
            device_signable_tx_hash,
            tx_signed_inputs);

        // check sign results
        CARROT_CHECK_AND_THROW(sign_success, carrot::carrot_runtime_error,
            "Spend device refused to sign transaction");
        CARROT_CHECK_AND_THROW(device_signable_tx_hash == signable_tx_hash,
            carrot::carrot_logic_error, "Spend device and this device calculated different signable tx hashes");
        CARROT_CHECK_AND_THROW(tx_signed_inputs.size() == n_inputs,
            carrot::component_out_of_order, "Spend device returned the wrong number of signed inputs");
        for (const auto &p : tx_signed_inputs)
        {
            const crypto::key_image &ki = p.first;
            const crypto::public_key &ota = p.second.first;
            CARROT_CHECK_AND_THROW(key_image_by_ota.count(ota) && key_image_by_ota.at(ota) == ki,
                carrot::component_out_of_order, "Spend device returned a signed input set with mismatched OTAs/KIs");
        }
        signed_txs_out.signed_inputs.merge(tx_signed_inputs);

        // get ephemeral tx privkeys
        std::vector<std::pair<bool, std::size_t>> enote_order;
        carrot::get_sender_receiver_secrets_from_proposal_v1(expanded_tx_proposal.normal_payment_proposals,
            expanded_tx_proposal.selfsend_payment_proposals,
            /*s_view_balance_dev=*/{},
            &addr_dev,
            input_key_images.at(0),
            ephemeral_tx_privkeys_out[signable_tx_hash],
            enote_order);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void finalize_proofs_for_signed_carrot_tx_set_v1(const SignedCarrotTransactionSetV1 &signed_txs,
    const std::function<HotColdCarrotTransactionProposalV1(const crypto::public_key&)> &supplemental_tx_proposals,
    const std::function<carrot::InputProposalV1(const crypto::public_key&)> &supplemental_opening_hints,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    const fcmp_pp::curve_trees::TreeCacheV1 &tree_cache,
    const fcmp_pp::curve_trees::CurveTreesV1 &curve_trees,
    std::vector<carrot::CarrotTransactionProposalV1> &expanded_tx_proposals_out,
    std::vector<cryptonote::transaction> &txs_out)
{
    using signed_input_t = std::pair<crypto::key_image, std::pair<crypto::public_key, fcmp_pp::FcmpPpSalProof>>;

    expanded_tx_proposals_out.clear();
    txs_out.clear();

    // collect key images by one-time address provided in tx set
    std::unordered_map<crypto::public_key, crypto::key_image> key_image_by_ota;
    for (const auto &signed_input : signed_txs.signed_inputs)
        key_image_by_ota[signed_input.second.first] = signed_input.first;

    // fetch tx proposals by one-time address, either explicitly provided in tx set, or supplemented
    std::vector<HotColdCarrotTransactionProposalV1> cold_tx_proposals;
    std::unordered_map<crypto::public_key, std::size_t> cold_tx_proposal_by_ota;
    const auto add_tx_prop = [&](const HotColdCarrotTransactionProposalV1 &p)
    {
        const std::size_t new_idx = cold_tx_proposals.size();
        for (const crypto::public_key &onetime_address : p.input_onetime_addresses)
        {
            CARROT_CHECK_AND_THROW(cold_tx_proposal_by_ota.count(onetime_address) == 0,
                carrot::too_many_inputs, "multiple cold tx proposals for the same one-time address in signed tx set");
            CARROT_CHECK_AND_THROW(key_image_by_ota.count(onetime_address) == 1,
                carrot::missing_components, "cold tx proposal contains a one-time address not in the signed tx set");
            cold_tx_proposal_by_ota[onetime_address] = new_idx;
        }
        cold_tx_proposals.push_back(p);
    };
    for (const HotColdCarrotTransactionProposalV1 &tx_proposal : signed_txs.tx_proposals)
        add_tx_prop(tx_proposal);
    for (const auto &signed_input : signed_txs.signed_inputs)
        if (cold_tx_proposal_by_ota.count(signed_input.second.first) == 0)
            add_tx_prop(supplemental_tx_proposals(signed_input.second.first));

    // collect signed inputs by tx proposal
    const std::size_t n_txs = cold_tx_proposals.size();
    std::vector<std::vector<signed_input_t>> signed_inputs(n_txs);
    for (const auto &signed_input : signed_txs.signed_inputs)
    {
        const std::size_t prop_idx = cold_tx_proposal_by_ota.at(signed_input.second.first);
        CARROT_CHECK_AND_THROW(prop_idx < signed_inputs.size(),
            carrot::carrot_logic_error, "BUG: cold tx proposal index out of bounds");
        signed_inputs.at(prop_idx).push_back(signed_input);
    }

    // sort signed inputs in each tx by descending key image
    for (std::vector<signed_input_t> &tx_signed_inputs : signed_inputs)
    {
        std::sort(tx_signed_inputs.begin(), tx_signed_inputs.end(), [](const auto &a, const auto &b){
            return std::greater{}(a.first, b.first);
        });
    }

    // key image device (pre-computed)
    carrot::key_image_device_precompted key_image_dev(std::move(key_image_by_ota));

    // expand cold tx proposals, using either in-tx-set opening hints or supplemental
    std::vector<std::vector<crypto::key_image>> input_key_images;
    std::vector<std::vector<FcmpRerandomizedOutputCompressed>> rerandomized_outputs;
    std::vector<std::vector<fcmp_pp::OutputPair>> input_pairs;
    input_key_images.reserve(n_txs);
    rerandomized_outputs.reserve(n_txs);
    input_pairs.reserve(n_txs);
    expanded_tx_proposals_out.reserve(n_txs);
    const auto input_proposals_by_ota = [&signed_txs, &supplemental_opening_hints](const crypto::public_key &ota)
        -> carrot::InputProposalV1
    {
        const auto signed_txs_it = signed_txs.tx_input_proposals.find(ota);
        if (signed_txs_it != signed_txs.tx_input_proposals.cend())
            return signed_txs_it->second;
        return supplemental_opening_hints(ota);
    };
    for (const HotColdCarrotTransactionProposalV1 &cold_tx_proposal : cold_tx_proposals)
    {
        carrot::CarrotTransactionProposalV1 &expanded_tx_proposal = expanded_tx_proposals_out.emplace_back();
        expand_carrot_transaction_proposal_and_rerandomized_outputs(cold_tx_proposal,
            input_proposals_by_ota,
            addr_dev,
            key_image_dev,
            expanded_tx_proposal,
            input_key_images.emplace_back(),
            rerandomized_outputs.emplace_back());

        std::vector<fcmp_pp::OutputPair> &input_pairs_tx = input_pairs.emplace_back();
        for (const carrot::InputProposalV1 &input_proposal : expanded_tx_proposal.input_proposals)
            input_pairs_tx.push_back(carrot::to_output_pair(input_proposal));
    }

    // finalize FCMPs and BP+s and form into actual txs
    txs_out.reserve(n_txs);
    for (std::size_t tx_idx = 0; tx_idx < n_txs; ++tx_idx)
    {
        const carrot::CarrotTransactionProposalV1 &tx_proposal = expanded_tx_proposals_out.at(tx_idx);
        const std::size_t n_inputs = tx_proposal.input_proposals.size();
        const std::vector<signed_input_t> &tx_signed_inputs = signed_inputs.at(tx_idx);
        const std::vector<crypto::key_image> &tx_input_key_images = input_key_images.at(tx_idx);
        const std::vector<FcmpRerandomizedOutputCompressed> &tx_rerandomized_outputs = rerandomized_outputs.at(tx_idx);
        const std::vector<fcmp_pp::OutputPair> &tx_input_pairs = input_pairs.at(tx_idx);

        // collect SA/Ls per tx
        std::vector<fcmp_pp::FcmpPpSalProof> tx_sal_proofs;
        tx_sal_proofs.reserve(n_inputs);
        for (const signed_input_t &signed_input : tx_signed_inputs)
            tx_sal_proofs.push_back(signed_input.second.second);

        // get output enote proposals
        std::vector<carrot::RCTOutputEnoteProposal> output_enote_proposals;
        carrot::encrypted_payment_id_t encrypted_payment_id;
        carrot::get_output_enote_proposals_from_proposal_v1(tx_proposal,
            nullptr,
            &addr_dev,
            tx_input_key_images.at(0),
            output_enote_proposals,
            encrypted_payment_id);

        // prove for tx
        txs_out.emplace_back() = finalize_fcmps_and_range_proofs(tx_input_key_images,
            tx_rerandomized_outputs,
            tx_input_pairs,
            tx_sal_proofs,
            output_enote_proposals,
            encrypted_payment_id,
            tx_proposal.fee,
            tree_cache,
            curve_trees);
    }
}
//-------------------------------------------------------------------------------------------------------------------
SignedFullTransactionSet finalize_signed_carrot_tx_set_v1_into_full_set(
    const SignedCarrotTransactionSetV1 &signed_txs,
    const std::function<HotColdCarrotTransactionProposalV1(const crypto::public_key&)> &supplemental_tx_proposals,
    const std::function<carrot::InputProposalV1(const crypto::public_key&)> &supplemental_input_proposals,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    const fcmp_pp::curve_trees::TreeCacheV1 &tree_cache,
    const fcmp_pp::curve_trees::CurveTreesV1 &curve_trees)
{
    std::vector<carrot::CarrotTransactionProposalV1> expanded_tx_proposals;
    std::vector<cryptonote::transaction> txs;
    finalize_proofs_for_signed_carrot_tx_set_v1(signed_txs,
        supplemental_tx_proposals,
        supplemental_input_proposals,
        addr_dev,
        tree_cache,
        curve_trees,
        expanded_tx_proposals,
        txs);

    const std::size_t n_txs = txs.size();
    CARROT_CHECK_AND_THROW(expanded_tx_proposals.size() == n_txs,
        carrot::carrot_logic_error, "BUG: expanded_tx_proposals and txs size mismatch");

    SignedFullTransactionSet full_signed_txs;
    full_signed_txs.ptx.reserve(n_txs);
    for (std::size_t tx_idx = 0; tx_idx < n_txs; ++tx_idx)
    {
        // collect key images from tx
        cryptonote::transaction &tx = txs[tx_idx];
        std::vector<crypto::key_image> sorted_input_key_images;
        sorted_input_key_images.reserve(tx.vin.size());
        for (const cryptonote::txin_v &in : tx.vin)
            sorted_input_key_images.push_back(boost::get<cryptonote::txin_to_key>(in).k_image);

        pending_tx &ptx = full_signed_txs.ptx.emplace_back(make_pending_carrot_tx(expanded_tx_proposals.at(tx_idx),
            sorted_input_key_images, addr_dev));
        ptx.tx = std::move(tx);
        ptx.tx_key = rct::rct2sk(rct::identity());
        ptx.additional_tx_keys.clear();
    }

    full_signed_txs.tx_key_images = signed_txs.other_key_images;

    return full_signed_txs;
}
//-------------------------------------------------------------------------------------------------------------------
void prove_key_image_proof(const carrot::OutputOpeningHintVariant &opening_hint,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    const crypto::secret_key &k_spend,
    KeyImageProofVariant &ki_proof_out,
    crypto::key_image &key_image_out)
{
    // x = k_s
    crypto::secret_key x = k_spend;

    // x += k^j_subext
    const carrot::subaddress_index_extended subaddr_index = subaddress_index_ref(opening_hint);
    CARROT_CHECK_AND_THROW(subaddr_index.derive_type == carrot::AddressDeriveType::PreCarrot,
        carrot::unexpected_scan_failure, "currently unsupported to make key image proofs with carrot keys derive type");
    crypto::secret_key subaddr_extension_g;
    crypto::secret_key dummy_subaddress_scalar;
    addr_dev.get_address_openings({{subaddr_index.index.major, subaddr_index.index.minor}},
        subaddr_extension_g, dummy_subaddress_scalar);
    assert(dummy_subaddress_scalar == crypto::secret_key{{1}});
    sc_add(to_bytes(x), to_bytes(subaddr_extension_g), to_bytes(x));

    // K_s = k_s G
    crypto::public_key main_address_spend_pubkey;
    addr_dev.get_address_spend_pubkey({}, main_address_spend_pubkey);

    const bool is_univariate = std::holds_alternative<carrot::LegacyOutputOpeningHintV1>(opening_hint);

    // get k^g_o, k^t_o
    crypto::secret_key sender_extension_g;
    crypto::secret_key sender_extension_t;
    const bool ki_scan_res = try_scan_opening_hint_sender_extensions(opening_hint,
        {&main_address_spend_pubkey, 1},
        &addr_dev,
        /*s_view_balance_dev=*/nullptr,
        sender_extension_g,
        sender_extension_t);
    CARROT_CHECK_AND_THROW(ki_scan_res,
        carrot::unexpected_scan_failure, "failed to scan legacy opening hint for key image proof");
    CARROT_CHECK_AND_THROW(!is_univariate || sender_extension_t == crypto::null_skey,
        carrot::unexpected_scan_failure, "sender extension over T is non-zero: cannot make univariate key image proof");

    // x += k^g_o
    sc_add(to_bytes(x), to_bytes(sender_extension_g), to_bytes(x));

    const crypto::public_key onetime_address = onetime_address_ref(opening_hint);
    if (is_univariate)
    {
        // x G ?= O
        crypto::public_key recomputed_onetime_address;
        crypto::secret_key_to_public_key(x, recomputed_onetime_address);
        CARROT_CHECK_AND_THROW(recomputed_onetime_address == onetime_address,
            carrot::unexpected_scan_failure, "failed to correctly recompute OTA for legacy opening hint");

        crypto::signature ki_proof;
        prove_ring_signature_key_image_proof(x, ki_proof, key_image_out);
        ki_proof_out = ki_proof;
    }
    else
    {
        // x G + y T ?= O
        crypto::public_key recomputed_onetime_address;
        crypto::secret_key_to_public_key(x, recomputed_onetime_address);
        recomputed_onetime_address = rct::rct2pk(rct::addKeys(rct::pk2rct(recomputed_onetime_address),
            rct::scalarmultKey(rct::pk2rct(crypto::get_T()), rct::sk2rct(sender_extension_t))));
        CARROT_CHECK_AND_THROW(recomputed_onetime_address == onetime_address,
            carrot::unexpected_scan_failure, "failed to correctly recompute OTA for bi-variate opening hint");

        fcmp_pp::FcmpPpSalProof ki_proof;
        prove_fcmp_sal_key_image_proof(x,
            sender_extension_t,
            carrot::use_biased_hash_to_point(opening_hint),
            ki_proof,
            key_image_out);
        ki_proof_out = ki_proof;
    }

    THROW_WALLET_EXCEPTION_IF(!validate_key_image_proof(onetime_address, key_image_out, ki_proof_out),
        error::signature_check_failed, std::string("key image proof immediately failed verification")
            + ": one-time address " + epee::string_tools::pod_to_hex(onetime_address)
            + ", key image " + epee::string_tools::pod_to_hex(key_image_out)
            + ", signature " + key_image_proof_to_readable_string(ki_proof_out)
            + ", univariate " + std::to_string(is_univariate)
            + ", subaddress " + std::to_string(subaddr_index.index.is_subaddress()));

    MDEBUG("Proved key image " << epee::string_tools::pod_to_hex(key_image_out) << " is associated to one-time address"
        << epee::string_tools::pod_to_hex(onetime_address));
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_ring_signature_key_image_proof(const crypto::public_key &onetime_address,
    const crypto::key_image &key_image,
    const crypto::signature &ki_proof)
{
    MDEBUG("Validating key image " << epee::string_tools::pod_to_hex(key_image) << " association to one-time address "
        << epee::string_tools::pod_to_hex(onetime_address) << " using bLSAG signature");

    const bool ki_in_main_group = rct::scalarmultKey(rct::ki2rct(key_image), rct::curveOrder()) == rct::identity();
    CHECK_AND_ASSERT_MES(ki_in_main_group, false,
        "Key image out of validity domain: " << epee::string_tools::pod_to_hex(key_image));

    return crypto::check_ring_signature(ki2hash(key_image),
        key_image,
        {&onetime_address},
        &ki_proof);
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_fcmp_pp_sal_key_image_proof(const crypto::public_key &onetime_address,
    const crypto::key_image &key_image,
    const fcmp_pp::FcmpPpSalProof &ki_proof)
{
    MDEBUG("Validating key image " << epee::string_tools::pod_to_hex(key_image) << " association to one-time address "
        << epee::string_tools::pod_to_hex(onetime_address) << " using FCMP++ SA/L signature");

    const bool ki_in_main_group = rct::scalarmultKey(rct::ki2rct(key_image), rct::curveOrder()) == rct::identity();
    CHECK_AND_ASSERT_MES(ki_in_main_group, false,
        "Key image out of validity domain: " << epee::string_tools::pod_to_hex(key_image));

    /**
     * WARNING: Trying to validate against both biased and unbiased key images may be insecure.
     *          It at least reduces security by 1 bit. Double check that this is okay.
     */
    for (int use_biased_hash_to_point = 0; use_biased_hash_to_point < 2; ++use_biased_hash_to_point)
    {
        const bool ver = fcmp_pp::verify_sal(ki2hash(key_image),
            ota_to_ki_proof_rerand_out(onetime_address, use_biased_hash_to_point).input,
            key_image,
            ki_proof);
        if (ver)
            return true;
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_key_image_proof(const crypto::public_key &onetime_address,
    const crypto::key_image &key_image,
    const KeyImageProofVariant &ki_proof)
{
    struct validate_key_image_proof_visitor
    {
        bool operator()(const crypto::signature &p) const
        { return validate_ring_signature_key_image_proof(onetime_address, key_image, p);}
        bool operator()(const fcmp_pp::FcmpPpSalProof &p) const
        { return validate_fcmp_pp_sal_key_image_proof(onetime_address, key_image, p);}

        const crypto::public_key &onetime_address;
        const crypto::key_image &key_image;
    };

    return std::visit(validate_key_image_proof_visitor{onetime_address, key_image}, ki_proof);
}
//-------------------------------------------------------------------------------------------------------------------
void encrypt_exported_outputs(const std::uint64_t transfers_offset,
    const std::uint64_t transfers_size,
    const std::vector<exported_transfer_details_variant> &outputs,
    const crypto::public_key &account_spend_pubkey,
    const crypto::secret_key &k_view,
    const std::uint64_t kdf_rounds,
    std::string &payload_out)
{
    // K^0_v = k_v G
    crypto::public_key main_address_view_pubkey;
    crypto::secret_key_to_public_key(k_view, main_address_view_pubkey);

    // serialize payload
    outputs_message_v5 msg{
        .main_address_spend_pubkey = account_spend_pubkey,
        .main_address_view_pubkey = main_address_view_pubkey,
        .transfers_offset = transfers_offset,
        .transfers_size = transfers_size,
        .outputs = outputs
    };

    std::string plaintext_payload;
    THROW_WALLET_EXCEPTION_IF(!::serialization::dump_binary(msg, plaintext_payload),
        error::wallet_internal_error, "outputs payload v5 failed to serialize");

    // encrypt
    payload_out = encrypt_with_ec_key(plaintext_payload.data(),
        plaintext_payload.size(),
        k_view,
        /*authenticated=*/true,
        kdf_rounds);
    memwipe(&plaintext_payload[0], plaintext_payload.size());

    // add prefix
    static constexpr char msg_version = 5;
    payload_out.insert(payload_out.begin(), msg_version);
    payload_out.insert(0, OUTPUT_EXPORT_FILE_MAGIC);
}
//-------------------------------------------------------------------------------------------------------------------
void decrypt_exported_outputs(const std::string &payload,
    const crypto::public_key &account_spend_pubkey,
    const crypto::secret_key &k_view,
    const std::uint64_t kdf_rounds,
    std::uint64_t &transfers_offset_out,
    std::uint64_t &transfers_size_out,
    std::vector<exported_transfer_details_variant> &outputs_out)
{
    transfers_offset_out = 0;
    transfers_size_out = 0;
    outputs_out.clear();

    // magic check
    const std::size_t magic_size = OUTPUT_EXPORT_FILE_MAGIC.size();
    const std::size_t prefix_size = magic_size + 1;
    THROW_WALLET_EXCEPTION_IF(payload.size() <= prefix_size,
        error::wallet_internal_error, "outputs payload too short");
    THROW_WALLET_EXCEPTION_IF(memcmp(payload.data(), OUTPUT_EXPORT_FILE_MAGIC.data(), magic_size),
        error::wallet_internal_error, "outputs payload magic mismatch");

    // version check
    const std::uint8_t msg_version = payload.at(magic_size);
    THROW_WALLET_EXCEPTION_IF(msg_version < 5, error::wallet_internal_error, "outputs payload version too low");

    // decrypt
    const epee::wipeable_string decrypted_payload = decrypt_with_ec_key(payload.data() + prefix_size,
        payload.size() - prefix_size,
        k_view,
        /*authenticated=*/true,
        kdf_rounds);

    // K^0_v = k_v G
    crypto::public_key main_address_view_pubkey;
    crypto::secret_key_to_public_key(k_view, main_address_view_pubkey);

    // deserialize
    binary_archive<false> ar({reinterpret_cast<const uint8_t*>(decrypted_payload.data()), decrypted_payload.size()});
    if (msg_version == 5)
    {
        outputs_message_v5 msg;
        THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar, msg),
            tools::error::wallet_internal_error, "key images payload v3 failed to deserialize");
        THROW_WALLET_EXCEPTION_IF(msg.main_address_spend_pubkey != account_spend_pubkey,
            tools::error::wallet_internal_error, "key images payload meant for another wallet");
        THROW_WALLET_EXCEPTION_IF(msg.main_address_view_pubkey != main_address_view_pubkey,
            tools::error::wallet_internal_error, "key images payload meant for another wallet");
        transfers_offset_out = msg.transfers_offset;
        transfers_size_out = msg.transfers_size;
        outputs_out = std::move(msg.outputs);
    }
    else
    {
        THROW_WALLET_EXCEPTION(error::wallet_internal_error, "unrecognized outputs payload version");
    }
}
//-------------------------------------------------------------------------------------------------------------------
void encrypt_key_images(const std::uint64_t offset,
    const std::vector<std::pair<crypto::key_image, KeyImageProofVariant>> &key_images,
    const crypto::public_key &account_spend_pubkey,
    const crypto::secret_key &k_view,
    const std::uint64_t kdf_rounds,
    std::string &payload_out)
{
    // K^0_v = k_v G
    crypto::public_key main_address_view_pubkey;
    crypto::secret_key_to_public_key(k_view, main_address_view_pubkey);

    // use v3 if possible
    bool is_v3_possible = true;
    for (const auto &p : key_images)
        if (!std::holds_alternative<crypto::signature>(p.second))
            is_v3_possible = false;
    const std::uint8_t msg_version = is_v3_possible ? 3 : 4;

    // serialize payload
    std::stringstream ss;
    binary_archive<true> ar(ss);
    if (msg_version == 3)
    {
        key_image_message_v3 msg;
        msg.offset = offset;
        msg.main_address_spend_pubkey = account_spend_pubkey;
        msg.main_address_view_pubkey = main_address_view_pubkey;
        for (const auto &p : key_images)
            msg.univariate_key_images.emplace_back(p.first, std::get<crypto::signature>(p.second));
        THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar, msg),
            tools::error::wallet_internal_error, "key images payload v3 failed to serialize");
    }
    else if (msg_version == 4)
    {
        key_image_message_v4 msg;
        msg.offset = offset;
        msg.main_address_spend_pubkey = account_spend_pubkey;
        msg.main_address_view_pubkey = main_address_view_pubkey;
        msg.key_images = std::move(key_images);
        THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar, msg),
            tools::error::wallet_internal_error, "key images payload v4 failed to serialize");
    }
    else
    {
        throw carrot::carrot_logic_error("unrecognized key image payload message version");
    }

    // encrypt
    std::string plaintext_payload = ss.str();
    payload_out = encrypt_with_ec_key(plaintext_payload.data(),
        plaintext_payload.size(),
        k_view,
        /*authenticated=*/true,
        kdf_rounds);
    memwipe(&plaintext_payload[0], plaintext_payload.size());

    // add prefix
    payload_out.insert(payload_out.begin(), msg_version);
    payload_out.insert(0, KEY_IMAGE_EXPORT_FILE_MAGIC);
}
//-------------------------------------------------------------------------------------------------------------------
void decrypt_key_images(const std::string &payload,
    const crypto::public_key &account_spend_pubkey,
    const crypto::secret_key &k_view,
    const std::uint64_t kdf_rounds,
    std::uint64_t &offset_out,
    std::vector<std::pair<crypto::key_image, KeyImageProofVariant>> &key_images_out)
{
    offset_out = 0;
    key_images_out.clear();

    // magic check
    const std::size_t magic_size = KEY_IMAGE_EXPORT_FILE_MAGIC.size();
    const std::size_t prefix_size = magic_size + 1;
    THROW_WALLET_EXCEPTION_IF(payload.size() <= prefix_size,
        error::wallet_internal_error, "key images payload too short");
    THROW_WALLET_EXCEPTION_IF(memcmp(payload.data(), KEY_IMAGE_EXPORT_FILE_MAGIC.data(), magic_size),
        error::wallet_internal_error, "key images payload magic mismatch");

    // version check
    const std::uint8_t msg_version = payload.at(magic_size);
    THROW_WALLET_EXCEPTION_IF(msg_version < 3, error::wallet_internal_error, "key images payload version too low");

    // decrypt
    const epee::wipeable_string decrypted_payload = decrypt_with_ec_key(payload.data() + prefix_size,
        payload.size() - prefix_size,
        k_view,
        /*authenticated=*/true,
        kdf_rounds);

    // K^0_v = k_v G
    crypto::public_key main_address_view_pubkey;
    crypto::secret_key_to_public_key(k_view, main_address_view_pubkey);

    // deserialize
    binary_archive<false> ar({reinterpret_cast<const uint8_t*>(decrypted_payload.data()), decrypted_payload.size()});
    if (msg_version == 3)
    {
        key_image_message_v3 msg;
        THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar, msg),
            tools::error::wallet_internal_error, "key images payload v3 failed to deserialize");
        THROW_WALLET_EXCEPTION_IF(msg.main_address_spend_pubkey != account_spend_pubkey,
            tools::error::wallet_internal_error, "key images payload meant for another wallet");
        THROW_WALLET_EXCEPTION_IF(msg.main_address_view_pubkey != main_address_view_pubkey,
            tools::error::wallet_internal_error, "key images payload meant for another wallet");
        offset_out = msg.offset;
        key_images_out.reserve(msg.univariate_key_images.size());
        for (const auto &p : msg.univariate_key_images)
            key_images_out.emplace_back(p.first, p.second);
    }
    else if (msg_version == 4)
    {
        key_image_message_v4 msg;
        THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar, msg),
            tools::error::wallet_internal_error, "key images payload v4 failed to deserialize");
        THROW_WALLET_EXCEPTION_IF(msg.main_address_spend_pubkey != account_spend_pubkey,
            tools::error::wallet_internal_error, "key images payload meant for another wallet");
        THROW_WALLET_EXCEPTION_IF(msg.main_address_view_pubkey != main_address_view_pubkey,
            tools::error::wallet_internal_error, "key images payload meant for another wallet");
        offset_out = msg.offset;
        key_images_out = msg.key_images;
    }
    else
    {
        THROW_WALLET_EXCEPTION(error::wallet_internal_error, "unrecognized key images payload version");
    }
}
//-------------------------------------------------------------------------------------------------------------------
void encrypt_unsigned_tx_set(const UnsignedTransactionSetVariant &unsigned_txs,
    const crypto::secret_key &k_view,
    const std::uint64_t kdf_rounds,
    std::string &payload_out)
{
    // serialize payload
    std::string plaintext_payload;
    THROW_WALLET_EXCEPTION_IF(!::serialization::dump_binary(const_cast<UnsignedTransactionSetVariant&>(unsigned_txs),
            plaintext_payload),
        error::wallet_internal_error, "unsigned tx set payload failed to serialize");

    // encrypt
    payload_out = encrypt_with_ec_key(plaintext_payload.data(),
        plaintext_payload.size(),
        k_view,
        /*authenticated=*/true,
        kdf_rounds);
    memwipe(&plaintext_payload[0], plaintext_payload.size());

    // add prefix
    const bool is_v5_possible = std::holds_alternative<UnsignedPreCarrotTransactionSet>(unsigned_txs);
    const char msg_version = is_v5_possible ? 5 : 6;
    payload_out.insert(payload_out.begin(), msg_version);
    payload_out.insert(0, UNSIGNED_TX_PREFIX);
}
//-------------------------------------------------------------------------------------------------------------------
void decrypt_unsigned_tx_set(const std::string payload,
    const crypto::secret_key &k_view,
    const std::uint64_t kdf_rounds,
    UnsignedTransactionSetVariant &unsigned_txs_out)
{
    unsigned_txs_out = {};

    // magic check
    const std::size_t magic_size = UNSIGNED_TX_PREFIX.size();
    const std::size_t prefix_size = magic_size + 1;
    THROW_WALLET_EXCEPTION_IF(payload.size() <= prefix_size,
        error::wallet_internal_error, "unsigned tx set payload too short");
    THROW_WALLET_EXCEPTION_IF(memcmp(payload.data(), UNSIGNED_TX_PREFIX.data(), magic_size),
        error::wallet_internal_error, "unsigned tx set payload magic mismatch");

    // version check
    const std::uint8_t msg_version = payload.at(magic_size);
    THROW_WALLET_EXCEPTION_IF(msg_version < 5, error::wallet_internal_error, "unsigned tx set payload version too low");

    // decrypt
    const epee::wipeable_string decrypted_payload = decrypt_with_ec_key(payload.data() + prefix_size,
        payload.size() - prefix_size,
        k_view,
        /*authenticated=*/true,
        kdf_rounds);

    // deserialize
    binary_archive<false> ar({reinterpret_cast<const uint8_t*>(decrypted_payload.data()), decrypted_payload.size()});
    if (msg_version == 5 || msg_version == 6)
    {
        THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar, unsigned_txs_out),
            tools::error::wallet_internal_error, "unsigned tx set failed to deserialize");
    }
    else
    {
        THROW_WALLET_EXCEPTION(error::wallet_internal_error, "unrecognized unsigned tx set payload version");
    }
}
//-------------------------------------------------------------------------------------------------------------------
void encrypt_signed_tx_set(const SignedTransactionSetVariant &signed_txs,
    const crypto::secret_key &k_view,
    const std::uint64_t kdf_rounds,
    std::string &payload_out)
{
    // serialize payload
    std::string plaintext_payload;
    THROW_WALLET_EXCEPTION_IF(!::serialization::dump_binary(const_cast<SignedTransactionSetVariant&>(signed_txs),
            plaintext_payload),
        error::wallet_internal_error, "signed tx set payload failed to serialize");

    // encrypt
    payload_out = encrypt_with_ec_key(plaintext_payload.data(),
        plaintext_payload.size(),
        k_view,
        /*authenticated=*/true,
        kdf_rounds);
    memwipe(&plaintext_payload[0], plaintext_payload.size());

    // add prefix
    const bool is_v5_possible = std::holds_alternative<SignedFullTransactionSet>(signed_txs);
    const char msg_version = is_v5_possible ? 5 : 6;
    payload_out.insert(payload_out.begin(), msg_version);
    payload_out.insert(0, SIGNED_TX_PREFIX);
}
//-------------------------------------------------------------------------------------------------------------------
void decrypt_signed_tx_set(const std::string payload,
    const crypto::secret_key &k_view,
    const std::uint64_t kdf_rounds,
    SignedTransactionSetVariant &signed_txs_out)
{
    signed_txs_out = {};

    // magic check
    const std::size_t magic_size = SIGNED_TX_PREFIX.size();
    const std::size_t prefix_size = magic_size + 1;
    THROW_WALLET_EXCEPTION_IF(payload.size() <= prefix_size,
        error::wallet_internal_error, "signed tx set payload too short");
    THROW_WALLET_EXCEPTION_IF(memcmp(payload.data(), SIGNED_TX_PREFIX.data(), magic_size),
        error::wallet_internal_error, "signed tx set payload magic mismatch");

    // version check
    const std::uint8_t msg_version = payload.at(magic_size);
    THROW_WALLET_EXCEPTION_IF(msg_version < 5, error::wallet_internal_error, "signed tx set payload version too low");

    // decrypt
    const epee::wipeable_string decrypted_payload = decrypt_with_ec_key(payload.data() + prefix_size,
        payload.size() - prefix_size,
        k_view,
        /*authenticated=*/true,
        kdf_rounds);

    // deserialize
    binary_archive<false> ar({reinterpret_cast<const uint8_t*>(decrypted_payload.data()), decrypted_payload.size()});
    if (msg_version == 5 || msg_version == 6)
    {
        THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar, signed_txs_out),
            tools::error::wallet_internal_error, "signed tx set failed to deserialize");
    }
    else
    {
        THROW_WALLET_EXCEPTION(error::wallet_internal_error, "unrecognized unsigned tx set payload version");
    }
}
//-------------------------------------------------------------------------------------------------------------------
std::string key_image_proof_to_readable_string(const KeyImageProofVariant &ki_proof)
{
    struct key_image_proof_to_readable_string_visitor
    {
        std::string operator()(const crypto::signature &s) const {return epee::string_tools::pod_to_hex(s);}
        std::string operator()(const fcmp_pp::FcmpPpSalProof &s) const {return epee::to_hex::string(epee::to_span(s));}
    };
    return std::visit(key_image_proof_to_readable_string_visitor{}, ki_proof);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_key_image_proof_from_readable_string(const std::string &str, KeyImageProofVariant &ki_proof_out)
{
    static constexpr std::size_t max_byte_size = FCMP_PP_SAL_PROOF_SIZE_V1;

    if (str.size() > max_byte_size * 2 || str.size() % 2 == 1)
        return false;

    // decode hex into bytes
    std::vector<std::uint8_t> bytes;
    bytes.resize(str.size() / 2);
    if (!epee::from_hex::to_buffer(epee::to_mut_span(bytes), str))
        return false;

    // depending on size of bytes, set variant
    switch (bytes.size())
    {
    case sizeof(crypto::signature):
        memcpy(&ki_proof_out.emplace<crypto::signature>(), bytes.data(), sizeof(crypto::signature));
        break;
    case FCMP_PP_SAL_PROOF_SIZE_V1:
        ki_proof_out = std::move(bytes);
        break;
    default:
        return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace cold
} //namespace wallet
} //namespace tools
