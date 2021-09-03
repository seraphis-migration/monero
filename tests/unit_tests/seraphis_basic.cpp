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

#include "common/container_helpers.h"
#include "crypto/crypto.h"
#include "crypto/x25519.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "device/device.hpp"
#include "misc_language.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/binned_reference_set.h"
#include "seraphis_core/binned_reference_set_utils.h"
#include "seraphis_core/discretized_fee.h"
#include "seraphis_core/jamtis_address_tag_utils.h"
#include "seraphis_core/jamtis_address_utils.h"
#include "seraphis_core/jamtis_core_utils.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_core/jamtis_enote_utils.h"
#include "seraphis_core/jamtis_payment_proposal.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_core/sp_core_enote_utils.h"
#include "seraphis_core/sp_core_types.h"
#include "seraphis_core/sp_ref_set_index_mapper_flat.h"
#include "seraphis_core/tx_extra.h"
#include "seraphis_crypto/sp_composition_proof.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_crypto/sp_hash_functions.h"
#include "seraphis_crypto/sp_transcript.h"
#include "seraphis_main/enote_record_types.h"
#include "seraphis_main/enote_record_utils.h"
#include "seraphis_main/tx_builder_types.h"
#include "seraphis_main/tx_builder_types_legacy.h"
#include "seraphis_main/tx_builders_inputs.h"
#include "seraphis_main/tx_builders_legacy_inputs.h"
#include "seraphis_main/tx_builders_mixed.h"
#include "seraphis_main/tx_builders_outputs.h"
#include "seraphis_main/tx_component_types.h"
#include "seraphis_main/tx_component_types_legacy.h"
#include "seraphis_main/txtype_base.h"
#include "seraphis_main/txtype_squashed_v1.h"
#include "seraphis_mocks/seraphis_mocks.h"

#include "boost/multiprecision/cpp_int.hpp"
#include "gtest/gtest.h"

#include <algorithm>
#include <memory>
#include <vector>

using namespace sp;
using namespace jamtis;
using namespace sp::mocks;
using namespace jamtis::mocks;


//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static crypto::secret_key make_secret_key()
{
    return rct::rct2sk(rct::skGen());
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_secret_key(crypto::secret_key &skey_out)
{
    skey_out = make_secret_key();
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_secret_key(crypto::x25519_secret_key &skey_out)
{
    skey_out = crypto::x25519_secret_key_gen();
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void check_is_owned_with_intermediate_record(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const jamtis_mock_keys &keys,
    const address_index_t &j_expected,
    const rct::xmr_amount amount_expected)
{
    // try to extract intermediate information from the enote
    // - only succeeds if enote is owned and is a plain jamtis enote
    SpIntermediateEnoteRecordV1 intermediate_enote_record;
    EXPECT_TRUE(try_get_intermediate_enote_record_v1(enote,
        enote_ephemeral_pubkey,
        input_context,
        keys.K_1_base,
        keys.xk_ua,
        keys.xk_fr,
        keys.s_ga,
        intermediate_enote_record));

    // check misc fields
    EXPECT_TRUE(intermediate_enote_record.amount == amount_expected);
    EXPECT_TRUE(intermediate_enote_record.address_index == j_expected);

    // get full enote record from intermediate record
    SpEnoteRecordV1 enote_record;
    EXPECT_TRUE(try_get_enote_record_v1_plain(intermediate_enote_record, keys.K_1_base, keys.k_vb, enote_record));

    // check misc fields
    EXPECT_TRUE(enote_record.type == JamtisEnoteType::PLAIN);
    EXPECT_TRUE(enote_record.amount == amount_expected);
    EXPECT_TRUE(enote_record.address_index == j_expected);

    // check key image
    rct::key spendkey_U_component{keys.K_1_base};
    reduce_seraphis_spendkey_x(keys.k_vb, spendkey_U_component);
    extend_seraphis_spendkey_u(enote_record.enote_view_extension_u, spendkey_U_component);
    crypto::key_image reproduced_key_image;
    make_seraphis_key_image(add_secrets(enote_record.enote_view_extension_x, keys.k_vb),
        rct::rct2pk(spendkey_U_component),
        reproduced_key_image);
    EXPECT_TRUE(enote_record.key_image == reproduced_key_image);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void check_is_owned(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const jamtis_mock_keys &keys,
    const address_index_t &j_expected,
    const rct::xmr_amount amount_expected,
    const JamtisEnoteType type_expected)
{
    // try to extract information from the enote (only succeeds if enote is owned)
    SpEnoteRecordV1 enote_record;
    EXPECT_TRUE(try_get_enote_record_v1(enote,
        enote_ephemeral_pubkey,
        input_context,
        keys.K_1_base,
        keys.k_vb,
        enote_record));

    // check misc fields
    EXPECT_TRUE(enote_record.type == type_expected);
    EXPECT_TRUE(enote_record.amount == amount_expected);
    EXPECT_TRUE(enote_record.address_index == j_expected);

    // check onetime address can be recomputed from the enote record
    rct::key recipient_address_spend_key;
    make_jamtis_address_spend_key(keys.K_1_base, keys.s_ga, j_expected, recipient_address_spend_key);

    rct::key sender_receiver_secret;
    if (enote_record.type == JamtisEnoteType::PLAIN)
    {
        make_jamtis_sender_receiver_secret_plain(keys.xk_fr,
            enote_record.enote_ephemeral_pubkey,
            enote_record.enote_ephemeral_pubkey,
            enote_record.input_context,
            sender_receiver_secret);
    }
    else
    {
        JamtisSelfSendType selfsend_type;
        EXPECT_TRUE(try_get_jamtis_self_send_type(enote_record.type, selfsend_type));

        make_jamtis_sender_receiver_secret_selfsend(keys.k_vb,
            enote_record.enote_ephemeral_pubkey,
            enote_record.input_context,
            selfsend_type,
            sender_receiver_secret);
    }

    EXPECT_TRUE(test_jamtis_onetime_address(recipient_address_spend_key,
        sender_receiver_secret,
        amount_commitment_ref(enote),
        onetime_address_ref(enote)));

    // check key image
    rct::key spendkey_U_component{keys.K_1_base};
    reduce_seraphis_spendkey_x(keys.k_vb, spendkey_U_component);
    extend_seraphis_spendkey_u(enote_record.enote_view_extension_u, spendkey_U_component);
    crypto::key_image reproduced_key_image;
    make_seraphis_key_image(add_secrets(enote_record.enote_view_extension_x, keys.k_vb),
        rct::rct2pk(spendkey_U_component),
        reproduced_key_image);
    EXPECT_TRUE(enote_record.key_image == reproduced_key_image);

    // for plain enotes, double-check ownership with an intermediate record
    if (enote_record.type == JamtisEnoteType::PLAIN)
    {
        check_is_owned_with_intermediate_record(enote,
            enote_ephemeral_pubkey,
            input_context,
            keys,
            j_expected,
            amount_expected);
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void check_is_owned(const SpCoinbaseOutputProposalV1 &test_proposal,
    const std::uint64_t block_height,
    const jamtis_mock_keys &keys,
    const address_index_t &j_expected,
    const rct::xmr_amount amount_expected,
    const JamtisEnoteType type_expected)
{
    // prepare coinbase input context
    rct::key input_context;
    make_jamtis_input_context_coinbase(block_height, input_context);

    // check info
    check_is_owned(test_proposal.enote,
        test_proposal.enote_ephemeral_pubkey,
        input_context,
        keys,
        j_expected,
        amount_expected,
        type_expected);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void check_is_owned(const SpOutputProposalV1 &test_proposal,
    const jamtis_mock_keys &keys,
    const address_index_t &j_expected,
    const rct::xmr_amount amount_expected,
    const JamtisEnoteType type_expected)
{
    // convert to enote
    SpEnoteV1 enote;
    get_enote_v1(test_proposal, enote);

    // check info
    check_is_owned(enote,
        test_proposal.enote_ephemeral_pubkey,
        rct::zero(),
        keys,
        j_expected,
        amount_expected,
        type_expected);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void check_is_owned(const JamtisPaymentProposalSelfSendV1 &test_proposal,
    const jamtis_mock_keys &keys,
    const address_index_t &j_expected,
    const rct::xmr_amount amount_expected,
    const JamtisEnoteType type_expected)
{
    // convert to output proposal
    SpOutputProposalV1 output_proposal;
    make_v1_output_proposal_v1(test_proposal, keys.k_vb, rct::zero(), output_proposal);

    // check ownership
    check_is_owned(output_proposal, keys, j_expected, amount_expected, type_expected);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool test_binned_reference_set(const std::uint64_t distribution_min_index,
    const std::uint64_t distribution_max_index,
    const ref_set_bin_dimension_v1_t bin_radius,
    const ref_set_bin_dimension_v1_t num_bin_members,
    const std::uint64_t reference_set_size,
    const std::uint64_t real_reference_index)
{
    const SpRefSetIndexMapperFlat flat_index_mapper{distribution_min_index, distribution_max_index};
    const SpBinnedReferenceSetConfigV1 bin_config{
            .bin_radius = bin_radius,
            .num_bin_members = num_bin_members
        };

    for (std::size_t i{0}; i < 50; ++i)
    {
        // make a reference set
        SpBinnedReferenceSetV1 binned_reference_set;
        make_binned_reference_set_v1(flat_index_mapper,
            bin_config,
            rct::pkGen(),
            reference_set_size,
            real_reference_index,
            binned_reference_set);

        // bin config should persist
        if (binned_reference_set.bin_config != bin_config)
            return false;

        // bins should be sorted
        if (!std::is_sorted(binned_reference_set.bin_loci.begin(), binned_reference_set.bin_loci.end()))
            return false;

        // extract the references twice (should get the same results)
        std::vector<std::uint64_t> reference_indices_1;
        std::vector<std::uint64_t> reference_indices_2;
        if(!try_get_reference_indices_from_binned_reference_set_v1(binned_reference_set, reference_indices_1))
            return false;
        if(!try_get_reference_indices_from_binned_reference_set_v1(binned_reference_set, reference_indices_2))
            return false;

        if (reference_indices_1 != reference_indices_2)
            return false;

        // check the references
        if (reference_indices_1.size() != reference_set_size)
            return false;

        bool found_real{false};
        for (const std::uint64_t reference_index : reference_indices_1)
        {
            if (reference_index < distribution_min_index)
                return false;
            if (reference_index > distribution_max_index)
                return false;

            if (reference_index == real_reference_index)
                found_real = true;
        }
        if (!found_real)
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_sp_txtype_squashed_v1(const std::size_t legacy_ring_size,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    const std::size_t num_random_memo_elements,
    const std::vector<rct::xmr_amount> &in_legacy_amounts,
    const std::vector<rct::xmr_amount> &in_sp_amounts,
    const std::vector<rct::xmr_amount> &out_amounts,
    const DiscretizedFee discretized_transaction_fee,
    const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    MockLedgerContext &ledger_context_inout,
    SpTxSquashedV1 &tx_out)
{
    /// build a tx from base components

    rct::xmr_amount raw_transaction_fee;
    CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(discretized_transaction_fee, raw_transaction_fee),
        "SpTxSquashedV1 (unit test): tried to raw make tx with invalid discretized fee.");

    CHECK_AND_ASSERT_THROW_MES(in_legacy_amounts.size() + in_sp_amounts.size() > 0,
        "SpTxSquashedV1 (unit test): tried to raw make tx without any inputs.");
    CHECK_AND_ASSERT_THROW_MES(out_amounts.size() > 0, "SpTxSquashedV1: tried to raw make tx without any outputs.");

    std::vector<rct::xmr_amount> all_in_amounts{in_legacy_amounts};
    all_in_amounts.insert(all_in_amounts.end(), in_sp_amounts.begin(), in_sp_amounts.end());
    CHECK_AND_ASSERT_THROW_MES(balance_check_in_out_amnts(all_in_amounts, out_amounts, raw_transaction_fee),
        "SpTxSquashedV1 (unit test): tried to raw make tx with unbalanced amounts.");

    // make wallet core privkeys (spend keys for legacy and seraphis, view key for seraphis)
    const crypto::secret_key legacy_spend_privkey{rct::rct2sk(rct::skGen())};
    const crypto::secret_key sp_spend_privkey{rct::rct2sk(rct::skGen())};
    const crypto::secret_key k_view_balance{rct::rct2sk(rct::skGen())};

    // make mock legacy input proposals
    std::vector<LegacyInputProposalV1> legacy_input_proposals{
            gen_mock_legacy_input_proposals_v1(legacy_spend_privkey, in_legacy_amounts)
        };

    // make mock seraphis input proposals
    std::vector<SpInputProposalV1> sp_input_proposals{
            gen_mock_sp_input_proposals_v1(sp_spend_privkey, k_view_balance, in_sp_amounts)
        };

    // make mock output proposals
    std::vector<SpOutputProposalV1> output_proposals{
            gen_mock_sp_output_proposals_v1(out_amounts, num_random_memo_elements)
        };

    // for 2-out txs, can only have one unique enote ephemeral pubkey
    if (output_proposals.size() == 2)
        output_proposals[1].enote_ephemeral_pubkey = output_proposals[0].enote_ephemeral_pubkey;

    // pre-sort inputs and outputs (doing this here makes everything else easier)
    std::sort(legacy_input_proposals.begin(),
        legacy_input_proposals.end(),
        tools::compare_func<LegacyInputProposalV1>(compare_KI));
    std::sort(sp_input_proposals.begin(),
        sp_input_proposals.end(),
        tools::compare_func<SpInputProposalV1>(compare_KI));
    std::sort(output_proposals.begin(),
        output_proposals.end(),
        tools::compare_func<SpOutputProposalV1>(compare_Ko));

    // make mock memo elements
    std::vector<ExtraFieldElement> additional_memo_elements;
    additional_memo_elements.resize(num_random_memo_elements);
    for (ExtraFieldElement &element : additional_memo_elements)
        element = gen_extra_field_element();

    // versioning for proofs
    const tx_version_t tx_version{tx_version_from(semantic_rules_version)};

    // tx components
    std::vector<LegacyEnoteImageV2> legacy_input_images;
    std::vector<SpEnoteImageV1> sp_input_images;
    std::vector<SpEnoteV1> outputs;
    SpBalanceProofV1 balance_proof;
    std::vector<LegacyRingSignatureV4> tx_legacy_ring_signatures;
    std::vector<SpImageProofV1> tx_sp_image_proofs;
    std::vector<SpAlignableMembershipProofV1> tx_sp_alignable_membership_proofs;
    std::vector<SpMembershipProofV1> tx_sp_membership_proofs;
    SpTxSupplementV1 tx_supplement;

    // info shuttles for making components
    std::vector<rct::xmr_amount> output_amounts;
    std::vector<crypto::secret_key> output_amount_commitment_blinding_factors;
    rct::key tx_proposal_prefix;
    std::vector<rct::xmr_amount> input_legacy_amounts;
    std::vector<rct::xmr_amount> input_sp_amounts;
    std::vector<crypto::secret_key> legacy_input_image_amount_commitment_blinding_factors;
    std::vector<crypto::secret_key> sp_input_image_amount_commitment_blinding_factors;

    legacy_input_images.reserve(legacy_input_proposals.size());
    sp_input_images.reserve(sp_input_proposals.size());

    // make everything
    make_v1_outputs_v1(output_proposals,
        outputs,
        output_amounts,
        output_amount_commitment_blinding_factors,
        tx_supplement.output_enote_ephemeral_pubkeys);
    for (const SpOutputProposalV1 &output_proposal : output_proposals)
        accumulate_extra_field_elements(output_proposal.partial_memo, additional_memo_elements);
    make_tx_extra(std::move(additional_memo_elements), tx_supplement.tx_extra);
    for (const LegacyInputProposalV1 &legacy_input_proposal : legacy_input_proposals)
    {
        legacy_input_images.emplace_back();
        get_enote_image_v2(legacy_input_proposal, legacy_input_images.back());
    }
    for (const SpInputProposalV1 &sp_input_proposal : sp_input_proposals)
    {
        sp_input_images.emplace_back();
        get_enote_image_v1(sp_input_proposal, sp_input_images.back());
    }
    make_tx_proposal_prefix_v1(tx_version,
        legacy_input_images,
        sp_input_images,
        outputs,
        discretized_transaction_fee,
        tx_supplement,
        tx_proposal_prefix);
    std::vector<LegacyRingSignaturePrepV1> legacy_ring_signature_preps{
            gen_mock_legacy_ring_signature_preps_v1(tx_proposal_prefix,
                legacy_input_proposals,
                legacy_ring_size,
                ledger_context_inout)
        };
    make_v3_legacy_ring_signatures_v1(std::move(legacy_ring_signature_preps),
        legacy_spend_privkey,
        hw::get_device("default"),
        tx_legacy_ring_signatures);
    make_v1_image_proofs_v1(sp_input_proposals,
        tx_proposal_prefix,
        sp_spend_privkey,
        k_view_balance,
        tx_sp_image_proofs);
    get_legacy_input_commitment_factors_v1(legacy_input_proposals,
        input_legacy_amounts,
        legacy_input_image_amount_commitment_blinding_factors);
    get_input_commitment_factors_v1(sp_input_proposals,
        input_sp_amounts,
        sp_input_image_amount_commitment_blinding_factors);
    make_v1_balance_proof_v1(input_legacy_amounts,
        input_sp_amounts, //note: must range proof seraphis input image commitments in squashed enote model
        output_amounts,
        raw_transaction_fee,
        legacy_input_image_amount_commitment_blinding_factors,
        sp_input_image_amount_commitment_blinding_factors,
        output_amount_commitment_blinding_factors,
        balance_proof);
    std::vector<SpMembershipProofPrepV1> sp_membership_proof_preps{
            gen_mock_sp_membership_proof_preps_v1(sp_input_proposals,
                ref_set_decomp_n,
                ref_set_decomp_m,
                bin_config,
                ledger_context_inout)
        };
    make_v1_alignable_membership_proofs_v1(std::move(sp_membership_proof_preps),
        tx_sp_alignable_membership_proofs);  //alignable membership proofs could theoretically be user inputs as well
    align_v1_membership_proofs_v1(sp_input_images, std::move(tx_sp_alignable_membership_proofs), tx_sp_membership_proofs);

    make_seraphis_tx_squashed_v1(semantic_rules_version, std::move(legacy_input_images), std::move(sp_input_images),
        std::move(outputs), std::move(balance_proof), std::move(tx_legacy_ring_signatures), std::move(tx_sp_image_proofs),
        std::move(tx_sp_membership_proofs), std::move(tx_supplement), discretized_transaction_fee, tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool test_info_recovery_addressindex(const address_index_t &j)
{
    // cipher and decipher the index
    crypto::secret_key cipher_key;
    make_secret_key(cipher_key);
    const address_tag_t address_tag{cipher_address_index(cipher_key, j)};
    address_index_t decipher_j;
    if (!try_decipher_address_index(cipher_key, address_tag, decipher_j))
        return false;
    if (decipher_j != j)
        return false;

    // encrypt and decrypt an address tag
    const rct::key sender_receiver_secret{rct::skGen()};
    const rct::key onetime_address{rct::pkGen()};
    const encrypted_address_tag_t encrypted_address_tag{
            encrypt_address_tag(sender_receiver_secret, onetime_address, address_tag)
        };
    if (decrypt_address_tag(sender_receiver_secret, onetime_address, encrypted_address_tag) != address_tag)
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_basic, information_recovery_keyimage)
{
    // different methods for making key images all have same results
    crypto::secret_key y, z, k_a_sender_x, k_a_recipient_x;
    rct::key zU, k_bU;
    crypto::key_image key_image1, key_image2, key_image_jamtis;

    make_secret_key(y);
    k_a_sender_x = y;
    k_a_recipient_x = y;
    sc_add(to_bytes(y), to_bytes(y), to_bytes(y));
    make_secret_key(z);
    make_seraphis_core_spendkey(z, zU);
    make_seraphis_core_spendkey(z, k_bU);

    make_seraphis_key_image(y, z, key_image1);  // y X + y X + z U -> (z/2y) U
    make_seraphis_key_image(y, rct::rct2pk(zU), key_image2);

    rct::key jamtis_spend_pubkey{k_bU};
    crypto::secret_key k_view_balance, spendkey_extension;
    sc_add(to_bytes(k_view_balance), to_bytes(y), to_bytes(y));  // k_vb = 2*(2*y)
    const rct::key MINUS_ONE{minus_one()};
    sc_mul(to_bytes(spendkey_extension), MINUS_ONE.bytes, to_bytes(k_a_sender_x));  // k^j_x = -y
    extend_seraphis_spendkey_x(k_view_balance, jamtis_spend_pubkey);  // 4*y X + z U
    make_seraphis_key_image_jamtis_style(jamtis_spend_pubkey,
        k_view_balance,
        spendkey_extension,
        rct::rct2sk(rct::zero()),
        spendkey_extension,
        rct::rct2sk(rct::zero()),
        key_image_jamtis);  // -y X + -y X + (4*y X + z U) -> (z/2y) U

    EXPECT_TRUE(key_image1 == key_image2);
    EXPECT_TRUE(key_image1 == key_image_jamtis);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_basic, information_recovery_amountencoding)
{
    // encoding/decoding amounts
    crypto::secret_key sender_receiver_secret;
    make_secret_key(sender_receiver_secret);
    const rct::xmr_amount amount{rct::randXmrAmount(rct::xmr_amount{static_cast<rct::xmr_amount>(-1)})};

    rct::key fake_baked_key;
    memcpy(&fake_baked_key, rct::zero().bytes, sizeof(rct::key));

    jamtis::encoded_amount_t encoded_amount{
            encode_jamtis_amount(amount, rct::sk2rct(sender_receiver_secret), fake_baked_key)
        };
    rct::xmr_amount decoded_amount{
            decode_jamtis_amount(encoded_amount, rct::sk2rct(sender_receiver_secret), fake_baked_key)
        };
    //EXPECT_TRUE(encoded_amount != amount);  //might fail (collision in ~ 2^32 attempts)
    EXPECT_TRUE(decoded_amount == amount);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_basic, information_recovery_jamtisaddresstaghint)
{
    // cipher an index
    const address_index_t j{gen_address_index()};
    crypto::secret_key cipher_key;
    make_secret_key(cipher_key);
    const address_tag_t address_tag{cipher_address_index(cipher_key, j)};

    // split the tag into encrypted index and tag hint
    address_index_t enc_j;
    address_tag_hint_t hint;
    memcpy(enc_j.bytes, address_tag.bytes, sizeof(address_index_t));
    memcpy(hint.bytes, address_tag.bytes + sizeof(address_index_t), sizeof(address_tag_hint_t));

    // make a tag hint using SpKDFTranscript: H_2(k, cipher[k](j))
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_ADDRESS_TAG_HINT, sizeof(rct::key) + sizeof(address_index_t)};
    transcript.append("cipher_key", cipher_key);
    transcript.append("enc_j", enc_j.bytes);

    address_tag_hint_t reconstructed_hint;
    sp_hash_to_2(transcript.data(), transcript.size(), reconstructed_hint.bytes);

    // verify that the hint can be reproduced using the SpKDFTranscript utility
    ASSERT_TRUE(memcmp(hint.bytes, reconstructed_hint.bytes, sizeof(address_tag_hint_t)) == 0);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_basic, information_recovery_addressindex)
{
    // test address indices
    EXPECT_TRUE(test_info_recovery_addressindex(address_index_t{}));
    EXPECT_TRUE(test_info_recovery_addressindex(max_address_index()));

    for (std::size_t i{0}; i < 10; ++i)
    {
        address_index_t temp_j;
        temp_j = gen_address_index();
        EXPECT_TRUE(test_info_recovery_addressindex(temp_j));
    }
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_basic, information_recovery_jamtisdestination)
{
    // user wallet keys
    jamtis_mock_keys keys;
    make_jamtis_mock_keys(keys);

    // test making a jamtis destination then recovering the index
    JamtisDestinationV1 destination_known;
    const address_index_t j{gen_address_index()};
    make_jamtis_destination_v1(keys.K_1_base, keys.xK_ua, keys.xK_fr, keys.s_ga, j, destination_known);

    address_index_t j_nominal;
    EXPECT_TRUE(try_get_jamtis_index_from_destination_v1(destination_known,
        keys.K_1_base,
        keys.xK_ua,
        keys.xK_fr,
        keys.s_ga,
        j_nominal));
    EXPECT_TRUE(j_nominal == j);

    // test generating a random address
    JamtisDestinationV1 destination_unknown;
    destination_unknown = gen_jamtis_destination_v1();
    EXPECT_FALSE(try_get_jamtis_index_from_destination_v1(destination_unknown,
        keys.K_1_base,
        keys.xK_ua,
        keys.xK_fr,
        keys.s_ga,
        j_nominal));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_basic, information_recovery_coinbase_enote_v1_plain)
{
    // user wallet keys
    jamtis_mock_keys keys;
    make_jamtis_mock_keys(keys);

    // user address
    const address_index_t j{gen_address_index()};
    JamtisDestinationV1 user_address;

    make_jamtis_destination_v1(keys.K_1_base,
        keys.xK_ua,
        keys.xK_fr,
        keys.s_ga,
        j,
        user_address);

    // make a plain enote paying to address
    const rct::xmr_amount amount{crypto::rand_idx<rct::xmr_amount>(0)};
    const crypto::x25519_secret_key enote_privkey{crypto::x25519_secret_key_gen()};

    const std::uint64_t block_height{0};
    JamtisPaymentProposalV1 payment_proposal{user_address, amount, enote_privkey};
    SpCoinbaseOutputProposalV1 output_proposal;
    make_v1_coinbase_output_proposal_v1(payment_proposal, block_height, output_proposal);

    // check the enote
    check_is_owned(output_proposal, block_height, keys, j, amount, JamtisEnoteType::PLAIN);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_basic, information_recovery_enote_v1_plain)
{
    // user wallet keys
    jamtis_mock_keys keys;
    make_jamtis_mock_keys(keys);

    // user address
    const address_index_t j{gen_address_index()};
    JamtisDestinationV1 user_address;

    make_jamtis_destination_v1(keys.K_1_base,
        keys.xK_ua,
        keys.xK_fr,
        keys.s_ga,
        j,
        user_address);

    // make a plain enote paying to address
    const rct::xmr_amount amount{crypto::rand_idx<rct::xmr_amount>(0)};
    const crypto::x25519_secret_key enote_privkey{crypto::x25519_secret_key_gen()};

    JamtisPaymentProposalV1 payment_proposal{user_address, amount, enote_privkey};
    SpOutputProposalV1 output_proposal;
    make_v1_output_proposal_v1(payment_proposal, rct::zero(), output_proposal);

    // check the enote
    check_is_owned(output_proposal, keys, j, amount, JamtisEnoteType::PLAIN);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_basic, information_recovery_enote_v1_selfsend)
{
    // user wallet keys
    jamtis_mock_keys keys;
    make_jamtis_mock_keys(keys);

    // user address
    const address_index_t j{gen_address_index()};
    JamtisDestinationV1 user_address;

    make_jamtis_destination_v1(keys.K_1_base,
        keys.xK_ua,
        keys.xK_fr,
        keys.s_ga,
        j,
        user_address);

    // make a self-spend enote paying to address
    rct::xmr_amount amount{crypto::rand_idx<rct::xmr_amount>(0)};
    crypto::x25519_secret_key enote_privkey{crypto::x25519_secret_key_gen()};

    JamtisPaymentProposalSelfSendV1 payment_proposal_selfspend{user_address,
        amount,
        JamtisSelfSendType::SELF_SPEND,
        enote_privkey};
    SpOutputProposalV1 output_proposal;
    make_v1_output_proposal_v1(payment_proposal_selfspend, keys.k_vb, rct::zero(), output_proposal);

    // check the enote
    check_is_owned(output_proposal, keys, j, amount, JamtisEnoteType::SELF_SPEND);

    // make a change enote paying to address
    amount = crypto::rand_idx<rct::xmr_amount>(0);
    enote_privkey = crypto::x25519_secret_key_gen();

    JamtisPaymentProposalSelfSendV1 payment_proposal_change{user_address,
        amount,
        JamtisSelfSendType::CHANGE,
        enote_privkey};
    make_v1_output_proposal_v1(payment_proposal_change, keys.k_vb, rct::zero(), output_proposal);

    // check the enote
    check_is_owned(output_proposal, keys, j, amount, JamtisEnoteType::CHANGE);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_basic, finalize_v1_output_proposal_set_v1)
{
    /// setup

    // user wallet keys
    jamtis_mock_keys keys;
    make_jamtis_mock_keys(keys);

    // user addresses
    address_index_t j_selfspend;
    address_index_t j_change;
    address_index_t j_dummy;
    j_selfspend = gen_address_index();
    j_change = gen_address_index();
    j_dummy = gen_address_index();
    JamtisDestinationV1 selfspend_dest;
    JamtisDestinationV1 change_dest;
    JamtisDestinationV1 dummy_dest;
    make_jamtis_destination_v1(keys.K_1_base, keys.xK_ua, keys.xK_fr, keys.s_ga, j_selfspend, selfspend_dest);
    make_jamtis_destination_v1(keys.K_1_base, keys.xK_ua, keys.xK_fr, keys.s_ga, j_change, change_dest);
    make_jamtis_destination_v1(keys.K_1_base, keys.xK_ua, keys.xK_fr, keys.s_ga, j_dummy, dummy_dest);

    // prepare self-spend payment proposals
    JamtisPaymentProposalSelfSendV1 self_spend_payment_proposal1_amnt_1;
    self_spend_payment_proposal1_amnt_1.destination = selfspend_dest;
    self_spend_payment_proposal1_amnt_1.amount      = 1;
    self_spend_payment_proposal1_amnt_1.type        = JamtisSelfSendType::SELF_SPEND;
    make_secret_key(self_spend_payment_proposal1_amnt_1.enote_ephemeral_privkey);

    JamtisPaymentProposalSelfSendV1 self_spend_payment_proposal2_amnt_1{self_spend_payment_proposal1_amnt_1};
    make_secret_key(self_spend_payment_proposal2_amnt_1.enote_ephemeral_privkey);

    // prepare change output
    JamtisPaymentProposalSelfSendV1 change_payment_proposal_amnt_1;
    change_payment_proposal_amnt_1.destination = change_dest;
    change_payment_proposal_amnt_1.amount      = 1;
    change_payment_proposal_amnt_1.type        = JamtisSelfSendType::CHANGE;
    make_secret_key(change_payment_proposal_amnt_1.enote_ephemeral_privkey);

    // sanity checks
    SpOutputProposalV1 self_spend_proposal1_amnt_1;
    SpOutputProposalV1 self_spend_proposal2_amnt_1;
    SpOutputProposalV1 change_proposal_amnt_1;
    make_v1_output_proposal_v1(self_spend_payment_proposal1_amnt_1, keys.k_vb, rct::zero(), self_spend_proposal1_amnt_1);
    make_v1_output_proposal_v1(self_spend_payment_proposal2_amnt_1, keys.k_vb, rct::zero(), self_spend_proposal2_amnt_1);
    make_v1_output_proposal_v1(change_payment_proposal_amnt_1, keys.k_vb, rct::zero(), change_proposal_amnt_1);
    check_is_owned(self_spend_proposal2_amnt_1, keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);
    check_is_owned(self_spend_proposal1_amnt_1, keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);
    check_is_owned(change_proposal_amnt_1, keys, j_change, 1, JamtisEnoteType::CHANGE);


    /// test cases
    boost::multiprecision::uint128_t in_amount{0};
    const rct::xmr_amount fee{1};
    std::vector<JamtisPaymentProposalV1> normal_proposals;
    std::vector<JamtisPaymentProposalSelfSendV1> selfsend_proposals;

    auto finalize_outputs_for_test =
        [&](std::vector<JamtisPaymentProposalV1> &normal_payment_proposals_inout,
            std::vector<JamtisPaymentProposalSelfSendV1> &selfsend_payment_proposals_inout)
        {
            finalize_v1_output_proposal_set_v1(in_amount,
                fee,
                change_dest,
                dummy_dest,
                keys.k_vb,
                normal_payment_proposals_inout,
                selfsend_payment_proposals_inout);
        };

    // 0 outputs, 0 change: error
    in_amount = 0 + fee;
    normal_proposals.clear();
    selfsend_proposals.clear();
    EXPECT_ANY_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));

    // 0 outputs, >0 change: error
    in_amount = 1 + fee;
    normal_proposals.clear();
    selfsend_proposals.clear();  //change = 1
    EXPECT_ANY_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));

    // 1 normal output, 0 change: 2 outputs (1 self-send dummy)
    in_amount = 1 + fee;
    normal_proposals.resize(1);
    normal_proposals[0] = gen_jamtis_payment_proposal_v1(1, 0);
    selfsend_proposals.clear();
    EXPECT_NO_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));
    EXPECT_TRUE(normal_proposals.size() == 1);
    EXPECT_TRUE(selfsend_proposals.size() == 1);
    check_is_owned(selfsend_proposals[0], keys, j_dummy, 0, JamtisEnoteType::DUMMY);

    // 1 normal output, >0 change: 2 outputs (1 change)
    in_amount = 2 + fee;
    normal_proposals.resize(1);
    normal_proposals[0] = gen_jamtis_payment_proposal_v1(1, 0);  //change = 1
    selfsend_proposals.clear();
    EXPECT_NO_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));
    EXPECT_TRUE(normal_proposals.size() == 1);
    EXPECT_TRUE(selfsend_proposals.size() == 1);
    check_is_owned(selfsend_proposals[0], keys, j_change, 1, JamtisEnoteType::CHANGE);

    // 2 normal outputs, 0 change: 3 outputs (1 self-send dummy)
    in_amount = 2 + fee;
    normal_proposals.resize(2);
    normal_proposals[0] = gen_jamtis_payment_proposal_v1(1, 0);
    normal_proposals[1] = gen_jamtis_payment_proposal_v1(1, 0);
    selfsend_proposals.clear();
    EXPECT_NO_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));
    EXPECT_TRUE(normal_proposals.size() == 2);
    EXPECT_TRUE(selfsend_proposals.size() == 1);
    check_is_owned(selfsend_proposals[0], keys, j_dummy, 0, JamtisEnoteType::DUMMY);

    // 2 normal outputs (shared ephemeral pubkey), 0 change: error
    in_amount = 2 + fee;
    normal_proposals.resize(2);
    normal_proposals[0] = gen_jamtis_payment_proposal_v1(1, 0);
    normal_proposals[1] = gen_jamtis_payment_proposal_v1(1, 0);
    normal_proposals[1].enote_ephemeral_privkey = normal_proposals[0].enote_ephemeral_privkey;
    normal_proposals[1].destination.addr_K3 = normal_proposals[0].destination.addr_K3;
    selfsend_proposals.clear();
    EXPECT_ANY_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));

    // 2 normal outputs (shared ephemeral pubkey), >0 change: error
    in_amount = 3 + fee;
    normal_proposals.resize(2);
    normal_proposals[0] = gen_jamtis_payment_proposal_v1(1, 0);
    normal_proposals[1] = gen_jamtis_payment_proposal_v1(1, 0);  //change = 1
    normal_proposals[1].enote_ephemeral_privkey = normal_proposals[0].enote_ephemeral_privkey;
    normal_proposals[1].destination.addr_K3 = normal_proposals[0].destination.addr_K3;
    selfsend_proposals.clear();
    EXPECT_ANY_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));

    // 3 normal outputs, 0 change: 4 outputs (1 self-send dummy)
    in_amount = 3 + fee;
    normal_proposals.resize(3);
    normal_proposals[0] = gen_jamtis_payment_proposal_v1(1, 0);
    normal_proposals[1] = gen_jamtis_payment_proposal_v1(1, 0);
    normal_proposals[2] = gen_jamtis_payment_proposal_v1(1, 0);
    selfsend_proposals.clear();
    EXPECT_NO_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));
    EXPECT_TRUE(normal_proposals.size() == 3);
    EXPECT_TRUE(selfsend_proposals.size() == 1);
    check_is_owned(selfsend_proposals[0], keys, j_dummy, 0, JamtisEnoteType::DUMMY);

    // 3 normal outputs, >0 change: 4 outputs (1 change)
    in_amount = 4 + fee;
    normal_proposals.resize(3);
    normal_proposals[0] = gen_jamtis_payment_proposal_v1(1, 0);
    normal_proposals[1] = gen_jamtis_payment_proposal_v1(1, 0);
    normal_proposals[2] = gen_jamtis_payment_proposal_v1(1, 0);  //change = 1
    selfsend_proposals.clear();
    EXPECT_NO_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));
    EXPECT_TRUE(normal_proposals.size() == 3);
    EXPECT_TRUE(selfsend_proposals.size() == 1);
    check_is_owned(selfsend_proposals[0], keys, j_change, 1, JamtisEnoteType::CHANGE);

    // 1 self-send output, 0 change: 2 outputs (1 dummy)
    in_amount = 1 + fee;
    normal_proposals.clear();
    selfsend_proposals.resize(1);
    selfsend_proposals[0] = self_spend_payment_proposal1_amnt_1;
    EXPECT_NO_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));
    EXPECT_TRUE(normal_proposals.size() == 1);
    EXPECT_TRUE(selfsend_proposals.size() == 1);
    EXPECT_TRUE(normal_proposals[0].amount == 0);
    check_is_owned(selfsend_proposals[0], keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);

    // 1 self-send output, >0 change: 2 outputs (1 change)
    in_amount = 2 + fee;
    normal_proposals.clear();
    selfsend_proposals.resize(1);
    selfsend_proposals[0] = self_spend_payment_proposal1_amnt_1;  //change = 1
    EXPECT_NO_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));
    EXPECT_TRUE(normal_proposals.size() == 0);
    EXPECT_TRUE(selfsend_proposals.size() == 2);
    check_is_owned(selfsend_proposals[0], keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);
    check_is_owned(selfsend_proposals[1], keys, j_change, 1, JamtisEnoteType::CHANGE);

    // 1 change output, >0 change: error
    in_amount = 2 + fee;
    normal_proposals.clear();
    selfsend_proposals.resize(1);
    selfsend_proposals[0] = change_payment_proposal_amnt_1;  //change = 1
    EXPECT_ANY_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));

    // 1 self-send output & 1 normal output (shared ephemeral pubkey), 0 change: 2 outputs
    in_amount = 2 + fee;
    normal_proposals.resize(1);
    normal_proposals[0] = gen_jamtis_payment_proposal_v1(1, 0);
    selfsend_proposals.resize(1);
    selfsend_proposals[0] = self_spend_payment_proposal1_amnt_1;
    normal_proposals[0].enote_ephemeral_privkey = selfsend_proposals[0].enote_ephemeral_privkey;
    normal_proposals[0].destination.addr_K3 = selfsend_proposals[0].destination.addr_K3;
    EXPECT_NO_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));
    EXPECT_TRUE(normal_proposals.size() == 1);
    EXPECT_TRUE(selfsend_proposals.size() == 1);
    check_is_owned(selfsend_proposals[0], keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);

    // 1 self-send output & 1 normal output (shared ephemeral pubkey), >0 change: error
    in_amount = 3 + fee;
    normal_proposals.resize(1);
    normal_proposals[0] = gen_jamtis_payment_proposal_v1(1, 0);
    selfsend_proposals.resize(1);
    selfsend_proposals[0] = self_spend_payment_proposal1_amnt_1;  //change = 1
    normal_proposals[0].enote_ephemeral_privkey = selfsend_proposals[0].enote_ephemeral_privkey;
    normal_proposals[0].destination.addr_K3 = selfsend_proposals[0].destination.addr_K3;
    EXPECT_ANY_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));

    // 1 self-send output, 1 normal output, 0 change: 3 outputs (1 dummy)
    in_amount = 2 + fee;
    normal_proposals.resize(1);
    normal_proposals[0] = gen_jamtis_payment_proposal_v1(1, 0);
    selfsend_proposals.resize(1);
    selfsend_proposals[0] = self_spend_payment_proposal1_amnt_1;
    EXPECT_NO_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));
    EXPECT_TRUE(normal_proposals.size() == 2);
    EXPECT_TRUE(selfsend_proposals.size() == 1);
    EXPECT_TRUE(normal_proposals[1].amount == 0);
    check_is_owned(selfsend_proposals[0], keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);

    // 1 self-send output, 1 normal output, >0 change: 3 outputs (1 change)
    in_amount = 3 + fee;
    normal_proposals.resize(1);
    normal_proposals[0] = gen_jamtis_payment_proposal_v1(1, 0);
    selfsend_proposals.resize(1);
    selfsend_proposals[0] = self_spend_payment_proposal1_amnt_1;  //change = 1
    EXPECT_NO_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));
    EXPECT_TRUE(normal_proposals.size() == 1);
    EXPECT_TRUE(selfsend_proposals.size() == 2);
    check_is_owned(selfsend_proposals[0], keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);
    check_is_owned(selfsend_proposals[1], keys, j_change, 1, JamtisEnoteType::CHANGE);

    // 1 self-send output, 2 normal outputs, 0 change: 3 outputs
    in_amount = 3 + fee;
    normal_proposals.resize(2);
    normal_proposals[0] = gen_jamtis_payment_proposal_v1(1, 0);
    normal_proposals[1] = gen_jamtis_payment_proposal_v1(1, 0);
    selfsend_proposals.resize(1);
    selfsend_proposals[0] = self_spend_payment_proposal1_amnt_1;
    EXPECT_NO_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));
    EXPECT_TRUE(normal_proposals.size() == 2);
    EXPECT_TRUE(selfsend_proposals.size() == 1);
    check_is_owned(selfsend_proposals[0], keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);

    // 1 self-send output, 2 normal outputs, >0 change: 4 outputs (1 change)
    in_amount = 4 + fee;
    normal_proposals.resize(2);
    normal_proposals[0] = gen_jamtis_payment_proposal_v1(1, 0);
    normal_proposals[1] = gen_jamtis_payment_proposal_v1(1, 0);
    selfsend_proposals.resize(1);
    selfsend_proposals[0] = self_spend_payment_proposal1_amnt_1;  //change = 1
    EXPECT_NO_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));
    EXPECT_TRUE(normal_proposals.size() == 2);
    EXPECT_TRUE(selfsend_proposals.size() == 2);
    check_is_owned(selfsend_proposals[0], keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);
    check_is_owned(selfsend_proposals[1], keys, j_change, 1, JamtisEnoteType::CHANGE);

    // 2 self-send outputs (shared ephemeral pubkey), 0 change: error
    in_amount = 2 + fee;
    normal_proposals.clear();
    selfsend_proposals.resize(2);
    selfsend_proposals[0] = self_spend_payment_proposal1_amnt_1;
    selfsend_proposals[1] = self_spend_payment_proposal1_amnt_1;
    EXPECT_ANY_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));

    // 2 self-send outputs (shared ephemeral pubkey), >0 change: error
    in_amount = 3 + fee;
    normal_proposals.clear();
    selfsend_proposals.resize(2);
    selfsend_proposals[0] = self_spend_payment_proposal1_amnt_1;
    selfsend_proposals[1] = self_spend_payment_proposal1_amnt_1;  //change = 1
    EXPECT_ANY_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));

    // 2 self-send outputs, 0 change: 3 outputs (1 dummy)
    in_amount = 2 + fee;
    normal_proposals.clear();
    selfsend_proposals.resize(2);
    selfsend_proposals[0] = self_spend_payment_proposal1_amnt_1;
    selfsend_proposals[1] = self_spend_payment_proposal2_amnt_1;
    EXPECT_NO_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));
    EXPECT_TRUE(normal_proposals.size() == 1);
    EXPECT_TRUE(selfsend_proposals.size() == 2);
    EXPECT_TRUE(normal_proposals[0].amount == 0);
    check_is_owned(selfsend_proposals[0], keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);
    check_is_owned(selfsend_proposals[1], keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);

    // 2 self-send outputs, >0 change: 3 outputs (1 change)
    in_amount = 3 + fee;
    normal_proposals.clear();
    selfsend_proposals.resize(2);
    selfsend_proposals[0] = self_spend_payment_proposal1_amnt_1;
    selfsend_proposals[1] = self_spend_payment_proposal2_amnt_1;  //change = 1
    EXPECT_NO_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));
    EXPECT_TRUE(normal_proposals.size() == 0);
    EXPECT_TRUE(selfsend_proposals.size() == 3);
    check_is_owned(selfsend_proposals[0], keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);
    check_is_owned(selfsend_proposals[1], keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);
    check_is_owned(selfsend_proposals[2], keys, j_change, 1, JamtisEnoteType::CHANGE);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_basic, tx_extra)
{
    /// make elements
    std::vector<ExtraFieldElement> extra_field_elements;
    extra_field_elements.resize(3);

    // rct::key
    extra_field_elements[0].type = 1;
    extra_field_elements[0].value.resize(32);
    memcpy(extra_field_elements[0].value.data(), rct::identity().bytes, 32);

    // std::uint64_t
    std::uint64_t one{1};
    extra_field_elements[1].type = 2;
    extra_field_elements[1].value.resize(8);
    memcpy(extra_field_elements[1].value.data(), &one, 8);

    // std::uint64_t
    extra_field_elements[2].type = 0;
    extra_field_elements[2].value.resize(8);
    memcpy(extra_field_elements[2].value.data(), &one, 8);


    /// make an extra field
    TxExtra tx_extra;
    make_tx_extra(std::move(extra_field_elements), tx_extra);


    /// validate field and recover elemeents
    auto validate_field_and_recover =
        [&]()
        {
            extra_field_elements.clear();
            EXPECT_TRUE(try_get_extra_field_elements(tx_extra, extra_field_elements));
            ASSERT_TRUE(extra_field_elements.size() == 3);
            EXPECT_TRUE(extra_field_elements[0].type == 0);
            EXPECT_TRUE(extra_field_elements[0].value.size() == 8);
            std::uint64_t element0;
            memcpy(&element0, extra_field_elements[0].value.data(), 8);
            EXPECT_TRUE(element0 == one);
            EXPECT_TRUE(extra_field_elements[1].type == 1);
            EXPECT_TRUE(extra_field_elements[1].value.size() == 32);
            rct::key element1;
            memcpy(element1.bytes, extra_field_elements[1].value.data(), 32);
            EXPECT_TRUE(element1 == rct::identity());
            EXPECT_TRUE(extra_field_elements[2].type == 2);
            EXPECT_TRUE(extra_field_elements[2].value.size() == 8);
            std::uint64_t element2;
            memcpy(&element2, extra_field_elements[2].value.data(), 8);
            EXPECT_TRUE(element2 == one);
        };

    // basic recovery
    validate_field_and_recover();

    // partial field to full field reconstruction
    std::vector<ExtraFieldElement> extra_field_elements2;
    std::vector<ExtraFieldElement> extra_field_elements3;
    EXPECT_TRUE(try_get_extra_field_elements(tx_extra, extra_field_elements2));
    extra_field_elements3.push_back(extra_field_elements2.back());
    extra_field_elements2.pop_back();

    TxExtra tx_extra_partial;
    make_tx_extra(std::move(extra_field_elements2), tx_extra_partial);

    extra_field_elements.clear();
    accumulate_extra_field_elements(tx_extra_partial, extra_field_elements);        //first two elements
    accumulate_extra_field_elements(extra_field_elements3, extra_field_elements);   //last element
    make_tx_extra(std::move(extra_field_elements), tx_extra);

    validate_field_and_recover();


    /// adding a byte to the end causes failure
    tx_extra.push_back(0);
    extra_field_elements.clear();
    EXPECT_FALSE(try_get_extra_field_elements(tx_extra, extra_field_elements));


    /// removing 2 bytes causes failure
    tx_extra.pop_back();
    tx_extra.pop_back();
    extra_field_elements.clear();
    EXPECT_FALSE(try_get_extra_field_elements(tx_extra, extra_field_elements));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_basic, binned_reference_set)
{
    EXPECT_ANY_THROW(test_binned_reference_set(0, 0, 0, 0, 0, 0));  //invalid reference set size and bin num members
    EXPECT_ANY_THROW(test_binned_reference_set(1, 0, 0, 1, 1, 0));  //invalid range
    EXPECT_ANY_THROW(test_binned_reference_set(0, 0, 1, 1, 1, 0));  //invalid bin radius
    EXPECT_ANY_THROW(test_binned_reference_set(0, 0, 0, 2, 1, 0));  //invalid bin num members
    EXPECT_ANY_THROW(test_binned_reference_set(0, 0, 0, 1, 1, 1));  //invalid real reference location
    EXPECT_NO_THROW(EXPECT_TRUE(test_binned_reference_set(0, 0, 0, 1, 1, 0)));  //1 bin member in 1 bin in [0, 0]
    EXPECT_NO_THROW(EXPECT_TRUE(test_binned_reference_set(0, 0, 0, 1, 2, 0)));  //1 bin member in 2 bins in [0, 0]
    EXPECT_NO_THROW(EXPECT_TRUE(test_binned_reference_set(0, 0, 0, 1, 3, 0)));  //1 bin member in 3 bins in [0, 0]
    EXPECT_NO_THROW(EXPECT_TRUE(test_binned_reference_set(0, 1, 0, 1, 1, 0)));  //1 bin member in 1 bins in [0, 1]
    EXPECT_NO_THROW(EXPECT_TRUE(test_binned_reference_set(0, 1, 0, 1, 2, 0)));  //1 bin member in 2 bins in [0, 1]
    EXPECT_NO_THROW(EXPECT_TRUE(test_binned_reference_set(0, 2, 1, 2, 2, 0)));  //2 bin members in 1 bin in [0, 2]
    EXPECT_NO_THROW(EXPECT_TRUE(test_binned_reference_set(0, 2, 1, 2, 4, 0)));  //2 bin members in 2 bins in [0, 2]
    EXPECT_NO_THROW(EXPECT_TRUE(test_binned_reference_set(0, 2, 1, 2, 4, 1)));  //2 bin members in 2 bins in [0, 2]
    EXPECT_NO_THROW(EXPECT_TRUE(test_binned_reference_set(0, 2, 1, 2, 4, 1)));  //2 bin members in 2 bins in [0, 2]
    EXPECT_NO_THROW(EXPECT_TRUE(test_binned_reference_set(0,
        static_cast<std::uint64_t>(-1),
        100,
        10,
        50,
        static_cast<std::uint64_t>(-1))));  //max range, real at top
    EXPECT_NO_THROW(EXPECT_TRUE(test_binned_reference_set(0,
        static_cast<std::uint64_t>(-1),
        100,
        10,
        50,
        0)));  //max range, real at bottom
    EXPECT_NO_THROW(EXPECT_TRUE(test_binned_reference_set(0, 40000, 127, 8, 128, 40000/2)));  //realistic example

    // intermittently fails if unstably sorting bins will make the resulting reference set malformed
    // note: this is a legacy test (current implementation is agnostic to unstable sorting)
    EXPECT_NO_THROW(EXPECT_TRUE(test_binned_reference_set(0, 100, 40, 4, 100, 0)));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_basic, discretized_fees)
{
    // test the fee discretizer
    std::uint64_t test_fee_value, fee_value;
    DiscretizedFee discretized_fee;

    // fee value 0 (should perfectly discretize)
    test_fee_value = 0;
    discretized_fee = discretize_fee(test_fee_value);
    EXPECT_TRUE(try_get_fee_value(discretized_fee, fee_value));
    EXPECT_TRUE(fee_value == test_fee_value);
    EXPECT_TRUE(discretized_fee == test_fee_value);

    // fee value 1 (should perfectly discretize)
    test_fee_value = 1;
    discretized_fee = discretize_fee(test_fee_value);
    EXPECT_TRUE(try_get_fee_value(discretized_fee, fee_value));
    EXPECT_TRUE(fee_value == test_fee_value);
    EXPECT_TRUE(discretized_fee == test_fee_value);

    // fee value with more digits than sig figs (should round up)
    test_fee_value = 1;
    for (std::size_t sig_fig{0}; sig_fig < config::DISCRETIZED_FEE_SIG_FIGS; ++sig_fig)
    {
        test_fee_value *= 10;
        test_fee_value += 1;
    }
    discretized_fee = discretize_fee(test_fee_value);
    EXPECT_TRUE(try_get_fee_value(discretized_fee, fee_value));
    EXPECT_TRUE(fee_value > test_fee_value);
    EXPECT_FALSE(discretized_fee == test_fee_value);

    // fee value MAX (should perfectly discretize)
    test_fee_value = std::numeric_limits<std::uint64_t>::max();
    discretized_fee = discretize_fee(test_fee_value);
    EXPECT_TRUE(try_get_fee_value(discretized_fee, fee_value));
    EXPECT_TRUE(fee_value == test_fee_value);
    EXPECT_TRUE(discretized_fee == test_fee_value);

    // unknown fee level
    discretized_fee.fee_encoding = static_cast<discretized_fee_encoding_t>(-1);
    EXPECT_FALSE(try_get_fee_value(discretized_fee, fee_value));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_basic, txtype_squashed_v1)
{
    // demo making SpTxTypeSquasedV1 with raw tx builder API
    const std::size_t num_txs{3};
    const std::size_t num_ins_outs{11};

    // fake ledger context for this test
    MockLedgerContext ledger_context{0, 10000};

    // prepare input/output amounts
    std::vector<rct::xmr_amount> in_legacy_amounts;
    std::vector<rct::xmr_amount> in_sp_amounts;
    std::vector<rct::xmr_amount> out_amounts;

    for (int i{0}; i < num_ins_outs; ++i)
    {
        in_legacy_amounts.push_back(1);  //initial tx_fee = num_ins_outs
        in_sp_amounts.push_back(3);
        out_amounts.push_back(3);
    }

    // set fee
    const DiscretizedFee discretized_transaction_fee{num_ins_outs};
    rct::xmr_amount real_transaction_fee;
    EXPECT_TRUE(try_get_fee_value(discretized_transaction_fee, real_transaction_fee));

    // add an input to cover any extra fee added during discretization
    const rct::xmr_amount extra_fee_amount{real_transaction_fee - num_ins_outs};

    if (extra_fee_amount > 0)
        in_sp_amounts.push_back(extra_fee_amount);

    // make txs
    std::vector<SpTxSquashedV1> txs;
    std::vector<const SpTxSquashedV1*> tx_ptrs;
    txs.reserve(num_txs);
    tx_ptrs.reserve(num_txs);

    for (std::size_t tx_index{0}; tx_index < num_txs; ++tx_index)
    {
        make_sp_txtype_squashed_v1(2,
            2,
            2,
            SpBinnedReferenceSetConfigV1{
                .bin_radius = 1,
                .num_bin_members = 2
            },
            3,
            in_legacy_amounts,
            in_sp_amounts,
            out_amounts,
            discretized_transaction_fee,
            SpTxSquashedV1::SemanticRulesVersion::MOCK,
            ledger_context,
            tools::add_element(txs));
        tx_ptrs.push_back(&(txs.back()));
    }

    const TxValidationContextMock tx_validation_context{ledger_context};

    EXPECT_TRUE(validate_txs(tx_ptrs, tx_validation_context));

    // insert key images to ledger
    for (const SpTxSquashedV1 &tx : txs)
        EXPECT_TRUE(try_add_tx_to_ledger(tx, ledger_context));

    // validation should fail due to double-spend
    EXPECT_FALSE(validate_txs(tx_ptrs, tx_validation_context));
}
//-------------------------------------------------------------------------------------------------------------------
