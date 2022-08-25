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

#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
#include "mx25519.h"
}
#include "device/device.hpp"
#include "misc_language.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis/jamtis_address_tag_utils.h"
#include "seraphis/jamtis_address_utils.h"
#include "seraphis/jamtis_core_utils.h"
#include "seraphis/jamtis_destination.h"
#include "seraphis/jamtis_enote_utils.h"
#include "seraphis/jamtis_payment_proposal.h"
#include "seraphis/jamtis_support_types.h"
#include "seraphis/mock_ledger_context.h"
#include "seraphis/seraphis_config_temp.h"
#include "seraphis/sp_composition_proof.h"
#include "seraphis/sp_core_enote_utils.h"
#include "seraphis/sp_core_types.h"
#include "seraphis/sp_crypto_utils.h"
#include "seraphis/tx_base.h"
#include "seraphis/tx_binned_reference_set.h"
#include "seraphis/tx_binned_reference_set_utils.h"
#include "seraphis/tx_builder_types.h"
#include "seraphis/tx_builders_inputs.h"
#include "seraphis/tx_builders_mixed.h"
#include "seraphis/tx_builders_outputs.h"
#include "seraphis/tx_component_types.h"
#include "seraphis/tx_discretized_fee.h"
#include "seraphis/tx_enote_record_types.h"
#include "seraphis/tx_enote_record_utils.h"
#include "seraphis/tx_extra.h"
#include "seraphis/tx_misc_utils.h"
#include "seraphis/tx_ref_set_index_mapper_flat.h"
#include "seraphis/tx_validation_context_mock.h"
#include "seraphis/txtype_squashed_v1.h"

#include "boost/multiprecision/cpp_int.hpp"
#include "gtest/gtest.h"

#include <memory>
#include <vector>


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
static void make_secret_key(sp::x25519_secret_key &skey_out)
{
    skey_out = sp::x25519_privkey_gen();
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void check_is_owned_with_intermediate_record(const sp::SpOutputProposalV1 &test_proposal,
    const sp::jamtis::jamtis_mock_keys &keys,
    const sp::jamtis::address_index_t j_expected,
    const rct::xmr_amount amount_expected)
{
    // convert to enote
    sp::SpEnoteV1 enote;
    test_proposal.get_enote_v1(enote);

    // try to extract intermediate information from the enote
    // - only succeeds if enote is owned and is a plain jamtis enote
    sp::SpIntermediateEnoteRecordV1 intermediate_enote_record;
    EXPECT_TRUE(sp::try_get_intermediate_enote_record_v1(enote,
        test_proposal.m_enote_ephemeral_pubkey,
        rct::zero(),
        keys.K_1_base,
        keys.xk_ua,
        keys.xk_fr,
        keys.s_ga,
        intermediate_enote_record));

    // check misc fields
    EXPECT_TRUE(intermediate_enote_record.m_amount == amount_expected);
    EXPECT_TRUE(intermediate_enote_record.m_address_index == j_expected);

    // get full enote record from intermediate record
    sp::SpEnoteRecordV1 enote_record;
    EXPECT_TRUE(sp::try_get_enote_record_v1_plain(intermediate_enote_record, keys.K_1_base, keys.k_vb, enote_record));

    // check misc fields
    EXPECT_TRUE(enote_record.m_type == sp::jamtis::JamtisEnoteType::PLAIN);
    EXPECT_TRUE(enote_record.m_amount == amount_expected);
    EXPECT_TRUE(enote_record.m_address_index == j_expected);

    // check key image
    rct::key spendkey_base{keys.K_1_base};
    sp::reduce_seraphis_spendkey(keys.k_vb, spendkey_base);
    crypto::key_image reproduced_key_image;
    sp::make_seraphis_key_image(enote_record.m_enote_view_privkey, rct::rct2pk(spendkey_base), reproduced_key_image);
    EXPECT_TRUE(enote_record.m_key_image == reproduced_key_image);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void check_is_owned(const sp::SpOutputProposalV1 &test_proposal,
    const sp::jamtis::jamtis_mock_keys &keys,
    const sp::jamtis::address_index_t j_expected,
    const rct::xmr_amount amount_expected,
    const sp::jamtis::JamtisEnoteType type_expected)
{
    // convert to enote
    sp::SpEnoteV1 enote;
    test_proposal.get_enote_v1(enote);

    // try to extract information from the enote (only succeeds if enote is owned)
    sp::SpEnoteRecordV1 enote_record;
    EXPECT_TRUE(sp::try_get_enote_record_v1(enote,
        test_proposal.m_enote_ephemeral_pubkey,
        rct::zero(),
        keys.K_1_base,
        keys.k_vb,
        enote_record));

    // check misc fields
    EXPECT_TRUE(enote_record.m_type == type_expected);
    EXPECT_TRUE(enote_record.m_amount == amount_expected);
    EXPECT_TRUE(enote_record.m_address_index == j_expected);

    // check key image
    rct::key spendkey_base{keys.K_1_base};
    sp::reduce_seraphis_spendkey(keys.k_vb, spendkey_base);
    crypto::key_image reproduced_key_image;
    sp::make_seraphis_key_image(enote_record.m_enote_view_privkey, rct::rct2pk(spendkey_base), reproduced_key_image);
    EXPECT_TRUE(enote_record.m_key_image == reproduced_key_image);

    // for plain enotes, double-check ownership with an intermediate record
    if (enote_record.m_type == sp::jamtis::JamtisEnoteType::PLAIN)
        check_is_owned_with_intermediate_record(test_proposal, keys, j_expected, amount_expected);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void check_is_owned(const sp::jamtis::JamtisPaymentProposalSelfSendV1 &test_proposal,
    const sp::jamtis::jamtis_mock_keys &keys,
    const sp::jamtis::address_index_t j_expected,
    const rct::xmr_amount amount_expected,
    const sp::jamtis::JamtisEnoteType type_expected)
{
    // convert to output proposal
    sp::SpOutputProposalV1 output_proposal;
    test_proposal.get_output_proposal_v1(keys.k_vb, rct::zero(), output_proposal);

    // check ownership
    check_is_owned(output_proposal, keys, j_expected, amount_expected, type_expected);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool test_binned_reference_set(const std::uint64_t distribution_min_index,
    const std::uint64_t distribution_max_index,
    const sp::ref_set_bin_dimension_v1_t bin_radius,
    const sp::ref_set_bin_dimension_v1_t num_bin_members,
    const std::uint64_t reference_set_size,
    const std::uint64_t real_reference_index)
{
    const sp::SpRefSetIndexMapperFlat flat_index_mapper{distribution_min_index, distribution_max_index};
    const sp::SpBinnedReferenceSetConfigV1 bin_config{
            .m_bin_radius = bin_radius,
            .m_num_bin_members = num_bin_members
        };

    for (std::size_t i{0}; i < 50; ++i)
    {
        // make a reference set
        sp::SpBinnedReferenceSetV1 binned_reference_set;
        sp::make_binned_reference_set_v1(flat_index_mapper,
            bin_config,
            rct::pkGen(),
            reference_set_size,
            real_reference_index,
            binned_reference_set);

        // bin config should persist
        if (binned_reference_set.m_bin_config != bin_config)
            return false;

        // bins should be sorted
        if (!std::is_sorted(binned_reference_set.m_bin_loci.begin(), binned_reference_set.m_bin_loci.end()))
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
static void make_sp_txtype_squashed_v1(const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const sp::SpBinnedReferenceSetConfigV1 &bin_config,
    const std::size_t num_random_memo_elements,
    const std::vector<rct::xmr_amount> &in_amounts,
    const std::vector<rct::xmr_amount> &out_amounts,
    const sp::DiscretizedFee &discretized_transaction_fee,
    const sp::SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    sp::MockLedgerContext &ledger_context_inout,
    sp::SpTxSquashedV1 &tx_out)
{
    /// build a tx from base components
    using namespace sp;

    rct::xmr_amount raw_transaction_fee;
    CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(discretized_transaction_fee, raw_transaction_fee),
        "SpTxSquashedV1: tried to raw make tx with invalid discretized fee.");

    CHECK_AND_ASSERT_THROW_MES(in_amounts.size() > 0, "SpTxSquashedV1: tried to raw make tx without any inputs.");
    CHECK_AND_ASSERT_THROW_MES(out_amounts.size() > 0, "SpTxSquashedV1: tried to raw make tx without any outputs.");
    CHECK_AND_ASSERT_THROW_MES(balance_check_in_out_amnts(in_amounts, out_amounts, raw_transaction_fee),
        "SpTxSquashedV1: tried to raw make tx with unbalanced amounts.");

    // make wallet spendbase privkey (master key)
    const crypto::secret_key spendbase_privkey{rct::rct2sk(rct::skGen())};

    // make mock inputs
    // enote, ks, view key stuff, amount, amount blinding factor
    std::vector<SpInputProposalV1> input_proposals{gen_mock_sp_input_proposals_v1(spendbase_privkey, in_amounts)};

    // make mock output proposals
    std::vector<SpOutputProposalV1> output_proposals{
            gen_mock_sp_output_proposals_v1(out_amounts, num_random_memo_elements)
        };

    // for 2-out txs, can only have one unique enote ephemeral pubkey
    if (output_proposals.size() == 2)
        output_proposals[1].m_enote_ephemeral_pubkey = output_proposals[0].m_enote_ephemeral_pubkey;

    // pre-sort inputs and outputs (doing this here makes everything else easier)
    std::sort(input_proposals.begin(), input_proposals.end());  //note: this is very inefficient for large input counts
    std::sort(output_proposals.begin(), output_proposals.end());

    // make mock membership proof ref sets
    std::vector<SpMembershipProofPrepV1> membership_proof_preps{
            gen_mock_sp_membership_proof_preps_v1(input_proposals,
                ref_set_decomp_n,
                ref_set_decomp_m,
                bin_config,
                ledger_context_inout)
        };

    // make mock memo elements
    std::vector<ExtraFieldElement> additional_memo_elements;
    additional_memo_elements.resize(num_random_memo_elements);
    for (ExtraFieldElement &element : additional_memo_elements)
        element.gen();

    // versioning for proofs
    std::string version_string;
    version_string.reserve(3);
    make_versioning_string(semantic_rules_version, version_string);

    // tx components
    std::vector<SpEnoteImageV1> input_images;
    std::vector<SpEnoteV1> outputs;
    SpBalanceProofV1 balance_proof;
    std::vector<SpImageProofV1> tx_image_proofs;
    std::vector<SpAlignableMembershipProofV1> tx_alignable_membership_proofs;
    std::vector<SpMembershipProofV1> tx_membership_proofs;
    SpTxSupplementV1 tx_supplement;

    // info shuttles for making components
    std::vector<rct::xmr_amount> output_amounts;
    std::vector<crypto::secret_key> output_amount_commitment_blinding_factors;
    std::vector<crypto::secret_key> image_address_masks;
    std::vector<crypto::secret_key> image_amount_masks;
    rct::key image_proofs_message;
    std::vector<rct::xmr_amount> input_amounts;
    std::vector<crypto::secret_key> input_image_amount_commitment_blinding_factors;

    input_images.resize(input_proposals.size());
    image_address_masks.resize(input_proposals.size());
    image_amount_masks.resize(input_proposals.size());

    // make everything
    make_v1_outputs_v1(output_proposals,
        outputs,
        output_amounts,
        output_amount_commitment_blinding_factors,
        tx_supplement.m_output_enote_ephemeral_pubkeys);
    for (const SpOutputProposalV1 &output_proposal : output_proposals)
        accumulate_extra_field_elements(output_proposal.m_partial_memo, additional_memo_elements);
    make_tx_extra(std::move(additional_memo_elements), tx_supplement.m_tx_extra);
    for (std::size_t input_index{0}; input_index < input_proposals.size(); ++input_index)
    {
        input_proposals[input_index].get_enote_image_v1(input_images[input_index]);
        image_address_masks[input_index] = input_proposals[input_index].m_core.m_address_mask;
        image_amount_masks[input_index] = input_proposals[input_index].m_core.m_commitment_mask;
    }
    make_tx_image_proof_message_v1(version_string,
        input_images,
        outputs,
        tx_supplement,
        discretized_transaction_fee,
        image_proofs_message);
    make_v1_image_proofs_v1(input_proposals,
        image_proofs_message,
        spendbase_privkey,
        tx_image_proofs);
    prepare_input_commitment_factors_for_balance_proof_v1(input_proposals,
        image_amount_masks,
        input_amounts,
        input_image_amount_commitment_blinding_factors);
    make_v1_balance_proof_v1(input_amounts, //note: must range proof input image commitments in squashed enote model
        output_amounts,
        raw_transaction_fee,
        input_image_amount_commitment_blinding_factors,
        output_amount_commitment_blinding_factors,
        balance_proof);
    make_v1_membership_proofs_v1(std::move(membership_proof_preps),
        tx_alignable_membership_proofs);  //alignable membership proofs could theoretically be user inputs as well
    align_v1_membership_proofs_v1(input_images, std::move(tx_alignable_membership_proofs), tx_membership_proofs);

    make_seraphis_tx_squashed_v1(std::move(input_images), std::move(outputs),
        std::move(balance_proof), std::move(tx_image_proofs), std::move(tx_membership_proofs),
        std::move(tx_supplement), discretized_transaction_fee, semantic_rules_version, tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool test_info_recovery_addressindex(const sp::jamtis::address_index_t j)
{
    using namespace sp;
    using namespace jamtis;

    // convert the index to/from raw tag form
    const address_tag_t raw_address_tag{j};
    address_index_t j_recovered;
    if (!try_get_address_index(raw_address_tag, j_recovered))
        return false;

    // cipher and decipher the index
    crypto::secret_key cipher_key;
    make_secret_key(cipher_key);
    const address_tag_t ciphered_tag{cipher_address_index(rct::sk2rct(cipher_key), j)};
    address_tag_MAC_t decipher_mac;
    address_index_t decipher_j;
    if (!try_decipher_address_index(rct::sk2rct(cipher_key), ciphered_tag, decipher_j))
        return false;
    if (decipher_j != j)
        return false;

    // encrypt and decrypt an address tag
    const rct::key sender_receiver_secret{rct::skGen()};
    const rct::key onetime_address{rct::pkGen()};
    const encrypted_address_tag_t encrypted_ciphered_tag{
            encrypt_address_tag(sender_receiver_secret, onetime_address, ciphered_tag)
        };
    if (decrypt_address_tag(sender_receiver_secret, onetime_address, encrypted_ciphered_tag) != ciphered_tag)
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, information_recovery_keyimage)
{
    // different methods for making key images all have same results
    crypto::secret_key y, z, k_a_sender, k_a_recipient;
    rct::key zU, k_bU;
    crypto::key_image key_image1, key_image2, key_image3, key_image_jamtis;

    make_secret_key(y);
    k_a_sender = y;
    k_a_recipient = y;
    sc_add(to_bytes(y), to_bytes(y), to_bytes(y));
    make_secret_key(z);
    sp::make_seraphis_spendbase(z, zU);
    sp::make_seraphis_spendbase(z, k_bU);

    sp::make_seraphis_key_image(y, z, key_image1);  // y X + y X + z U -> (z/2y) U
    sp::make_seraphis_key_image(y, rct::rct2pk(zU), key_image2);
    sp::make_seraphis_key_image(k_a_sender, k_a_recipient, rct::rct2pk(k_bU), key_image3);

    rct::key wallet_spend_pubkey{k_bU};
    crypto::secret_key k_view_balance, spendkey_extension;
    sc_add(to_bytes(k_view_balance), to_bytes(y), to_bytes(y));  // k_vb = 2*(2*y)
    const rct::key MINUS_ONE{sp::minus_one()};
    sc_mul(to_bytes(spendkey_extension), MINUS_ONE.bytes, to_bytes(k_a_sender));  // k^j_x = -y
    sp::extend_seraphis_spendkey(k_view_balance, wallet_spend_pubkey);  // 4*y X + z U
    sp::jamtis::make_seraphis_key_image_jamtis_style(wallet_spend_pubkey,
        k_view_balance,
        spendkey_extension,
        spendkey_extension,
        key_image_jamtis);  // -y X + -y X + (4*y X + z U) -> (z/2y) U

    EXPECT_TRUE(key_image1 == key_image2);
    EXPECT_TRUE(key_image1 == key_image3);
    EXPECT_TRUE(key_image1 == key_image_jamtis);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, information_recovery_amountencoding)
{
    using namespace sp;
    using namespace jamtis;

    // encoding/decoding amounts
    crypto::secret_key sender_receiver_secret;
    make_secret_key(sender_receiver_secret);
    const rct::xmr_amount amount{rct::randXmrAmount(rct::xmr_amount{static_cast<rct::xmr_amount>(-1)})};

    x25519_pubkey fake_baked_key;
    memcpy(&fake_baked_key, rct::zero().bytes, sizeof(rct::key));

    rct::xmr_amount encoded_amount{
            encode_jamtis_amount_plain(amount, rct::sk2rct(sender_receiver_secret), fake_baked_key)
        };
    rct::xmr_amount decoded_amount{
            decode_jamtis_amount_plain(encoded_amount, rct::sk2rct(sender_receiver_secret), fake_baked_key)
        };
    EXPECT_TRUE(encoded_amount != amount);  //might fail (collision in ~ 2^32 attempts)
    EXPECT_TRUE(decoded_amount == amount);

    encoded_amount = encode_jamtis_amount_selfsend(amount, rct::sk2rct(sender_receiver_secret));
    decoded_amount = decode_jamtis_amount_selfsend(encoded_amount, rct::sk2rct(sender_receiver_secret));
    EXPECT_TRUE(encoded_amount != amount);  //might fail (collision in ~ 2^32 attempts)
    EXPECT_TRUE(decoded_amount == amount);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, information_recovery_addressindex)
{
    using namespace sp;
    using namespace jamtis;

    // test address indices
    EXPECT_TRUE(test_info_recovery_addressindex(0));
    EXPECT_TRUE(test_info_recovery_addressindex(address_index_t::max()));

    for (std::size_t i{0}; i < 10; ++i)
    {
        address_index_t temp_j;
        temp_j.gen();
        EXPECT_TRUE(test_info_recovery_addressindex(temp_j));
    }
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, information_recovery_jamtisdestination)
{
    using namespace sp;
    using namespace jamtis;

    // user wallet keys
    jamtis_mock_keys keys;
    make_jamtis_mock_keys(keys);

    // test making a jamtis destination then recovering the index
    JamtisDestinationV1 destination_known;
    address_index_t j;
    j.gen();
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
    destination_unknown.gen();
    EXPECT_FALSE(try_get_jamtis_index_from_destination_v1(destination_unknown,
        keys.K_1_base,
        keys.xK_ua,
        keys.xK_fr,
        keys.s_ga,
        j_nominal));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, information_recovery_enote_v1_plain)
{
    using namespace sp;
    using namespace jamtis;

    // user wallet keys
    jamtis_mock_keys keys;
    make_jamtis_mock_keys(keys);

    // user address
    address_index_t j;
    j.gen();
    JamtisDestinationV1 user_address;

    make_jamtis_destination_v1(keys.K_1_base,
        keys.xK_ua,
        keys.xK_fr,
        keys.s_ga,
        j,
        user_address);

    // make a plain enote paying to address
    const rct::xmr_amount amount{crypto::rand_idx(static_cast<rct::xmr_amount>(-1))};
    const x25519_secret_key enote_privkey{x25519_privkey_gen()};

    JamtisPaymentProposalV1 payment_proposal{user_address, amount, enote_privkey};
    SpOutputProposalV1 output_proposal;
    payment_proposal.get_output_proposal_v1(rct::zero(), output_proposal);

    // check the enote
    check_is_owned(output_proposal, keys, j, amount, JamtisEnoteType::PLAIN);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, information_recovery_enote_v1_selfsend)
{
    using namespace sp;
    using namespace jamtis;

    // user wallet keys
    jamtis_mock_keys keys;
    make_jamtis_mock_keys(keys);

    // user address
    address_index_t j;
    j.gen();
    JamtisDestinationV1 user_address;

    make_jamtis_destination_v1(keys.K_1_base,
        keys.xK_ua,
        keys.xK_fr,
        keys.s_ga,
        j,
        user_address);

    // make a self-spend enote paying to address
    rct::xmr_amount amount{crypto::rand_idx(static_cast<rct::xmr_amount>(-1))};
    x25519_secret_key enote_privkey{x25519_privkey_gen()};

    JamtisPaymentProposalSelfSendV1 payment_proposal_selfspend{user_address,
        amount,
        JamtisSelfSendType::SELF_SPEND,
        enote_privkey};
    SpOutputProposalV1 output_proposal;
    payment_proposal_selfspend.get_output_proposal_v1(keys.k_vb, rct::zero(), output_proposal);

    // check the enote
    check_is_owned(output_proposal, keys, j, amount, JamtisEnoteType::SELF_SPEND);

    // make a change enote paying to address
    amount = crypto::rand_idx(static_cast<rct::xmr_amount>(-1));
    enote_privkey = x25519_privkey_gen();

    JamtisPaymentProposalSelfSendV1 payment_proposal_change{user_address,
        amount,
        JamtisSelfSendType::CHANGE,
        enote_privkey};
    payment_proposal_change.get_output_proposal_v1(keys.k_vb, rct::zero(), output_proposal);

    // check the enote
    check_is_owned(output_proposal, keys, j, amount, JamtisEnoteType::CHANGE);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, finalize_v1_output_proposal_set_v1)
{
    /// setup
    using namespace sp;
    using namespace jamtis;

    // user wallet keys
    jamtis_mock_keys keys;
    make_jamtis_mock_keys(keys);

    // user addresses
    address_index_t j_selfspend;
    address_index_t j_change;
    address_index_t j_dummy;
    j_selfspend.gen();
    j_change.gen();
    j_dummy.gen();
    JamtisDestinationV1 selfspend_dest;
    JamtisDestinationV1 change_dest;
    JamtisDestinationV1 dummy_dest;
    make_jamtis_destination_v1(keys.K_1_base, keys.xK_ua, keys.xK_fr, keys.s_ga, j_selfspend, selfspend_dest);
    make_jamtis_destination_v1(keys.K_1_base, keys.xK_ua, keys.xK_fr, keys.s_ga, j_change, change_dest);
    make_jamtis_destination_v1(keys.K_1_base, keys.xK_ua, keys.xK_fr, keys.s_ga, j_dummy, dummy_dest);

    // prepare self-spend payment proposals
    JamtisPaymentProposalSelfSendV1 self_spend_payment_proposal1_amnt_1;
    self_spend_payment_proposal1_amnt_1.m_destination = selfspend_dest;
    self_spend_payment_proposal1_amnt_1.m_amount = 1;
    self_spend_payment_proposal1_amnt_1.m_type = JamtisSelfSendType::SELF_SPEND;
    make_secret_key(self_spend_payment_proposal1_amnt_1.m_enote_ephemeral_privkey);

    JamtisPaymentProposalSelfSendV1 self_spend_payment_proposal2_amnt_1{self_spend_payment_proposal1_amnt_1};
    make_secret_key(self_spend_payment_proposal2_amnt_1.m_enote_ephemeral_privkey);

    // prepare change output
    JamtisPaymentProposalSelfSendV1 change_payment_proposal_amnt_1;
    change_payment_proposal_amnt_1.m_destination = change_dest;
    change_payment_proposal_amnt_1.m_amount = 1;
    change_payment_proposal_amnt_1.m_type = JamtisSelfSendType::CHANGE;
    make_secret_key(change_payment_proposal_amnt_1.m_enote_ephemeral_privkey);

    // sanity checks
    SpOutputProposalV1 self_spend_proposal1_amnt_1;
    SpOutputProposalV1 self_spend_proposal2_amnt_1;
    SpOutputProposalV1 change_proposal_amnt_1;
    self_spend_payment_proposal1_amnt_1.get_output_proposal_v1(keys.k_vb, rct::zero(), self_spend_proposal1_amnt_1);
    self_spend_payment_proposal2_amnt_1.get_output_proposal_v1(keys.k_vb, rct::zero(), self_spend_proposal2_amnt_1);
    change_payment_proposal_amnt_1.get_output_proposal_v1(keys.k_vb, rct::zero(), change_proposal_amnt_1);
    check_is_owned(self_spend_proposal2_amnt_1, keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);
    check_is_owned(self_spend_proposal1_amnt_1, keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);
    check_is_owned(change_proposal_amnt_1, keys, j_change, 1, JamtisEnoteType::CHANGE);


    /// test cases
    boost::multiprecision::uint128_t in_amount{0};
    const rct::xmr_amount fee{1};
    std::vector<jamtis::JamtisPaymentProposalV1> normal_proposals;
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_proposals;

    auto finalize_outputs_for_test =
        [&](std::vector<jamtis::JamtisPaymentProposalV1> &normal_payment_proposals_inout,
            std::vector<jamtis::JamtisPaymentProposalSelfSendV1> &selfsend_payment_proposals_inout)
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
    normal_proposals[0].gen(1, 0);
    selfsend_proposals.clear();
    EXPECT_NO_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));
    EXPECT_TRUE(normal_proposals.size() == 1);
    EXPECT_TRUE(selfsend_proposals.size() == 1);
    check_is_owned(selfsend_proposals[0], keys, j_dummy, 0, JamtisEnoteType::DUMMY);

    // 1 normal output, >0 change: 2 outputs (1 change)
    in_amount = 2 + fee;
    normal_proposals.resize(1);
    normal_proposals[0].gen(1, 0);  //change = 1
    selfsend_proposals.clear();
    EXPECT_NO_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));
    EXPECT_TRUE(normal_proposals.size() == 1);
    EXPECT_TRUE(selfsend_proposals.size() == 1);
    check_is_owned(selfsend_proposals[0], keys, j_change, 1, JamtisEnoteType::CHANGE);

    // 2 normal outputs, 0 change: 3 outputs (1 self-send dummy)
    in_amount = 2 + fee;
    normal_proposals.resize(2);
    normal_proposals[0].gen(1, 0);
    normal_proposals[1].gen(1, 0);
    selfsend_proposals.clear();
    EXPECT_NO_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));
    EXPECT_TRUE(normal_proposals.size() == 2);
    EXPECT_TRUE(selfsend_proposals.size() == 1);
    check_is_owned(selfsend_proposals[0], keys, j_dummy, 0, JamtisEnoteType::DUMMY);

    // 2 normal outputs (shared ephemeral pubkey), 0 change: error
    in_amount = 2 + fee;
    normal_proposals.resize(2);
    normal_proposals[0].gen(1, 0);
    normal_proposals[1].gen(1, 0);
    normal_proposals[1].m_enote_ephemeral_privkey = normal_proposals[0].m_enote_ephemeral_privkey;
    normal_proposals[1].m_destination.m_addr_K3 = normal_proposals[0].m_destination.m_addr_K3;
    selfsend_proposals.clear();
    EXPECT_ANY_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));

    // 2 normal outputs (shared ephemeral pubkey), >0 change: error
    in_amount = 3 + fee;
    normal_proposals.resize(2);
    normal_proposals[0].gen(1, 0);
    normal_proposals[1].gen(1, 0);  //change = 1
    normal_proposals[1].m_enote_ephemeral_privkey = normal_proposals[0].m_enote_ephemeral_privkey;
    normal_proposals[1].m_destination.m_addr_K3 = normal_proposals[0].m_destination.m_addr_K3;
    selfsend_proposals.clear();
    EXPECT_ANY_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));

    // 3 normal outputs, 0 change: 4 outputs (1 self-send dummy)
    in_amount = 3 + fee;
    normal_proposals.resize(3);
    normal_proposals[0].gen(1, 0);
    normal_proposals[1].gen(1, 0);
    normal_proposals[2].gen(1, 0);
    selfsend_proposals.clear();
    EXPECT_NO_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));
    EXPECT_TRUE(normal_proposals.size() == 3);
    EXPECT_TRUE(selfsend_proposals.size() == 1);
    check_is_owned(selfsend_proposals[0], keys, j_dummy, 0, JamtisEnoteType::DUMMY);

    // 3 normal outputs, >0 change: 4 outputs (1 change)
    in_amount = 4 + fee;
    normal_proposals.resize(3);
    normal_proposals[0].gen(1, 0);
    normal_proposals[1].gen(1, 0);
    normal_proposals[2].gen(1, 0);  //change = 1
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
    EXPECT_TRUE(normal_proposals[0].m_amount == 0);
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
    normal_proposals[0].gen(1, 0);
    selfsend_proposals.resize(1);
    selfsend_proposals[0] = self_spend_payment_proposal1_amnt_1;
    normal_proposals[0].m_enote_ephemeral_privkey = selfsend_proposals[0].m_enote_ephemeral_privkey;
    normal_proposals[0].m_destination.m_addr_K3 = selfsend_proposals[0].m_destination.m_addr_K3;
    EXPECT_NO_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));
    EXPECT_TRUE(normal_proposals.size() == 1);
    EXPECT_TRUE(selfsend_proposals.size() == 1);
    check_is_owned(selfsend_proposals[0], keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);

    // 1 self-send output & 1 normal output (shared ephemeral pubkey), >0 change: error
    in_amount = 3 + fee;
    normal_proposals.resize(1);
    normal_proposals[0].gen(1, 0);
    selfsend_proposals.resize(1);
    selfsend_proposals[0] = self_spend_payment_proposal1_amnt_1;  //change = 1
    normal_proposals[0].m_enote_ephemeral_privkey = selfsend_proposals[0].m_enote_ephemeral_privkey;
    normal_proposals[0].m_destination.m_addr_K3 = selfsend_proposals[0].m_destination.m_addr_K3;
    EXPECT_ANY_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));

    // 1 self-send output, 1 normal output, 0 change: 3 outputs (1 dummy)
    in_amount = 2 + fee;
    normal_proposals.resize(1);
    normal_proposals[0].gen(1, 0);
    selfsend_proposals.resize(1);
    selfsend_proposals[0] = self_spend_payment_proposal1_amnt_1;
    EXPECT_NO_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));
    EXPECT_TRUE(normal_proposals.size() == 2);
    EXPECT_TRUE(selfsend_proposals.size() == 1);
    EXPECT_TRUE(normal_proposals[1].m_amount == 0);
    check_is_owned(selfsend_proposals[0], keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);

    // 1 self-send output, 1 normal output, >0 change: 3 outputs (1 change)
    in_amount = 3 + fee;
    normal_proposals.resize(1);
    normal_proposals[0].gen(1, 0);
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
    normal_proposals[0].gen(1, 0);
    normal_proposals[1].gen(1, 0);
    selfsend_proposals.resize(1);
    selfsend_proposals[0] = self_spend_payment_proposal1_amnt_1;
    EXPECT_NO_THROW(finalize_outputs_for_test(normal_proposals, selfsend_proposals));
    EXPECT_TRUE(normal_proposals.size() == 2);
    EXPECT_TRUE(selfsend_proposals.size() == 1);
    check_is_owned(selfsend_proposals[0], keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);

    // 1 self-send output, 2 normal outputs, >0 change: 4 outputs (1 change)
    in_amount = 4 + fee;
    normal_proposals.resize(2);
    normal_proposals[0].gen(1, 0);
    normal_proposals[1].gen(1, 0);
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
    EXPECT_TRUE(normal_proposals[0].m_amount == 0);
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
TEST(seraphis, tx_extra)
{
    /// make elements
    std::vector<sp::ExtraFieldElement> extra_field_elements;
    extra_field_elements.resize(3);

    // rct::key
    extra_field_elements[0].m_type = 1;
    extra_field_elements[0].m_value.resize(32);
    memcpy(extra_field_elements[0].m_value.data(), rct::identity().bytes, 32);

    // std::uint64_t
    std::uint64_t one{1};
    extra_field_elements[1].m_type = 2;
    extra_field_elements[1].m_value.resize(8);
    memcpy(extra_field_elements[1].m_value.data(), &one, 8);

    // std::uint64_t
    extra_field_elements[2].m_type = 0;
    extra_field_elements[2].m_value.resize(8);
    memcpy(extra_field_elements[2].m_value.data(), &one, 8);


    /// make an extra field
    sp::TxExtra tx_extra;
    sp::make_tx_extra(std::move(extra_field_elements), tx_extra);


    /// validate field and recover elemeents
    auto validate_field_and_recover =
        [&]()
        {
            extra_field_elements.clear();
            EXPECT_TRUE(sp::try_get_extra_field_elements(tx_extra, extra_field_elements));
            ASSERT_TRUE(extra_field_elements.size() == 3);
            EXPECT_TRUE(extra_field_elements[0].m_type == 0);
            EXPECT_TRUE(extra_field_elements[0].m_value.size() == 8);
            std::uint64_t element0;
            memcpy(&element0, extra_field_elements[0].m_value.data(), 8);
            EXPECT_TRUE(element0 == one);
            EXPECT_TRUE(extra_field_elements[1].m_type == 1);
            EXPECT_TRUE(extra_field_elements[1].m_value.size() == 32);
            rct::key element1;
            memcpy(element1.bytes, extra_field_elements[1].m_value.data(), 32);
            EXPECT_TRUE(element1 == rct::identity());
            EXPECT_TRUE(extra_field_elements[2].m_type == 2);
            EXPECT_TRUE(extra_field_elements[2].m_value.size() == 8);
            std::uint64_t element2;
            memcpy(&element2, extra_field_elements[2].m_value.data(), 8);
            EXPECT_TRUE(element2 == one);
        };

    // basic recovery
    validate_field_and_recover();

    // partial field to full field reconstruction
    std::vector<sp::ExtraFieldElement> extra_field_elements2;
    std::vector<sp::ExtraFieldElement> extra_field_elements3;
    EXPECT_TRUE(sp::try_get_extra_field_elements(tx_extra, extra_field_elements2));
    extra_field_elements3.push_back(extra_field_elements2.back());
    extra_field_elements2.pop_back();

    sp::TxExtra tx_extra_partial;
    sp::make_tx_extra(std::move(extra_field_elements2), tx_extra_partial);

    extra_field_elements.clear();
    sp::accumulate_extra_field_elements(tx_extra_partial, extra_field_elements);        //first two elements
    sp::accumulate_extra_field_elements(extra_field_elements3, extra_field_elements);   //last element
    sp::make_tx_extra(std::move(extra_field_elements), tx_extra);

    validate_field_and_recover();


    /// adding a byte to the end causes failure
    tx_extra.push_back(0);
    extra_field_elements.clear();
    EXPECT_FALSE(sp::try_get_extra_field_elements(tx_extra, extra_field_elements));


    /// removing 2 bytes causes failure
    tx_extra.pop_back();
    tx_extra.pop_back();
    extra_field_elements.clear();
    EXPECT_FALSE(sp::try_get_extra_field_elements(tx_extra, extra_field_elements));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, binned_reference_set)
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
TEST(seraphis, discretized_fees)
{
    // test the fee discretizer
    std::uint64_t test_fee_value, fee_value;
    sp::DiscretizedFee discretized_fee;

    // fee value 0 (should perfectly discretize)
    test_fee_value = 0;
    discretized_fee = sp::DiscretizedFee{test_fee_value};
    EXPECT_TRUE(sp::try_get_fee_value(discretized_fee, fee_value));
    EXPECT_TRUE(fee_value == test_fee_value);
    EXPECT_TRUE(discretized_fee == test_fee_value);

    // fee value 1 (should perfectly discretize)
    test_fee_value = 1;
    discretized_fee = sp::DiscretizedFee{test_fee_value};
    EXPECT_TRUE(sp::try_get_fee_value(discretized_fee, fee_value));
    EXPECT_TRUE(fee_value == test_fee_value);
    EXPECT_TRUE(discretized_fee == test_fee_value);

    // fee value more digits than sig figs (should round up)
    test_fee_value = 1;
    for (std::size_t sig_fig{0}; sig_fig < config::DISCRETIZED_FEE_SIG_FIGS; ++sig_fig)
    {
        test_fee_value *= 10;
        test_fee_value += 1;
    }
    discretized_fee = sp::DiscretizedFee{test_fee_value};
    EXPECT_TRUE(sp::try_get_fee_value(discretized_fee, fee_value));
    EXPECT_TRUE(fee_value > test_fee_value);
    EXPECT_FALSE(discretized_fee == test_fee_value);

    // fee value MAX (should perfectly discretize)
    test_fee_value = std::numeric_limits<std::uint64_t>::max();
    discretized_fee = sp::DiscretizedFee{test_fee_value};
    EXPECT_TRUE(sp::try_get_fee_value(discretized_fee, fee_value));
    EXPECT_TRUE(fee_value == test_fee_value);
    EXPECT_TRUE(discretized_fee == test_fee_value);

    // unknown fee level
    discretized_fee.m_fee_level = static_cast<sp::discretized_fee_level_t>(-1);
    EXPECT_FALSE(sp::try_get_fee_value(discretized_fee, fee_value));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, txtype_squashed_v1)
{
    // demo making SpTxTypeSquasedV1 with raw tx builder API
    const std::size_t num_txs{3};
    const std::size_t num_ins_outs{11};

    // fake ledger context for this test
    sp::MockLedgerContext ledger_context{0, 0};

    // prepare input/output amounts
    std::vector<rct::xmr_amount> in_amounts;
    std::vector<rct::xmr_amount> out_amounts;

    for (int i{0}; i < num_ins_outs; ++i)
    {
        in_amounts.push_back(3);  //initial tx_fee = num_ins_outs
        out_amounts.push_back(2);
    }

    // set fee
    const sp::DiscretizedFee discretized_transaction_fee{num_ins_outs};
    rct::xmr_amount real_transaction_fee;
    EXPECT_TRUE(try_get_fee_value(discretized_transaction_fee, real_transaction_fee));

    // add an input to cover any extra fee added during discretization
    const rct::xmr_amount extra_fee_amount{real_transaction_fee - num_ins_outs};

    if (extra_fee_amount > 0)
        in_amounts.push_back(extra_fee_amount);

    // make txs
    std::vector<sp::SpTxSquashedV1> txs;
    std::vector<const sp::SpTxSquashedV1*> tx_ptrs;
    txs.reserve(num_txs);
    tx_ptrs.reserve(num_txs);

    for (std::size_t tx_index{0}; tx_index < num_txs; ++tx_index)
    {
        txs.emplace_back();
        make_sp_txtype_squashed_v1(2,
            2,
            sp::SpBinnedReferenceSetConfigV1{
                .m_bin_radius = 1,
                .m_num_bin_members = 2
            },
            3,
            in_amounts,
            out_amounts,
            discretized_transaction_fee,
            sp::SpTxSquashedV1::SemanticRulesVersion::MOCK,
            ledger_context,
            txs.back());
        tx_ptrs.push_back(&(txs.back()));
    }

    const sp::TxValidationContextMock tx_validation_context{ledger_context};

    EXPECT_TRUE(sp::validate_txs(tx_ptrs, tx_validation_context));

    // insert key images to ledger
    for (const sp::SpTxSquashedV1 &tx : txs)
        EXPECT_TRUE(sp::try_add_tx_to_ledger(tx, ledger_context));

    // validation should fail due to double-spend
    EXPECT_FALSE(sp::validate_txs(tx_ptrs, tx_validation_context));
}
//-------------------------------------------------------------------------------------------------------------------
