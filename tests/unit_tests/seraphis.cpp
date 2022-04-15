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
}
#include "device/device.hpp"
#include "misc_language.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis/jamtis_address_tags.h"
#include "seraphis/jamtis_address_utils.h"
#include "seraphis/jamtis_core_utils.h"
#include "seraphis/jamtis_destination.h"
#include "seraphis/jamtis_enote_utils.h"
#include "seraphis/jamtis_payment_proposal.h"
#include "seraphis/jamtis_support_types.h"
#include "seraphis/ledger_context.h"
#include "seraphis/mock_ledger_context.h"
#include "seraphis/sp_composition_proof.h"
#include "seraphis/sp_core_enote_utils.h"
#include "seraphis/sp_core_types.h"
#include "seraphis/sp_crypto_utils.h"
#include "seraphis/tx_base.h"
#include "seraphis/tx_builder_types.h"
#include "seraphis/tx_builders_inputs.h"
#include "seraphis/tx_builders_mixed.h"
#include "seraphis/tx_builders_outputs.h"
#include "seraphis/tx_component_types.h"
#include "seraphis/tx_extra.h"
#include "seraphis/tx_misc_utils.h"
#include "seraphis/tx_record_types.h"
#include "seraphis/tx_record_utils.h"
#include "seraphis/txtype_squashed_v1.h"

#include "boost/multiprecision/cpp_int.hpp"
#include "gtest/gtest.h"

#include <memory>
#include <vector>


struct jamtis_keys
{
    crypto::secret_key k_m;   //master
    crypto::secret_key k_vb;  //view-balance
    crypto::secret_key k_fr;  //find-received
    crypto::secret_key s_ga;  //generate-address
    crypto::secret_key s_ct;  //cipher-tag
    rct::key K_1_base;        //wallet spend base
    rct::key K_fr;            //find-received pubkey
};

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_secret_key(crypto::secret_key &skey_out)
{
    skey_out = rct::rct2sk(rct::skGen());
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_jamtis_keys(jamtis_keys &keys_out)
{
    using namespace sp;
    using namespace jamtis;

    make_secret_key(keys_out.k_m);
    make_secret_key(keys_out.k_vb);
    make_jamtis_findreceived_key(keys_out.k_vb, keys_out.k_fr);
    make_jamtis_generateaddress_secret(keys_out.k_vb, keys_out.s_ga);
    make_jamtis_ciphertag_secret(keys_out.s_ga, keys_out.s_ct);
    make_seraphis_spendkey(keys_out.k_vb, keys_out.k_m, keys_out.K_1_base);
    rct::scalarmultBase(keys_out.K_fr, rct::sk2rct(keys_out.k_fr));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_fake_sp_masked_address(crypto::secret_key &mask,
    crypto::secret_key &view_stuff,
    crypto::secret_key &spendkey,
    rct::key &masked_address)
{
    make_secret_key(mask);
    make_secret_key(view_stuff);
    make_secret_key(spendkey);

    // K' = x G + kv_stuff X + ks U
    sp::make_seraphis_spendkey(view_stuff, spendkey, masked_address);
    sp::mask_key(mask, masked_address, masked_address);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void check_is_owned_with_intermediate_record(const sp::SpOutputProposalV1 &test_proposal,
    const jamtis_keys &keys,
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
        keys.K_1_base,
        keys.k_fr,
        keys.s_ga,
        intermediate_enote_record));

    // check misc fields
    EXPECT_TRUE(intermediate_enote_record.m_amount == amount_expected);
    EXPECT_TRUE(intermediate_enote_record.m_address_index == j_expected);

    // get full enote record from intermediate record
    sp::SpEnoteRecordV1 enote_record;
    sp::get_enote_record_v1_plain(intermediate_enote_record, keys.K_1_base, keys.k_vb, keys.s_ga, enote_record);

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
    const jamtis_keys &keys,
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
static void make_sp_txtype_squashed_v1(const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const std::size_t num_random_memo_elements,
    const std::vector<rct::xmr_amount> &in_amounts,
    const std::vector<rct::xmr_amount> &out_amounts,
    const rct::xmr_amount transaction_fee,
    const sp::SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    sp::MockLedgerContext &ledger_context_inout,
    sp::SpTxSquashedV1 &tx_out)
{
    /// build a tx from base components
    using namespace sp;

    CHECK_AND_ASSERT_THROW_MES(in_amounts.size() > 0, "Tried to make tx without any inputs.");
    CHECK_AND_ASSERT_THROW_MES(out_amounts.size() > 0, "Tried to make tx without any outputs.");
    CHECK_AND_ASSERT_THROW_MES(balance_check_in_out_amnts(in_amounts, out_amounts, transaction_fee),
        "Tried to make tx with unbalanced amounts.");

    // make mock inputs
    // enote, ks, view key stuff, amount, amount blinding factor
    std::vector<SpInputProposalV1> input_proposals{gen_mock_sp_input_proposals_v1(in_amounts)};

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
    std::vector<SpEnote> input_enotes;
    input_enotes.reserve(input_proposals.size());

    for (const auto &input_proposal : input_proposals)
    {
        input_enotes.emplace_back();
        input_proposal.m_core.get_enote_core(input_enotes.back());
    }

    std::vector<SpMembershipReferenceSetV1> membership_ref_sets{
            gen_mock_sp_membership_ref_sets_v1(input_enotes,
                ref_set_decomp_n,
                ref_set_decomp_m,
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
    make_tx_image_proof_message_v1(version_string, outputs, tx_supplement, image_proofs_message);
    make_v1_image_proofs_v1(input_proposals,
        image_proofs_message,
        tx_image_proofs);
    prepare_input_commitment_factors_for_balance_proof_v1(input_proposals,
        image_amount_masks,
        input_amounts,
        input_image_amount_commitment_blinding_factors);
    make_v1_balance_proof_v1(input_amounts, //note: must range proof input image commitments in squashed enote model
        output_amounts,
        transaction_fee,
        input_image_amount_commitment_blinding_factors,
        output_amount_commitment_blinding_factors,
        balance_proof);
    make_v1_membership_proofs_v1(membership_ref_sets,
        image_address_masks,
        image_amount_masks,
        tx_alignable_membership_proofs);  //alignable membership proofs could theoretically be inputs as well
    align_v1_membership_proofs_v1(input_images, std::move(tx_alignable_membership_proofs), tx_membership_proofs);

    make_seraphis_tx_squashed_v1(std::move(input_images), std::move(outputs),
        std::move(balance_proof), std::move(tx_image_proofs), std::move(tx_membership_proofs),
        std::move(tx_supplement), transaction_fee, semantic_rules_version, tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool test_info_recovery_addressindex(const sp::jamtis::address_index_t j)
{
    using namespace sp;
    using namespace jamtis;

    // convert the index to/from raw tag form
    address_tag_t raw_tag{address_index_to_tag(j, 0)};
    address_tag_MAC_t raw_mac;
    if (address_tag_to_index(raw_tag, raw_mac) != j)
        return false;
    if (raw_mac != 0)
        return false;

    // cipher and decipher the index
    crypto::secret_key cipher_key;
    make_secret_key(cipher_key);
    address_tag_t ciphered_tag{cipher_address_index(rct::sk2rct(cipher_key), j, 0)};
    address_tag_MAC_t decipher_mac;
    if (decipher_address_index(rct::sk2rct(cipher_key), ciphered_tag, decipher_mac) != j)
        return false;
    if (decipher_mac != 0)
        return false;

    // encrypt and decrypt an address tag
    crypto::secret_key encryption_key;
    make_secret_key(encryption_key);
    encrypted_address_tag_t encrypted_ciphered_tag{encrypt_address_tag(rct::sk2rct(encryption_key), ciphered_tag)};
    if (decrypt_address_tag(rct::sk2rct(encryption_key), encrypted_ciphered_tag) != ciphered_tag)
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, composition_proof)
{
    rct::key K;
    crypto::key_image KI;
    crypto::secret_key x, y, z;
    rct::key message{rct::zero()};
    sp::SpCompositionProof proof;

    try
    {
        make_fake_sp_masked_address(x, y, z, K);
        proof = sp::sp_composition_prove(message, K, x, y, z);

        sp::make_seraphis_key_image(y, z, KI);
        EXPECT_TRUE(sp::sp_composition_verify(proof, message, K, KI));
    }
    catch (...)
    {
        EXPECT_TRUE(false);
    }

    // check: works even if x = 0
    try
    {
        make_fake_sp_masked_address(x, y, z, K);

        rct::key xG;
        rct::scalarmultBase(xG, rct::sk2rct(x));
        rct::subKeys(K, K, xG);   // kludge: remove x part manually
        x = rct::rct2sk(rct::zero());

        proof = sp::sp_composition_prove(message, K, x, y, z);

        sp::make_seraphis_key_image(y, z, KI);
        EXPECT_TRUE(sp::sp_composition_verify(proof, message, K, KI));
    }
    catch (...)
    {
        EXPECT_TRUE(false);
    }
}
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
    sc_mul(to_bytes(spendkey_extension), sp::MINUS_ONE.bytes, to_bytes(k_a_sender));  // k^j_x = -y
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
    rct::xmr_amount amount = rct::randXmrAmount(rct::xmr_amount{static_cast<rct::xmr_amount>(-1)});

    crypto::key_derivation fake_baked_key;
    memcpy(&fake_baked_key, rct::zero().bytes, sizeof(rct::key));

    rct::xmr_amount encoded_amount{encode_jamtis_amount_plain(amount, rct::sk2rct(sender_receiver_secret), fake_baked_key)};
    rct::xmr_amount decoded_amount{decode_jamtis_amount_plain(encoded_amount, rct::sk2rct(sender_receiver_secret), fake_baked_key)};
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
    EXPECT_TRUE(test_info_recovery_addressindex(MAX_ADDRESS_INDEX));
    EXPECT_FALSE(test_info_recovery_addressindex(MAX_ADDRESS_INDEX + 1));

    for (std::size_t i{0}; i < 10; ++i)
        EXPECT_TRUE(test_info_recovery_addressindex(crypto::rand_idx(MAX_ADDRESS_INDEX)));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, information_recovery_jamtisdestination)
{
    using namespace sp;
    using namespace jamtis;

    // user wallet keys
    jamtis_keys keys;
    make_jamtis_keys(keys);

    // test making a jamtis destination then recovering the index
    JamtisDestinationV1 destination_known;
    address_index_t j{crypto::rand_idx(MAX_ADDRESS_INDEX)};
    make_jamtis_destination_v1(keys.K_1_base, keys.K_fr, keys.s_ga, j, destination_known);

    address_index_t j_nominal;
    EXPECT_TRUE(try_get_jamtis_index_from_destination_v1(destination_known,
        keys.K_1_base,
        keys.K_fr,
        keys.s_ga,
        j_nominal));
    EXPECT_TRUE(j_nominal == j);

    // test generating a random address
    JamtisDestinationV1 destination_unknown;
    destination_unknown.gen();
    EXPECT_FALSE(try_get_jamtis_index_from_destination_v1(destination_unknown,
        keys.K_1_base,
        keys.K_fr,
        keys.s_ga,
        j_nominal));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, information_recovery_enote_v1_plain)
{
    using namespace sp;
    using namespace jamtis;

    // user wallet keys
    jamtis_keys keys;
    make_jamtis_keys(keys);

    // user address
    address_index_t j{crypto::rand_idx(MAX_ADDRESS_INDEX)};
    JamtisDestinationV1 user_address;

    make_jamtis_destination_v1(keys.K_1_base,
        keys.K_fr,
        keys.s_ga,
        j,
        user_address);

    // make a plain enote paying to address
    rct::xmr_amount amount{crypto::rand_idx(static_cast<rct::xmr_amount>(-1))};
    crypto::secret_key enote_privkey{rct::rct2sk(rct::skGen())};

    JamtisPaymentProposalV1 payment_proposal{user_address, amount, enote_privkey};
    SpOutputProposalV1 output_proposal;
    payment_proposal.get_output_proposal_v1(output_proposal);

    // check the enote
    check_is_owned(output_proposal, keys, j, amount, JamtisEnoteType::PLAIN);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, information_recovery_enote_v1_selfsend)
{
    using namespace sp;
    using namespace jamtis;

    // user wallet keys
    jamtis_keys keys;
    make_jamtis_keys(keys);

    // user address
    address_index_t j{crypto::rand_idx(MAX_ADDRESS_INDEX)};
    JamtisDestinationV1 user_address;

    make_jamtis_destination_v1(keys.K_1_base,
        keys.K_fr,
        keys.s_ga,
        j,
        user_address);

    // make a self-spend enote paying to address
    rct::xmr_amount amount{crypto::rand_idx(static_cast<rct::xmr_amount>(-1))};
    crypto::secret_key enote_privkey{rct::rct2sk(rct::skGen())};

    JamtisPaymentProposalSelfSendV1 payment_proposal_selfspend{user_address,
        amount,
        JamtisSelfSendMAC::SELF_SPEND,
        enote_privkey,
        keys.k_vb};
    SpOutputProposalV1 output_proposal;
    payment_proposal_selfspend.get_output_proposal_v1(output_proposal);

    // check the enote
    check_is_owned(output_proposal, keys, j, amount, JamtisEnoteType::SELF_SPEND);

    // make a change enote paying to address
    amount = crypto::rand_idx(static_cast<rct::xmr_amount>(-1));
    enote_privkey = rct::rct2sk(rct::skGen());

    JamtisPaymentProposalSelfSendV1 payment_proposal_change{user_address,
        amount,
        JamtisSelfSendMAC::CHANGE,
        enote_privkey,
        keys.k_vb};
    payment_proposal_change.get_output_proposal_v1(output_proposal);

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
    jamtis_keys keys;
    make_jamtis_keys(keys);

    // user addresses
    address_index_t j_selfspend{crypto::rand_idx(MAX_ADDRESS_INDEX)};
    address_index_t j_change{crypto::rand_idx(MAX_ADDRESS_INDEX)};
    address_index_t j_dummy{crypto::rand_idx(MAX_ADDRESS_INDEX)};
    JamtisDestinationV1 selfspend_dest;
    JamtisDestinationV1 change_dest;
    JamtisDestinationV1 dummy_dest;
    make_jamtis_destination_v1(keys.K_1_base, keys.K_fr, keys.s_ga, j_selfspend, selfspend_dest);
    make_jamtis_destination_v1(keys.K_1_base, keys.K_fr, keys.s_ga, j_change, change_dest);
    make_jamtis_destination_v1(keys.K_1_base, keys.K_fr, keys.s_ga, j_dummy, dummy_dest);

    // prepare self-spend outputs
    JamtisPaymentProposalSelfSendV1 self_spend_payment_proposal;
    SpOutputProposalV1 self_spend_proposal_amnt_1;
    self_spend_payment_proposal.m_destination = selfspend_dest;
    self_spend_payment_proposal.m_amount = 1;
    self_spend_payment_proposal.m_type = JamtisSelfSendMAC::SELF_SPEND;
    make_secret_key(self_spend_payment_proposal.m_enote_ephemeral_privkey);
    self_spend_payment_proposal.m_viewbalance_privkey = keys.k_vb;
    self_spend_payment_proposal.get_output_proposal_v1(self_spend_proposal_amnt_1);
    check_is_owned(self_spend_proposal_amnt_1, keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);

    JamtisPaymentProposalSelfSendV1 self_spend_payment_proposal2{self_spend_payment_proposal};
    SpOutputProposalV1 self_spend_proposal2_amnt_1;
    make_secret_key(self_spend_payment_proposal2.m_enote_ephemeral_privkey);
    self_spend_payment_proposal2.get_output_proposal_v1(self_spend_proposal2_amnt_1);
    check_is_owned(self_spend_proposal2_amnt_1, keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);

    /// test cases
    boost::multiprecision::uint128_t in_amount{0};
    rct::xmr_amount fee{1};
    std::vector<SpOutputProposalV1> out_proposals{};

    // 0 outputs, 0 change: error
    in_amount = 0 + fee;
    out_proposals.clear();
    EXPECT_ANY_THROW(finalize_v1_output_proposal_set_v1(in_amount, fee, change_dest, dummy_dest, keys.K_1_base, keys.k_vb, out_proposals));

    // 0 outputs, >0 change: error
    in_amount = 1 + fee;
    out_proposals.clear();  //change = 1
    EXPECT_ANY_THROW(finalize_v1_output_proposal_set_v1(in_amount, fee, change_dest, dummy_dest, keys.K_1_base, keys.k_vb, out_proposals));

    // 1 normal output, 0 change: 2 outputs (1 self-send dummy)
    in_amount = 1 + fee;
    out_proposals.resize(1);
    out_proposals[0].gen(1, 0);
    EXPECT_NO_THROW(finalize_v1_output_proposal_set_v1(in_amount, fee, change_dest, dummy_dest, keys.K_1_base, keys.k_vb, out_proposals));
    EXPECT_TRUE(out_proposals.size() == 2);
    check_is_owned(out_proposals[1], keys, j_dummy, 0, JamtisEnoteType::DUMMY);

    // 1 normal output, >0 change: 2 outputs (1 change)
    in_amount = 2 + fee;
    out_proposals.resize(1);
    out_proposals[0].gen(1, 0);  //change = 1
    EXPECT_NO_THROW(finalize_v1_output_proposal_set_v1(in_amount, fee, change_dest, dummy_dest, keys.K_1_base, keys.k_vb, out_proposals));
    EXPECT_TRUE(out_proposals.size() == 2);
    check_is_owned(out_proposals[1], keys, j_change, 1, JamtisEnoteType::CHANGE);

    // 2 normal outputs, 0 change: 3 outputs (1 self-send dummy)
    in_amount = 2 + fee;
    out_proposals.resize(2);
    out_proposals[0].gen(1, 0);
    out_proposals[1].gen(1, 0);
    EXPECT_NO_THROW(finalize_v1_output_proposal_set_v1(in_amount, fee, change_dest, dummy_dest, keys.K_1_base, keys.k_vb, out_proposals));
    EXPECT_TRUE(out_proposals.size() == 3);
    check_is_owned(out_proposals[2], keys, j_dummy, 0, JamtisEnoteType::DUMMY);

    // 2 normal outputs (shared ephemeral pubkey), 0 change: error
    in_amount = 2 + fee;
    out_proposals.resize(2);
    out_proposals[0].gen(1, 0);
    out_proposals[1].gen(1, 0);
    out_proposals[1].m_enote_ephemeral_pubkey = out_proposals[0].m_enote_ephemeral_pubkey;
    EXPECT_ANY_THROW(finalize_v1_output_proposal_set_v1(in_amount, fee, change_dest, dummy_dest, keys.K_1_base, keys.k_vb, out_proposals));

    // 2 normal outputs (shared ephemeral pubkey), >0 change: error
    in_amount = 3 + fee;
    out_proposals.resize(2);
    out_proposals[0].gen(1, 0);
    out_proposals[1].gen(1, 0);  //change = 1
    out_proposals[1].m_enote_ephemeral_pubkey = out_proposals[0].m_enote_ephemeral_pubkey;
    EXPECT_ANY_THROW(finalize_v1_output_proposal_set_v1(in_amount, fee, change_dest, dummy_dest, keys.K_1_base, keys.k_vb, out_proposals));

    // 3 normal outputs, 0 change: 4 outputs (1 self-send dummy)
    in_amount = 3 + fee;
    out_proposals.resize(3);
    out_proposals[0].gen(1, 0);
    out_proposals[1].gen(1, 0);
    out_proposals[2].gen(1, 0);
    EXPECT_NO_THROW(finalize_v1_output_proposal_set_v1(in_amount, fee, change_dest, dummy_dest, keys.K_1_base, keys.k_vb, out_proposals));
    EXPECT_TRUE(out_proposals.size() == 4);
    check_is_owned(out_proposals[3], keys, j_dummy, 0, JamtisEnoteType::DUMMY);

    // 3 normal outputs, >0 change: 4 outputs (1 change)
    in_amount = 4 + fee;
    out_proposals.resize(3);
    out_proposals[0].gen(1, 0);
    out_proposals[1].gen(1, 0);
    out_proposals[2].gen(1, 0);  //change = 1
    EXPECT_NO_THROW(finalize_v1_output_proposal_set_v1(in_amount, fee, change_dest, dummy_dest, keys.K_1_base, keys.k_vb, out_proposals));
    EXPECT_TRUE(out_proposals.size() == 4);
    check_is_owned(out_proposals[3], keys, j_change, 1, JamtisEnoteType::CHANGE);

    // 1 self-send output, 0 change: 2 outputs (1 dummy)
    in_amount = 1 + fee;
    out_proposals.resize(1);
    out_proposals[0] = self_spend_proposal_amnt_1;
    EXPECT_NO_THROW(finalize_v1_output_proposal_set_v1(in_amount, fee, change_dest, dummy_dest, keys.K_1_base, keys.k_vb, out_proposals));
    EXPECT_TRUE(out_proposals.size() == 2);
    check_is_owned(out_proposals[0], keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);
    EXPECT_FALSE(is_self_send_output_proposal(out_proposals[1], keys.K_1_base, keys.k_vb));  //dummy

    // 1 self-send output, >0 change: 3 outputs (1 dummy, 1 change)
    in_amount = 2 + fee;
    out_proposals.resize(1);
    out_proposals[0] = self_spend_proposal_amnt_1;  //change = 1
    EXPECT_NO_THROW(finalize_v1_output_proposal_set_v1(in_amount, fee, change_dest, dummy_dest, keys.K_1_base, keys.k_vb, out_proposals));
    EXPECT_TRUE(out_proposals.size() == 3);
    check_is_owned(out_proposals[0], keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);
    EXPECT_FALSE(is_self_send_output_proposal(out_proposals[1], keys.K_1_base, keys.k_vb));  //dummy
    check_is_owned(out_proposals[2], keys, j_change, 1, JamtisEnoteType::CHANGE);

    // 1 self-send output & 1 normal output (shared ephemeral pubkey), 0 change: 2 outputs
    in_amount = 2 + fee;
    out_proposals.resize(2);
    out_proposals[0] = self_spend_proposal_amnt_1;
    out_proposals[1].gen(1, 0);
    out_proposals[1].m_enote_ephemeral_pubkey = out_proposals[0].m_enote_ephemeral_pubkey;
    EXPECT_NO_THROW(finalize_v1_output_proposal_set_v1(in_amount, fee, change_dest, dummy_dest, keys.K_1_base, keys.k_vb, out_proposals));
    EXPECT_TRUE(out_proposals.size() == 2);

    // 1 self-send output & 1 normal output (shared ephemeral pubkey), >0 change: error
    in_amount = 3 + fee;
    out_proposals.resize(2);
    out_proposals[0] = self_spend_proposal_amnt_1;
    out_proposals[1].gen(1, 0);  //change = 1
    out_proposals[1].m_enote_ephemeral_pubkey = out_proposals[0].m_enote_ephemeral_pubkey;
    EXPECT_ANY_THROW(finalize_v1_output_proposal_set_v1(in_amount, fee, change_dest, dummy_dest, keys.K_1_base, keys.k_vb, out_proposals));

    // 1 self-send output, 1 normal output, 0 change: 3 outputs (1 dummy)
    in_amount = 2 + fee;
    out_proposals.resize(2);
    out_proposals[0] = self_spend_proposal_amnt_1;
    out_proposals[1].gen(1, 0);
    EXPECT_NO_THROW(finalize_v1_output_proposal_set_v1(in_amount, fee, change_dest, dummy_dest, keys.K_1_base, keys.k_vb, out_proposals));
    EXPECT_TRUE(out_proposals.size() == 3);
    check_is_owned(out_proposals[0], keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);
    EXPECT_FALSE(is_self_send_output_proposal(out_proposals[2], keys.K_1_base, keys.k_vb));

    // 1 self-send output, 1 normal output, >0 change: 3 outputs (1 change)
    in_amount = 3 + fee;
    out_proposals.resize(2);
    out_proposals[0] = self_spend_proposal_amnt_1;
    out_proposals[1].gen(1, 0);  //change = 1
    EXPECT_NO_THROW(finalize_v1_output_proposal_set_v1(in_amount, fee, change_dest, dummy_dest, keys.K_1_base, keys.k_vb, out_proposals));
    EXPECT_TRUE(out_proposals.size() == 3);
    check_is_owned(out_proposals[0], keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);
    check_is_owned(out_proposals[2], keys, j_change, 1, JamtisEnoteType::CHANGE);

    // 1 self-send output, 2 normal outputs, 0 change: 3 outputs
    in_amount = 3 + fee;
    out_proposals.resize(3);
    out_proposals[0] = self_spend_proposal_amnt_1;
    out_proposals[1].gen(1, 0);
    out_proposals[2].gen(1, 0);
    EXPECT_NO_THROW(finalize_v1_output_proposal_set_v1(in_amount, fee, change_dest, dummy_dest, keys.K_1_base, keys.k_vb, out_proposals));
    EXPECT_TRUE(out_proposals.size() == 3);
    check_is_owned(out_proposals[0], keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);

    // 1 self-send output, 2 normal outputs, >0 change: 4 outputs (1 change)
    in_amount = 4 + fee;
    out_proposals.resize(3);
    out_proposals[0] = self_spend_proposal_amnt_1;
    out_proposals[1].gen(1, 0);
    out_proposals[2].gen(1, 0);  //change = 1
    EXPECT_NO_THROW(finalize_v1_output_proposal_set_v1(in_amount, fee, change_dest, dummy_dest, keys.K_1_base, keys.k_vb, out_proposals));
    EXPECT_TRUE(out_proposals.size() == 4);
    check_is_owned(out_proposals[0], keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);
    check_is_owned(out_proposals[3], keys, j_change, 1, JamtisEnoteType::CHANGE);

    // 2 self-send outputs (shared ephemeral pubkey), 0 change: error
    in_amount = 2 + fee;
    out_proposals.resize(2);
    out_proposals[0] = self_spend_proposal_amnt_1;
    out_proposals[1] = self_spend_proposal_amnt_1;
    EXPECT_ANY_THROW(finalize_v1_output_proposal_set_v1(in_amount, fee, change_dest, dummy_dest, keys.K_1_base, keys.k_vb, out_proposals));

    // 2 self-send outputs (shared ephemeral pubkey), >0 change: error
    in_amount = 3 + fee;
    out_proposals.resize(2);
    out_proposals[0] = self_spend_proposal_amnt_1;
    out_proposals[1] = self_spend_proposal_amnt_1;  //change = 1
    EXPECT_ANY_THROW(finalize_v1_output_proposal_set_v1(in_amount, fee, change_dest, dummy_dest, keys.K_1_base, keys.k_vb, out_proposals));

    // 2 self-send outputs, 0 change: 3 outputs (1 dummy)
    in_amount = 2 + fee;
    out_proposals.resize(2);
    out_proposals[0] = self_spend_proposal_amnt_1;
    out_proposals[1] = self_spend_proposal2_amnt_1;
    EXPECT_NO_THROW(finalize_v1_output_proposal_set_v1(in_amount, fee, change_dest, dummy_dest, keys.K_1_base, keys.k_vb, out_proposals));
    EXPECT_TRUE(out_proposals.size() == 3);
    check_is_owned(out_proposals[0], keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);
    check_is_owned(out_proposals[1], keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);
    EXPECT_FALSE(is_self_send_output_proposal(out_proposals[2], keys.K_1_base, keys.k_vb));

    // 2 self-send outputs, >0 change: 3 outputs (1 change)
    in_amount = 3 + fee;
    out_proposals.resize(2);
    out_proposals[0] = self_spend_proposal_amnt_1;
    out_proposals[1] = self_spend_proposal2_amnt_1;  //change = 1
    EXPECT_NO_THROW(finalize_v1_output_proposal_set_v1(in_amount, fee, change_dest, dummy_dest, keys.K_1_base, keys.k_vb, out_proposals));
    EXPECT_TRUE(out_proposals.size() == 3);
    check_is_owned(out_proposals[0], keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);
    check_is_owned(out_proposals[1], keys, j_selfspend, 1, JamtisEnoteType::SELF_SPEND);
    check_is_owned(out_proposals[2], keys, j_change, 1, JamtisEnoteType::CHANGE);
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
    extra_field_elements.clear();
    EXPECT_TRUE(sp::try_get_extra_field_elements(tx_extra, extra_field_elements));
    EXPECT_TRUE(extra_field_elements.size() == 3);
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
TEST(seraphis, txtype_squashed_v1)
{
    // demo making SpTxTypeSquasedV1 with raw tx builder API
    std::size_t num_txs{3};
    std::size_t num_ins_outs{11};

    // fake ledger context for this test
    sp::MockLedgerContext ledger_context{};

    // make txs
    std::vector<sp::SpTxSquashedV1> txs;
    std::vector<const sp::SpTxSquashedV1*> tx_ptrs;
    txs.reserve(num_txs);
    tx_ptrs.reserve(num_txs);

    std::vector<rct::xmr_amount> in_amounts;
    std::vector<rct::xmr_amount> out_amounts;

    for (int i{0}; i < num_ins_outs; ++i)
    {
        in_amounts.push_back(3);  //tx_fee = num_ins_outs
        out_amounts.push_back(2);
    }

    for (std::size_t tx_index{0}; tx_index < num_txs; ++tx_index)
    {
        txs.emplace_back();
        make_sp_txtype_squashed_v1(2, 2, 3, in_amounts, out_amounts, rct::xmr_amount{num_ins_outs},
            sp::SpTxSquashedV1::SemanticRulesVersion::MOCK, ledger_context, txs.back());
        tx_ptrs.push_back(&(txs.back()));
    }

    EXPECT_TRUE(sp::validate_txs(tx_ptrs, ledger_context));

    // insert key images to ledger
    for (const sp::SpTxSquashedV1 &tx : txs)
        EXPECT_TRUE(sp::try_add_tx_to_ledger<sp::SpTxSquashedV1>(tx, ledger_context));

    // validation should fail due to double-spend
    EXPECT_FALSE(sp::validate_txs(tx_ptrs, ledger_context));
}
//-------------------------------------------------------------------------------------------------------------------
