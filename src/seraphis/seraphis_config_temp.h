// Copyright (c) 2014-2020, The Monero Project
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
// 

//TODO: transfer this file to cryptonote_config.h (separate file for better compile-time during development)

#pragma once

#include <cstdint>

namespace config
{
  // note: version number should line up with intended grootle n^m decomposition
  const constexpr std::uint64_t SP_REF_SET_BIN_RADIUS_V1 = 127;
  const constexpr std::uint64_t SP_REF_SET_NUM_BIN_MEMBERS_V1 = 8;
  const constexpr std::uint64_t DISCRETIZED_FEE_LEVEL_NUMERATOR_X100 = 150;  //fee level factor = 1.5
  const constexpr std::uint64_t DISCRETIZED_FEE_SIG_FIGS = 1;

  const constexpr char SERAPHIS_TRANSCRIPT_PREFIX[] = "sp_tscrpt";

  const constexpr char HASH_KEY_JAMTIS_UNLOCKAMOUNTS_KEY[] = "jamtis_unlock_amounts_key";

  const constexpr char HASH_KEY_JAMTIS_INPUT_CONTEXT_COINBASE[] = "jamtis_input_context_coinbase";
  const constexpr char HASH_KEY_JAMTIS_INPUT_CONTEXT_STANDARD[] = "jamtis_input_context_standard";
  const constexpr char HASH_KEY_JAMTIS_SENDER_RECEIVER_SECRET_SELF_SEND_ENOTE_DUMMY[] = "jamtis_self_send_enote_dummy";
  const constexpr char HASH_KEY_JAMTIS_SENDER_RECEIVER_SECRET_SELF_SEND_ENOTE_CHANGE[] = "jamtis_self_send_enote_change";
  const constexpr char HASH_KEY_JAMTIS_SENDER_RECEIVER_SECRET_SELF_SEND_ENOTE_SELF_SPEND[] = "jamtis_self_send_enote_self_spend";

  const constexpr char HASH_KEY_SERAPHIS_TRANSACTION_TYPE_SQUASHED_V1[] = "sp_transaction_type_squashed_v1";
  const constexpr char HASH_KEY_SERAPHIS_INPUT_IMAGES_PREFIX_V1[] = "sp_input_images_prefix_v1";
  const constexpr char HASH_KEY_SERAPHIS_TRANSACTION_PROOFS_PREFIX_V1[] = "sp_transaction_proofs_prefix_v1";
  const constexpr char HASH_KEY_GROOTLE_Hi_A[] = "grootle_Hi_A";
  const constexpr char HASH_KEY_GROOTLE_Hi_B[] = "grootle_Hi_B";
  const constexpr char HASH_KEY_GROOTLE_CHALLENGE[] = "grootle_challenge";
  const constexpr char HASH_KEY_SERAPHIS_MEMBERSHIP_PROOF_MESSAGE_V1[] = "sp_membership_proof_message_v1";
  const constexpr char HASH_KEY_SP_COMPOSITION_PROOF_CHALLENGE_MESSAGE[] = "sp_composition_proof_challenge_message";
  const constexpr char HASH_KEY_SP_COMPOSITION_PROOF_CHALLENGE[] = "sp_composition_proof_challenge";
  const constexpr char HASH_KEY_SERAPHIS_IMAGE_PROOF_MESSAGE_V1[] = "sp_image_proof_message_v1";
  const constexpr char HASH_KEY_BINNED_REF_SET_GENERATOR_SEED[] = "binned_rset_generator_seed";
  const constexpr char HASH_KEY_BINNED_REF_SET_MEMBER[] = "binned_rset_member";

  const constexpr char HASH_KEY_SERAPHIS_SQUASHED_ENOTE[] = "sp_squashed_enote";
  const constexpr char HASH_KEY_MULTISIG_BINONCE_MERGE_FACTOR[] = "multisig_binonce_merge_factor";
  const constexpr char HASH_KEY_JAMTIS_GENERATEADDRESS_SECRET[] = "jamtis_generate_address_secret";
  const constexpr char HASH_KEY_JAMTIS_CIPHERTAG_SECRET[] = "jamtis_cipher_tag_secret";
  const constexpr char HASH_KEY_JAMTIS_IDENTIFYWALLET_KEY[] = "jamtis_identify_wallet_key";
  const constexpr char HASH_KEY_JAMTIS_FINDRECEIVED_KEY[] = "jamtis_find_received_key";
  const constexpr char HASH_KEY_JAMTIS_ADDRESS_PRIVKEY[] = "jamtis_address_privkey";
  const constexpr char HASH_KEY_JAMTIS_SPENDKEY_EXTENSION[] = "jamtis_spendkey_extension";
  const constexpr char HASH_KEY_JAMTIS_ENCRYPTED_ADDRESS_TAG[] = "jamtis_encrypted_address_tag";
  const constexpr char HASH_KEY_JAMTIS_VIEW_TAG[] = "jamtis_view_tag";
  const constexpr char HASH_KEY_JAMTIS_SENDER_RECEIVER_SECRET_PLAIN[] = "jamtis_sender_receiver_secret_plain";
  const constexpr char HASH_KEY_JAMTIS_SENDER_ONETIME_ADDRESS_EXTENSION[] = "jamtis_sender_onetime_address_extension";
  const constexpr char HASH_KEY_JAMTIS_AMOUNT_BLINDING_FACTOR_PLAIN[] = "jamtis_enote_amount_commitment_blinding_factor_plain";
  const constexpr char HASH_KEY_JAMTIS_AMOUNT_BLINDING_FACTOR_SELF[] = "jamtis_enote_amount_commitment_blinding_factor_self";
  const constexpr char HASH_KEY_JAMTIS_AMOUNT_ENC[] = "jamtis_enote_amount_encoding";
}
