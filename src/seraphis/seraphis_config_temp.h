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

  const constexpr char SERAPHIS_TRANSCRIPT_PREFIX[] = "seraphis_transcript";

  const constexpr char HASH_KEY_JAMTIS_UNLOCKAMOUNTS_KEY[] = "jamtis_unlock_amounts_key";

  const constexpr char HASH_KEY_JAMTIS_INPUT_CONTEXT_COINBASE[] = "jamtis_input_context_coinbase";
  const constexpr char HASH_KEY_JAMTIS_INPUT_CONTEXT_STANDARD[] = "jamtis_input_context_standard";
  const constexpr char HASH_KEY_JAMTIS_SENDER_RECEIVER_SECRET_SELF_SEND_ENOTE_DUMMY[] = "jamtis_self_send_enote_dummy";
  const constexpr char HASH_KEY_JAMTIS_SENDER_RECEIVER_SECRET_SELF_SEND_ENOTE_CHANGE[] = "jamtis_self_send_enote_change";
  const constexpr char HASH_KEY_JAMTIS_SENDER_RECEIVER_SECRET_SELF_SEND_ENOTE_SELF_SPEND[] = "jamtis_self_send_enote_self_spend";

  const constexpr char HASH_KEY_SERAPHIS_TRANSACTION_TYPE_SQUASHED_V1[] = "seraphis_transaction_type_squashed_v1";
  const constexpr char HASH_KEY_SERAPHIS_INPUT_IMAGES_PREFIX_V1[] = "seraphis_input_images_prefix_v1";
  const constexpr char HASH_KEY_SERAPHIS_TRANSACTION_PROOFS_PREFIX_V1[] = "seraphis_transaction_proofs_prefix_v1";
  const constexpr char HASH_KEY_GROOTLE_Hi_A[] = "grootle_Hi_A";
  const constexpr char HASH_KEY_GROOTLE_Hi_B[] = "grootle_Hi_B";
  const constexpr char HASH_KEY_GROOTLE_CHALLENGE[] = "grootle_challenge";
  const constexpr char HASH_KEY_SERAPHIS_MEMBERSHIP_PROOF_MESSAGE_V1[] = "seraphis_membership_proof_message_v1";
  const constexpr char HASH_KEY_SP_COMPOSITION_PROOF_CHALLENGE_MESSAGE[] = "seraphis_composition_proof_challenge_message";
  const constexpr char HASH_KEY_SP_COMPOSITION_PROOF_CHALLENGE[] = "seraphis_composition_proof_challenge";
  const constexpr char HASH_KEY_SERAPHIS_IMAGE_PROOF_MESSAGE_V1[] = "seraphis_image_proof_message_v1";
  const constexpr char HASH_KEY_BINNED_REF_SET_GENERATOR_SEED[] = "binned_ref_set_generator_seed";
  const constexpr char HASH_KEY_BINNED_REF_SET_MEMBER[] = "binned_ref_set_member";
}
