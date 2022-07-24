# Copyright (c) 2021, The Monero Project
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

set(seraphis_sources
  bulletproofs_plus2.cpp
  grootle.cpp
  jamtis_address_tag_utils.cpp
  jamtis_address_utils.cpp
  jamtis_core_utils.cpp
  jamtis_destination.cpp
  jamtis_enote_utils.cpp
  jamtis_payment_proposal.cpp
  jamtis_support_types.cpp
  legacy_core_utils.cpp
  legacy_enote_types.cpp
  legacy_enote_utils.cpp
  mock_ledger_context.cpp
  mock_offchain_context.cpp
  sp_composition_proof.cpp
  sp_core_enote_utils.cpp
  sp_core_types.cpp
  sp_crypto_utils.cpp
  sp_multisig_nonce_record.cpp
  sp_generator_factory.cpp
  sp_hash_functions.cpp
  sp_multiexp.cpp
  tx_base.cpp
  tx_binned_reference_set.cpp
  tx_binned_reference_set_utils.cpp
  tx_builder_types.cpp
  tx_builder_types_multisig.cpp
  tx_builders_inputs.cpp
  tx_builders_mixed.cpp
  tx_builders_multisig.cpp
  tx_builders_outputs.cpp
  tx_component_types.cpp
  tx_contextual_enote_record_utils.cpp
  tx_discretized_fee.cpp
  tx_enote_finding_context_mocks.cpp
  tx_enote_record_utils.cpp
  tx_enote_scanning.cpp
  tx_enote_scanning_utils.cpp
  tx_enote_store_mocks.cpp
  tx_enote_store_updater_mocks.cpp
  tx_extra.cpp
  tx_fee_calculator_squashed_v1.cpp
  tx_input_selection.cpp
  tx_input_selection_output_context_v1.cpp
  tx_input_selector_mocks.cpp
  tx_legacy_enote_record_utils.cpp
  tx_misc_utils.cpp
  tx_ref_set_index_mapper_flat.cpp
  tx_validators.cpp
  txtype_squashed_v1.cpp)

monero_find_all_headers(seraphis_headers, "${CMAKE_CURRENT_SOURCE_DIR}")

monero_add_library(seraphis
  ${seraphis_sources}
  ${seraphis_headers})

target_link_libraries(seraphis
  PUBLIC
    cncrypto
    common
    cryptonote_basic
    device
    epee
    multisig
    ringct
  PRIVATE
    ${EXTRA_LIBRARIES})

target_include_directories(seraphis
  PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}"
  PRIVATE
    ${Boost_INCLUDE_DIRS})
