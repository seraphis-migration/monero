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

set(seraphis_main_sources
  contextual_enote_record_types.cpp
  contextual_enote_record_utils.cpp
  enote_record_utils.cpp
  enote_record_utils_legacy.cpp
  scan_balance_recovery_utils.cpp
  scan_machine.cpp
  scan_misc_utils.cpp
  sp_knowledge_proof_utils.cpp
  tx_builder_types.cpp
  tx_builder_types_legacy.cpp
  tx_builder_types_multisig.cpp
  tx_builders_inputs.cpp
  tx_builders_legacy_inputs.cpp
  tx_builders_mixed.cpp
  tx_builders_multisig.cpp
  tx_builders_outputs.cpp
  tx_component_types.cpp
  tx_component_types_legacy.cpp
  tx_input_selection.cpp
  tx_validators.cpp
  txtype_base.cpp
  txtype_coinbase_v1.cpp
  txtype_squashed_v1.cpp)

monero_find_all_headers(seraphis_main_headers, "${CMAKE_CURRENT_SOURCE_DIR}")

monero_add_library(seraphis_main
  ${seraphis_main_sources}
  ${seraphis_main_headers})

target_link_libraries(seraphis_main
  PUBLIC
    cncrypto
    common
    cryptonote_basic
    device
    epee
    multisig
    ringct
    seraphis_core
    seraphis_crypto
  PRIVATE
    ${EXTRA_LIBRARIES})

target_include_directories(seraphis_main
  PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}"
  PRIVATE
    ${Boost_INCLUDE_DIRS})
