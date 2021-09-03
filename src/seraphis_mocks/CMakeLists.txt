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

set(seraphis_mocks_sources
  enote_finding_context_mocks.cpp
  enote_store_mock_simple_v1.cpp
  jamtis_mock_keys.cpp
  legacy_mock_keys.cpp
  make_mock_tx.cpp
  mock_ledger_context.cpp
  mock_offchain_context.cpp
  mock_send_receive.cpp
  mock_tx_builders_inputs.cpp
  mock_tx_builders_legacy_inputs.cpp
  mock_tx_builders_outputs.cpp
  scan_chunk_consumer_mocks.cpp
  tx_input_selector_mocks.cpp)

monero_find_all_headers(seraphis_mocks_headers, "${CMAKE_CURRENT_SOURCE_DIR}")

monero_add_library(seraphis_mocks
  ${seraphis_mocks_sources}
  ${seraphis_mocks_headers})

target_link_libraries(seraphis_mocks
  PUBLIC
    cncrypto
    common
    cryptonote_basic
    device
    epee
    ringct
    seraphis_core
    seraphis_crypto
    seraphis_impl
    seraphis_main
  PRIVATE
    ${EXTRA_LIBRARIES})

target_include_directories(seraphis_mocks
  PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}"
  PRIVATE
    ${Boost_INCLUDE_DIRS})
