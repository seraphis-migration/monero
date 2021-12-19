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
  concise_grootle.cpp
  mock_ledger_context.cpp
  sp_base_types.cpp
  sp_composition_proof.cpp
  sp_core_utils.cpp
  sp_crypto_utils.cpp
  sp_tx_base.cpp
  sp_tx_builder_types.cpp
  sp_tx_component_types.cpp
  sp_tx_misc_utils.cpp
  sp_tx_utils.cpp
  sp_tx_validators.cpp
  sp_txtype_concise_v1.cpp
  sp_txtype_merge_v1.cpp
  sp_txtype_squashed_v1.cpp)

monero_find_all_headers(seraphis_headers, "${CMAKE_CURRENT_SOURCE_DIR}")

monero_add_library(seraphis
  ${seraphis_sources}
  ${seraphis_headers})

target_link_libraries(seraphis
  PUBLIC
    cncrypto
    common
    device
    epee
    ringct
  PRIVATE
    ${EXTRA_LIBRARIES})

target_include_directories(seraphis
  PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}"
  PRIVATE
    ${Boost_INCLUDE_DIRS})
