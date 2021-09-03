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

set(seraphis_core_sources
  binned_reference_set.cpp
  binned_reference_set_utils.cpp
  discretized_fee.cpp
  jamtis_address_tag_utils.cpp
  jamtis_address_utils.cpp
  jamtis_core_utils.cpp
  jamtis_destination.cpp
  jamtis_enote_utils.cpp
  jamtis_payment_proposal.cpp
  jamtis_support_types.cpp
  legacy_core_utils.cpp
  legacy_decoy_selector_flat.cpp
  legacy_enote_types.cpp
  legacy_enote_utils.cpp
  sp_core_enote_utils.cpp
  sp_core_types.cpp
  sp_ref_set_index_mapper_flat.cpp
  tx_extra.cpp)

monero_find_all_headers(seraphis_core_headers, "${CMAKE_CURRENT_SOURCE_DIR}")

monero_add_library(seraphis_core
  ${seraphis_core_sources}
  ${seraphis_core_headers})

target_link_libraries(seraphis_core
  PUBLIC
    cncrypto
    common
    cryptonote_basic
    device
    epee
    ringct
    seraphis_crypto
  PRIVATE
    ${EXTRA_LIBRARIES})

target_include_directories(seraphis_core
  PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}"
  PRIVATE
    ${Boost_INCLUDE_DIRS})
