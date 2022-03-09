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

#pragma once

#include "cryptonote_config.h"
#include "ringct/rctTypes.h"

#include <cstdint>
#include <vector>


namespace multisig
{
  /**
  * multisig signer set filter
  * 
  * - a set of multisig signers, represented as bit flags that correspond 1:1 with a list of sorted signer ids
  * - note: must rework implementation if max signers increases
  */
  using signer_set_filter = std::uint16_t;
  static_assert(8*sizeof(signer_set_filter) == config::MULTISIG_MAX_SIGNERS, "");

  /**
  * brief: validate_multisig_signer_set_filter - Check that a signer set is valid.
  *   - Only possible signers are flagged.
  *   - Only 'threshold' number of signers are flagged.
  * param: num_signers - number of participants in multisig (N)
  * param: threshold - threshold of multisig (M)
  * param: filter - a set of multisig signers to test validity of
  * return: true/false on validation result
  */
  bool validate_multisig_signer_set_filter(const std::uint32_t num_signers,
    const std::uint32_t threshold,
    const signer_set_filter filter);
  bool validate_multisig_signer_set_filters(const std::uint32_t num_signers,
    const std::uint32_t threshold,
    const std::vector<signer_set_filter> &sets);
  /**
  * brief: get_multisig_signers_from_set - Filter a signer list using a signer_set_filter.
  * param: signer_list - list of signer ids
  * param: filter - signer set filter
  * outparam: filtered_signers_out - a filtered set of multisig signer ids
  */
  void get_multisig_signers_from_set(const std::vector<rct::key> &signer_list,
    const signer_set_filter filter,
    std::vector<rct::key> &filtered_signers_out);
} //namespace multisig
