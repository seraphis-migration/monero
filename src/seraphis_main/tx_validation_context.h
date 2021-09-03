// Copyright (c) 2022, The Monero Project
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

// Interface for interacting with a context where a tx should be valid (e.g. a ledger).

#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace sp
{

class TxValidationContext
{
public:
//destructor
    virtual ~TxValidationContext() = default;

//overloaded operators
    /// disable copy/move (this is a pure virtual base class)
    TxValidationContext& operator=(TxValidationContext&&) = delete;

//member functions
    /**
    * brief: cryptonote_key_image_exists - checks if a cryptonote-style key image exists in the validation context
    * param: key_image -
    * return: true/false on check result
    */
    virtual bool cryptonote_key_image_exists(const crypto::key_image &key_image) const = 0;
    /**
    * brief: seraphis_key_image_exists - checks if a seraphis-style key image exists in the validation context
    * param: key_image -
    * return: true/false on check result
    */
    virtual bool seraphis_key_image_exists(const crypto::key_image &key_image) const = 0;
    /**
    * brief: get_reference_set_proof_elements_v1 - gets legacy {KI, C} pairs stored in the validation context
    *   - note: should only return elements that are valid to reference in a tx (e.g. locked elements are invalid)
    * param: indices -
    * outparam: proof_elements_out - {KI, C}
    */
    virtual void get_reference_set_proof_elements_v1(const std::vector<std::uint64_t> &indices,
        rct::ctkeyV &proof_elements_out) const = 0;
    /**
    * brief: get_reference_set_proof_elements_v2 - gets seraphis squashed enotes stored in the validation context
    *   - note: should only return elements that are valid to reference in a tx (e.g. locked elements are invalid)
    * param: indices -
    * outparam: proof_elements_out - {squashed enote}
    */
    virtual void get_reference_set_proof_elements_v2(const std::vector<std::uint64_t> &indices,
        rct::keyV &proof_elements_out) const = 0;
};

} //namespace sp
