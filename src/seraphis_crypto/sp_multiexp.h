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

// Utilities for performing multiexponentiations.

#pragma once

//local headers
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "ringct/multiexp.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

//third party headers
#include <boost/optional/optional.hpp>

//standard headers
#include <list>
#include <vector>

//forward declarations


namespace sp
{

////
// SpMultiexpBuilder
// - collect data points for a multiexponentiation
// - all data points added to the builder are weighted by some factor w
// - for efficiency, pre-defined generators are provided
// - multiexp stored: w * (a G + b_0 G_0 + ... + b_n G_n + c_0 P_0 + ... + c_m P_m)
//   - G, H, X, U: ed25519 generators
//   - G_0..G_n: generators defined in 'generator_factory' namespace
//   - P_0..P_m: user-defined base points
///
class SpMultiexpBuilder final
{
    friend class SpMultiexp;

public:
//constructors
    /// normal constructor
    /// - define a non-zero weight to apply to all elements
    ///   - use identity if this builder won't be merged with other builders
    SpMultiexpBuilder(const rct::key &weight,
        const std::size_t estimated_num_predefined_generator_elements,
        const std::size_t estimated_num_user_defined_elements);

//member functions
    void add_G_element(rct::key scalar);
    void add_H_element(rct::key scalar);
    void add_X_element(rct::key scalar);
    void add_U_element(rct::key scalar);
    void add_element_at_generator_index(rct::key scalar, const std::size_t predef_generator_index);
    void add_element(rct::key scalar, const ge_p3 &base_point);
    void add_element(const rct::key &scalar, const rct::key &base_point);
    void add_element(const rct::key &scalar, const crypto::public_key &base_point);

//member variables
protected:
    /// ed25519 generator scalar
    boost::optional<rct::key> m_G_scalar;
    /// Pedersen commitment generator scalar
    boost::optional<rct::key> m_H_scalar;
    /// seraphis spend key extension generator scalar
    boost::optional<rct::key> m_X_scalar;
    /// seraphis spend key generator scalar
    boost::optional<rct::key> m_U_scalar;
    /// pre-defined generators scalars
    std::vector<rct::key> m_predef_scalars;
    /// user-defined [scalar, base point] pairs
    std::vector<rct::MultiexpData> m_user_def_elements;

private:
    /// element weight
    boost::optional<rct::key> m_weight;
};

////
// SpMultiexp
// - use a set of multiexp builders to perform a multiexponentiation, then store the result
///
class SpMultiexp final
{
public:
//constructors
    SpMultiexp(const std::list<SpMultiexpBuilder> &multiexp_builders);

//member functions
    bool evaluates_to_point_at_infinity() const;
    void get_result(rct::key &result) const;
    void get_result_p3(ge_p3 &result) const;

//member variables
private:
    ge_p3 m_result;
};

} //namespace sp
