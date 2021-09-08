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

// Mock tx interface
// NOT FOR PRODUCTION

#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <memory>
#include <type_traits>
#include <vector>

//forward declarations

namespace crypto
{
// type conversions for easier calls to sc_add(), sc_sub()
static inline unsigned char *operator &(crypto::ec_scalar &scalar)
{
    return &reinterpret_cast<unsigned char &>(scalar);
}
static inline const unsigned char *operator &(const crypto::ec_scalar &scalar)
{
    return &reinterpret_cast<const unsigned char &>(scalar);
}
} //namespace crypto


namespace mock_tx
{

// ref set size = n^m
std::size_t ref_set_size_from_decomp(const std::size_t ref_set_decomp_n, const std::size_t ref_set_decomp_m);

////
// given a number of amounts, split them into power-of-2 groups up to 'max num splits' times; e.g. ...
// n = 7, split = 1: [4, 3]
// n = 7, split = 2: [2, 2, 2, 1]
// n = 11, split = 1: [8, 3]
// n = 11, split = 2: [4, 4, 3]
///
std::size_t compute_rangeproof_grouping_size(const std::size_t num_amounts, const std::size_t max_num_splits);

template <typename MockTxType>
struct MockENote
{
    // recommended
    static std::size_t get_size_bytes();
};

template <typename MockTxType>
struct MockENoteImage
{
    // recommended
    static std::size_t get_size_bytes();
};

template <typename MockTxType>
struct MockInput
{
    // recommended
    std::size_t m_amount;

    // convert this input to an e-note-image (recommended)
    MockENoteImage<MockTxType> to_enote_image(const crypto::secret_key &pseudo_blinding_factor) const;
};

template <typename MockTxType>
struct MockDest
{
    /// destination (for creating an e-note to send an amount to someone)

    // recommended
    std::size_t m_amount;

    // convert this destination into an e-note (recommended)
    MockENote<MockTxType> to_enote() const;
};

// check if two commitment sets balance based on a sum to zero
bool balance_check_equality(const rct::keyV &commitment_set1, const rct::keyV &commitment_set2);

// check if input and output amounts balance
template <typename MockTxType>
bool balance_check_in_out_amnts(const std::vector<MockInput<MockTxType>> &inputs_to_spend,
    const std::vector<MockDest<MockTxType>> &destinations)
{
    using boost::multiprecision::uint128_t;
    uint128_t input_sum{0};
    uint128_t output_sum{0};

    for (const auto &input : inputs_to_spend)
        input_sum += input.m_amount;

    for (const auto &dest : destinations)
        output_sum += dest.m_amount;

    return input_sum == output_sum;
}

// create mock inputs
// note: number of inputs implied by size of 'amounts'
template <typename MockTxType>
std::vector<MockInput<MockTxType>> gen_mock_tx_inputs(const std::vector<rct::xmr_amount> &amounts,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m);

// create mock destinations
// note: number of destinations implied by size of 'amounts'
template <typename MockTxType>
std::vector<MockDest<MockTxType>> gen_mock_tx_dests(const std::vector<rct::xmr_amount> &amounts);

// parameter pack for mock tx
template <typename MockTxType>
struct MockTxParamPack {};

// mock transaction interface
template <typename MockTxType>
class MockTx
{
public:
//constructors
    // default constructor
    MockTx() = default;

    // normal constructor: new tx
    MockTx(const std::vector<MockInput<MockTxType>> &inputs_to_spend,
        const std::vector<MockDest<MockTxType>> &destinations,
        const MockTxParamPack<MockTxType> &param_pack)
    {}

    // normal constructor: from existing tx byte blob
    //mock tx doesn't do this

//destructor: default

//member functions
    // validate the transaction
    // - if 'defer_batchable' is set, then batchable validation steps won't be executed
    virtual bool validate(const bool defer_batchable = false) const = 0;

    // get size of tx
    virtual std::size_t get_size_bytes() const = 0;

    //get_tx_byte_blob()

private:
//member variables
};

// validate a set of mock tx
template <typename MockTxType>
bool validate_mock_txs(const std::vector<std::shared_ptr<MockTxType>> &txs_to_validate);

} //namespace mock_tx








