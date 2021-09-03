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

//paired header
#include "discretized_fee.h"

//local headers
#include "cryptonote_config.h"
#include "misc_log_ex.h"
#include "seraphis_crypto/sp_transcript.h"

//third party headers

//standard headers
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <utility>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{

/// discretized fee context: set of <encoding, value> pairs
struct DiscretizedFeeContext final
{
    std::vector<discretized_fee_encoding_t> fee_encodings;
    std::vector<std::uint64_t> value_encodings;
    std::unordered_map<discretized_fee_encoding_t, std::uint64_t> mapped_values;
};

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static long double round_down_to_sig_figs(long double value, const std::uint64_t num_sig_figs)
{
    // 1. put value into scientific notation (with each desired significant digit left above the decimal point)
    std::size_t decimal_scale{0};

    while (value >= std::pow(10.0, num_sig_figs))
    {
        value /= 10.0;
        ++decimal_scale;
    }

    // 2. remove digits that have been moved below the decimal
    value = std::round(value);

    // 3. put value back into normal notation
    while (decimal_scale)
    {
        value *= 10.0;
        --decimal_scale;
    }

    return value;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static DiscretizedFeeContext generate_discretized_fee_context(const long double fee_level_factor,
    const std::uint64_t fee_sig_figs)
{
    CHECK_AND_ASSERT_THROW_MES(fee_level_factor > 0.01 && fee_sig_figs > 0,
        "generate seraphis discretized fees: invalid config.");

    DiscretizedFeeContext fee_context;
    fee_context.fee_encodings.reserve(
            (std::log(std::numeric_limits<std::uint64_t>::max()) / std::log(fee_level_factor)) + 10
        );
    fee_context.value_encodings.reserve(fee_context.fee_encodings.capacity());

    // 1. special encoding: 0
    fee_context.fee_encodings.emplace_back(0);
    fee_context.value_encodings.emplace_back(0);
    fee_context.mapped_values[fee_context.fee_encodings.back()] = fee_context.value_encodings.back();

    // 2. collect powers of the fee level factor (e.g. powers of 1.5, powers of 2, etc.)
    static_assert(sizeof(discretized_fee_encoding_t) <= sizeof(std::size_t), "");
    const std::size_t recorded_levels_offset(fee_context.fee_encodings.size());
    const std::size_t max_level_allowed{
            std::numeric_limits<discretized_fee_encoding_t>::max() - recorded_levels_offset - 2
        };
    std::size_t current_level{0};
    std::uint64_t prev_fee_value{static_cast<std::uint64_t>(-1)};
    std::uint64_t fee_value;

    do
    {
        CHECK_AND_ASSERT_THROW_MES(current_level <= max_level_allowed,
            "generate seraphis discretized fees: invalid config (too many fee levels).");

        // a. value = factor ^ level -> crop digits below specified number of significant digits
        fee_value = static_cast<std::uint64_t>(
                round_down_to_sig_figs(std::pow(fee_level_factor, current_level), fee_sig_figs)
            );

        // b. skip if we already have this value (i.e. because we got the same fee value due to rounding)
        if (fee_value == prev_fee_value)
            continue;

        // c. save fee level and value
        fee_context.fee_encodings.emplace_back(
                static_cast<discretized_fee_encoding_t>(current_level + recorded_levels_offset)
            );
        fee_context.value_encodings.emplace_back(fee_value);
        fee_context.mapped_values[fee_context.fee_encodings.back()] = fee_context.value_encodings.back();
        prev_fee_value = fee_value;

        // d. increase the fee level and check the termination condition
        // note: increment within the condition expression in case 'continue' was called
    } while (round_down_to_sig_figs(std::pow(fee_level_factor, ++current_level), fee_sig_figs) <
        static_cast<long double>(std::numeric_limits<std::uint64_t>::max()));

    // 3. special encoding: uint64::max
    fee_context.fee_encodings.emplace_back(
            static_cast<discretized_fee_encoding_t>(current_level + recorded_levels_offset)
        );
    fee_context.value_encodings.emplace_back(std::numeric_limits<std::uint64_t>::max());
    fee_context.mapped_values[fee_context.fee_encodings.back()] = fee_context.value_encodings.back();

    // 4. special encoding: invalid
    // - all remaining levels are invalid (there should be at least one)
    CHECK_AND_ASSERT_THROW_MES(fee_context.mapped_values.find(std::numeric_limits<discretized_fee_encoding_t>::max()) ==
            fee_context.mapped_values.end(),
        "generate seraphis discretized fees: invalid discretized maps, there is no 'invalid fee' encoding.");

    return fee_context;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::size_t num_encodings(const DiscretizedFeeContext &fee_context)
{
    CHECK_AND_ASSERT_THROW_MES(fee_context.fee_encodings.size() == fee_context.value_encodings.size(),
        "seraphis discretized fee context num encodings: invalid context.");
    CHECK_AND_ASSERT_THROW_MES(fee_context.fee_encodings.size() == fee_context.mapped_values.size(),
        "seraphis discretized fee context num encodings: invalid context.");

    return fee_context.fee_encodings.size();
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static DiscretizedFee discretize_fee(const DiscretizedFeeContext &fee_context, const rct::xmr_amount raw_fee_value)
{
    // find the closest discretized fee that is >= the specified fee value

    // 1. start with the highest fee level (should be invalid)
    discretized_fee_encoding_t fee_encoding = std::numeric_limits<discretized_fee_encoding_t>::max();

    // 2. start with the max discretized fee value, so we can reduce it as we get closer to the final solution
    std::uint64_t closest_discretized_fee_value{static_cast<std::uint64_t>(-1)};

    // 3. search the fees for the closest encoded fee value >= our raw fee value
    for (std::size_t encoding_index{0}; encoding_index < num_encodings(fee_context); ++encoding_index)
    {
        // a. check if this encoding value is below our raw fee value
        if (fee_context.value_encodings[encoding_index] < raw_fee_value)
            continue;

        // b. check if this encoding value is closer to our raw fee value than the previous saved encoding
        if (fee_context.value_encodings[encoding_index] <= closest_discretized_fee_value)
        {
            fee_encoding = fee_context.fee_encodings[encoding_index];
            closest_discretized_fee_value = fee_context.value_encodings[encoding_index];
        }
    }

    return DiscretizedFee{fee_encoding};
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_get_fee_value(const DiscretizedFeeContext &fee_context,
    const DiscretizedFee discretized_fee,
    std::uint64_t &fee_value_out)
{
    // try to find the discretized fee in the map and return its fee value
    const auto found_fee = fee_context.mapped_values.find(discretized_fee.fee_encoding);
    if (found_fee == fee_context.mapped_values.end())
        return false;

    fee_value_out = found_fee->second;
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static const DiscretizedFeeContext& default_fee_context()
{
    static const DiscretizedFeeContext fee_context{
        generate_discretized_fee_context(
                config::DISCRETIZED_FEE_LEVEL_NUMERATOR_X100 / 100.0,
                config::DISCRETIZED_FEE_SIG_FIGS
            )
        };
    return fee_context;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const DiscretizedFee container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("fee_encoding", container.fee_encoding);
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const DiscretizedFee a, const DiscretizedFee b)
{
    return a.fee_encoding == b.fee_encoding;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const DiscretizedFee fee, const discretized_fee_encoding_t fee_level)
{
    return fee.fee_encoding == fee_level;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const discretized_fee_encoding_t fee_level, const DiscretizedFee fee)
{
    return fee_level == fee.fee_encoding;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const DiscretizedFee fee, const rct::xmr_amount raw_fee_value)
{
    rct::xmr_amount fee_value;
    CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(fee, fee_value),
        "seraphis discretized fee equality check with a raw fee failed: the discretized fee is an invalid encoding.");

    return fee_value == raw_fee_value;
}
//-------------------------------------------------------------------------------------------------------------------
DiscretizedFee discretize_fee(const rct::xmr_amount raw_fee_value)
{
    return discretize_fee(default_fee_context(), raw_fee_value);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_fee_value(const DiscretizedFee discretized_fee, std::uint64_t &fee_value_out)
{
    return try_get_fee_value(default_fee_context(), discretized_fee, fee_value_out);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
