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

// Seraphis tx validator implementations
// NOT FOR PRODUCTION

#pragma once

//local headers

//third party headers

//standard headers

//forward declarations


namespace sp
{


struct DefaultSemanticConfig final {};

struct SemanticConfigComponentCountsV1 final
{
    std::size_t m_min_inputs;
    std::size_t m_max_inputs;
    std::size_t m_min_outputs;
    std::size_t m_max_outputs;
    bool m_two_out_one_ephemeral_key;
};

struct SemanticConfigRefSetSizeV1 final
{
    std::size_t m_decom_n_min;
    std::size_t m_decom_n_max;
    std::size_t m_decom_m_min;
    std::size_t m_decom_m_max;
};

template <typename SpTxType>
SemanticConfigComponentCountsV1 semantic_config_component_counts_v1(const unsigned char tx_semantic_rules_version);

template <typename SpTxType>
SemanticConfigRefSetSizeV1 semantic_config_ref_set_size_v1(const unsigned char tx_semantic_rules_version);

template <typename SpTxType>
DefaultSemanticConfig semantic_config_input_images_v1(const unsigned char tx_semantic_rules_version)
{
    return DefaultSemanticConfig{};
}

template <typename SpTxType>
DefaultSemanticConfig semantic_config_sorting_v1(const unsigned char tx_semantic_rules_version)
{
    return DefaultSemanticConfig{};
}


} //namespace sp
