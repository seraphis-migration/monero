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

// NOT FOR PRODUCTION

// Seraphis core types.


#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"

//third party headers
#include <boost/variant/get.hpp>
#include <boost/variant/variant.hpp>

//standard headers

//forward declarations


namespace sp
{

////
// LegacyEnoteV1
// - onetime address
// - cleartext amount
///
struct LegacyEnoteV1 final
{
    /// Ko
    rct::key m_onetime_address;
    /// a
    rct::xmr_amount m_amount;

    static std::size_t get_size_bytes() { return 32 + 8; }

    /**
    * brief: gen() - generate a legacy v1 enote (all random)
    */
    void gen();
};

////
// LegacyEnoteV2
// - onetime address
// - amount commitment
// - encoded amount commitment mask
// - encoded amount (version 1: 32 bytes)
///
struct LegacyEnoteV2 final
{
    /// Ko
    rct::key m_onetime_address;
    /// C
    rct::key m_amount_commitment;
    /// enc(x)
    rct::key m_encoded_amount_blinding_factor;
    /// enc(a)
    rct::key m_encoded_amount;

    static std::size_t get_size_bytes() { return 4*32; }

    /**
    * brief: gen() - generate a legacy v2 enote (all random)
    */
    void gen();
};

////
// LegacyEnoteV3
// - onetime address
// - amount commitment
// - encoded amount (version 2: 8 bytes)
///
struct LegacyEnoteV3 final
{
    /// Ko
    rct::key m_onetime_address;
    /// C
    rct::key m_amount_commitment;
    /// enc(a)
    rct::xmr_amount m_encoded_amount;

    static std::size_t get_size_bytes() { return 2*32 + 8; }

    /**
    * brief: gen() - generate a legacy v3 enote (all random)
    */
    void gen();
};

////
// LegacyEnoteV4
// - onetime address
// - amount commitment
// - encoded amount (version 2: 8 bytes)
// - view tag
///
struct LegacyEnoteV4 final
{
    /// Ko
    rct::key m_onetime_address;
    /// C
    rct::key m_amount_commitment;
    /// enc(a)
    rct::xmr_amount m_encoded_amount;
    /// view_tag
    crypto::view_tag m_view_tag;

    static std::size_t get_size_bytes() { return 2*32 + 8 + sizeof(crypto::view_tag); }

    /**
    * brief: gen() - generate a legacy v4 enote (all random)
    */
    void gen();
};

////
// LegacyEnoteVariant
// - variant of all legacy enote types
///
struct LegacyEnoteVariant final
{
    /// variant of all legacy enote types
    boost::variant<LegacyEnoteV1, LegacyEnoteV2, LegacyEnoteV3, LegacyEnoteV4> m_enote;

    /// constructors
    LegacyEnoteVariant() = default;
    template <typename T>
    LegacyEnoteVariant(const T &enote) : m_enote{enote} {}

    /// get the enote's onetime address
    const rct::key& onetime_address() const;
    /// get the enote's amount commitment
    rct::key amount_commitment() const;

    /// interact with the variant
    template <typename T>
    bool is_type() const { return boost::get<T>(&m_enote) != nullptr; }

    template <typename T>
    const T& get_enote() const { static const T empty{}; return is_type<T>() ? boost::get<T>(m_enote) : empty; }
};

} //namespace sp
