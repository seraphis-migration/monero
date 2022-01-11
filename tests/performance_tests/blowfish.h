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

extern "C"
{
    #include "crypto/blowfish.h"
}
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "performance_tests.h"


struct blowfish_LR
{
    std::uint32_t L;
    std::uint32_t R;
};

/// address id's with blowfish
class test_blowfish_address_id
{
public:
    static const size_t loop_count = 100;
    static const size_t internal_loop_count = 10000;

    bool init()
    {
        // blowfish key
        m_secret_key = rct::skGen();

        // initialize blowfish context
        Blowfish_Init(&m_blowfish_context, m_secret_key.bytes, sizeof(rct::key));

        // copy original id into format desired by blowfish
        blowfish_LR LR;
        memcpy(&LR, &m_original_id, 8);

        // create encrypted id
        Blowfish_Encrypt(&m_blowfish_context, &LR.L, &LR.R);

        // copy encrypted id into proper variable
        memcpy(&m_encrypted_id, &LR, 8);

        return true;
    }

    bool test()
    {
        std::uint64_t decrypted_id;
        blowfish_LR LR;

        for (std::size_t i{0}; i < internal_loop_count; ++i)
        {
            // copy encrypted id into format desired by blowfish
            memcpy(&LR, &m_encrypted_id, 8);

            // decrypt the id
            Blowfish_Decrypt(&m_blowfish_context, &LR.L, &LR.R);

            // copy decrypted id into proper variable
            memcpy(&decrypted_id, &LR, 8);
        }

        return decrypted_id == m_original_id;
    }

private:
    BLOWFISH_CTX m_blowfish_context;

    rct::key m_secret_key;

    std::uint64_t m_original_id{0};
    std::uint64_t m_encrypted_id{};
};

/// setting up blowfish context
class test_blowfish_context_init
{
public:
    static const size_t loop_count = 100;

    bool init()
    {
        // blowfish key
        m_secret_key = rct::skGen();
        return true;
    }

    bool test()
    {
        // initialize blowfish context
        Blowfish_Init(&m_blowfish_context, m_secret_key.bytes, sizeof(rct::key));

        return true;
    }

private:
    BLOWFISH_CTX m_blowfish_context;

    rct::key m_secret_key;
};
