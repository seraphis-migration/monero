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

#include "gtest/gtest.h"

#include "common/base32.h"
#include "crypto/crypto.h"
#include "include_base_utils.h"
#include "string_tools.h"

#include <string>

using namespace tools;
using namespace std;

void do_test_simple()
{
    // a
    std::string test{"a"};
    std::string encoded_test;

    base32::encode(test,encoded_test);

    ASSERT_EQ(encoded_test, "ga");

    std::string recovered_test;
    base32::decode(encoded_test, recovered_test);

    ASSERT_EQ(recovered_test, test);

    // aaaaaa....
    test = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    base32::encode(test,encoded_test);

    ASSERT_EQ(encoded_test, "gskwr0fmgskwr0fmgskwr0fmgskwr0fmgskwr0fmgskwr0fmgskwr0fmgskwr0fmgskwr0fmgskwr0fmgskwr0fmgskwr02");

    base32::decode(encoded_test, recovered_test);

    ASSERT_EQ(recovered_test, test);
}



TEST(base32, encode_decode) 
{
    do_test_simple();
}


