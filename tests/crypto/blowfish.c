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
// 
// Parts of this file are originally copyright (c) 1997 Paul Kocher

#include "crypto/blowfish.h"

#include <stdbool.h>
#include <stdint.h>

bool check_blowfish_block(uint8_t *key,
    unsigned int key_length,
    uint32_t L_enc,
    uint32_t R_enc,
    uint32_t L_expected,
    uint32_t R_expected)
{
  uint32_t L_temp = L_expected, R_temp = R_expected;

  // initialize the blowfish context
  BLOWFISH_CTX ctx;
  Blowfish_Init(&ctx, key, key_length);

  // encrypt the test values
  Blowfish_Encrypt(&ctx, &L_temp, &R_temp);
  if (!(L_temp == L_enc && R_temp == R_enc))
      return false;

  // decrypt the test encryption values
  Blowfish_Decrypt(&ctx, &L_temp, &R_temp);
  if (!(L_temp == L_expected && R_temp == R_expected))
      return false;

  return true;
}

bool blowfish_test(void)
{
    const char test_key[] = "TESTKEY";
    return check_blowfish_block((uint8_t *)test_key, 7, 0xDF333FD2L, 0x30A71BB4L, 1, 2);
}
