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

// State machine for scanning a LIFO chain of blocks by incrementally processing chunks of that chain.

#pragma once

//local headers
#include "scan_machine_types.h"

//third party headers

//standard headers

//forward declarations
namespace sp
{
namespace scanning
{
    class ScanContextLedger;
    class ChunkConsumer;
}
}

namespace sp
{
namespace scanning
{

/**
* brief: try_advance_state_machine - advance the scan state machine to the next state
* inoutparam: scan_context_inout -
* inoutparam: chunk_consumer_inout -
* inoutparam: state_inout -
* return: true if the machine was advanced to a new non-terminal state, false if the machine is in a terminal state
*/
bool try_advance_state_machine(ScanContextLedger &scan_context_inout,
    ChunkConsumer &chunk_consumer_inout,
    ScanMachineState &state_inout);

} //namespace scanning
} //namespace sp
