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

// Core types for making enotes with Jamtis addresses
// - Jamtis is a specification for Seraphis-compatible addresses


#pragma once

//local headers
#include "jamtis_address_tags.h"
#include "jamtis_destination.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace sp
{
namespace jamtis
{

/// normal proposal type, used to define enote-construction procedure for normal proposals
enum class JamtisPlainType : public address_tag_MAC_t
{
    PLAIN = 0
};

/// self-send proposal type, used to define enote-construction procedure for self-sends
enum class JamtisSelfSendType : public address_tag_MAC_t
{
    CHANGE = 0,
    SELF_SPEND = 1
};

////
// JamtisPaymentProposalV1
// - for creating an output proposal to send an amount to someone
// - JamtisPlainType::PLAIN (implicit)
///
struct JamtisPaymentProposalV1 final
{
    /// user address
    JamtisDestinationV1 m_destination;

    /// b
    rct::xmr_amount m_amount;

    /// enote ephemeral privkey: r
    crypto::secret_key m_enote_ephemeral_privkey;
    ///TODO: misc memo

    /**
    * brief: get_output_proposal_v1 - convert this proposal to a concrete output proposal
    * outparam: output_proposal_out -
    */
    void get_output_proposal_v1(SpOutputProposalV1 &output_proposal_out) const;

    /**
    * brief: gen - generate a random proposal
    * param: amount -
    */
    void gen(const rct::xmr_amount amount);
};

////
// JamtisPaymentProposalSelfSendV1
// - for creating an output proposal to send an amount to the tx author
///
struct JamtisPaymentProposalSelfSendV1 final
{
    /// user address
    JamtisDestinationV1 m_destination;

    /// b
    rct::xmr_amount m_amount;

    /// type
    JamtisSelfSendType m_type;
    /// enote ephemeral privkey: r
    crypto::secret_key m_enote_ephemeral_privkey;
    /// view-balance privkey: k_vb
    crypto::secret_key m_viewbalance_privkey;
    ///TODO: misc memo suggestion (fields to add to memo)

    /**
    * brief: get_output_proposal_v1 - convert this proposal to a concrete output proposal
    * outparam: output_proposal_out -
    */
    void get_output_proposal_v1(SpOutputProposalV1 &output_proposal_out) const;

    /**
    * brief: gen - generate a random proposal
    * param: amount -
    */
    void gen(const rct::xmr_amount amount, const JamtisSelfSendType type);
};

} //namespace jamtis
} //namespace sp
