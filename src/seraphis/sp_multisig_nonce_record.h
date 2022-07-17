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

// Record of Musig2-style nonces for multisig signing.


#pragma once

//local headers
#include "crypto/crypto.h"
#include "multisig/multisig_signer_set_filter.h"
#include "ringct/rctTypes.h"

//third party headers
#include <boost/utility/string_ref.hpp>

//standard headers
#include <unordered_map>

//forward declarations
namespace sp { class SpTranscriptBuilder; }


namespace sp
{

////
// Multisig prep struct
// - store multisig participant's MuSig2-style signature opening nonces for an arbitrary base point J
//
// WARNINGS:
// - must only use a 'prep' to make ONE 'partial signature', after that the opening nonce privkeys should be deleted
//   immediately
// - the nonce privkeys are for local storage, only the pubkeys should be transmitted to other multisig participants
// - the user is expected to maintain consistency between the J used to define nonce pubkeys and the J used when signing
///
struct SpMultisigPubNonces final
{
    // signature nonce pubkey: (1/8) * alpha_{1,e}*J
    rct::key signature_nonce_1_pub;
    // signature nonce pubkey: (1/8) * alpha_{2,e}*J
    rct::key signature_nonce_2_pub;

    /// overload operator< for sorting: compare nonce_1 then nonce_2
    bool operator<(const SpMultisigPubNonces &other) const;
    bool operator==(const SpMultisigPubNonces &other) const;

    /// get size in bytes
    static std::size_t get_size_bytes() { return 2*sizeof(rct::key); }
};
inline const boost::string_ref get_container_name(const SpMultisigPubNonces&) { return "SpMultisigPubNonces"; }
void append_to_transcript(const SpMultisigPubNonces &container, SpTranscriptBuilder &transcript_inout);

struct SpMultisigPrep final
{
    // signature nonce privkey: alpha_{1,e}
    crypto::secret_key signature_nonce_1_priv;
    // signature nonce privkey: alpha_{2,e}
    crypto::secret_key signature_nonce_2_priv;
    // signature nonce pubkey: (1/8) * alpha_{1,e}*J
    // signature nonce pubkey: (1/8) * alpha_{2,e}*J
    SpMultisigPubNonces signature_nonces_pub;
};

////
// Multisig nonce record
// - store a multisig participant's nonces for multiple signing attempts
//   - multiple messages to sign
//   - multiple signer groups per message
///
class SpMultisigNonceRecord final
{
public:
//constructors
    /// default constructor
    SpMultisigNonceRecord() = default;
    /// copy constructor: disabled
    SpMultisigNonceRecord(const SpMultisigNonceRecord&) = delete;
    /// move constructor: defaulted
    SpMultisigNonceRecord(SpMultisigNonceRecord&&) = default;
//overloaded operators
    /// copy assignment: disabled
    SpMultisigNonceRecord& operator=(const SpMultisigNonceRecord&) = delete;
    /// move assignment: defaulted
    SpMultisigNonceRecord& operator=(SpMultisigNonceRecord&&) = default;

//member functions
    /// true if there is a nonce record for a given signing scenario
    bool has_record(const rct::key &message, const rct::key &proof_key, const multisig::signer_set_filter &filter) const;
    /// true if successfully added nonces for a given signing scenario
    bool try_add_nonces(const rct::key &message,
        const rct::key &proof_key,
        const multisig::signer_set_filter &filter,
        const SpMultisigPrep &prep);
    /// true if found nonce privkeys for a given signing scenario
    bool try_get_recorded_nonce_privkeys(const rct::key &message,
        const rct::key &proof_key,
        const multisig::signer_set_filter &filter,
        crypto::secret_key &nonce_privkey_1_out,
        crypto::secret_key &nonce_privkey_2_out) const;
    /// true if found nonce pubkeys for a given signing scenario
    bool try_get_recorded_nonce_pubkeys(const rct::key &message,
        const rct::key &proof_key,
        const multisig::signer_set_filter &filter,
        SpMultisigPubNonces &nonce_pubkeys_out) const;
    /// true if removed a record for a given signing scenario
    bool try_remove_record(const rct::key &message, const rct::key &proof_key, const multisig::signer_set_filter &filter);

//member variables
private:
    // [message : [proof key : [filter, nonces]]]
    std::unordered_map<
        rct::key,                                //message to sign
        std::unordered_map<
            rct::key,                            //proof key to be signed
            std::unordered_map<
                multisig::signer_set_filter,     //filter representing a signer group
                SpMultisigPrep                   //nonces
            >
        >
    > m_record;
};

//todo
SpMultisigPrep sp_multisig_init(const rct::key &base_point);

} //namespace sp
