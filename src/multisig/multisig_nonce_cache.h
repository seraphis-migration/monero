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

// Caches Musig2-style nonces for multisig signing.

#pragma once

//local headers
#include "crypto/crypto.h"
#include "multisig_signer_set_filter.h"
#include "ringct/rctTypes.h"
#include "seraphis_crypto/sp_transcript.h"

//third party headers
#include <boost/utility/string_ref.hpp>

//standard headers
#include <tuple>
#include <unordered_map>
#include <vector>

//forward declarations
namespace sp { class SpTranscriptBuilder; }

namespace multisig
{

////
// Multisig public nonces
// - store multisig participant's MuSig2-style signature opening nonces for an arbitrary base point J
// - IMPORTANT: these are stored *(1/8) so another person can efficiently mul8 and be confident the result is canonical
//
// WARNINGS:
// - must only use nonces to make ONE 'partial signature', after that the opening nonce privkeys should be deleted
//   immediately
// - the nonce privkeys are for local storage, only the pubkeys should be transmitted to other multisig participants
// - the user is expected to maintain consistency between the J used to define nonce pubkeys and the J used when signing
///
struct MultisigPubNonces final
{
    // signature nonce pubkey: (1/8) * alpha_{1,e}*J
    rct::key signature_nonce_1_pub;
    // signature nonce pubkey: (1/8) * alpha_{2,e}*J
    rct::key signature_nonce_2_pub;
};
inline const boost::string_ref container_name(const MultisigPubNonces&) { return "MultisigPubNonces"; }
void append_to_transcript(const MultisigPubNonces &container, sp::SpTranscriptBuilder &transcript_inout);

/// overload operator< for sorting: compare nonce_1 then nonce_2 (does not need to be constant time)
bool operator<(const MultisigPubNonces &a, const MultisigPubNonces &b);
bool operator==(const MultisigPubNonces &a, const MultisigPubNonces &b);
/// get size in bytes
inline std::size_t multisig_pub_nonces_size_bytes() { return 2*sizeof(rct::key); }

////
// Multisig nonce cache
// - store a multisig signer's signature nonces
// - nonces may be stored for multiple signing attempts on different messages, keys, and for different signer subgroups
//   of which the signer is a member
//
// WARNING: a nonce removed from the cache may still exist in persistent storage (a file somewhere); users should
//          ALWAYS refresh that storage after making a signature and before exposing that signature outside the local
//          context, to avoid a situation where the signature is exported then the local context crashes/closes without
//          updating the nonces in storage; those nonces could be used to make another signature, thereby leaking the
//          local signer's private multisig key material
///
struct MultisigNonces final
{
    // signature nonce privkey: alpha_{1,e}
    crypto::secret_key signature_nonce_1_priv;
    // signature nonce privkey: alpha_{2,e}
    crypto::secret_key signature_nonce_2_priv;
};

class MultisigNonceCache final
{
public:
//constructors
    /// default constructor
    MultisigNonceCache() = default;
    /// import raw nonce data (e.g. from a file)
    MultisigNonceCache(const std::vector<
            std::tuple<rct::key, rct::key, signer_set_filter, MultisigNonces>
        > &raw_nonce_data);
    /// copy constructor: disabled (don't want copies of the nonces floating around)
    MultisigNonceCache(const MultisigNonceCache&) = delete;
    /// move constructor: defaulted
    MultisigNonceCache(MultisigNonceCache&&) = default;
//overloaded operators
    /// copy assignment: disabled (don't want copies of the nonces floating around)
    MultisigNonceCache& operator=(const MultisigNonceCache&) = delete;
    /// move assignment: defaulted
    MultisigNonceCache& operator=(MultisigNonceCache&&) = default;

//member functions
    /// true if there is a nonce record for a given signing scenario
    bool has_record(const rct::key &message, const rct::key &proof_key, const signer_set_filter &filter) const;
    /// true if successfully added nonces for a given signing scenario
    /// note: nonces are generated internally and only exposed by try_get_recorded_nonce_privkeys()
    bool try_add_nonces(const rct::key &message, const rct::key &proof_key, const signer_set_filter &filter);
    /// true if created nonce pubkeys for a given signing scenario on the specified base key J
    bool try_get_nonce_pubkeys_for_base(const rct::key &message,
        const rct::key &proof_key,
        const signer_set_filter &filter,
        const rct::key &pubkey_base,
        MultisigPubNonces &nonce_pubkeys_out) const;
    /// true if found nonce privkeys for a given signing scenario
    bool try_get_recorded_nonce_privkeys(const rct::key &message,
        const rct::key &proof_key,
        const signer_set_filter &filter,
        crypto::secret_key &nonce_privkey_1_out,
        crypto::secret_key &nonce_privkey_2_out) const;
    /// true if successfully removed a record for a given signing scenario
    bool try_remove_record(const rct::key &message, const rct::key &proof_key, const signer_set_filter &filter);
    /// export the nonce data (e.g. to record in a file)
    std::vector<std::tuple<rct::key, rct::key, signer_set_filter, MultisigNonces>> export_data() const;

private:
    /// true if successfully added nonces for a given signing scenario
    bool try_add_nonces_impl(const rct::key &message,
        const rct::key &proof_key,
        const signer_set_filter &filter,
        const MultisigNonces &nonces);

//member variables
    /// [ message : [ proof key : [ filter : nonces ] ] ]
    std::unordered_map<
        rct::key,                   //message to sign
        std::unordered_map<
            rct::key,               //proof key to sign with using multisig
            std::unordered_map<
                signer_set_filter,  //filter representing the signer group that should make this signature
                MultisigNonces      //the local signer's private nonce material for this signing attempt
            >
        >
    > m_cache;
};

} //namespace multisig
