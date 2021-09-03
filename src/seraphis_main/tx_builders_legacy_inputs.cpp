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
#include "tx_builders_legacy_inputs.h"

//local headers
#include "common/container_helpers.h"
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_config.h"
#include "device/device.hpp"
#include "enote_record_types.h"
#include "enote_record_utils.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctSigs.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_enote_utils.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_crypto/sp_hash_functions.h"
#include "seraphis_crypto/sp_transcript.h"
#include "tx_builder_types_legacy.h"
#include "tx_component_types_legacy.h"

//third party headers

//standard headers
#include <algorithm>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void prepare_clsag_proof_keys(const rct::ctkeyV &referenced_enotes,
    const rct::key &masked_commitment,
    rct::keyV &referenced_onetime_addresses_out,
    rct::keyV &referenced_amount_commitments_out,
    rct::keyV &nominal_commitments_to_zero_out)
{
    referenced_onetime_addresses_out.clear();
    referenced_onetime_addresses_out.reserve(referenced_enotes.size());
    referenced_amount_commitments_out.clear();
    referenced_amount_commitments_out.reserve(referenced_enotes.size());
    nominal_commitments_to_zero_out.clear();
    nominal_commitments_to_zero_out.reserve(referenced_enotes.size());

    for (const rct::ctkey &referenced_enote : referenced_enotes)
    {
        referenced_onetime_addresses_out.emplace_back(referenced_enote.dest);
        referenced_amount_commitments_out.emplace_back(referenced_enote.mask);
        rct::subKeys(tools::add_element(nominal_commitments_to_zero_out), referenced_enote.mask, masked_commitment);
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void check_v1_legacy_input_proposal_semantics_v1(const LegacyInputProposalV1 &input_proposal,
    const rct::key &legacy_spend_pubkey)
{
    // 1. the onetime address must be reproducible
    // Ko ?= k_v_stuff + k^s G
    rct::key onetime_address_reproduced{legacy_spend_pubkey};
    mask_key(input_proposal.enote_view_extension, onetime_address_reproduced, onetime_address_reproduced);

    CHECK_AND_ASSERT_THROW_MES(onetime_address_reproduced == input_proposal.onetime_address,
        "legacy input proposal v1 semantics check: could not reproduce the onetime address.");

    // 2. the key image must be canonical (note: legacy key image can't be reproduced in a semantics checker because it
    //    needs the legacy private spend key [assumed not available in semantics checkers])
    CHECK_AND_ASSERT_THROW_MES(key_domain_is_prime_subgroup(rct::ki2rct(input_proposal.key_image)),
        "legacy input proposal v1 semantics check: the key image is not canonical.");

    // 3. the amount commitment must be reproducible
    const rct::key amount_commitment_reproduced{
            rct::commit(input_proposal.amount, rct::sk2rct(input_proposal.amount_blinding_factor))
        };

    CHECK_AND_ASSERT_THROW_MES(amount_commitment_reproduced == input_proposal.amount_commitment,
        "legacy input proposal v1 semantics check: could not reproduce the amount commitment.");

    // 4. the commitment mask must be canonical and > 1
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(input_proposal.commitment_mask)) == 0,
        "legacy input proposal v1 semantics check: invalid commitment mask.");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(input_proposal.commitment_mask)),
        "legacy input proposal v1 semantics check: commitment mask is zero.");
    CHECK_AND_ASSERT_THROW_MES(!(rct::sk2rct(input_proposal.commitment_mask) == rct::identity()),
        "legacy input proposal v1 semantics check: commitment mask is 1.");
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_legacy_input_proposal_v1(const rct::key &onetime_address,
    const rct::key &amount_commitment,
    const crypto::key_image &key_image,
    const crypto::secret_key &enote_view_extension,
    const rct::xmr_amount &input_amount,
    const crypto::secret_key &input_amount_blinding_factor,
    const crypto::secret_key &commitment_mask,
    LegacyInputProposalV1 &proposal_out)
{
    // make an input proposal
    proposal_out.onetime_address        = onetime_address;
    proposal_out.amount_commitment      = amount_commitment;
    proposal_out.key_image              = key_image;
    proposal_out.enote_view_extension   = enote_view_extension;
    proposal_out.amount                 = input_amount;
    proposal_out.amount_blinding_factor = input_amount_blinding_factor;
    proposal_out.commitment_mask        = commitment_mask;
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_legacy_input_proposal_v1(const LegacyEnoteRecord &enote_record,
    const crypto::secret_key &commitment_mask,
    LegacyInputProposalV1 &proposal_out)
{
    // make input proposal from enote record
    make_v1_legacy_input_proposal_v1(onetime_address_ref(enote_record.enote),
        amount_commitment_ref(enote_record.enote),
        enote_record.key_image,
        enote_record.enote_view_extension,
        enote_record.amount,
        enote_record.amount_blinding_factor,
        commitment_mask,
        proposal_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_tx_legacy_ring_signature_message_v1(const rct::key &tx_proposal_message,
    const std::vector<std::uint64_t> &reference_set_indices,
    rct::key &message_out)
{
    // m = H_32(tx proposal message, {reference set indices})
    SpFSTranscript transcript{
            config::HASH_KEY_LEGACY_RING_SIGNATURES_MESSAGE_V1,
            32 + reference_set_indices.size() * 8
        };
    transcript.append("tx_proposal_message", tx_proposal_message);
    transcript.append("reference_set_indices", reference_set_indices);

    sp_hash_to_32(transcript.data(), transcript.size(), message_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v3_legacy_ring_signature(const rct::key &message,
    std::vector<std::uint64_t> reference_set,
    const rct::ctkeyV &referenced_enotes,
    const std::uint64_t real_reference_index,
    const rct::key &masked_commitment,
    const crypto::secret_key &reference_view_privkey,
    const crypto::secret_key &reference_commitment_mask,
    const crypto::secret_key &legacy_spend_privkey,
    hw::device &hwdev,
    LegacyRingSignatureV4 &ring_signature_out)
{
    // make ring signature

    /// checks

    // 1. reference sets
    CHECK_AND_ASSERT_THROW_MES(tools::is_sorted_and_unique(reference_set),
        "make v3 legacy ring signature: reference set indices are not sorted and unique.");
    CHECK_AND_ASSERT_THROW_MES(reference_set.size() == referenced_enotes.size(),
        "make v3 legacy ring signature: reference set indices don't match referenced enotes.");
    CHECK_AND_ASSERT_THROW_MES(real_reference_index < referenced_enotes.size(),
        "make v3 legacy ring signature: real reference index is outside range of referenced enotes.");

    // 2. reference onetime address is reproducible
    rct::key onetime_address_reproduced{rct::scalarmultBase(rct::sk2rct(legacy_spend_privkey))};
    mask_key(reference_view_privkey, onetime_address_reproduced, onetime_address_reproduced);

    CHECK_AND_ASSERT_THROW_MES(onetime_address_reproduced == referenced_enotes[real_reference_index].dest,
        "make v3 legacy ring signature: could not reproduce onetime address.");

    // 3. masked commitment is reproducible
    rct::key masked_commitment_reproduced{referenced_enotes[real_reference_index].mask};
    mask_key(reference_commitment_mask, masked_commitment_reproduced, masked_commitment_reproduced);

    CHECK_AND_ASSERT_THROW_MES(masked_commitment_reproduced == masked_commitment,
        "make v3 legacy ring signature: could not reproduce masked commitment (pseudo-output commitment).");


    /// prepare to make proof

    // 1. prepare proof pubkeys
    rct::keyV referenced_onetime_addresses;
    rct::keyV referenced_amount_commitments;
    rct::keyV nominal_commitments_to_zero;

    prepare_clsag_proof_keys(referenced_enotes,
        masked_commitment,
        referenced_onetime_addresses,
        referenced_amount_commitments,
        nominal_commitments_to_zero);

    // 2. prepare signing key
    crypto::secret_key signing_privkey;
    sc_add(to_bytes(signing_privkey), to_bytes(reference_view_privkey), to_bytes(legacy_spend_privkey));

    // 3. prepare commitment to zero key (negated mask): z
    crypto::secret_key z;
    sc_mul(to_bytes(z), minus_one().bytes, to_bytes(reference_commitment_mask));


    /// make clsag proof
    ring_signature_out.clsag_proof = rct::CLSAG_Gen(message,
        referenced_onetime_addresses,
        rct::sk2rct(signing_privkey),
        nominal_commitments_to_zero,
        rct::sk2rct(z),
        referenced_amount_commitments,
        masked_commitment,
        real_reference_index,
        hwdev);


    /// save the reference set
    ring_signature_out.reference_set = std::move(reference_set);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v3_legacy_ring_signature_v1(LegacyRingSignaturePrepV1 ring_signature_prep,
    const crypto::secret_key &legacy_spend_privkey,
    hw::device &hwdev,
    LegacyRingSignatureV4 &ring_signature_out)
{
    // proof message
    rct::key message;
    make_tx_legacy_ring_signature_message_v1(ring_signature_prep.tx_proposal_prefix,
        ring_signature_prep.reference_set,
        message);

    // complete signature
    make_v3_legacy_ring_signature(message,
        std::move(ring_signature_prep.reference_set),
        ring_signature_prep.referenced_enotes,
        ring_signature_prep.real_reference_index,
        ring_signature_prep.reference_image.masked_commitment,
        ring_signature_prep.reference_view_privkey,
        ring_signature_prep.reference_commitment_mask,
        legacy_spend_privkey,
        hwdev,
        ring_signature_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v3_legacy_ring_signatures_v1(std::vector<LegacyRingSignaturePrepV1> ring_signature_preps,
    const crypto::secret_key &legacy_spend_privkey,
    hw::device &hwdev,
    std::vector<LegacyRingSignatureV4> &ring_signatures_out)
{
    // only allow signatures on the same tx proposal
    for (const LegacyRingSignaturePrepV1 &signature_prep : ring_signature_preps)
    {
        CHECK_AND_ASSERT_THROW_MES(signature_prep.tx_proposal_prefix == ring_signature_preps[0].tx_proposal_prefix,
            "make v3 legacy ring signatures: inconsistent proposal prefixes.");
    }

    // sort ring signature preps
    std::sort(ring_signature_preps.begin(),
        ring_signature_preps.end(),
        tools::compare_func<LegacyRingSignaturePrepV1>(compare_KI));

    // make multiple ring signatures
    ring_signatures_out.clear();
    ring_signatures_out.reserve(ring_signature_preps.size());

    for (LegacyRingSignaturePrepV1 &signature_prep : ring_signature_preps)
    {
        make_v3_legacy_ring_signature_v1(std::move(signature_prep),
            legacy_spend_privkey,
            hwdev,
            tools::add_element(ring_signatures_out));
    }
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_legacy_input_semantics_v1(const LegacyInputV1 &input)
{
    // 1. masked commitment can be reconstructed
    const rct::key masked_commitment_reproduced{
            rct::commit(input.input_amount, rct::sk2rct(input.input_masked_commitment_blinding_factor))
        };

    CHECK_AND_ASSERT_THROW_MES(masked_commitment_reproduced == input.input_image.masked_commitment,
        "legacy input semantics (v1): could not reproduce masked commitment (pseudo-output commitment).");

    // 2. key image is consistent between input image and cached value in the ring signature
    CHECK_AND_ASSERT_THROW_MES(input.input_image.key_image == rct::rct2ki(input.ring_signature.clsag_proof.I),
        "legacy input semantics (v1): key image is not consistent between input image and ring signature.");

    // 3. ring signature reference indices are sorted and unique and match with the cached reference enotes
    CHECK_AND_ASSERT_THROW_MES(tools::is_sorted_and_unique(input.ring_signature.reference_set),
        "legacy input semantics (v1): reference set indices are not sorted and unique.");
    CHECK_AND_ASSERT_THROW_MES(input.ring_signature.reference_set.size() == input.ring_members.size(),
        "legacy input semantics (v1): reference set indices don't match referenced enotes.");

    // 4. ring signature message
    rct::key ring_signature_message;
    make_tx_legacy_ring_signature_message_v1(input.tx_proposal_prefix,
        input.ring_signature.reference_set,
        ring_signature_message);

    // 4. ring signature is valid
    CHECK_AND_ASSERT_THROW_MES(rct::verRctCLSAGSimple(ring_signature_message,
            input.ring_signature.clsag_proof,
            input.ring_members,
            input.input_image.masked_commitment),
        "legacy input semantics (v1): ring signature is invalid.");
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_legacy_input_v1(const rct::key &tx_proposal_prefix,
    const LegacyInputProposalV1 &input_proposal,
    LegacyRingSignatureV4 ring_signature,
    rct::ctkeyV referenced_enotes,
    const rct::key &legacy_spend_pubkey,
    LegacyInputV1 &input_out)
{
    // 1. check input proposal semantics
    check_v1_legacy_input_proposal_semantics_v1(input_proposal, legacy_spend_pubkey);

    // 2. prepare input image
    get_enote_image_v2(input_proposal, input_out.input_image);

    // 3. set remaining legacy input info
    input_out.ring_signature     = std::move(ring_signature);
    input_out.input_amount       = input_proposal.amount;
    sc_add(to_bytes(input_out.input_masked_commitment_blinding_factor),
        to_bytes(input_proposal.commitment_mask),
        to_bytes(input_proposal.amount_blinding_factor));
    input_out.ring_members       = std::move(referenced_enotes);
    input_out.tx_proposal_prefix = tx_proposal_prefix;
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_legacy_input_v1(const rct::key &tx_proposal_prefix,
    const LegacyInputProposalV1 &input_proposal,
    LegacyRingSignaturePrepV1 ring_signature_prep,
    const crypto::secret_key &legacy_spend_privkey,
    hw::device &hwdev,
    LegacyInputV1 &input_out)
{
    // 1. ring signature prep must line up with specified proposal prefix
    CHECK_AND_ASSERT_THROW_MES(tx_proposal_prefix == ring_signature_prep.tx_proposal_prefix,
        "make v1 legacy input: ring signature prep does not have desired proposal prefix.");

    // 2. misc initialization
    rct::ctkeyV referenced_enotes_copy{ring_signature_prep.referenced_enotes};
    const rct::key legacy_spend_pubkey{rct::scalarmultBase(rct::sk2rct(legacy_spend_privkey))};

    // 3. construct ring signature
    LegacyRingSignatureV4 ring_signature;
    make_v3_legacy_ring_signature_v1(std::move(ring_signature_prep), legacy_spend_privkey, hwdev, ring_signature);

    // 4. finish making the input
    make_v1_legacy_input_v1(tx_proposal_prefix,
        input_proposal,
        std::move(ring_signature),
        std::move(referenced_enotes_copy),
        legacy_spend_pubkey,
        input_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_legacy_inputs_v1(const rct::key &tx_proposal_prefix,
    const std::vector<LegacyInputProposalV1> &input_proposals,
    std::vector<LegacyRingSignaturePrepV1> ring_signature_preps,
    const crypto::secret_key &legacy_spend_privkey,
    hw::device &hwdev,
    std::vector<LegacyInputV1> &inputs_out)
{
    // checks
    CHECK_AND_ASSERT_THROW_MES(input_proposals.size() == ring_signature_preps.size(),
        "make v1 legacy inputs: input proposals don't line up with ring signature preps.");

    inputs_out.clear();
    inputs_out.reserve(input_proposals.size());

    // make all inputs
    for (std::size_t input_index{0}; input_index < input_proposals.size(); ++input_index)
    {
        make_v1_legacy_input_v1(tx_proposal_prefix,
            input_proposals[input_index],
            std::move(ring_signature_preps[input_index]),
            legacy_spend_privkey,
            hwdev,
            tools::add_element(inputs_out));
    }
}
//-------------------------------------------------------------------------------------------------------------------
void get_legacy_input_commitment_factors_v1(const std::vector<LegacyInputProposalV1> &input_proposals,
    std::vector<rct::xmr_amount> &input_amounts_out,
    std::vector<crypto::secret_key> &blinding_factors_out)
{
    // use legacy input proposals to get amounts/blinding factors
    input_amounts_out.clear();
    input_amounts_out.reserve(input_proposals.size());
    blinding_factors_out.clear();
    blinding_factors_out.reserve(input_proposals.size());

    for (const LegacyInputProposalV1 &input_proposal : input_proposals)
    {
        // input amount: a
        input_amounts_out.emplace_back(input_proposal.amount);

        // input image amount commitment blinding factor: x" = mask + x
        sc_add(to_bytes(tools::add_element(blinding_factors_out)),
            to_bytes(input_proposal.commitment_mask),          //mask
            to_bytes(input_proposal.amount_blinding_factor));  //x
    }
}
//-------------------------------------------------------------------------------------------------------------------
void get_legacy_input_commitment_factors_v1(const std::vector<LegacyInputV1> &inputs,
    std::vector<rct::xmr_amount> &input_amounts_out,
    std::vector<crypto::secret_key> &blinding_factors_out)
{
    // use legacy inputs to get amounts/blinding factors
    input_amounts_out.clear();
    input_amounts_out.reserve(inputs.size());
    blinding_factors_out.clear();
    blinding_factors_out.reserve(inputs.size());

    for (const LegacyInputV1 &input : inputs)
    {
        // input amount: a
        input_amounts_out.emplace_back(input.input_amount);

        // masked commitment blinding factor: x" = mask + x
        blinding_factors_out.emplace_back(input.input_masked_commitment_blinding_factor);
    }
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
