// Copyright (c) 2023, The Monero Project
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
#include "sp_knowledge_proof_utils.h"

//local headers
#include "common/container_helpers.h"
#include "crypto/crypto.h"
#include "crypto/generators.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_address_utils.h"
#include "seraphis_core/jamtis_core_utils.h"
#include "seraphis_core/jamtis_enote_utils.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_core/sp_core_enote_utils.h"
#include "seraphis_core/sp_core_types.h"
#include "seraphis_crypto/matrix_proof.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_crypto/sp_hash_functions.h"
#include "seraphis_crypto/sp_transcript.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/enote_record_types.h"
#include "seraphis_main/sp_knowledge_proof_types.h"
#include "seraphis_main/tx_component_types.h"
#include "seraphis_main/tx_validation_context.h"

//third party headers
#include <boost/multiprecision/cpp_int.hpp>

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
namespace knowledge_proofs
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_address_ownership_proof_k_g_offset(const rct::key &K, crypto::secret_key &offset)
{
    // H_n(K)
    SpFSTranscript transcript{
            config::HASH_KEY_SERAPHIS_ADDRESS_OWNERSHIP_PROOF_OFFSET_V1,
            sizeof(rct::key),
        };
    transcript.append("K", K);

    sp_hash_to_scalar(transcript.data(), transcript.size(),to_bytes(offset));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_enote_key_image_proof_message_v1(const rct::key &onetime_address,
    const crypto::key_image &KI,
    rct::key &message_out)
{
    // H_32(Ko, KI)
    SpFSTranscript transcript{
            config::HASH_KEY_SERAPHIS_ENOTE_KEY_IMAGE_PROOF_MESSAGE_V1,
            2*sizeof(rct::key),
        };
    transcript.append("Ko", onetime_address);
    transcript.append("KI", KI);

    sp_hash_to_32(transcript.data(), transcript.size(), message_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_enote_unspent_proof_message_v1(const rct::key &onetime_address,
    const crypto::key_image &KI,
    rct::key &message_out)
{
    // H_32(Ko, KI)
    SpFSTranscript transcript{
            config::HASH_KEY_SERAPHIS_ENOTE_UNSPENT_PROOF_MESSAGE_V1,
            2*sizeof(rct::key),
        };
    transcript.append("Ko", onetime_address);
    transcript.append("KI", KI);

    sp_hash_to_32(transcript.data(), transcript.size(), message_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void make_address_ownership_proof_v1(const rct::key &message,
    const rct::key &address,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z,
    AddressOwnershipProofV1 &proof_out)
{
    // 1. k_g_offset = H_n(K)
    crypto::secret_key k_g_offset;
    make_address_ownership_proof_k_g_offset(address, k_g_offset);

    // 2. K" = k_g_offset G + K
    // note: we add an offset in case x == 0 (e.g. if K == K_s)
    rct::key masked_address;
    mask_key(k_g_offset, address, masked_address);

    // 3. x" = k_g_offset + x
    crypto::secret_key x_factor;
    sc_add(to_bytes(x_factor), to_bytes(k_g_offset), to_bytes(x)); 

    // 4. make a composition proof on the masked address
    SpCompositionProof proof;
    make_sp_composition_proof(message, masked_address, x_factor, y, z, proof);

    // 5. prepare the address's 'key image'
    crypto::key_image addr_key_image;
    make_seraphis_key_image(y,z,addr_key_image); 

    // 6. assemble the full proof
    proof_out = AddressOwnershipProofV1{
            .message           = message,
            .K                 = address,
            .addr_key_image    = addr_key_image,
            .composition_proof = proof
        };
}
//-------------------------------------------------------------------------------------------------------------------
void make_address_ownership_proof_v1(const rct::key &message,
    const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_view_balance,
    AddressOwnershipProofV1 &proof_out)
{
    // for address ownership of K_s

    // 1. prepare K_s = k_vb X + k_m U
    rct::key jamtis_spend_pubkey;
    make_seraphis_spendkey(k_view_balance, sp_spend_privkey, jamtis_spend_pubkey);

    // 2. finish the proof
    make_address_ownership_proof_v1(message,
        jamtis_spend_pubkey,
        rct::rct2sk(rct::zero()),
        k_view_balance,
        sp_spend_privkey,
        proof_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_address_ownership_proof_v1(const rct::key &message,
    const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_view_balance,
    const jamtis::address_index_t &j,
    AddressOwnershipProofV1 &proof_out)
{
    // for address ownership of K_1

    // 1. prepare privkey
    crypto::secret_key s_generate_address;
    jamtis::make_jamtis_generateaddress_secret(k_view_balance, s_generate_address);

    // 2. prepare K_s = k_vb X + k_m U
    rct::key jamtis_spend_pubkey;
    make_seraphis_spendkey(k_view_balance, sp_spend_privkey, jamtis_spend_pubkey);

    // 3. prepare address privkey components
    // a. x = k^j_g
    crypto::secret_key x;
    jamtis::make_jamtis_spendkey_extension_g(jamtis_spend_pubkey, s_generate_address, j, x);  //k^j_g

    // b. y = k^j_x + k_vb
    crypto::secret_key y;
    jamtis::make_jamtis_spendkey_extension_x(jamtis_spend_pubkey, s_generate_address, j, y);  //k^j_x
    sc_add(to_bytes(y), to_bytes(k_view_balance), to_bytes(y));  //+ k_vb

    // c. z = k^j_u + k_m
    crypto::secret_key z;
    jamtis::make_jamtis_spendkey_extension_u(jamtis_spend_pubkey, s_generate_address, j, z);  //k^j_u
    sc_add(to_bytes(z), to_bytes(sp_spend_privkey), to_bytes(z));  //+ k_m

    // 4. compute address
    // K_1 = x G + y X + z U
    rct::key jamtis_address_spend_key;
    make_seraphis_spendkey(y, z, jamtis_address_spend_key);  //y X + z U
    mask_key(x, jamtis_address_spend_key, jamtis_address_spend_key);  //+ x G

    // 5. finish the proof
    make_address_ownership_proof_v1(message, jamtis_address_spend_key, x, y, z, proof_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool verify_address_ownership_proof_v1(const AddressOwnershipProofV1 &proof,
    const rct::key &expected_message,
    const rct::key &expected_address)
{
    // 1. check the expected message
    if (!(proof.message == expected_message))
        return false;

    // 2. check the expected address
    if (!(proof.K == expected_address))
        return false;

    // 3. k_g_offset
    crypto::secret_key k_g_offset;
    make_address_ownership_proof_k_g_offset(proof.K, k_g_offset);

    // 4. K" = k_g_offset G + K
    rct::key masked_address;
    mask_key(k_g_offset, proof.K, masked_address);

    // 5. verify the composition proof
    if (!verify_sp_composition_proof(proof.composition_proof, proof.message, masked_address, proof.addr_key_image))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void make_address_index_proof_v1(const rct::key &jamtis_spend_pubkey,
    const jamtis::address_index_t &j,
    const crypto::secret_key &s_generate_address,
    AddressIndexProofV1 &proof_out)
{
    // 1. prepare the address index extension generator
    crypto::secret_key generator;
    jamtis::make_jamtis_index_extension_generator(s_generate_address, j, generator);

    // 2. compute K_1
    rct::key K_1;
    jamtis::make_jamtis_address_spend_key(jamtis_spend_pubkey, s_generate_address, j, K_1);

    // 3. assemble the full proof
    proof_out = AddressIndexProofV1{
            .K_s       = jamtis_spend_pubkey,
            .j         = j,
            .generator = rct::sk2rct(generator),
            .K_1       = K_1
        };
}
//-------------------------------------------------------------------------------------------------------------------
bool verify_address_index_proof_v1(const AddressIndexProofV1 &proof, const rct::key &expected_address)
{
    // 1. check the proof matches the expected address
    if (!(proof.K_1 == expected_address))
        return false;

    // 2. reproduce the address index extensions
    // a. k^j_u
    crypto::secret_key address_extension_key_u;
    make_jamtis_spendkey_extension(config::HASH_KEY_JAMTIS_SPENDKEY_EXTENSION_U,
        proof.K_s,
        proof.j,
        rct::rct2sk(proof.generator),
        address_extension_key_u);

    // b. k^j_x
    crypto::secret_key address_extension_key_x;
    make_jamtis_spendkey_extension(config::HASH_KEY_JAMTIS_SPENDKEY_EXTENSION_X,
        proof.K_s,
        proof.j,
        rct::rct2sk(proof.generator),
        address_extension_key_x);

    // c. k^j_g
    crypto::secret_key address_extension_key_g;
    make_jamtis_spendkey_extension(config::HASH_KEY_JAMTIS_SPENDKEY_EXTENSION_G,
        proof.K_s,
        proof.j,
        rct::rct2sk(proof.generator),
        address_extension_key_g);

    // 3. compute the nominal address spendkey
    // K_1 = k^j_g G + k^j_x X + k^j_u U + K_s
    rct::key nominal_address{proof.K_s};  //K_s
    extend_seraphis_spendkey_u(address_extension_key_u, nominal_address);  //k^j_u U + K_s
    extend_seraphis_spendkey_x(address_extension_key_x, nominal_address);  //k^j_x X + k^j_u U + K_s
    mask_key(address_extension_key_g, nominal_address, nominal_address);   //k^j_g G + k^j_x X + k^j_u U + K_s

    // 4. check that the proof address spendkey was recreated
    if (!(nominal_address == proof.K_1))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void make_enote_ownership_proof_v1(const rct::key &jamtis_address_spend_key,
    const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    const rct::key &onetime_address,
    EnoteOwnershipProofV1 &proof_out)
{
    proof_out = EnoteOwnershipProofV1{
            .K_1 = jamtis_address_spend_key,
            .q   = sender_receiver_secret,
            .C   = amount_commitment,
            .Ko  = onetime_address
        };
}
//-------------------------------------------------------------------------------------------------------------------
void make_enote_ownership_proof_v1_sender_plain(const crypto::x25519_secret_key &enote_ephemeral_privkey,
    const jamtis::JamtisDestinationV1 &recipient_destination,
    const rct::key &input_context,
    const rct::key &amount_commitment,
    const rct::key &onetime_address,
    EnoteOwnershipProofV1 &proof_out)
{
    // 1. compute the enote ephemeral pubkey
    crypto::x25519_pubkey enote_ephemeral_pubkey;
    jamtis::make_jamtis_enote_ephemeral_pubkey(enote_ephemeral_privkey,
        recipient_destination.addr_K3,
        enote_ephemeral_pubkey);

    // 2. prepare the sender-receiver secret
    rct::key sender_receiver_secret;
    jamtis::make_jamtis_sender_receiver_secret_plain(enote_ephemeral_privkey,
        recipient_destination.addr_K2,
        enote_ephemeral_pubkey,
        input_context,
        sender_receiver_secret);

    // 3. complete the proof
    make_enote_ownership_proof_v1(recipient_destination.addr_K1,
        sender_receiver_secret,
        amount_commitment,
        onetime_address,
        proof_out);

    // 4. verify that the proof was created successfully
    // - will fail if the enote is a jamtis selfsend type
    CHECK_AND_ASSERT_THROW_MES(verify_enote_ownership_proof_v1(proof_out, amount_commitment, onetime_address),
        "make enote ownership proof (v1 sender plain): failed to make proof.");
}
//-------------------------------------------------------------------------------------------------------------------
void make_enote_ownership_proof_v1_sender_selfsend(const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &jamtis_address_spend_key,
    const rct::key &input_context,
    const crypto::secret_key &k_view_balance,
    const jamtis::JamtisSelfSendType self_send_type,
    const rct::key &amount_commitment,
    const rct::key &onetime_address,
    EnoteOwnershipProofV1 &proof_out)
{
    // 1. prepare the sender-receiver secret
    rct::key sender_receiver_secret;
    jamtis::make_jamtis_sender_receiver_secret_selfsend(k_view_balance,
        enote_ephemeral_pubkey,
        input_context,
        self_send_type,
        sender_receiver_secret);

    // 2. complete the proof
    make_enote_ownership_proof_v1(jamtis_address_spend_key,
        sender_receiver_secret,
        amount_commitment,
        onetime_address,
        proof_out);

    // 3. verify that the proof was created successfully
    // - will fail if the enote is a jamtis plain type
    CHECK_AND_ASSERT_THROW_MES(verify_enote_ownership_proof_v1(proof_out, amount_commitment, onetime_address),
        "make enote ownership proof (v1 sender selfsend): failed to make proof.");
}
//-------------------------------------------------------------------------------------------------------------------
void make_enote_ownership_proof_v1_receiver(const SpEnoteRecordV1 &enote_record,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    EnoteOwnershipProofV1 &proof_out)
{
    // 1. helper privkeys
    crypto::x25519_secret_key xk_find_received;
    crypto::secret_key s_generate_address;
    jamtis::make_jamtis_findreceived_key(k_view_balance, xk_find_received);
    jamtis::make_jamtis_generateaddress_secret(k_view_balance, s_generate_address);

    // 2. get the owning address's spendkey K_1
    rct::key jamtis_address_spend_key;
    jamtis::make_jamtis_address_spend_key(jamtis_spend_pubkey,
        s_generate_address,
        enote_record.address_index,
        jamtis_address_spend_key);

    // 3. prepare the sender-receiver secret
    rct::key sender_receiver_secret;
    jamtis::JamtisSelfSendType self_send_type;

    if (jamtis::try_get_jamtis_self_send_type(enote_record.type, self_send_type))
    {
        jamtis::make_jamtis_sender_receiver_secret_selfsend(k_view_balance,
            enote_record.enote_ephemeral_pubkey,
            enote_record.input_context,
            self_send_type,
            sender_receiver_secret);
    }
    else
    {
        jamtis::make_jamtis_sender_receiver_secret_plain(xk_find_received,
            enote_record.enote_ephemeral_pubkey,
            enote_record.enote_ephemeral_pubkey,
            enote_record.input_context,
            sender_receiver_secret);
    }

    // 4. complete the proof
    make_enote_ownership_proof_v1(jamtis_address_spend_key,
        sender_receiver_secret,
        amount_commitment_ref(enote_record.enote),
        onetime_address_ref(enote_record.enote),
        proof_out);

    // 5. verify that the proof was created successfully
    CHECK_AND_ASSERT_THROW_MES(verify_enote_ownership_proof_v1(proof_out,
            amount_commitment_ref(enote_record.enote),
            onetime_address_ref(enote_record.enote)),
        "make enote ownership proof (v1 recipient): failed to make proof.");
}
//-------------------------------------------------------------------------------------------------------------------
bool verify_enote_ownership_proof_v1(const EnoteOwnershipProofV1 &proof,
    const rct::key &expected_amount_commitment,
    const rct::key &expected_onetime_address)
{
    // 1. check the proof matches with the expected enote
    if (!(proof.C == expected_amount_commitment))
        return false;
    if (!(proof.Ko == expected_onetime_address))
        return false;

    // 2. reproduce the onetime address
    rct::key reproduced_Ko;
    jamtis::make_jamtis_onetime_address(proof.K_1, proof.q, proof.C, reproduced_Ko);

    // 3. check the reproduced onetime address matches the proof
    if (!(proof.Ko == reproduced_Ko))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void make_enote_amount_proof_v1(const rct::xmr_amount &amount,
    const crypto::secret_key &mask,
    const rct::key &commitment,
    EnoteAmountProofV1 &proof_out)
{
    proof_out = EnoteAmountProofV1{
            .a = amount,
            .x = rct::sk2rct(mask),
            .C = commitment
        };
}
//-------------------------------------------------------------------------------------------------------------------
bool verify_enote_amount_proof_v1(const EnoteAmountProofV1 &proof, const rct::key &expected_commitment)
{
    // 1. check the proof matches the expected amount commitment
    if (!(proof.C == expected_commitment))
        return false;

    // 2. check the commitment can be reproduced
    if (!(proof.C == rct::commit(proof.a, proof.x)))
        return false;;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void make_enote_key_image_proof_v1(const rct::key &onetime_address,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z,
    EnoteKeyImageProofV1 &proof_out)
{
    // 1. prepare KI
    crypto::key_image KI;
    make_seraphis_key_image(y, z, KI); 

    // 2. prepare the message to sign
    rct::key message;
    make_enote_key_image_proof_message_v1(onetime_address, KI, message);

    // 3. create the composition proof
    SpCompositionProof composition_proof;
    make_sp_composition_proof(message, onetime_address, x, y, z, composition_proof);

    // 4. assemble the full proof
    proof_out = EnoteKeyImageProofV1{
            .Ko                = onetime_address,
            .KI                = KI,
            .composition_proof = composition_proof
        };
}
//-------------------------------------------------------------------------------------------------------------------
void make_enote_key_image_proof_v1(const SpEnoteRecordV1 &enote_record,
    const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_view_balance,
    EnoteKeyImageProofV1 &proof_out)
{
    // 1. y = k_x + k_vb
    crypto::secret_key y;
    sc_add(to_bytes(y), to_bytes(enote_record.enote_view_extension_x), to_bytes(k_view_balance));

    // 2. z = k_u + k_m
    crypto::secret_key z;
    sc_add(to_bytes(z), to_bytes(enote_record.enote_view_extension_u), to_bytes(sp_spend_privkey));

    // 3. complete the full proof
    make_enote_key_image_proof_v1(onetime_address_ref(enote_record.enote),
        enote_record.enote_view_extension_g,
        y,
        z,
        proof_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool verify_enote_key_image_proof_v1(const EnoteKeyImageProofV1 &proof,
    const rct::key &expected_onetime_address,
    const crypto::key_image &expected_KI)
{
    // 1. check the proof Ko matches the expected onetime address
    if (!(proof.Ko == expected_onetime_address))
        return false;

    // 2. check the proof KI matches the expected key image
    if (!(proof.KI == expected_KI))
        return false;

    // 3. verify that the key image is in the prime-order subgroup
    if (!key_domain_is_prime_subgroup(rct::ki2rct(proof.KI)))
        return false;

    // 4. validate the composition proof
    rct::key message;
    make_enote_key_image_proof_message_v1(proof.Ko, proof.KI, message);

    if (!verify_sp_composition_proof(proof.composition_proof, message, proof.Ko, proof.KI))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void make_enote_unspent_proof_v1(const SpEnoteRecordV1 &enote_record,
    const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_view_balance,
    const crypto::key_image &test_KI,
    EnoteUnspentProofV1 &proof_out)
{
    // 1. prepare private key components
    // note: pubkey components will be stored in the matrix proofs
    // a. ko_g = k_g
    const crypto::secret_key kog_skey{enote_record.enote_view_extension_g};

    // b. ko_x = (k_x + k_vb)
    crypto::secret_key kox_skey;
    sc_add(to_bytes(kox_skey), to_bytes(enote_record.enote_view_extension_x), to_bytes(k_view_balance));

    // c. ko_u = (k_u + k_m)
    crypto::secret_key kou_skey;
    sc_add(to_bytes(kou_skey), to_bytes(enote_record.enote_view_extension_u), to_bytes(sp_spend_privkey));

    // 2. message to sign in the proofs
    rct::key message;
    make_enote_unspent_proof_message_v1(onetime_address_ref(enote_record.enote), test_KI, message);

    // 3. proof: k_g G on G
    MatrixProof kog_proof;
    make_matrix_proof(message, {crypto::get_G()}, {kog_skey}, kog_proof);

    // 4. proof: {ko_x X, (k_x + k_vb)*test_KI}  on  {X, test_KI}
    MatrixProof kox_proof;
    make_matrix_proof(message, {crypto::get_X(), rct::rct2pk(rct::ki2rct(test_KI))}, {kox_skey}, kox_proof);

    // 5. proof: ko_u U on U
    MatrixProof kou_proof;
    make_matrix_proof(message, {crypto::get_U()}, {kou_skey}, kou_proof);

    // 6. assemble full proof
    proof_out = EnoteUnspentProofV1{
            .Ko                          = onetime_address_ref(enote_record.enote),
            .test_KI                     = test_KI,
            .g_component_proof           = std::move(kog_proof),
            .x_component_transform_proof = std::move(kox_proof),
            .u_component_proof           = std::move(kou_proof)
        };
}
//-------------------------------------------------------------------------------------------------------------------
bool verify_enote_unspent_proof_v1(const EnoteUnspentProofV1 &proof,
    const rct::key &expected_onetime_address,
    const crypto::key_image &expected_test_KI)
{
    // 1. check the proof matches with the expected onetime address
    if (!(proof.Ko == expected_onetime_address))
        return false;

    // 2. check the proof matches with the expected test key image
    if (!(proof.test_KI == expected_test_KI))
        return false;

    // 3. check that the onetime address can be reconstructed from internal proof components
    if (proof.g_component_proof.M.size() != 1 ||
        proof.g_component_proof.M[0].size() != 1)
        return false;
    if (proof.x_component_transform_proof.M.size() != 2 ||
        proof.x_component_transform_proof.M[0].size() != 1 ||
        proof.x_component_transform_proof.M[1].size() != 1)
        return false;
    if (proof.u_component_proof.M.size() != 1 ||
        proof.u_component_proof.M[0].size() != 1)
        return false;

    rct::key nominal_Ko{rct::pk2rct(proof.g_component_proof.M[0][0])};  //Ko_g
    rct::addKeys(nominal_Ko, rct::pk2rct(proof.x_component_transform_proof.M[0][0]), nominal_Ko);  //+ Ko_x
    rct::addKeys(nominal_Ko, rct::pk2rct(proof.u_component_proof.M[0][0]), nominal_Ko);  //+ Ko_u
    nominal_Ko = rct::scalarmult8(nominal_Ko);

    if (!(proof.Ko == nominal_Ko))
        return false;

    // 4. message that should have been signed in the proofs
    rct::key expected_message;
    make_enote_unspent_proof_message_v1(proof.Ko, proof.test_KI, expected_message);

    // 5. validate proof on Ko_g
    if (!(proof.g_component_proof.m == expected_message))
        return false;
    if (!verify_matrix_proof(proof.g_component_proof, {crypto::get_G()}))
        return false;

    // 6. validate proof on Ko_x
    if (!(proof.x_component_transform_proof.m == expected_message))
        return false;
    if (!verify_matrix_proof(
            proof.x_component_transform_proof,
            {
                crypto::get_X(),
                rct::rct2pk(rct::ki2rct(proof.test_KI))
            }
        ))
        return false;

    // 7. validate proof on Ko_u
    if (!(proof.u_component_proof.m == expected_message))
        return false;
    if (!verify_matrix_proof(proof.u_component_proof, {crypto::get_U()}))
        return false;

    // 8. check if Ko_u == (k_x + k_vb)*test_KI
    // - if so, then the test KI corresponds to the proof's enote, which implies the enote is spent (assuming only key
    //   images of spent enotes are tested)
    if (rct::scalarmult8(rct::pk2rct(proof.u_component_proof.M[0][0])) ==
        rct::scalarmult8(rct::pk2rct(proof.x_component_transform_proof.M[1][0])))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void make_tx_funded_proof_v1(const rct::key &message,
    const SpEnoteRecordV1 &enote_record,
    const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_view_balance,
    TxFundedProofV1 &proof_out)
{
    // 1. prepare a masked version of our enote's onetime address
    const crypto::secret_key t_k_new{rct::rct2sk(rct::skGen())};

    rct::key masked_address;
    mask_key(t_k_new, onetime_address_ref(enote_record.enote), masked_address);  //K" = t_k_new G + Ko

    // 2. prepare privkeys of K"
    // a. x = t_k_new + k_g
    crypto::secret_key x;
    sc_add(to_bytes(x), to_bytes(t_k_new), to_bytes(enote_record.enote_view_extension_g));

    // b. y = k_x + k_vb
    crypto::secret_key y;
    sc_add(to_bytes(y), to_bytes(enote_record.enote_view_extension_x), to_bytes(k_view_balance));

    // c. z = k_u + k_m
    crypto::secret_key z;
    sc_add(to_bytes(z), to_bytes(enote_record.enote_view_extension_u), to_bytes(sp_spend_privkey));

    // 3. make the composition proof
    SpCompositionProof composition_proof;
    make_sp_composition_proof(message, masked_address, x, y, z, composition_proof);

    // 4. assemble the full proof
    proof_out = TxFundedProofV1{
            .message           = message,
            .masked_address    = masked_address,
            .KI                = enote_record.key_image,
            .composition_proof = composition_proof
        };
}
//-------------------------------------------------------------------------------------------------------------------
bool verify_tx_funded_proof_v1(const TxFundedProofV1 &proof,
    const rct::key &expected_message,
    const crypto::key_image &expected_KI)
{
    // 1. check the proof matches with the expected message
    if (!(proof.message == expected_message))
        return false;

    // 2. check the proof matches with the expected key image
    if (!(proof.KI == expected_KI))
        return false;

    // 3. validate the composition proof
    if (!verify_sp_composition_proof(proof.composition_proof, proof.message, proof.masked_address, proof.KI))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void make_enote_sent_proof_v1(const EnoteOwnershipProofV1 &ownership_proof,
    const EnoteAmountProofV1 &amount_proof,
    EnoteSentProofV1 &proof_out)
{
    proof_out = EnoteSentProofV1{
            .enote_ownership_proof = ownership_proof,
            .amount_proof          = amount_proof
        };
}
//-------------------------------------------------------------------------------------------------------------------
bool verify_enote_sent_proof_v1(const EnoteSentProofV1 &proof,
    const rct::key &expected_amount_commitment,
    const rct::key &expected_onetime_address)
{
    // 1. verify the enote ownership proof
    if (!verify_enote_ownership_proof_v1(proof.enote_ownership_proof,
            expected_amount_commitment,
            expected_onetime_address))
        return false;

    // 2. verify the amount proof
    if (!verify_enote_amount_proof_v1(proof.amount_proof, expected_amount_commitment))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void make_reserved_enote_proof_v1(const EnoteOwnershipProofV1 &enote_ownership_proof,
    const EnoteAmountProofV1 &amount_proof,
    const EnoteKeyImageProofV1 &key_image_proof,
    const std::uint64_t enote_ledger_index,
    ReservedEnoteProofV1 &proof_out)
{
    proof_out = ReservedEnoteProofV1{
            .enote_ownership_proof = enote_ownership_proof,
            .amount_proof          = amount_proof,
            .KI_proof              = key_image_proof,
            .enote_ledger_index    = enote_ledger_index
        };
}
//-------------------------------------------------------------------------------------------------------------------
void make_reserved_enote_proof_v1(const SpContextualEnoteRecordV1 &contextual_record,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_view_balance,
    ReservedEnoteProofV1 &proof_out)
{
    // 1. make enote ownership proof
    EnoteOwnershipProofV1 enote_ownership_proof;
    make_enote_ownership_proof_v1_receiver(contextual_record.record,
        jamtis_spend_pubkey,
        k_view_balance,
        enote_ownership_proof);

    // 2. make amount proof
    EnoteAmountProofV1 amount_proof;
    make_enote_amount_proof_v1(contextual_record.record.amount,
        contextual_record.record.amount_blinding_factor,
        amount_commitment_ref(contextual_record.record.enote),
        amount_proof);

    // 3. make key image proof
    EnoteKeyImageProofV1 key_image_proof;
    make_enote_key_image_proof_v1(contextual_record.record,
        sp_spend_privkey,
        k_view_balance,
        key_image_proof);

    // 4. complete full proof
    make_reserved_enote_proof_v1(enote_ownership_proof,
        amount_proof,
        key_image_proof,
        contextual_record.origin_context.enote_ledger_index,
        proof_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool verify_reserved_enote_proof_v1(const ReservedEnoteProofV1 &proof,
    const rct::key &expected_amount_commitment,
    const rct::key &expected_onetime_address,
    const std::uint64_t expected_enote_ledger_index)
{
    // 1. verify the enote ownership proof
    if (!verify_enote_ownership_proof_v1(proof.enote_ownership_proof,
            expected_amount_commitment,
            expected_onetime_address))
        return false;

    // 2. verify the enote amount proof
    if (!verify_enote_amount_proof_v1(proof.amount_proof, expected_amount_commitment))
        return false;

    // 3. verify the key image proof
    // note: we don't need an 'expected key image' here because our key image proof just needs to show that the proof's
    //       key image is derived from the onetime address of the reserved enote
    if (!verify_enote_key_image_proof_v1(proof.KI_proof, expected_onetime_address, proof.KI_proof.KI))
        return false;

    // 4. check the proof matches the expected enote ledger index
    if (proof.enote_ledger_index != expected_enote_ledger_index)
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool reserved_enote_is_reserved_v1(const ReservedEnoteProofV1 &proof, const TxValidationContext &validation_context)
{
    // 1. try to get the squashed enote from the context
    // - an enote is only 'reserved' if it exists onchain
    rct::keyV squashed_enote_ref;

    try { validation_context.get_reference_set_proof_elements_v2({proof.enote_ledger_index}, squashed_enote_ref); }
    catch (...) { return false; }

    if (squashed_enote_ref.size() != 1)
        return false;

    // 2. compute the reserved enote's squashed enote representation
    rct::key squashed_enote_representation;
    make_seraphis_squashed_enote_Q(proof.enote_ownership_proof.Ko,
        proof.enote_ownership_proof.C,
        squashed_enote_representation);

    // 3. check that the squashed enote reference matches the representation
    if (!(squashed_enote_ref[0] == squashed_enote_representation))
        return false;

    // 4. check that the key image is not in the context
    // - an enote is only 'reserved' if it is unspent
    if (validation_context.seraphis_key_image_exists(proof.KI_proof.KI))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void make_reserve_proof_v1(const rct::key &message,
    const std::vector<SpContextualEnoteRecordV1> &reserved_enote_records,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_view_balance,
    ReserveProofV1 &proof_out)
{
    // 1. make randomized indices into the records
    std::vector<std::size_t> record_indices(reserved_enote_records.size(), 0);
    std::iota(record_indices.begin(), record_indices.end(), 0);
    std::shuffle(record_indices.begin(), record_indices.end(), crypto::random_device{});

    // 2. make reserved enote proofs and collect addresses that need address ownership proofs
    std::vector<ReservedEnoteProofV1> reserved_enote_proofs;
    reserved_enote_proofs.reserve(reserved_enote_records.size());
    std::unordered_set<jamtis::address_index_t> address_indices;
    address_indices.reserve(reserved_enote_records.size());

    for (const std::size_t i : record_indices)
    {
        const SpContextualEnoteRecordV1 &record{reserved_enote_records[i]};

        // a. skip records that aren't onchain
        if (record.origin_context.origin_status != SpEnoteOriginStatus::ONCHAIN)
            continue;

        // b. skip records that aren't unspent
        if (record.spent_context.spent_status != SpEnoteSpentStatus::UNSPENT)
            continue;

        // c. make a reserved enote proof
        make_reserved_enote_proof_v1(record,
            jamtis_spend_pubkey,
            sp_spend_privkey,
            k_view_balance,
            tools::add_element(reserved_enote_proofs));

        // d. save the address index
        address_indices.insert(record.record.address_index);
    }

    // 3. make address ownership proofs for all the unique addresses that own records in the reserve proof
    std::vector<AddressOwnershipProofV1> address_ownership_proofs;
    address_ownership_proofs.reserve(address_indices.size());

    for (const jamtis::address_index_t &j : address_indices)
    {
        make_address_ownership_proof_v1(message,
            sp_spend_privkey,
            k_view_balance,
            j,
            tools::add_element(address_ownership_proofs));
    }

    // 4. assemble the full proof
    proof_out = ReserveProofV1{
            .address_ownership_proofs = std::move(address_ownership_proofs),
            .reserved_enote_proofs    = std::move(reserved_enote_proofs)
        };
}
//-------------------------------------------------------------------------------------------------------------------
bool verify_reserve_proof_v1(const ReserveProofV1 &proof,
    const rct::key &expected_message,
    const TxValidationContext &validation_context)
{
    // 1. validate the address ownership proofs against the expected message
    std::unordered_set<rct::key> found_addresses;
    found_addresses.reserve(proof.address_ownership_proofs.size());

    for (const AddressOwnershipProofV1 &address_ownership_proof : proof.address_ownership_proofs)
    {
        // a. verify the proof
        // - we don't check expected addresses, since a reserve proof's goal is to demonstrate ownership of funds by
        //   'any' addresses
        if (!verify_address_ownership_proof_v1(address_ownership_proof, expected_message, address_ownership_proof.K))
            return false;

        // b. save the address from this proof
        found_addresses.insert(address_ownership_proof.K);
    }

    // 2. check all the reserved enote proofs
    for (const ReservedEnoteProofV1 &reserved_enote_proof : proof.reserved_enote_proofs)
    {
        // a. check that the owning address K_1 in each of the reserved enote proofs corresponds to an address owned by
        //    the prover
        if (found_addresses.find(reserved_enote_proof.enote_ownership_proof.K_1) == found_addresses.end())
            return false;

        // b. check that the enotes referenced by the reserved enote proofs are in the ledger and unspent
        if (!reserved_enote_is_reserved_v1(reserved_enote_proof, validation_context))
            return false;

        // c. validate the reserved enote proofs
        // - we don't check expected values because all we care about is validity (we already checked address consistency)
        if (!verify_reserved_enote_proof_v1(reserved_enote_proof,
                reserved_enote_proof.enote_ownership_proof.C,
                reserved_enote_proof.enote_ownership_proof.Ko,
                reserved_enote_proof.enote_ledger_index))
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
boost::multiprecision::uint128_t total_reserve_amount(const ReserveProofV1 &proof)
{
    boost::multiprecision::uint128_t total_amount{0};

    for (const ReservedEnoteProofV1 &reserved_enote_proof : proof.reserved_enote_proofs)
        total_amount += reserved_enote_proof.amount_proof.a;

    return total_amount;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace knowledge_proofs
} //namespace sp
