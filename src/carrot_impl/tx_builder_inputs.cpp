// Copyright (c) 2024-2026, The Monero Project
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
#include "tx_builder_inputs.h"

//local headers
#include "carrot_core/account_secrets.h"
#include "carrot_core/address_utils.h"
#include "carrot_core/core_types.h"
#include "carrot_core/exceptions.h"
#include "carrot_core/payment_proposal.h"
#include "carrot_impl/address_utils.h"
#include "crypto/crypto.h"
#include "fcmp_pp/prove.h"
#include "misc_log_ex.h"

//third party headers

//standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "carrot_impl.tx_builder_inputs"

namespace carrot
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static crypto::secret_key load_sk(const unsigned char s[32])
{
    crypto::secret_key sk;
    memcpy(sk.data, s, sizeof(sk.data));
    return sk;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_sal_proof_nominal_address(const crypto::hash &signable_tx_hash,
    const FcmpRerandomizedOutputCompressed &rerandomized_output,
    const crypto::secret_key &account_privkey_g,
    const crypto::secret_key &account_privkey_t,
    const OutputOpeningHintVariant &opening_hint,
    const address_device &addr_dev,
    const view_balance_secret_device *s_view_balance_dev,
    const view_incoming_key_device &k_view_incoming_dev,
    fcmp_pp::FcmpPpSalProof &sal_proof_out,
    crypto::key_image &key_image_out)
{
    CHECK_AND_ASSERT_THROW_MES(verify_rerandomized_output_basic(rerandomized_output,
            onetime_address_ref(opening_hint),
            amount_commitment_ref(opening_hint),
            use_biased_hash_to_point(opening_hint)),
        "Could not make SA/L proof: failed to verify rerandomized output against opening hint");

    crypto::secret_key x;
    crypto::secret_key y;
    get_onetime_address_full_openings(opening_hint, addr_dev, s_view_balance_dev,
        k_view_incoming_dev, account_privkey_g, account_privkey_t, x, y);

    std::tie(sal_proof_out, key_image_out) = fcmp_pp::prove_sal(signable_tx_hash,
        x,
        y,
        rerandomized_output);
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<FcmpRerandomizedOutputCompressed> generate_rerandomized_inputs_nonrefundable(
    epee::span<const carrot::RCTOutputEnoteProposal> output_enote_proposals,
    epee::span<const carrot::OutputOpeningHintVariant> input_proposals,
    const address_device &addr_dev,
    const carrot::view_balance_secret_device *s_view_balance_dev,
    const carrot::view_incoming_key_device &k_view_incoming_dev)
{
    const std::size_t n_inputs = input_proposals.size();

    // sum blinding factors on outputs
    crypto::secret_key output_amount_blinding_factor_sum{};
    for (const auto &output_enote_proposal : output_enote_proposals)
        sc_add(to_bytes(output_amount_blinding_factor_sum),
            to_bytes(output_amount_blinding_factor_sum),
            to_bytes(output_enote_proposal.amount_blinding_factor));

    // collect, collect, collect input info
    std::vector<crypto::public_key> input_onetime_addresses;
    std::vector<crypto::ec_point> input_amount_commitments;
    std::vector<bool> input_uses_biased_hash_to_point;
    std::vector<crypto::secret_key> input_amount_blinding_factors;
    input_onetime_addresses.reserve(n_inputs);
    input_amount_commitments.reserve(n_inputs);
    input_uses_biased_hash_to_point.reserve(n_inputs);
    input_amount_blinding_factors.reserve(n_inputs);
    for (const auto &input_proposal : input_proposals)
    {
        input_onetime_addresses.push_back(onetime_address_ref(input_proposal));
        input_amount_commitments.push_back(amount_commitment_ref(input_proposal));
        input_uses_biased_hash_to_point.push_back(use_biased_hash_to_point(input_proposal));

        carrot::xmr_amount amount;
        const bool scan_success = carrot::try_scan_opening_hint_amount(input_proposal,
            addr_dev,
            s_view_balance_dev,
            &k_view_incoming_dev,
            amount,
            input_amount_blinding_factors.emplace_back());
        CARROT_CHECK_AND_THROW(scan_success,
            carrot::unexpected_scan_failure, "Could not generate rerandomized inputs: opening hint is not scannable");
    }

    // generate random r_o for inputs
    std::vector<crypto::secret_key> r_o(n_inputs);
    for (auto &s : r_o)
        crypto::random32_unbiased(to_bytes(s));

    std::vector<FcmpRerandomizedOutputCompressed> rerandomized_inputs;
    rerandomized_inputs.reserve(n_inputs);
    fcmp_pp::make_balanced_rerandomized_output_set(input_onetime_addresses,
        input_amount_commitments,
        input_uses_biased_hash_to_point,
        input_amount_blinding_factors,
        r_o,
        output_amount_blinding_factor_sum,
        rerandomized_inputs);
    return rerandomized_inputs;
}
//-------------------------------------------------------------------------------------------------------------------
bool verify_rerandomized_output_basic(const FcmpRerandomizedOutputCompressed &rerandomized_output,
    const crypto::public_key &onetime_address,
    const amount_commitment_t &amount_commitment,
    const bool use_biased_hash_to_point)
{
    const FcmpInputCompressed recomputed_input = fcmp_pp::calculate_fcmp_input_for_rerandomizations(
        onetime_address,
        amount_commitment,
        use_biased_hash_to_point,
        load_sk(rerandomized_output.r_o),
        load_sk(rerandomized_output.r_i),
        load_sk(rerandomized_output.r_r_i),
        load_sk(rerandomized_output.r_c));

    return 0 == memcmp(&recomputed_input, &rerandomized_output.input, sizeof(FcmpInputCompressed));
}
//-------------------------------------------------------------------------------------------------------------------
void get_onetime_address_full_openings(const OutputOpeningHintVariant &opening_hint,
    const address_device &addr_dev,
    const view_balance_secret_device *s_view_balance_dev,
    const view_incoming_key_device &k_view_incoming_dev,
    const crypto::secret_key &account_privkey_g,
    const crypto::secret_key &account_privkey_t,
    crypto::secret_key &x_out,
    crypto::secret_key &y_out)
{
    // scan k^g_o, k^t_o
    crypto::secret_key sender_extension_g;
    crypto::secret_key sender_extension_t;
    CHECK_AND_ASSERT_THROW_MES(try_scan_opening_hint_sender_extensions(opening_hint,
            addr_dev,
            s_view_balance_dev,
            &k_view_incoming_dev,
            sender_extension_g,
            sender_extension_t),
        "Could not make SA/L proof: failed to scan opening hint");

    // get address openings
    crypto::secret_key address_extension_g;
    crypto::secret_key address_scalar;
    addr_dev.get_address_openings(subaddress_index_ref(opening_hint),
        address_extension_g,
        address_scalar);

    // x = `account_privkey_g` * k^j_subscal + k^j_{g,addr} + k^g_o
    sc_muladd(to_bytes(x_out), to_bytes(account_privkey_g),
        to_bytes(address_scalar), to_bytes(sender_extension_g));
    sc_add(to_bytes(x_out), to_bytes(x_out), to_bytes(address_extension_g));

    // y = `account_privkey_t` * k^j_subscal + k^t_o
    sc_muladd(to_bytes(y_out), to_bytes(account_privkey_t),
        to_bytes(address_scalar), to_bytes(sender_extension_t));
}
//-------------------------------------------------------------------------------------------------------------------
void make_sal_proof_any_to_legacy_v1(const crypto::hash &signable_tx_hash,
    const FcmpRerandomizedOutputCompressed &rerandomized_output,
    const OutputOpeningHintVariant &opening_hint,
    const crypto::secret_key &k_spend,
    const cryptonote_hierarchy_address_device &addr_dev,
    fcmp_pp::FcmpPpSalProof &sal_proof_out,
    crypto::key_image &key_image_out)
{
    make_sal_proof_nominal_address(signable_tx_hash,
        rerandomized_output,
        k_spend,
        crypto::null_skey,
        opening_hint,
        addr_dev,
        /*s_view_balance_dev=*/nullptr,
        addr_dev,
        sal_proof_out,
        key_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_sal_proof_any_to_carrot_v1(const crypto::hash &signable_tx_hash,
    const FcmpRerandomizedOutputCompressed &rerandomized_output,
    const OutputOpeningHintVariant &opening_hint,
    const crypto::secret_key &k_prove_spend,
    const crypto::secret_key &k_generate_image,
    const address_device &addr_dev,
    const view_balance_secret_device &s_view_balance_dev,
    const view_incoming_key_device &k_view_incoming_dev,
    fcmp_pp::FcmpPpSalProof &sal_proof_out,
    crypto::key_image &key_image_out)
{
    make_sal_proof_nominal_address(signable_tx_hash,
        rerandomized_output,
        k_generate_image,
        k_prove_spend,
        opening_hint,
        addr_dev,
        &s_view_balance_dev,
        k_view_incoming_dev,
        sal_proof_out,
        key_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_sal_proof_any_to_hybrid_v1(const crypto::hash &signable_tx_hash,
    const FcmpRerandomizedOutputCompressed &rerandomized_output,
    const OutputOpeningHintVariant &opening_hint,
    const crypto::secret_key &k_privkey_g,
    const crypto::secret_key &k_privkey_t,
    const view_balance_secret_device *s_view_balance_dev,
    const view_incoming_key_device &k_view_incoming_dev,
    const address_device &addr_dev,
    fcmp_pp::FcmpPpSalProof &sal_proof_out,
    crypto::key_image &key_image_out)
{
    make_sal_proof_nominal_address(signable_tx_hash,
        rerandomized_output,
        k_privkey_g,
        k_privkey_t,
        opening_hint,
        addr_dev,
        s_view_balance_dev,
        k_view_incoming_dev,
        sal_proof_out,
        key_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace carrot
