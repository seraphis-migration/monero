// Copyright (c) 2024, The Monero Project
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
#include "carrot_core/config.h"
#include "carrot_core/enote_utils.h"
#include "carrot_core/exceptions.h"
#include "carrot_core/scan.h"
#include "carrot_impl/address_utils.h"
#include "common/perf_timer.h"
#include "common/threadpool.h"
#include "crypto/generators.h"
#include "fcmp_pp/prove.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"

//third party headers

//standard headers
#include <algorithm>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "carrot_impl.tx_builder_inputs"

namespace carrot
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static rct::key load_key(const std::uint8_t bytes[32])
{
    rct::key k;
    memcpy(k.bytes, bytes, sizeof(k));
    return k;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static FcmpInputCompressed calculate_fcmp_input_for_rerandomizations(const crypto::public_key &onetime_address,
    const rct::key &amount_commitment,
    const bool use_biased_hash_to_point,
    const rct::key &r_o,
    const rct::key &r_i,
    const rct::key &r_r_i,
    const rct::key &r_c)
{
    return fcmp_pp::calculate_fcmp_input_for_rerandomizations(onetime_address,
        rct::rct2pt(amount_commitment),
        use_biased_hash_to_point,
        rct::rct2sk(r_o),
        rct::rct2sk(r_i),
        rct::rct2sk(r_r_i),
        rct::rct2sk(r_c));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_sal_proof_nominal_address(const crypto::hash &signable_tx_hash,
    const FcmpRerandomizedOutputCompressed &rerandomized_output,
    const crypto::secret_key &address_privkey_g,
    const crypto::secret_key &address_privkey_t,
    const OutputOpeningHintVariant &opening_hint,
    const epee::span<const crypto::public_key> main_address_spend_pubkeys,
    const view_incoming_key_device *k_view_incoming_dev,
    const view_balance_secret_device *s_view_balance_dev,
    fcmp_pp::FcmpPpSalProof &sal_proof_out,
    crypto::key_image &key_image_out)
{
    // O = x G + y T
    CHECK_AND_ASSERT_THROW_MES(verify_rerandomized_output_basic(rerandomized_output,
            onetime_address_ref(opening_hint),
            amount_commitment_ref(opening_hint),
            use_biased_hash_to_point(opening_hint)),
        "Could not make SA/L proof: failed to verify rerandomized output against opening hint");

    // scan k^g_o, k^t_o
    crypto::secret_key sender_extension_g;
    crypto::secret_key sender_extension_t;
    CHECK_AND_ASSERT_THROW_MES(try_scan_opening_hint_sender_extensions(opening_hint,
            main_address_spend_pubkeys,
            k_view_incoming_dev,
            s_view_balance_dev,
            sender_extension_g,
            sender_extension_t),
        "Could not make SA/L proof: failed to scan opening hint");

    // x = k^{j,g}_addr + k^g_o
    crypto::secret_key x;
    sc_add(to_bytes(x),
        to_bytes(address_privkey_g),
        to_bytes(sender_extension_g));

    // y = k^{j,t}_addr + k^t_o
    crypto::secret_key y;
    sc_add(to_bytes(y),
        to_bytes(address_privkey_t),
        to_bytes(sender_extension_t));

    std::tie(sal_proof_out, key_image_out) = fcmp_pp::prove_sal(signable_tx_hash,
        x,
        y,
        rerandomized_output);
}
//-------------------------------------------------------------------------------------------------------------------
void make_carrot_rerandomized_outputs_nonrefundable(const std::vector<crypto::public_key> &input_onetime_addresses,
    const std::vector<rct::key> &input_amount_commitments,
    const std::vector<bool> &input_uses_biased_hash_to_point,
    const std::vector<rct::key> &input_amount_blinding_factors,
    const std::vector<rct::key> &output_amount_blinding_factors,
    std::vector<FcmpRerandomizedOutputCompressed> &rerandomized_outputs_out)
{
    // collect input_amount_commitments as crypto::ec_point
    std::vector<crypto::ec_point> input_amount_commitments_pt;
    input_amount_commitments_pt.reserve(input_amount_commitments.size());
    for (const rct::key &input_amount_commitment : input_amount_commitments)
        input_amount_commitments_pt.push_back(rct::rct2pt(input_amount_commitment));

    // collect input_amount_blinding_factors as crypto::secret_key
    std::vector<crypto::secret_key> input_amount_blinding_factors_sk;
    input_amount_blinding_factors_sk.reserve(input_amount_blinding_factors_sk.size());
    for (const rct::key &input_amount_blinding_factor : input_amount_blinding_factors)
        input_amount_blinding_factors_sk.push_back(rct::rct2sk(input_amount_blinding_factor));

    // generate random r_o
    std::vector<crypto::secret_key> r_o(input_onetime_addresses.size());
    for (size_t i = 0; i < input_onetime_addresses.size(); ++i)
        crypto::random32_unbiased(to_bytes(r_o[i]));

    // calculate output_amount_blinding_factor_sum = sum(output_amount_blinding_factors)
    crypto::secret_key output_amount_blinding_factor_sum;
    sc_0(to_bytes(output_amount_blinding_factor_sum));
    for (const rct::key &output_amount_blinding_factor : output_amount_blinding_factors)
        sc_add(to_bytes(output_amount_blinding_factor_sum),
            to_bytes(output_amount_blinding_factor_sum),
            output_amount_blinding_factor.bytes);

    fcmp_pp::make_balanced_rerandomized_output_set(input_onetime_addresses,
        input_amount_commitments_pt,
        input_uses_biased_hash_to_point,
        input_amount_blinding_factors_sk,
        r_o,
        output_amount_blinding_factor_sum,
        rerandomized_outputs_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool verify_rerandomized_output_basic(const FcmpRerandomizedOutputCompressed &rerandomized_output,
    const crypto::public_key &onetime_address,
    const rct::key &amount_commitment,
    const bool use_biased_hash_to_point)
{
    const FcmpInputCompressed recomputed_input = calculate_fcmp_input_for_rerandomizations(
        onetime_address,
        amount_commitment,
        use_biased_hash_to_point,
        load_key(rerandomized_output.r_o),
        load_key(rerandomized_output.r_i),
        load_key(rerandomized_output.r_r_i),
        load_key(rerandomized_output.r_c));

    return 0 == memcmp(&recomputed_input, &rerandomized_output.input, sizeof(FcmpInputCompressed));
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
    // get K_s
    crypto::public_key main_address_spend_pubkey;
    addr_dev.get_address_spend_pubkey({}, main_address_spend_pubkey);

    // k^j_subext = ScalarDeriveLegacy("SubAddr" || IntToBytes8(0) || k_v || IntToBytes32(j_major) || IntToBytes32(j_minor))
    const subaddress_index_extended subaddr_index = subaddress_index_ref(opening_hint);
    crypto::secret_key address_privkey_g;
    crypto::secret_key dummy_subaddress_scalar;
    addr_dev.get_address_openings(subaddr_index, address_privkey_g, dummy_subaddress_scalar);

    // k^j_g = k^j_subext + k_s
    sc_add(to_bytes(address_privkey_g), to_bytes(address_privkey_g), to_bytes(k_spend));

    make_sal_proof_nominal_address(signable_tx_hash,
        rerandomized_output,
        address_privkey_g,
        crypto::null_skey,
        opening_hint,
        {&main_address_spend_pubkey, 1},
        &addr_dev,
        /*s_view_balance_dev=*/nullptr,
        sal_proof_out,
        key_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_sal_proof_any_to_carrot_v1(const crypto::hash &signable_tx_hash,
    const FcmpRerandomizedOutputCompressed &rerandomized_output,
    const OutputOpeningHintVariant &opening_hint,
    const crypto::secret_key &k_prove_spend,
    const crypto::secret_key &k_generate_image,
    const view_balance_secret_device &s_view_balance_dev,
    const view_incoming_key_device &k_view_incoming_dev,
    const generate_address_secret_device &s_generate_address_dev,
    fcmp_pp::FcmpPpSalProof &sal_proof_out,
    crypto::key_image &key_image_out)
{
    // K_s = k_gi G + k_ps T
    crypto::public_key main_address_spend_pubkey;
    carrot::make_carrot_spend_pubkey(k_generate_image, k_prove_spend, main_address_spend_pubkey);

    // K_v = k_v K_s
    crypto::public_key account_view_pubkey;
    k_view_incoming_dev.view_key_scalar_mult_ed25519(main_address_spend_pubkey, account_view_pubkey);

    // s^j_ap1 = H_32[s_ga](j_major, j_minor)
    const subaddress_index_extended subaddr_index = subaddress_index_ref(opening_hint);
    crypto::secret_key address_index_preimage_1;
    s_generate_address_dev.make_address_index_preimage_1(subaddr_index.index.major,
        subaddr_index.index.minor,
        address_index_preimage_1);

    // s^j_ap2 = H_32[s^j_ap1](j_major, j_minor, K_s, K_v)
    crypto::secret_key address_index_preimage_2;
    make_carrot_address_index_preimage_2(address_index_preimage_1,
        subaddr_index.index.major,
        subaddr_index.index.minor,
        main_address_spend_pubkey,
        account_view_pubkey,
        address_index_preimage_2);

    // k^j_subscal = H_n(K_s, j_major, j_minor, s^j_gen)
    crypto::secret_key subaddress_scalar;
    if (subaddr_index.index.is_subaddress())
    {
        make_carrot_subaddress_scalar(address_index_preimage_2,
            main_address_spend_pubkey,
            subaddress_scalar);
    }
    else // main address
    {
        sc_1(to_bytes(subaddress_scalar));
    }

    // k^j_g = k_gi * k^j_subscal
    crypto::secret_key address_privkey_g;
    sc_mul(to_bytes(address_privkey_g), to_bytes(k_generate_image), to_bytes(subaddress_scalar));

    // k^j_t = k_ps * k^j_subscal
    crypto::secret_key address_privkey_t;
    sc_mul(to_bytes(address_privkey_t), to_bytes(k_prove_spend), to_bytes(subaddress_scalar));

    make_sal_proof_nominal_address(signable_tx_hash,
        rerandomized_output,
        address_privkey_g,
        address_privkey_t,
        opening_hint,
        {&main_address_spend_pubkey, 1},
        &k_view_incoming_dev,
        &s_view_balance_dev,
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
    crypto::secret_key subaddress_extention_g;
    crypto::secret_key subaddress_scalar;
    addr_dev.get_address_openings(subaddress_index_ref(opening_hint), subaddress_extention_g, subaddress_scalar);

    // k^j_g = k_g * k^j_subscal + k^j_subext
    crypto::secret_key address_privkey_g;
    sc_muladd(to_bytes(address_privkey_g), to_bytes(k_privkey_g),
        to_bytes(subaddress_scalar), to_bytes(subaddress_extention_g));

    // k^j_t = k_t * k^j_subscal
    crypto::secret_key address_privkey_t;
    sc_mul(to_bytes(address_privkey_t), to_bytes(k_privkey_t), to_bytes(subaddress_scalar));

    crypto::public_key main_address_spend_pubkeys[2];
    make_sal_proof_nominal_address(signable_tx_hash,
        rerandomized_output,
        address_privkey_g,
        address_privkey_t,
        opening_hint,
        get_all_main_address_spend_pubkeys_span(addr_dev, main_address_spend_pubkeys),
        &k_view_incoming_dev,
        s_view_balance_dev,
        sal_proof_out,
        key_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
void generate_fcmp_blinds(
    const epee::span<const FcmpRerandomizedOutputCompressed> rerandomized_outputs,
    const epee::span<fcmp_pp::OutputBlinds> &output_blinds_out,
    const epee::span<fcmp_pp::SeleneBranchBlind> &selene_branch_blinds_out,
    const epee::span<fcmp_pp::HeliosBranchBlind> &helios_branch_blinds_out)
{
    CARROT_CHECK_AND_THROW(rerandomized_outputs.size() == output_blinds_out.size(),
        carrot_logic_error, "Wrong size of output span output_blinds_out");

    // start threadpool and waiter
    tools::threadpool& tpool = tools::threadpool::getInstanceForCompute();
    tools::threadpool::waiter waiter(tpool);

    LOG_PRINT_L3("Starting FCMP blind jobs...");
    const std::size_t n_outputs = output_blinds_out.size();
    const std::size_t n_jobs = 4 * n_outputs + selene_branch_blinds_out.size() + helios_branch_blinds_out.size();
    LOG_PRINT_L3("Will submit a total of " << n_jobs << " blind calculations");

    // Submit blinds calculation jobs
    std::vector<fcmp_pp::BlindedOBlind> blinded_o_blinds(n_outputs);
    std::vector<fcmp_pp::BlindedIBlind> blinded_i_blinds(n_outputs);
    std::vector<fcmp_pp::BlindedIBlindBlind> blinded_i_blind_blinds(n_outputs);
    std::vector<fcmp_pp::BlindedCBlind> blinded_c_blinds(n_outputs);

    for (size_t i = 0; i < n_outputs; ++i)
    {
        const FcmpRerandomizedOutputCompressed &rerandomized_output = rerandomized_outputs[i];
        tpool.submit(&waiter, [&rerandomized_output, &blinded_o_blinds, i]() {
            PERF_TIMER(blind_o_blind);
            blinded_o_blinds[i] = fcmp_pp::blind_o_blind(fcmp_pp::o_blind(rerandomized_output));});
        tpool.submit(&waiter, [&rerandomized_output, &blinded_i_blinds, i]() {
            PERF_TIMER(blind_i_blind);
            blinded_i_blinds[i] = fcmp_pp::blind_i_blind(fcmp_pp::i_blind(rerandomized_output));});
        tpool.submit(&waiter, [&rerandomized_output, &blinded_i_blind_blinds, i]() {
            PERF_TIMER(blind_i_blind_blind);
            blinded_i_blind_blinds[i] = fcmp_pp::blind_i_blind_blind(fcmp_pp::i_blind_blind(rerandomized_output));});
        tpool.submit(&waiter, [&rerandomized_output, &blinded_c_blinds, i]() {
            PERF_TIMER(blind_c_blind);
            blinded_c_blinds[i] = fcmp_pp::blind_c_blind(fcmp_pp::c_blind(rerandomized_output));});
    }

    for (fcmp_pp::SeleneBranchBlind &selene_branch_blind : selene_branch_blinds_out)
    {
        tpool.submit(&waiter, [&selene_branch_blind]() {
            PERF_TIMER(selene_branch_blind);
            selene_branch_blind = fcmp_pp::gen_selene_branch_blind();
        });
    }

    for (fcmp_pp::HeliosBranchBlind &helios_branch_blind : helios_branch_blinds_out)
    {
        tpool.submit(&waiter, [&helios_branch_blind]() {
            PERF_TIMER(helios_branch_blind);
            helios_branch_blind = fcmp_pp::gen_helios_branch_blind();
        });
    }

    // wait for jobs to complete
    LOG_PRINT_L3("Waiting onDCMP blind jobs...");
    CHECK_AND_ASSERT_THROW_MES(waiter.wait(), "some FCMP blind jobs failed");

    for (size_t i = 0; i < n_outputs; ++i)
    {
        output_blinds_out[i] = fcmp_pp::output_blinds_new(
            blinded_o_blinds.at(i),
            blinded_i_blinds.at(i),
            blinded_i_blind_blinds.at(i),
            blinded_c_blinds.at(i));
    }
}
//-------------------------------------------------------------------------------------------------------------------
void generate_fcmp_blinds_and_prove_membership(
    epee::span<const FcmpRerandomizedOutputCompressed> rerandomized_outputs,
    epee::span<const fcmp_pp::Path> paths,
    const std::uint8_t n_tree_layers,
    fcmp_pp::FcmpMembershipProof &membership_proof_out)
{
    const std::size_t n_inputs = rerandomized_outputs.size();
    CARROT_CHECK_AND_THROW(paths.size() == n_inputs, carrot_logic_error, "Wrong size of span paths");

    CARROT_CHECK_AND_THROW(n_tree_layers > 0, carrot_logic_error, "n_tree_layers must be non-zero");
    CARROT_CHECK_AND_THROW(n_tree_layers <= FCMP_PLUS_PLUS_MAX_LAYERS,
        carrot_logic_error, "n_tree_layers must be less than or equal to FCMP_PLUS_PLUS_MAX_LAYERS");

    const std::uint8_t n_c1_blinds = n_tree_layers / 2;       // per-input, not total
    const std::uint8_t n_c2_blinds = (n_tree_layers - 1) / 2; // per-input, not total

    std::vector<fcmp_pp::OutputBlinds> output_blinds(n_inputs);
    std::vector<fcmp_pp::SeleneBranchBlind> selene_branch_blinds(n_inputs * n_c1_blinds);
    std::vector<fcmp_pp::HeliosBranchBlind> helios_branch_blinds(n_inputs * n_c2_blinds);
    generate_fcmp_blinds(rerandomized_outputs,
        epee::to_mut_span(output_blinds),
        epee::to_mut_span(selene_branch_blinds),
        epee::to_mut_span(helios_branch_blinds));

    std::vector<fcmp_pp::SeleneBranchBlind> selene_branch_blinds_tmp;
    selene_branch_blinds_tmp.reserve(n_c1_blinds);
    std::vector<fcmp_pp::HeliosBranchBlind> helios_branch_blinds_tmp;
    helios_branch_blinds_tmp.reserve(n_c2_blinds);
    std::vector<fcmp_pp::FcmpPpProveMembershipInput> membership_proving_inputs;
    membership_proving_inputs.reserve(n_inputs);
    for (size_t i = 0; i < n_inputs; ++i)
    {
        selene_branch_blinds_tmp.clear();
        for (size_t j = 0; j < n_c1_blinds; ++j)
        {
            const size_t flat_idx = (i * n_c1_blinds) + j;
            selene_branch_blinds_tmp.emplace_back(std::move(selene_branch_blinds.at(flat_idx)));
        }

        helios_branch_blinds_tmp.clear();
        for (size_t j = 0; j < n_c2_blinds; ++j)
        {
            const size_t flat_idx = (i * n_c2_blinds) + j;
            helios_branch_blinds_tmp.emplace_back(std::move(helios_branch_blinds.at(flat_idx)));
        }

        membership_proving_inputs.push_back(fcmp_pp::fcmp_pp_prove_input_new(
            paths[i],
            output_blinds.at(i),
            selene_branch_blinds_tmp,
            helios_branch_blinds_tmp));
    }

    PERF_TIMER(prove_membership);
    membership_proof_out = fcmp_pp::prove_membership(membership_proving_inputs, n_tree_layers);
    PERF_TIMER_PAUSE(prove_membership);
    CARROT_CHECK_AND_THROW(membership_proof_out.size() == fcmp_pp::membership_proof_len(n_inputs, n_tree_layers),
        carrot_logic_error, "unexpected FCMP membership proof length");
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace carrot
