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
#include "scan_balance_recovery_utils.h"

//local headers
#include "contextual_enote_record_types.h"
#include "contextual_enote_record_utils.h"
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "cryptonote_basic/subaddress_index.h"
#include "device/device.hpp"
#include "enote_record_types.h"
#include "enote_record_utils.h"
#include "enote_record_utils_legacy.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_core_utils.h"
#include "seraphis_core/legacy_core_utils.h"
#include "seraphis_core/legacy_enote_types.h"
#include "seraphis_core/legacy_enote_utils.h"
#include "seraphis_core/tx_extra.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "tx_component_types.h"

//third party headers

//standard headers
#include <algorithm>
#include <functional>
#include <list>
#include <unordered_map>
#include <unordered_set>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
namespace scanning
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_view_scan_legacy_enote_v1(const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const std::uint64_t block_index,
    const std::uint64_t block_timestamp,
    const rct::key &transaction_id,
    const std::uint64_t total_enotes_before_tx,
    const std::uint64_t enote_index,
    const std::uint64_t unlock_time,
    const TxExtra &tx_memo,
    const LegacyEnoteVariant &legacy_enote,
    const crypto::public_key &legacy_enote_ephemeral_pubkey,
    const crypto::key_derivation &DH_derivation,
    const SpEnoteOriginStatus origin_status,
    hw::device &hwdev,
    LegacyContextualBasicEnoteRecordV1 &contextual_record_out)
{
    // 1. view scan the enote (in try block in case the enote is malformed)
    try
    {
        if (!try_get_legacy_basic_enote_record(legacy_enote,
                rct::pk2rct(legacy_enote_ephemeral_pubkey),
                enote_index,
                unlock_time,
                DH_derivation,
                legacy_base_spend_pubkey,
                legacy_subaddress_map,
                hwdev,
                contextual_record_out.record))
            return false;
    } catch (...) { return false; }

    // 2. set the origin context
    contextual_record_out.origin_context =
        SpEnoteOriginContextV1{
                .block_index        = block_index,
                .block_timestamp    = block_timestamp,
                .transaction_id     = transaction_id,
                .enote_tx_index     = enote_index,
                .enote_ledger_index = total_enotes_before_tx + enote_index,
                .origin_status      = origin_status,
                .memo               = tx_memo
            };

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void update_with_new_intermediate_record_legacy(const LegacyIntermediateEnoteRecord &new_enote_record,
    const SpEnoteOriginContextV1 &new_record_origin_context,
    std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1> &found_enote_records_inout)
{
    // 1. add new intermediate legacy record to found enotes (or refresh if already there)
    rct::key new_record_identifier;
    get_legacy_enote_identifier(onetime_address_ref(new_enote_record.enote),
        new_enote_record.amount,
        new_record_identifier);

    found_enote_records_inout[new_record_identifier].record = new_enote_record;

    // 2. update the record's origin context
    try_update_enote_origin_context_v1(new_record_origin_context,
        found_enote_records_inout[new_record_identifier].origin_context);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void update_with_new_record_legacy(const LegacyEnoteRecord &new_enote_record,
    const SpEnoteOriginContextV1 &new_record_origin_context,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> &found_enote_records_inout,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images_inout)
{
    // 1. add new legacy record to found enotes (or refresh if already there)
    rct::key new_record_identifier;
    get_legacy_enote_identifier(onetime_address_ref(new_enote_record.enote),
        new_enote_record.amount,
        new_record_identifier);

    found_enote_records_inout[new_record_identifier].record = new_enote_record;

    // 2. if the enote is spent in this chunk, update its spent context
    const crypto::key_image &new_record_key_image{new_enote_record.key_image};
    SpEnoteSpentContextV1 spent_context_update{};

    auto contextual_key_images_of_record_spent_in_this_chunk =
        std::find_if(
            chunk_contextual_key_images.begin(),
            chunk_contextual_key_images.end(),
            [&new_record_key_image](const SpContextualKeyImageSetV1 &contextual_key_image_set) -> bool
            {
                return has_key_image(contextual_key_image_set, new_record_key_image);
            }
        );

    if (contextual_key_images_of_record_spent_in_this_chunk != chunk_contextual_key_images.end())
    {
        // a. record that the enote is spent in this chunk
        found_spent_key_images_inout[new_record_key_image];

        // b. update its spent context (update instead of assignment in case of duplicates)
        try_update_enote_spent_context_v1(contextual_key_images_of_record_spent_in_this_chunk->spent_context,
            found_spent_key_images_inout[new_record_key_image]);

        // c. save the record's current spent context
        spent_context_update = found_spent_key_images_inout[new_record_key_image];
    }

    // 3. update the record's contexts
    // note: multiple legacy enotes can have the same key image but different amounts; only one of those can be spent,
    //       so we should expect all of them to end up referencing the same spent context
    update_contextual_enote_record_contexts_v1(new_record_origin_context,
        spent_context_update,
        found_enote_records_inout[new_record_identifier].origin_context,
        found_enote_records_inout[new_record_identifier].spent_context);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void update_with_new_intermediate_record_sp(const SpIntermediateEnoteRecordV1 &new_enote_record,
    const SpEnoteOriginContextV1 &new_record_origin_context,
    std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1> &found_enote_records_inout)
{
    // 1. add new seraphis record to found enotes (or refresh if already there)
    const rct::key &new_record_onetime_address{onetime_address_ref(new_enote_record.enote)};

    found_enote_records_inout[new_record_onetime_address].record = new_enote_record;

    // 2. update the record's origin context
    try_update_enote_origin_context_v1(new_record_origin_context,
        found_enote_records_inout[new_record_onetime_address].origin_context);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void update_with_new_record_sp(const SpEnoteRecordV1 &new_enote_record,
    const SpEnoteOriginContextV1 &new_record_origin_context,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records_inout,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images_inout,
    std::unordered_set<rct::key> &txs_have_spent_enotes_inout)
{
    // 1. add new record to found enotes (or refresh if already there)
    const crypto::key_image &new_record_key_image{new_enote_record.key_image};

    found_enote_records_inout[new_record_key_image].record = new_enote_record;

    // 2. if the enote is spent in this chunk, update its spent context
    SpEnoteSpentContextV1 spent_context_update{};

    auto contextual_key_images_of_record_spent_in_this_chunk =
        std::find_if(
            chunk_contextual_key_images.begin(),
            chunk_contextual_key_images.end(),
            [&new_record_key_image](const SpContextualKeyImageSetV1 &contextual_key_image_set) -> bool
            {
                return has_key_image(contextual_key_image_set, new_record_key_image);
            }
        );

    if (contextual_key_images_of_record_spent_in_this_chunk != chunk_contextual_key_images.end())
    {
        // a. record that the enote is spent in this chunk
        found_spent_key_images_inout[new_record_key_image];

        // b. update its spent context (update instead of assignment in case of duplicates)
        try_update_enote_spent_context_v1(contextual_key_images_of_record_spent_in_this_chunk->spent_context,
            found_spent_key_images_inout[new_record_key_image]);

        // c. save the record's current spent context
        spent_context_update = found_spent_key_images_inout[new_record_key_image];

        // d. save the tx id of the tx where this enote was spent (the tx is in this chunk)
        // note: use the spent context of the contextual key images instead of the spent context update in case the
        //       update did not resolve to a tx in this chunk (probably a bug, but better safe than sorry here)
        txs_have_spent_enotes_inout.insert(
                contextual_key_images_of_record_spent_in_this_chunk->spent_context.transaction_id
            );
    }

    // 3. update the record's contexts
    update_contextual_enote_record_contexts_v1(new_record_origin_context,
        spent_context_update,
        found_enote_records_inout[new_record_key_image].origin_context,
        found_enote_records_inout[new_record_key_image].spent_context);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void collect_legacy_key_images_from_tx(const rct::key &requested_tx_id,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &legacy_key_images_in_tx_inout)
{
    // 1. find key images of the requested tx
    auto contextual_key_images_of_requested_tx =
        std::find_if(
            chunk_contextual_key_images.begin(),
            chunk_contextual_key_images.end(),
            [&requested_tx_id](const SpContextualKeyImageSetV1 &contextual_key_image_set) -> bool
            {
                return contextual_key_image_set.spent_context.transaction_id == requested_tx_id;
            }
        );

    CHECK_AND_ASSERT_THROW_MES(contextual_key_images_of_requested_tx != chunk_contextual_key_images.end(),
        "enote scanning (collect legacy key images from tx): could not find tx's key images.");

    // 2. record legacy key images and their spent contexts
    for (const crypto::key_image &legacy_key_image : contextual_key_images_of_requested_tx->legacy_key_images)
    {
        try_update_enote_spent_context_v1(contextual_key_images_of_requested_tx->spent_context,
            legacy_key_images_in_tx_inout[legacy_key_image]);
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::unordered_set<rct::key> process_chunk_sp_selfsend_pass(
    const std::unordered_set<rct::key> &txs_have_spent_enotes,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::x25519_secret_key &xk_find_received,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records_inout,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_sp_key_images_inout,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &legacy_key_images_in_sp_selfspends_inout)
{
    // for each tx in this chunk that spends one of our enotes, check if any of the basic records attached to that
    //   tx contain a self-send enote owned by us
    // - if any self-send enotes identified here are also spent in txs in this chunk, return those txs' ids so this
    //   function can be called in a loop (those txs will contain self-send enotes that need to be scanned and that may
    //   in turn be spent in this chunk)
    std::unordered_set<rct::key> txs_have_spent_enotes_fresh;
    SpEnoteRecordV1 new_enote_record;

    for (const rct::key &tx_with_spent_enotes : txs_have_spent_enotes)
    {
        CHECK_AND_ASSERT_THROW_MES(chunk_basic_records_per_tx.find(tx_with_spent_enotes) !=
                chunk_basic_records_per_tx.end(),
            "enote scan process chunk (self-send passthroughs): tx with spent enotes not found in records map (bug).");

        for (const ContextualBasicRecordVariant &contextual_basic_record :
            chunk_basic_records_per_tx.at(tx_with_spent_enotes))
        {
            if (!contextual_basic_record.is_type<SpContextualBasicEnoteRecordV1>())
                continue;

            try
            {
                // a. check if the enote is owned by attempting to convert it to a full enote record (selfsend conversion)
                if (!try_get_enote_record_v1_selfsend(
                        contextual_basic_record.unwrap<SpContextualBasicEnoteRecordV1>().record.enote,
                        contextual_basic_record.unwrap<SpContextualBasicEnoteRecordV1>().record
                            .enote_ephemeral_pubkey,
                        contextual_basic_record.unwrap<SpContextualBasicEnoteRecordV1>().record
                            .input_context,
                        jamtis_spend_pubkey,
                        k_view_balance,
                        xk_find_received,
                        s_generate_address,
                        cipher_context,
                        new_enote_record))
                    continue;

                // b. we found an owned enote, so handle it
                // - this will also check if the enote was spent in this chunk, and update 'txs_have_spent_enotes'
                //   accordingly
                update_with_new_record_sp(new_enote_record,
                    origin_context_ref(contextual_basic_record),
                    chunk_contextual_key_images,
                    found_enote_records_inout,
                    found_spent_sp_key_images_inout,
                    txs_have_spent_enotes_fresh);

                // c. record all legacy key images attached to this selfsend for the caller to deal with
                // - all key images of legacy owned enotes spent in seraphis txs will be attached to seraphis
                //   txs with selfsend outputs, but during seraphis scanning it isn't guaranteed that we will be able
                //   to check if legacy key images attached to selfsend owned enotes are associated with owned legacy
                //   enotes; therefore we cache those legacy key images so they can be handled outside this scan process
                collect_legacy_key_images_from_tx(origin_context_ref(contextual_basic_record).transaction_id,
                    chunk_contextual_key_images,
                    legacy_key_images_in_sp_selfspends_inout);
            } catch (...) {}
        }
    }

    return txs_have_spent_enotes_fresh;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
bool try_find_legacy_enotes_in_tx(const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const std::uint64_t block_index,
    const std::uint64_t block_timestamp,
    const rct::key &transaction_id,
    const std::uint64_t total_enotes_before_tx,
    const std::uint64_t unlock_time,
    const TxExtra &tx_memo,
    const std::vector<LegacyEnoteVariant> &enotes_in_tx,
    const SpEnoteOriginStatus origin_status,
    hw::device &hwdev,
    std::list<ContextualBasicRecordVariant> &basic_records_in_tx_out)
{
    basic_records_in_tx_out.clear();

    // 1. extract enote ephemeral pubkeys from the memo
    crypto::public_key legacy_main_enote_ephemeral_pubkey;
    std::vector<crypto::public_key> legacy_additional_enote_ephemeral_pubkeys;

    extract_legacy_enote_ephemeral_pubkeys_from_tx_extra(tx_memo,
        legacy_main_enote_ephemeral_pubkey,
        legacy_additional_enote_ephemeral_pubkeys);

    // 2. check if there are a valid number of additional enote ephemeral pubkeys
    if (legacy_additional_enote_ephemeral_pubkeys.size() > 0 &&
        legacy_additional_enote_ephemeral_pubkeys.size() != enotes_in_tx.size())
        return false;

    // 3. scan each enote in the tx using the 'additional enote ephemeral pubkeys'
    // - this step is automatically skipped if legacy_additional_enote_ephemeral_pubkeys.size() == 0
    crypto::key_derivation temp_DH_derivation;
    LegacyContextualBasicEnoteRecordV1 temp_contextual_record{};
    bool found_an_enote{false};

    for (std::size_t enote_index{0}; enote_index < legacy_additional_enote_ephemeral_pubkeys.size(); ++enote_index)
    {
        // a. compute the DH derivation for this enote ephemeral pubkey
        hwdev.generate_key_derivation(legacy_additional_enote_ephemeral_pubkeys[enote_index],
            legacy_view_privkey,
            temp_DH_derivation);

        // b. try to recover a contextual basic record from the enote
        if (!try_view_scan_legacy_enote_v1(legacy_base_spend_pubkey,
                legacy_subaddress_map,
                block_index,
                block_timestamp,
                transaction_id,
                total_enotes_before_tx,
                enote_index,
                unlock_time,
                tx_memo,
                enotes_in_tx[enote_index],
                legacy_additional_enote_ephemeral_pubkeys[enote_index],
                temp_DH_derivation,
                origin_status,
                hwdev,
                temp_contextual_record))
            continue;

        // c. save the contextual basic record
        // note: it is possible for enotes with duplicate onetime addresses to be added here; it is assumed the
        //       upstream caller will be able to handle those without problems
        basic_records_in_tx_out.emplace_back(temp_contextual_record);

        // d. record that an owned enote has been found
        found_an_enote = true;
    }

    // 4. check if there is a main enote ephemeral pubkey
    if (legacy_main_enote_ephemeral_pubkey == rct::rct2pk(rct::I))
        return found_an_enote;

    // 5. compute the key derivation for the main enote ephemeral pubkey
    hwdev.generate_key_derivation(legacy_main_enote_ephemeral_pubkey, legacy_view_privkey, temp_DH_derivation);

    // 6. scan all enotes using the main key derivation
    for (std::size_t enote_index{0}; enote_index < enotes_in_tx.size(); ++enote_index)
    {
        // a. try to recover a contextual basic record from the enote
        if (!try_view_scan_legacy_enote_v1(legacy_base_spend_pubkey,
                legacy_subaddress_map,
                block_index,
                block_timestamp,
                transaction_id,
                total_enotes_before_tx,
                enote_index,
                unlock_time,
                tx_memo,
                enotes_in_tx[enote_index],
                legacy_main_enote_ephemeral_pubkey,
                temp_DH_derivation,
                origin_status,
                hwdev,
                temp_contextual_record))
            continue;

        // b. save the contextual basic record
        // note: it is possible for enotes with duplicate onetime addresses to be added here; it is assumed the
        //       upstream caller will be able to handle those without problems
        basic_records_in_tx_out.emplace_back(temp_contextual_record);

        // c. record that an owned enote has been found
        found_an_enote = true;
    }

    return found_an_enote;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_find_sp_enotes_in_tx(const crypto::x25519_secret_key &xk_find_received,
    const std::uint64_t block_index,
    const std::uint64_t block_timestamp,
    const rct::key &transaction_id,
    const std::uint64_t total_enotes_before_tx,
    const rct::key &input_context,
    const SpTxSupplementV1 &tx_supplement,
    const std::vector<SpEnoteVariant> &enotes_in_tx,
    const SpEnoteOriginStatus origin_status,
    std::list<ContextualBasicRecordVariant> &basic_records_in_tx_out)
{
    basic_records_in_tx_out.clear();

    // 1. check if any enotes can be scanned
    if (tx_supplement.output_enote_ephemeral_pubkeys.size() == 0 ||
        enotes_in_tx.size() == 0)
        return false;

    // 2. find-received scan each enote in the tx
    std::size_t ephemeral_pubkey_index{0};
    crypto::x25519_pubkey temp_DH_derivation;
    SpContextualBasicEnoteRecordV1 temp_contextual_record{};
    bool found_an_enote{false};

    for (std::size_t enote_index{0}; enote_index < enotes_in_tx.size(); ++enote_index)
    {
        // a. get the next Diffie-Hellman derivation
        // - there can be fewer ephemeral pubkeys than enotes; when we get to the end, keep using the last one
        if (enote_index < tx_supplement.output_enote_ephemeral_pubkeys.size())
        {
            ephemeral_pubkey_index = enote_index;
            crypto::x25519_scmul_key(xk_find_received,
                tx_supplement.output_enote_ephemeral_pubkeys[ephemeral_pubkey_index],
                temp_DH_derivation);
        }

        // b, find-receive scan the enote (in try block in case enote is malformed)
        try
        {
            if (!try_get_basic_enote_record_v1(enotes_in_tx[enote_index],
                    tx_supplement.output_enote_ephemeral_pubkeys[ephemeral_pubkey_index],
                    input_context,
                    temp_DH_derivation,
                    temp_contextual_record.record))
                continue;
        } catch (...) { continue; }

        // c. set the origin context
        temp_contextual_record.origin_context =
            SpEnoteOriginContextV1{
                    .block_index        = block_index,
                    .block_timestamp    = block_timestamp,
                    .transaction_id     = transaction_id,
                    .enote_tx_index     = enote_index,
                    .enote_ledger_index = total_enotes_before_tx + enote_index,
                    .origin_status      = origin_status,
                    .memo               = tx_supplement.tx_extra
                };

        // d. save the contextual basic record
        // note: it is possible for enotes with duplicate onetime addresses to be added here; it is assumed the
        //       upstream caller will be able to handle those without problems
        basic_records_in_tx_out.emplace_back(temp_contextual_record);

        // e. record that an enote was found
        found_an_enote = true;
    }

    return found_an_enote;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_collect_key_images_from_tx(const std::uint64_t block_index,
    const std::uint64_t block_timestamp,
    const rct::key &transaction_id,
    std::vector<crypto::key_image> legacy_key_images_in_tx,
    std::vector<crypto::key_image> sp_key_images_in_tx,
    const SpEnoteSpentStatus spent_status,
    SpContextualKeyImageSetV1 &contextual_key_images_out)
{
    // 1. don't make the set if there are no key images
    if (legacy_key_images_in_tx.size() == 0 &&
        sp_key_images_in_tx.size() == 0)
        return false;

    // 2. make the set
    contextual_key_images_out = SpContextualKeyImageSetV1{
            .legacy_key_images = std::move(legacy_key_images_in_tx),
            .sp_key_images     = std::move(sp_key_images_in_tx),
            .spent_context     =
                SpEnoteSpentContextV1{
                    .block_index     = block_index,
                    .block_timestamp = block_timestamp,
                    .transaction_id  = transaction_id,
                    .spent_status    = spent_status
                }
        };

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void process_chunk_intermediate_legacy(const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_view_privkey,
    const std::function<bool(const crypto::key_image&)> &check_key_image_is_known_func,
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    hw::device &hwdev,
    std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1> &found_enote_records_out,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images_out)
{
    found_enote_records_out.clear();
    found_spent_key_images_out.clear();

    // 1. check if any legacy owned enotes have been spent in this chunk (key image matches)
    auto key_image_handler =
        [&](const SpEnoteSpentContextV1 &spent_context, const crypto::key_image &key_image)
        {
            // ask callback if key image is known (i.e. if the key image is attached to an owned enote acquired before
            //    this chunk)
            if (check_key_image_is_known_func(key_image))
            {
                // a. record the found spent key image
                found_spent_key_images_out[key_image];

                // b. update its spent context (use update instead of assignment in case of duplicates)
                try_update_enote_spent_context_v1(spent_context, found_spent_key_images_out[key_image]);
            }
        };

    for (const SpContextualKeyImageSetV1 &contextual_key_image_set : chunk_contextual_key_images)
    {
        for (const crypto::key_image &key_image : contextual_key_image_set.legacy_key_images)
            key_image_handler(contextual_key_image_set.spent_context, key_image);
    }

    // 2. check for legacy owned enotes in this chunk
    LegacyIntermediateEnoteRecord new_enote_record;

    for (const auto &tx_basic_records : chunk_basic_records_per_tx)
    {
        for (const ContextualBasicRecordVariant &contextual_basic_record : tx_basic_records.second)
        {
            if (!contextual_basic_record.is_type<LegacyContextualBasicEnoteRecordV1>())
                continue;

            try
            {
                // a. check if we own the enote by attempting to convert it to an intermediate enote record
                if (!try_get_legacy_intermediate_enote_record(
                        contextual_basic_record.unwrap<LegacyContextualBasicEnoteRecordV1>().record,
                        legacy_base_spend_pubkey,
                        legacy_view_privkey,
                        hwdev,
                        new_enote_record))
                    continue;

                // b. we found an owned enote, so handle it
                update_with_new_intermediate_record_legacy(new_enote_record,
                    origin_context_ref(contextual_basic_record),
                    found_enote_records_out);
            } catch (...) {}
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
void process_chunk_full_legacy(const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_spend_privkey,
    const crypto::secret_key &legacy_view_privkey,
    const std::function<bool(const crypto::key_image&)> &check_key_image_is_known_func,
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    hw::device &hwdev,
    std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> &found_enote_records_out,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images_out)
{
    found_enote_records_out.clear();
    found_spent_key_images_out.clear();

    // 1. check if any legacy owned enotes acquired before this chunk were spent in this chunk (key image matches)
    auto key_image_handler =
        [&](const SpEnoteSpentContextV1 &spent_context, const crypto::key_image &key_image)
        {
            // a. ask callback if key image is known (i.e. if the key image is attached to an owned enote acquired before
            //    this chunk)
            if (check_key_image_is_known_func(key_image))
            {
                // i. record the found spent key image
                found_spent_key_images_out[key_image];

                // ii. update its spent context (use update instead of assignment in case of duplicates)
                try_update_enote_spent_context_v1(spent_context, found_spent_key_images_out[key_image]);
            }
        };

    for (const SpContextualKeyImageSetV1 &contextual_key_image_set : chunk_contextual_key_images)
    {
        for (const crypto::key_image &key_image : contextual_key_image_set.legacy_key_images)
            key_image_handler(contextual_key_image_set.spent_context, key_image);
    }

    // 2. check for legacy owned enotes in this chunk
    LegacyEnoteRecord new_enote_record;

    for (const auto &tx_basic_records : chunk_basic_records_per_tx)
    {
        for (const ContextualBasicRecordVariant &contextual_basic_record : tx_basic_records.second)
        {
            if (!contextual_basic_record.is_type<LegacyContextualBasicEnoteRecordV1>())
                continue;

            try
            {
                // a. check if we own the enote by attempting to convert it to a full enote record
                if (!try_get_legacy_enote_record(
                        contextual_basic_record.unwrap<LegacyContextualBasicEnoteRecordV1>().record,
                        legacy_base_spend_pubkey,
                        legacy_spend_privkey,
                        legacy_view_privkey,
                        hwdev,
                        new_enote_record))
                    continue;

                // b. we found an owned enote, so handle it
                update_with_new_record_legacy(new_enote_record,
                    origin_context_ref(contextual_basic_record),
                    chunk_contextual_key_images,
                    found_enote_records_out,
                    found_spent_key_images_out);
            } catch (...) {}
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
void process_chunk_intermediate_sp(const rct::key &jamtis_spend_pubkey,
    const crypto::x25519_secret_key &xk_unlock_amounts,
    const crypto::x25519_secret_key &xk_find_received,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1> &found_enote_records_out)
{
    found_enote_records_out.clear();

    // check for owned enotes in this chunk (non-self-send intermediate scanning pass)
    SpIntermediateEnoteRecordV1 new_enote_record;

    for (const auto &tx_basic_records : chunk_basic_records_per_tx)
    {
        for (const ContextualBasicRecordVariant &contextual_basic_record : tx_basic_records.second)
        {
            if (!contextual_basic_record.is_type<SpContextualBasicEnoteRecordV1>())
                continue;

            try
            {
                // a. check if we own the enote by attempting to convert it to an intermediate enote record
                if (!try_get_intermediate_enote_record_v1(
                        contextual_basic_record.unwrap<SpContextualBasicEnoteRecordV1>().record,
                        jamtis_spend_pubkey,
                        xk_unlock_amounts,
                        xk_find_received,
                        s_generate_address,
                        cipher_context,
                        new_enote_record))
                    continue;

                // b. we found an owned enote, so handle it
                update_with_new_intermediate_record_sp(new_enote_record,
                    origin_context_ref(contextual_basic_record),
                    found_enote_records_out);
            } catch (...) {}
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
void process_chunk_full_sp(const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::x25519_secret_key &xk_unlock_amounts,
    const crypto::x25519_secret_key &xk_find_received,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    const std::function<bool(const crypto::key_image&)> &check_key_image_is_known_func,
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records_out,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_sp_key_images_out,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &legacy_key_images_in_sp_selfspends_out)
{
    found_enote_records_out.clear();
    found_spent_sp_key_images_out.clear();
    legacy_key_images_in_sp_selfspends_out.clear();

    // 1. check if any owned enotes acquired before this chunk were spent in this chunk (key image matches)
    std::unordered_set<rct::key> txs_have_spent_enotes;

    auto key_image_handler =
        [&](const SpEnoteSpentContextV1 &spent_context, const crypto::key_image &key_image)
        {
            // a. ask callback if key image is known (i.e. if the key image is attached to an owned enote acquired before
            //    this chunk)
            if (check_key_image_is_known_func(key_image))
            {
                // i. record the found spent key image
                found_spent_sp_key_images_out[key_image];

                // ii. update its spent context (use update instead of assignment in case of duplicates)
                try_update_enote_spent_context_v1(spent_context, found_spent_sp_key_images_out[key_image]);

                // iii. record tx id of the tx that contains this key image (this tx spent an enote that we acquired
                //      before this chunk)
                txs_have_spent_enotes.insert(spent_context.transaction_id);
            }
        };

    for (const SpContextualKeyImageSetV1 &contextual_key_image_set : chunk_contextual_key_images)
    {
        // - We don't check if legacy key images are known from before this chunk because during a comprehensive view-only
        //   scan legacy key images are not computable by the legacy view key, so there may be owned legacy enotes with
        //   unknown key images. This means there may be txs in this chunk with our selfsends but only legacy key images
        //   that can't be identified - so we need to do a selfsend check on all of those txs. All legacy key images in
        //   txs that have both legacy key images and seraphis selfsends will be recorded along with their spent contexts
        //   for the caller to cache in preparation for when they are able to match key images with legacy enotes.

        // a. invoke the key image handler for seraphis key images in the chunk
        for (const crypto::key_image &key_image : contextual_key_image_set.sp_key_images)
            key_image_handler(contextual_key_image_set.spent_context, key_image);

        // b. save tx ids of txs that contain at least one legacy key image, so they can be examined by the selfsend pass
        if (contextual_key_image_set.legacy_key_images.size() > 0)
            txs_have_spent_enotes.insert(contextual_key_image_set.spent_context.transaction_id);
    }

    // 2. check if this chunk contains owned enotes (non-self-send pass)
    SpEnoteRecordV1 new_enote_record;

    for (const auto &tx_basic_records : chunk_basic_records_per_tx)
    {
        for (const ContextualBasicRecordVariant &contextual_basic_record : tx_basic_records.second)
        {
            if (!contextual_basic_record.is_type<SpContextualBasicEnoteRecordV1>())
                continue;

            try
            {
                // a. check if we own the enote by attempting to convert it to a full enote record
                if (!try_get_enote_record_v1_plain(
                        contextual_basic_record.unwrap<SpContextualBasicEnoteRecordV1>().record,
                        jamtis_spend_pubkey,
                        k_view_balance,
                        xk_unlock_amounts,
                        xk_find_received,
                        s_generate_address,
                        cipher_context,
                        new_enote_record))
                    continue;

                // b. we found an owned enote, so handle it
                // - this will also check if the enote was spent in this chunk, and update 'txs_have_spent_enotes'
                //   accordingly
                update_with_new_record_sp(new_enote_record,
                    origin_context_ref(contextual_basic_record),
                    chunk_contextual_key_images,
                    found_enote_records_out,
                    found_spent_sp_key_images_out,
                    txs_have_spent_enotes);
            } catch (...) {}
        }
    }

    // 3. check for owned enotes in this chunk (self-send passes)
    // - a selfsend pass identifies owned selfsend enotes in txs that have been flagged, and then flags txs where
    //   those enotes have been spent in this chunk
    // - we loop through selfsend passes until no more txs are flagged
    while (txs_have_spent_enotes.size() > 0)
    {
        txs_have_spent_enotes =
            process_chunk_sp_selfsend_pass(txs_have_spent_enotes,
                jamtis_spend_pubkey,
                k_view_balance,
                xk_find_received,
                s_generate_address,
                cipher_context,
                chunk_basic_records_per_tx,
                chunk_contextual_key_images,
                found_enote_records_out,
                found_spent_sp_key_images_out,
                legacy_key_images_in_sp_selfspends_out);
    }
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace scanning
} //namespace sp
