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

//paired header
#include "tx_enote_scanning_utils.h"

//local headers
#include "crypto/crypto.h"
#include "cryptonote_basic/subaddress_index.h"
#include "device/device.hpp"
#include "jamtis_core_utils.h"
#include "legacy_core_utils.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_crypto_utils.h"
#include "tx_component_types.h"
#include "tx_contextual_enote_record_types.h"
#include "tx_contextual_enote_record_utils.h"
#include "tx_enote_finding_context.h"
#include "tx_enote_record_types.h"
#include "tx_enote_record_utils.h"
#include "tx_enote_scanning.h"
#include "tx_enote_scanning_context.h"
#include "tx_extra.h"
#include "tx_legacy_enote_record_utils.h"

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
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void process_chunk_new_intermediate_record_update_legacy(const LegacyIntermediateEnoteRecord &new_enote_record,
    const SpEnoteOriginContextV1 &new_record_origin_context,
    std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1> &found_enote_records_inout)
{
    // 1. add new legacy record to found enotes (or refresh if already there)
    const rct::key new_record_identifier{
            rct::cn_fast_hash({new_enote_record.m_enote.onetime_address(), new_enote_record.m_enote.amount_commitment()})
        };

    found_enote_records_inout[new_record_identifier].m_record = new_enote_record;

    // 2. update the contextual enote record's origin context
    try_update_enote_origin_context_v1(new_record_origin_context,
        found_enote_records_inout[new_record_identifier].m_origin_context);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void process_chunk_new_intermediate_record_update_sp(const SpIntermediateEnoteRecordV1 &new_enote_record,
    const SpEnoteOriginContextV1 &new_record_origin_context,
    std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1> &found_enote_records_inout)
{
    // 1. add new record to found enotes (or refresh if already there)
    const rct::key &new_record_onetime_address{new_enote_record.m_enote.m_core.m_onetime_address};

    found_enote_records_inout[new_record_onetime_address].m_record = new_enote_record;

    // 2. update the contextual enote record's origin context
    try_update_enote_origin_context_v1(new_record_origin_context,
        found_enote_records_inout[new_record_onetime_address].m_origin_context);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void process_chunk_new_record_update_legacy(const LegacyEnoteRecord &new_enote_record,
    const SpEnoteOriginContextV1 &new_record_origin_context,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> &found_enote_records_inout,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images_inout)
{
    // 1. add new legacy record to found enotes (or refresh if already there)
    const rct::key new_record_identifier{
            rct::cn_fast_hash({new_enote_record.m_enote.onetime_address(), new_enote_record.m_enote.amount_commitment()})
        };

    found_enote_records_inout[new_record_identifier].m_record = new_enote_record;

    // 2. handle if this enote record is spent in this chunk
    const crypto::key_image &new_record_key_image{new_enote_record.m_key_image};
    SpEnoteSpentContextV1 spent_context_update{};

    auto contextual_key_images_of_record_spent_in_this_chunk =
        std::find_if(
            chunk_contextual_key_images.begin(),
            chunk_contextual_key_images.end(),
            [&](const SpContextualKeyImageSetV1 &contextual_key_image_set) -> bool
            {
                return contextual_key_image_set.has_key_image(new_record_key_image);
            }
        );

    if (contextual_key_images_of_record_spent_in_this_chunk != chunk_contextual_key_images.end())
    {
        // a. record that the enote is spent in this chunk
        found_spent_key_images_inout[new_record_key_image];

        // b. update its spent context (update instead of assignment in case of duplicates)
        try_update_enote_spent_context_v1(contextual_key_images_of_record_spent_in_this_chunk->m_spent_context,
            found_spent_key_images_inout[new_record_key_image]);

        // c. get the record's current spent context
        spent_context_update = found_spent_key_images_inout[new_record_key_image];
    }

    // 3. update the contextual enote record's contexts
    // note: multiple legacy enotes can have the same key image but different amounts; only one of those can be spent,
    //       so we should expect all of them to reference the same spent context
    update_contextual_enote_record_contexts_v1(new_record_origin_context,
        spent_context_update,
        found_enote_records_inout[new_record_identifier].m_origin_context,
        found_enote_records_inout[new_record_identifier].m_spent_context);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void process_chunk_new_record_update_sp(const SpEnoteRecordV1 &new_enote_record,
    const SpEnoteOriginContextV1 &new_record_origin_context,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records_inout,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images_inout,
    std::unordered_set<rct::key> &txs_have_spent_enotes_inout)
{
    // 1. add new record to found enotes (or refresh if already there)
    const crypto::key_image &new_record_key_image{new_enote_record.m_key_image};

    found_enote_records_inout[new_record_key_image].m_record = new_enote_record;

    // 2. handle if this enote record is spent in this chunk
    SpEnoteSpentContextV1 spent_context_update{};

    auto contextual_key_images_of_record_spent_in_this_chunk =
        std::find_if(
            chunk_contextual_key_images.begin(),
            chunk_contextual_key_images.end(),
            [&](const SpContextualKeyImageSetV1 &contextual_key_image_set) -> bool
            {
                return contextual_key_image_set.has_key_image(new_record_key_image);
            }
        );

    if (contextual_key_images_of_record_spent_in_this_chunk != chunk_contextual_key_images.end())
    {
        // a. record that the enote is spent in this chunk
        found_spent_key_images_inout[new_record_key_image];

        // b. update its spent context (update instead of assignment in case of duplicates)
        try_update_enote_spent_context_v1(contextual_key_images_of_record_spent_in_this_chunk->m_spent_context,
            found_spent_key_images_inout[new_record_key_image]);

        // c. get the record's current spent context
        spent_context_update = found_spent_key_images_inout[new_record_key_image];

        // d. save the tx id of the tx where this enote was spent
        txs_have_spent_enotes_inout.insert(spent_context_update.m_transaction_id);
    }

    // 3. update the contextual enote record's contexts
    update_contextual_enote_record_contexts_v1(new_record_origin_context,
        spent_context_update,
        found_enote_records_inout[new_record_key_image].m_origin_context,
        found_enote_records_inout[new_record_key_image].m_spent_context);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
bool try_find_legacy_enotes_in_tx(const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_view_privkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const std::uint64_t block_height,
    const std::uint64_t block_timestamp,
    const rct::key &transaction_id,
    const std::uint64_t total_enotes_before_tx,
    const std::uint64_t unlock_time,
    const TxExtra &tx_memo,
    const std::vector<LegacyEnoteVariant> &enotes_in_tx,
    const SpEnoteOriginStatus origin_status,
    hw::device &hwdev,
    std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &basic_records_per_tx_inout)
{
    // extract enote ephemeral pubkeys from memo
    std::vector<crypto::public_key> legacy_enote_ephemeral_pubkeys;
    extract_legacy_enote_ephemeral_pubkeys_from_tx_extra(tx_memo, legacy_enote_ephemeral_pubkeys);

    if (legacy_enote_ephemeral_pubkeys.size() == 0)
        return false;

    // scan each enote in the tx
    std::size_t ephemeral_pubkey_index{0};
    crypto::key_derivation temp_DH_derivation;
    LegacyContextualBasicEnoteRecordV1 temp_contextual_record{};
    bool found_an_enote{false};

    for (std::size_t enote_index{0}; enote_index < enotes_in_tx.size(); ++enote_index)
    {
        // there can be fewer ephemeral pubkeys than enotes
        // - when we get to the end, keep using the last one
        if (enote_index < legacy_enote_ephemeral_pubkeys.size())
        {
            ephemeral_pubkey_index = enote_index;
            hwdev.generate_key_derivation(
                legacy_enote_ephemeral_pubkeys[ephemeral_pubkey_index],
                legacy_view_privkey,
                temp_DH_derivation);
        }

        // view scan the enote (in try block in case enote is malformed)
        try
        {
            if (try_get_legacy_basic_enote_record(enotes_in_tx[enote_index],
                rct::pk2rct(legacy_enote_ephemeral_pubkeys[ephemeral_pubkey_index]),
                enote_index,
                unlock_time,
                temp_DH_derivation,
                legacy_base_spend_pubkey,
                legacy_subaddress_map,
                hwdev,
                temp_contextual_record.m_record))
            {
                temp_contextual_record.m_origin_context =
                    SpEnoteOriginContextV1{
                            .m_block_height = block_height,
                            .m_block_timestamp = block_timestamp,
                            .m_transaction_id = transaction_id,
                            .m_enote_ledger_index = total_enotes_before_tx + enote_index,
                            .m_origin_status = origin_status,
                            .m_memo = tx_memo
                        };

                // note: it is possible for enotes with duplicate onetime addresses to be added here; it is assumed the
                //       upstream caller will be able to handle that case without problems
                basic_records_per_tx_inout[transaction_id].emplace_back(temp_contextual_record);

                found_an_enote = true;
            }
        } catch (...) {}
    }

    return found_an_enote;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_find_sp_enotes_in_tx(const crypto::secret_key &k_find_received,
    const std::uint64_t block_height,
    const std::uint64_t block_timestamp,
    const rct::key &transaction_id,
    const std::uint64_t total_enotes_before_tx,
    const rct::key &input_context,
    const SpTxSupplementV1 &tx_supplement,
    const std::vector<SpEnoteV1> &enotes_in_tx,
    const SpEnoteOriginStatus origin_status,
    hw::device &hwdev,
    std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &basic_records_per_tx_inout)
{
    if (tx_supplement.m_output_enote_ephemeral_pubkeys.size() == 0)
        return false;

    // scan each enote in the tx
    std::size_t ephemeral_pubkey_index{0};
    crypto::key_derivation temp_DH_derivation;
    SpContextualBasicEnoteRecordV1 temp_contextual_record{};
    bool found_an_enote{false};

    for (std::size_t enote_index{0}; enote_index < enotes_in_tx.size(); ++enote_index)
    {
        // there can be fewer ephemeral pubkeys than enotes
        // - when we get to the end, keep using the last one
        if (enote_index < tx_supplement.m_output_enote_ephemeral_pubkeys.size())
        {
            ephemeral_pubkey_index = enote_index;
            hwdev.generate_key_derivation(
                rct::rct2pk(tx_supplement.m_output_enote_ephemeral_pubkeys[ephemeral_pubkey_index]),
                k_find_received,
                temp_DH_derivation);
        }

        // find-receive scan the enote (in try block in case enote is malformed)
        try
        {
            if (try_get_basic_enote_record_v1(enotes_in_tx[enote_index],
                tx_supplement.m_output_enote_ephemeral_pubkeys[ephemeral_pubkey_index],
                input_context,
                temp_DH_derivation,
                temp_contextual_record.m_record))
            {
                temp_contextual_record.m_origin_context =
                    SpEnoteOriginContextV1{
                            .m_block_height = block_height,
                            .m_block_timestamp = block_timestamp,
                            .m_transaction_id = transaction_id,
                            .m_enote_ledger_index = total_enotes_before_tx + enote_index,
                            .m_origin_status = origin_status,
                            .m_memo = tx_supplement.m_tx_extra
                        };

                // note: it is possible for enotes with duplicate onetime addresses to be added here; it is assumed the
                //       upstream caller will be able to handle that case without problems
                basic_records_per_tx_inout[transaction_id].emplace_back(temp_contextual_record);

                found_an_enote = true;
            }
        } catch (...) {}
    }

    return found_an_enote;
}
//-------------------------------------------------------------------------------------------------------------------
void collect_key_images_from_tx(const std::uint64_t block_height,
    const std::uint64_t block_timestamp,
    const rct::key &transaction_id,
    const std::vector<crypto::key_image> &legacy_key_images_in_tx,
    const std::vector<crypto::key_image> &sp_key_images_in_tx,
    const SpEnoteSpentStatus spent_status,
    std::list<SpContextualKeyImageSetV1> &contextual_key_images_inout)
{
    if (legacy_key_images_in_tx.size() == 0 &&
        sp_key_images_in_tx.size() == 0)
        return;

    contextual_key_images_inout.emplace_back(
            SpContextualKeyImageSetV1{
                .m_legacy_key_images = legacy_key_images_in_tx,
                .m_sp_key_images = sp_key_images_in_tx,
                .m_spent_context =
                    SpEnoteSpentContextV1{
                        .m_block_height = block_height,
                        .m_block_timestamp = block_timestamp,
                        .m_transaction_id = transaction_id,
                        .m_spent_status = spent_status
                    }
            }
        );
}
//-------------------------------------------------------------------------------------------------------------------
void process_chunk_intermediate_legacy(const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_view_privkey,
    const std::function<bool(const crypto::key_image&)> &check_key_image_is_known_func,
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1> &found_enote_records_inout,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images_inout)
{
    // 1. check if any legacy owned enotes have been spent in this chunk (key image matches)
    auto key_image_handler =
        [&](const SpEnoteSpentContextV1 &spent_context, const crypto::key_image &key_image)
        {
            // check if key image was known before this scan
            // note: this intermediate scan cannot detect if enotes owned in this scan are also spent in this scan
            if (check_key_image_is_known_func(key_image))
            {
                // record the found spent key image
                found_spent_key_images_inout[key_image];

                // update its spent context (use update instead of assignment in case of duplicates)
                try_update_enote_spent_context_v1(spent_context, found_spent_key_images_inout[key_image]);
            }
        };

    for (const SpContextualKeyImageSetV1 &contextual_key_image_set : chunk_contextual_key_images)
    {
        for (const crypto::key_image &key_image : contextual_key_image_set.m_legacy_key_images)
            key_image_handler(contextual_key_image_set.m_spent_context, key_image);
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
                if (try_get_legacy_intermediate_enote_record(
                    contextual_basic_record.get_contextual_record<LegacyContextualBasicEnoteRecordV1>().m_record,
                    legacy_base_spend_pubkey,
                    legacy_view_privkey,
                    new_enote_record))
                {
                    process_chunk_new_intermediate_record_update_legacy(new_enote_record,
                        contextual_basic_record.origin_context(),
                        found_enote_records_inout);
                }
            } catch (...) {}
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
void process_chunk_intermediate_sp(const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_unlock_amounts,
    const crypto::secret_key &k_find_received,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1> &found_enote_records_inout)
{
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
                if (try_get_intermediate_enote_record_v1(
                    contextual_basic_record.get_contextual_record<SpContextualBasicEnoteRecordV1>().m_record,
                    wallet_spend_pubkey,
                    k_unlock_amounts,
                    k_find_received,
                    s_generate_address,
                    cipher_context,
                    new_enote_record))
                {
                    process_chunk_new_intermediate_record_update_sp(new_enote_record,
                        contextual_basic_record.origin_context(),
                        found_enote_records_inout);
                }
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
    std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> &found_enote_records_inout,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images_inout)
{
    // 1. check if any legacy owned enotes have been spent in this chunk (key image matches)
    auto key_image_handler =
        [&](const SpEnoteSpentContextV1 &spent_context, const crypto::key_image &key_image)
        {
            // a. check if key image was known before this scan
            // b. check if key image matches with any enote records found before this chunk
            if (check_key_image_is_known_func(key_image) ||
                std::find_if(found_enote_records_inout.begin(), found_enote_records_inout.end(),
                    [&key_image](const std::pair<rct::key, LegacyContextualEnoteRecordV1> &mapped_legacy_record) -> bool
                    {
                        return mapped_legacy_record.second.m_record.m_key_image == key_image;
                    }) != found_enote_records_inout.end()
                )
            {
                // record the found spent key image
                found_spent_key_images_inout[key_image];

                // update its spent context (use update instead of assignment in case of duplicates)
                try_update_enote_spent_context_v1(spent_context, found_spent_key_images_inout[key_image]);
            }
        };

    for (const SpContextualKeyImageSetV1 &contextual_key_image_set : chunk_contextual_key_images)
    {
        for (const crypto::key_image &key_image : contextual_key_image_set.m_legacy_key_images)
            key_image_handler(contextual_key_image_set.m_spent_context, key_image);
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
                if (try_get_legacy_enote_record(
                    contextual_basic_record.get_contextual_record<LegacyContextualBasicEnoteRecordV1>().m_record,
                    legacy_base_spend_pubkey,
                    legacy_spend_privkey,
                    legacy_view_privkey,
                    new_enote_record))
                {
                    process_chunk_new_record_update_legacy(new_enote_record,
                        contextual_basic_record.origin_context(),
                        chunk_contextual_key_images,
                        found_enote_records_inout,
                        found_spent_key_images_inout);
                }
            } catch (...) {}
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
void process_chunk_full_sp(const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &k_unlock_amounts,
    const crypto::secret_key &k_find_received,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    const std::function<bool(const crypto::key_image&)> &check_key_image_is_known_func,
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records_inout,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images_inout)
{
    std::unordered_set<rct::key> txs_have_spent_enotes;

    // 1. check if any owned enotes have been spent in this chunk (key image matches)
    auto key_image_handler =
        [&](const SpEnoteSpentContextV1 &spent_context, const crypto::key_image &key_image)
        {
            // a. check if key image was known before this scan
            // b. check if key image matches with any enote records found before this chunk
            if (check_key_image_is_known_func(key_image) ||
                found_enote_records_inout.find(key_image) != found_enote_records_inout.end())
            {
                // record the found spent key image
                found_spent_key_images_inout[key_image];

                // update its spent context (use update instead of assignment in case of duplicates)
                try_update_enote_spent_context_v1(spent_context, found_spent_key_images_inout[key_image]);

                // record tx id of tx that contains one of our key images (i.e. the tx spent one of our known enotes)
                txs_have_spent_enotes.insert(spent_context.m_transaction_id);
            }
        };

    for (const SpContextualKeyImageSetV1 &contextual_key_image_set : chunk_contextual_key_images)
    {
        for (const crypto::key_image &key_image : contextual_key_image_set.m_legacy_key_images)
            key_image_handler(contextual_key_image_set.m_spent_context, key_image);

        for (const crypto::key_image &key_image : contextual_key_image_set.m_sp_key_images)
            key_image_handler(contextual_key_image_set.m_spent_context, key_image);

        // always save tx id of txs that contain at least one legacy key image
        // - checking key image is known may fail for legacy key images, which are not computable by the legacy view key
        if (contextual_key_image_set.m_legacy_key_images.size() > 0)
            txs_have_spent_enotes.insert(contextual_key_image_set.m_spent_context.m_transaction_id);
    }

    // 2. check for owned enotes in this chunk (non-self-send pass)
    SpEnoteRecordV1 new_enote_record;

    for (const auto &tx_basic_records : chunk_basic_records_per_tx)
    {
        for (const ContextualBasicRecordVariant &contextual_basic_record : tx_basic_records.second)
        {
            if (!contextual_basic_record.is_type<SpContextualBasicEnoteRecordV1>())
                continue;

            try
            {
                if (try_get_enote_record_v1_plain(
                    contextual_basic_record.get_contextual_record<SpContextualBasicEnoteRecordV1>().m_record,
                    wallet_spend_pubkey,
                    k_view_balance,
                    k_unlock_amounts,
                    k_find_received,
                    s_generate_address,
                    cipher_context,
                    new_enote_record))
                {
                    process_chunk_new_record_update_sp(new_enote_record,
                        contextual_basic_record.origin_context(),
                        chunk_contextual_key_images,
                        found_enote_records_inout,
                        found_spent_key_images_inout,
                        txs_have_spent_enotes);
                }
            } catch (...) {}
        }
    }

    // 3. check for owned enotes in this chunk (self-send passes)
    // - for each tx in this chunk that spends one of our enotes, check if any of the basic records attached to that
    //   tx contains a self-send enote owned by us
    // - loop in case any self-send enotes acquired in this chunk are also spent in this chunk
    std::unordered_set<rct::key> txs_have_spent_enotes_selfsend_passthrough;

    while (txs_have_spent_enotes.size() > 0)
    {
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
                    if (try_get_enote_record_v1_selfsend(
                        contextual_basic_record.get_contextual_record<SpContextualBasicEnoteRecordV1>().m_record.m_enote,
                        contextual_basic_record.get_contextual_record<SpContextualBasicEnoteRecordV1>().m_record
                            .m_enote_ephemeral_pubkey,
                        contextual_basic_record.get_contextual_record<SpContextualBasicEnoteRecordV1>().m_record
                            .m_input_context,
                        wallet_spend_pubkey,
                        k_view_balance,
                        s_generate_address,
                        new_enote_record))
                    {
                        process_chunk_new_record_update_sp(new_enote_record,
                            contextual_basic_record.origin_context(),
                            chunk_contextual_key_images,
                            found_enote_records_inout,
                            found_spent_key_images_inout,
                            txs_have_spent_enotes_selfsend_passthrough);
                    }
                } catch (...) {}
            }
        }

        txs_have_spent_enotes = std::move(txs_have_spent_enotes_selfsend_passthrough);
        txs_have_spent_enotes_selfsend_passthrough.clear();
    }
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
