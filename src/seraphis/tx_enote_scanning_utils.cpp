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
#include "device/device.hpp"
#include "jamtis_core_utils.h"
#include "ringct/rctTypes.h"
#include "sp_crypto_utils.h"
#include "tx_component_types.h"
#include "tx_enote_finding_context.h"
#include "tx_enote_record_types.h"
#include "tx_enote_record_utils.h"
#include "tx_enote_scanning.h"
#include "tx_enote_scanning_context.h"
#include "tx_enote_store.h"

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
static void process_chunk_new_record_update(const SpEnoteRecordV1 &new_enote_record,
    const SpEnoteOriginContextV1 &new_record_origin_context,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records_inout,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images_inout,
    std::unordered_set<rct::key> &txs_have_spent_enotes_inout)
{
    // 1. add new record to found enotes (or refresh if already there)
    const crypto::key_image new_record_key_image{new_enote_record.m_key_image};

    found_enote_records_inout[new_record_key_image].m_record = new_enote_record;

    // 2. handle if this enote record is spent in this chunk
    SpEnoteSpentContextV1 spent_context_update{};

    auto record_is_spent_in_this_chunk =
        std::find_if(
            chunk_contextual_key_images.begin(),
            chunk_contextual_key_images.end(),
            [&](const SpContextualKeyImageSetV1 &contextual_key_image_set) -> bool
            {
                return contextual_key_image_set.has_key_image(new_record_key_image);
            }
        );

    if (record_is_spent_in_this_chunk != chunk_contextual_key_images.end())
    {
        // a. record that the enote is spent in this chunk
        found_spent_key_images_inout[new_record_key_image];

        // b. update its spent context (update instead of assignment in case of duplicates)
        try_update_enote_spent_context_v1(record_is_spent_in_this_chunk->m_spent_context,
            found_spent_key_images_inout[new_record_key_image]);

        // c. get the record's current spent context
        spent_context_update = found_spent_key_images_inout[new_record_key_image];

        // d. save the tx id of the tx where this enote was spent
        txs_have_spent_enotes_inout.insert(spent_context_update.m_transaction_id);
    }

    // 3. update the contextual enote record's contexts
    update_contextual_enote_record_contexts_v1(new_record_origin_context,
        spent_context_update,
        found_enote_records_inout[new_record_key_image]);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
bool try_find_enotes_in_tx(const crypto::secret_key &k_find_received,
    const std::uint64_t block_height,
    const rct::key &transaction_id,
    const std::uint64_t total_enotes_before_tx,
    const rct::key &input_context,
    const SpTxSupplementV1 &tx_supplement,
    const std::vector<SpEnoteV1> &enotes_in_tx,
    const SpEnoteOriginStatus origin_status,
    hw::device &hwdev,
    std::unordered_map<rct::key, std::list<SpContextualBasicEnoteRecordV1>> &basic_records_per_tx_inout)
{
    if (tx_supplement.m_output_enote_ephemeral_pubkeys.size() == 0)
        return false;

    // scan each enote in the tx
    std::size_t ephemeral_pubkey_index{0};
    crypto::key_derivation temp_DH_derivation;
    std::list<SpContextualBasicEnoteRecordV1> temp_contextual_record;
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

        // prepare record shuttle
        if (temp_contextual_record.size() == 0)
            temp_contextual_record.emplace_back();

        // find-receive scan the enote (in try block in case enote is malformed)
        try
        {
            if (try_get_basic_enote_record_v1(enotes_in_tx[enote_index],
                tx_supplement.m_output_enote_ephemeral_pubkeys[ephemeral_pubkey_index],
                input_context,
                temp_DH_derivation,
                temp_contextual_record.back().m_record))
            {
                temp_contextual_record.back().m_origin_context =
                    SpEnoteOriginContextV1{
                            .m_block_height = block_height,
                            .m_transaction_id = transaction_id,
                            .m_enote_ledger_index = total_enotes_before_tx + enote_index,
                            .m_origin_status = origin_status,
                            .m_memo = tx_supplement.m_tx_extra
                        };

                // note: it is possible for enotes with duplicate onetime addresses to be added here; it is assumed the
                //       upstream caller will be able to handle that case without problems
                auto &basic_records_for_tx = basic_records_per_tx_inout[transaction_id];
                basic_records_for_tx.splice(basic_records_for_tx.end(),
                    temp_contextual_record,
                    temp_contextual_record.begin());

                found_an_enote = true;
            }
        } catch (...) {}
    }

    return found_an_enote;
}
//-------------------------------------------------------------------------------------------------------------------
void collect_key_images_from_tx(const std::uint64_t block_height,
    const rct::key &transaction_id,
    const std::vector<crypto::key_image> &key_images_in_tx,
    const SpEnoteSpentStatus spent_status,
    std::list<SpContextualKeyImageSetV1> &contextual_key_images_inout)
{
    contextual_key_images_inout.emplace_back(
            SpContextualKeyImageSetV1{
                .m_key_images = key_images_in_tx,
                .m_spent_context =
                    SpEnoteSpentContextV1{
                        .m_block_height = block_height,
                        .m_transaction_id = transaction_id,
                        .m_spent_status = spent_status
                    }
            }
        );
}
//-------------------------------------------------------------------------------------------------------------------
void process_chunk_full(const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &k_unlock_amounts,
    const crypto::secret_key &k_find_received,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    const std::function<bool(const crypto::key_image&)> &check_key_image_is_known_func,
    const std::unordered_map<rct::key, std::list<SpContextualBasicEnoteRecordV1>> &chunk_basic_records_per_tx,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records_inout,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images_inout)
{
    std::unordered_set<rct::key> txs_have_spent_enotes;

    // 1. check if any owned enotes have been spent in this chunk (key image matches)
    for (const SpContextualKeyImageSetV1 &contextual_key_image_set : chunk_contextual_key_images)
    {
        for (const crypto::key_image &key_image : contextual_key_image_set.m_key_images)
        {
            // a. check enote store
            // b. check enote records found before this chunk (but not updated in enote store)
            if (check_key_image_is_known_func(key_image) ||
                found_enote_records_inout.find(key_image) != found_enote_records_inout.end())
            {
                // record the found spent key image
                found_spent_key_images_inout[key_image];

                // update its spent context (use update instead of assignment in case of duplicates)
                try_update_enote_spent_context_v1(contextual_key_image_set.m_spent_context,
                    found_spent_key_images_inout[key_image]);

                // record tx id of tx that contains one of our key images (i.e. the tx spent one of our known enotes)
                txs_have_spent_enotes.insert(contextual_key_image_set.m_spent_context.m_transaction_id);
            }
        }
    }

    // 2. check for owned enotes in this chunk (non-self-send pass)
    SpEnoteRecordV1 new_enote_record;

    for (const auto &tx_basic_records : chunk_basic_records_per_tx)
    {
        for (const SpContextualBasicEnoteRecordV1 &contextual_basic_record : tx_basic_records.second)
        {
            try
            {
                if (try_get_enote_record_v1_plain(contextual_basic_record.m_record,
                    wallet_spend_pubkey,
                    k_view_balance,
                    k_unlock_amounts,
                    k_find_received,
                    s_generate_address,
                    cipher_context,
                    new_enote_record))
                {
                    process_chunk_new_record_update(new_enote_record,
                        contextual_basic_record.m_origin_context,
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
            // note: this should never throw since it should be caught in the chunk semantics check
            CHECK_AND_ASSERT_THROW_MES(chunk_basic_records_per_tx.find(tx_with_spent_enotes) !=
                    chunk_basic_records_per_tx.end(),
                "enote scan process chunk (self-send passthroughs): tx with spent enotes not found in records map (bug).");

            for (const SpContextualBasicEnoteRecordV1 &contextual_basic_record :
                chunk_basic_records_per_tx.at(tx_with_spent_enotes))
            {
                try
                {
                    if (try_get_enote_record_v1_selfsend(contextual_basic_record.m_record.m_enote,
                        contextual_basic_record.m_record.m_enote_ephemeral_pubkey,
                        contextual_basic_record.m_record.m_input_context,
                        wallet_spend_pubkey,
                        k_view_balance,
                        s_generate_address,
                        new_enote_record))
                    {
                        process_chunk_new_record_update(new_enote_record,
                            contextual_basic_record.m_origin_context,
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
