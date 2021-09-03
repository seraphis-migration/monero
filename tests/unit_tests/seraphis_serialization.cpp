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

#include "ringct/rctTypes.h"
#include "seraphis_core/binned_reference_set.h"
#include "seraphis_impl/serialization_demo_types.h"
#include "seraphis_impl/serialization_demo_utils.h"
#include "seraphis_main/txtype_base.h"
#include "seraphis_main/txtype_coinbase_v1.h"
#include "seraphis_main/txtype_squashed_v1.h"
#include "seraphis_mocks/seraphis_mocks.h"
#include "span.h"

#include "gtest/gtest.h"

using namespace sp;
using namespace mocks;

//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization_demo, seraphis_coinbase_empty)
{
    // make empty tx
    SpTxCoinbaseV1 tx{};

    // convert the tx to serializable form
    sp::serialization::ser_SpTxCoinbaseV1 serializable_tx;
    EXPECT_NO_THROW(sp::serialization::make_serializable_sp_tx_coinbase_v1(tx, serializable_tx));

    // serialize the tx
    std::string serialized_tx;
    EXPECT_TRUE(sp::serialization::try_append_serializable(serializable_tx, serialized_tx));

    // deserialize the tx
    sp::serialization::ser_SpTxCoinbaseV1 serializable_tx_recovered;
    EXPECT_TRUE(sp::serialization::try_get_serializable(epee::strspan<std::uint8_t>(serialized_tx),
        serializable_tx_recovered));

    // recover the tx
    SpTxCoinbaseV1 recovered_tx;
    EXPECT_NO_THROW(sp::serialization::recover_sp_tx_coinbase_v1(serializable_tx_recovered, recovered_tx));

    // check that the original tx was recovered
    rct::key original_tx_id;
    rct::key recovered_tx_id;

    EXPECT_NO_THROW(get_sp_tx_coinbase_v1_txid(tx, original_tx_id));
    EXPECT_NO_THROW(get_sp_tx_coinbase_v1_txid(recovered_tx, recovered_tx_id));

    EXPECT_TRUE(original_tx_id == recovered_tx_id);
    EXPECT_NO_THROW(EXPECT_TRUE(sp_tx_coinbase_v1_size_bytes(tx) == sp_tx_coinbase_v1_size_bytes(recovered_tx)));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization_demo, seraphis_squashed_empty)
{
    // make empty tx
    SpTxSquashedV1 tx{};

    // convert the tx to serializable form
    sp::serialization::ser_SpTxSquashedV1 serializable_tx;
    EXPECT_NO_THROW(sp::serialization::make_serializable_sp_tx_squashed_v1(tx, serializable_tx));

    // serialize the tx
    std::string serialized_tx;
    EXPECT_TRUE(sp::serialization::try_append_serializable(serializable_tx, serialized_tx));

    // deserialize the tx
    sp::serialization::ser_SpTxSquashedV1 serializable_tx_recovered;
    EXPECT_TRUE(sp::serialization::try_get_serializable(epee::strspan<std::uint8_t>(serialized_tx),
        serializable_tx_recovered));

    // recover the tx
    SpTxSquashedV1 recovered_tx;
    EXPECT_NO_THROW(sp::serialization::recover_sp_tx_squashed_v1(serializable_tx_recovered, {}, 0, 0, recovered_tx));

    // check that the original tx was recovered
    rct::key original_tx_id;
    rct::key recovered_tx_id;

    EXPECT_NO_THROW(get_sp_tx_squashed_v1_txid(tx, original_tx_id));
    EXPECT_NO_THROW(get_sp_tx_squashed_v1_txid(recovered_tx, recovered_tx_id));

    EXPECT_TRUE(original_tx_id == recovered_tx_id);
    EXPECT_NO_THROW(EXPECT_TRUE(sp_tx_squashed_v1_size_bytes(tx) == sp_tx_squashed_v1_size_bytes(recovered_tx)));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization_demo, seraphis_coinbase_standard)
{
    // ledger context
    MockLedgerContext ledger_context{0, 10000};
    const TxValidationContextMock tx_validation_context{ledger_context};

    // make a tx
    SpTxCoinbaseV1 tx;
    make_mock_tx<SpTxCoinbaseV1>(SpTxParamPackV1{}, {1}, {}, {1}, discretize_fee(0), ledger_context, tx);

    // convert the tx to serializable form
    sp::serialization::ser_SpTxCoinbaseV1 serializable_tx;
    EXPECT_NO_THROW(sp::serialization::make_serializable_sp_tx_coinbase_v1(tx, serializable_tx));

    // serialize the tx
    std::string serialized_tx;
    EXPECT_TRUE(sp::serialization::try_append_serializable(serializable_tx, serialized_tx));

    // deserialize the tx
    sp::serialization::ser_SpTxCoinbaseV1 serializable_tx_recovered;
    EXPECT_TRUE(sp::serialization::try_get_serializable(epee::strspan<std::uint8_t>(serialized_tx),
        serializable_tx_recovered));

    // recover the tx
    SpTxCoinbaseV1 recovered_tx;
    EXPECT_NO_THROW(sp::serialization::recover_sp_tx_coinbase_v1(serializable_tx_recovered, recovered_tx));

    // check the tx was recovered
    rct::key original_tx_id;
    rct::key recovered_tx_id;

    EXPECT_NO_THROW(get_sp_tx_coinbase_v1_txid(tx, original_tx_id));
    EXPECT_NO_THROW(get_sp_tx_coinbase_v1_txid(recovered_tx, recovered_tx_id));

    EXPECT_TRUE(original_tx_id == recovered_tx_id);
    EXPECT_NO_THROW(EXPECT_TRUE(sp_tx_coinbase_v1_size_bytes(tx) == sp_tx_coinbase_v1_size_bytes(recovered_tx)));
    EXPECT_TRUE(validate_tx(tx, tx_validation_context));
    EXPECT_TRUE(validate_tx(recovered_tx, tx_validation_context));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization_demo, seraphis_squashed_standard)
{
    // config
    SpTxParamPackV1 tx_params;

    tx_params.legacy_ring_size = 2;
    tx_params.ref_set_decomp_n = 2;
    tx_params.ref_set_decomp_m = 2;
    tx_params.bin_config =
        SpBinnedReferenceSetConfigV1{
            .bin_radius = 1,
            .num_bin_members = 1
        };

    // ledger context
    MockLedgerContext ledger_context{0, 10000};
    const TxValidationContextMock tx_validation_context{ledger_context};

    // make a tx
    SpTxSquashedV1 tx;
    make_mock_tx<SpTxSquashedV1>(tx_params,
        {1}, //legacy inputs
        {2, 3}, //seraphis inputs
        {3}, //outputs
        discretize_fee(3), //fee
        ledger_context,
        tx);

    // convert the tx to serializable form
    sp::serialization::ser_SpTxSquashedV1 serializable_tx;
    EXPECT_NO_THROW(sp::serialization::make_serializable_sp_tx_squashed_v1(tx, serializable_tx));

    // serialize the tx
    std::string serialized_tx;
    EXPECT_TRUE(sp::serialization::try_append_serializable(serializable_tx, serialized_tx));

    // deserialize the tx
    sp::serialization::ser_SpTxSquashedV1 serializable_tx_recovered;
    EXPECT_TRUE(sp::serialization::try_get_serializable(epee::strspan<std::uint8_t>(serialized_tx),
        serializable_tx_recovered));

    // recover the tx
    SpTxSquashedV1 recovered_tx;
    EXPECT_NO_THROW(sp::serialization::recover_sp_tx_squashed_v1(serializable_tx_recovered,
        tx_params.bin_config,
        tx_params.ref_set_decomp_n,
        tx_params.ref_set_decomp_m,
        recovered_tx));

    // check the tx was recovered
    rct::key original_tx_id;
    rct::key recovered_tx_id;

    EXPECT_NO_THROW(get_sp_tx_squashed_v1_txid(tx, original_tx_id));
    EXPECT_NO_THROW(get_sp_tx_squashed_v1_txid(recovered_tx, recovered_tx_id));

    EXPECT_TRUE(original_tx_id == recovered_tx_id);
    EXPECT_NO_THROW(EXPECT_TRUE(sp_tx_squashed_v1_size_bytes(tx) == sp_tx_squashed_v1_size_bytes(recovered_tx)));
    EXPECT_TRUE(validate_tx(tx, tx_validation_context));
    EXPECT_TRUE(validate_tx(recovered_tx, tx_validation_context));
}
//-------------------------------------------------------------------------------------------------------------------
