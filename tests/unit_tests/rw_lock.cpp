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

#include <gtest/gtest.h>

#include "async/rw_lock.h"

//-------------------------------------------------------------------------------------------------------------------
TEST(rw_lock, int_mutable)
{
    // manage an int (mutable)
    async::writable<int> writable{5};
    async::readable<int> readable{writable.get_readable()};

    // read the value
    {
        async::read_lock<int> read_lock{readable.lock()};
        EXPECT_TRUE(read_lock.value() == 5);
    }

    // update the value
    {
        async::write_lock<int> write_lock{writable.lock()};
        write_lock.value() = 10;
    }

    // check updated value
    {
        async::read_lock<int> read_lock{readable.lock()};
        EXPECT_TRUE(read_lock.value() == 10);
    }
}
//-------------------------------------------------------------------------------------------------------------------
TEST(rw_lock, int_immutable)
{
    // manage an int (immutable)
    async::readable<int> readable{5};

    // read the value
    {
        async::read_lock<int> read_lock{readable.lock()};
        EXPECT_TRUE(read_lock.value() == 5);
    }

    // read the value with multiple readers
    {
        async::read_lock<int> read_lock1{readable.lock()};
        async::read_lock<int> read_lock2{readable.lock()};
        async::read_lock<int> read_lock3{readable.lock()};
        EXPECT_TRUE(read_lock1.value() == 5);
        EXPECT_TRUE(read_lock2.value() == 5);
        EXPECT_TRUE(read_lock3.value() == 5);
    }
}
//-------------------------------------------------------------------------------------------------------------------
TEST(rw_lock, moved_from_throws)
{
    // manage an int (mutable)
    async::writable<int> writable{5};
    async::readable<int> readable{writable.get_readable()};

    // moved-from writable throws on access
    async::writable<int> writable2{std::move(writable)};
    EXPECT_ANY_THROW(writable.lock());
    EXPECT_ANY_THROW(writable.get_readable());

    // can read from readable created by original writable
    {
        async::read_lock<int> read_lock{readable.lock()};
        EXPECT_TRUE(read_lock.value() == 5);
    }

    // can read from readable created by second writable
    async::readable<int> readable2{writable2.get_readable()};
    {
        async::read_lock<int> read_lock{readable2.lock()};
        EXPECT_TRUE(read_lock.value() == 5);
    }

    // moved-from readable throws on access
    async::readable<int> readable3{std::move(readable)};
    EXPECT_ANY_THROW(readable.lock());

    // moved-from writable throws on access
    {
        async::write_lock<int> write_lock{writable2.lock()};
        async::write_lock<int> write_lock2{std::move(write_lock)};
        EXPECT_ANY_THROW(write_lock.value());
        EXPECT_NO_THROW(write_lock2.value() = 10);
    }

    // moved-from readable throws on access
    {
        async::read_lock<int> read_lock{readable3.lock()};
        async::read_lock<int> read_lock2{std::move(read_lock)};
        EXPECT_ANY_THROW(read_lock.value());
        EXPECT_NO_THROW(read_lock2.value());
        EXPECT_TRUE(read_lock2.value() == 10);
    }
}
//-------------------------------------------------------------------------------------------------------------------
TEST(rw_lock, single_writer_multi_reader)
{
    // multiple readables are allowed
    async::writable<int> writable{5};
    async::readable<int> readable1{writable.get_readable()};
    async::readable<int> readable2{writable.get_readable()};

    // multiple read locks are allowed
    {
        async::read_lock<int> read_lock1a{readable1.lock()};
        async::read_lock<int> read_lock1b{readable1.lock()};
        boost::optional<async::read_lock<int>> read_lock1c{readable1.try_lock()};
        async::read_lock<int> read_lock2a{readable2.lock()};
        async::read_lock<int> read_lock2b{readable2.lock()};
        boost::optional<async::read_lock<int>> read_lock2c{readable2.try_lock()};
        EXPECT_TRUE(read_lock1c);
        EXPECT_TRUE(read_lock2c);
        EXPECT_TRUE(read_lock1a.value() == 5);
        EXPECT_TRUE(read_lock1b.value() == 5);
        EXPECT_TRUE(read_lock1c->value() == 5);
        EXPECT_TRUE(read_lock2a.value() == 5);
        EXPECT_TRUE(read_lock2b.value() == 5);
        EXPECT_TRUE(read_lock2c->value() == 5);
    }

    // only one write lock is allowed
    {
        async::write_lock<int> write_lock{writable.lock()};
        boost::optional<async::write_lock<int>> write_lock_attempt{writable.try_lock()};
        EXPECT_TRUE(write_lock_attempt == boost::none);
    }

    // no concurrent read lock when there is a write lock
    {
        async::write_lock<int> write_lock{writable.lock()};
        boost::optional<async::read_lock<int>> read_lock_attempt{readable1.try_lock()};
        EXPECT_TRUE(read_lock_attempt == boost::none);
    }

    // no concurrent write lock when there is a read lock
    {
        async::read_lock<int> read_lock{readable1.lock()};
        boost::optional<async::write_lock<int>> write_lock_attempt{writable.try_lock()};
        EXPECT_TRUE(write_lock_attempt == boost::none);
    }
}
//-------------------------------------------------------------------------------------------------------------------
