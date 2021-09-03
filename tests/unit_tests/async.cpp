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

#include "async/task_types.h"
#include "async/threadpool.h"

#include <gtest/gtest.h>

#include <atomic>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <thread>

//-------------------------------------------------------------------------------------------------------------------
TEST(async, hello_world)
{
    async::Threadpool pool{1, 0, 40, std::chrono::seconds{1}};

    pool.submit(async::make_simple_task(0,
            []() -> async::TaskVariant
            {
                std::cout << "hello, world!\n";
                return boost::none;
            }
        ));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(async, basic_join)
{
    async::Threadpool pool{1, 0, 40, std::chrono::seconds{1}};

    // 1. make join signal
    auto join_signal = pool.make_join_signal();

    // 2. get join token
    auto join_token = pool.get_join_token(join_signal);

    // 3. submit tasks to join on
    pool.submit(async::make_simple_task(0,
            [join_token]() -> async::TaskVariant
            {
                std::cout << "A\n";
                return boost::none;
            }
        ));
    pool.submit(async::make_simple_task(0,
            [join_token]() -> async::TaskVariant
            {
                std::cout << "B\n";
                return boost::none;
            }
        ));

    // 4. get join condition
    auto join_condition = pool.get_join_condition(std::move(join_signal), std::move(join_token));

    // 5. join the tasks
    pool.work_while_waiting(std::move(join_condition));

    std::cout << "joining done!\n";
}
//-------------------------------------------------------------------------------------------------------------------
TEST(async, basic_fanout)
{
    async::Threadpool pool{1, 0, 40, std::chrono::seconds{1}};

    // launch task in the middle of a fanout
    {
        async::fanout_token_t fanout_token{pool.launch_temporary_worker()};

        pool.submit(async::make_simple_task(0,
                []() -> async::TaskVariant
                {
                    std::cout << "A\n";
                    return boost::none;
                }
            ));

        std::this_thread::sleep_for(std::chrono::milliseconds{500});
    }

    std::cout << "fanout closed!\n";
}
//-------------------------------------------------------------------------------------------------------------------
TEST(async, basic_multithreaded)
{
    async::Threadpool pool{1, 2, 40, std::chrono::seconds{1}};

    // 1. submit tasks
    pool.submit(async::make_simple_task(0,
            []() -> async::TaskVariant
            {
                std::cout << "A\n";
                return boost::none;
            }
        ));
    pool.submit(async::make_simple_task(0,
            []() -> async::TaskVariant
            {
                std::cout << "B\n";
                return boost::none;
            }
        ));
    pool.submit(async::make_simple_task(0,
            []() -> async::TaskVariant
            {
                std::cout << "C\n";
                return boost::none;
            }
        ));

    // 2. sleep the main thread
    std::this_thread::sleep_for(std::chrono::milliseconds{500});

    // 3. main thread marker
    std::cout << "tasks submitted\n";
}
//-------------------------------------------------------------------------------------------------------------------
