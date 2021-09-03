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

#pragma once

#include "async/parent_reference_tasking_system.h"
#include "async/task_types.h"
#include "async/threadpool.h"
#include "common/threadpool.h"
#include "performance_tests.h"

#include <chrono>
#include <memory>

//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------

struct ParamsShuttleAsync final : public ParamsShuttle
{
    std::string description{};
    std::size_t num_extra_threads{0};
    std::size_t num_tasks{0};
    std::size_t sleepy_task_cadence{0}; //e.g. 3 means 'every third' => normal, normal, sleepy, normal, normal, sleepy, ...
    std::chrono::nanoseconds task_duration{0};
    std::chrono::nanoseconds sleepy_task_sleep_duration{0};
};

static bool is_sleepy_task(const std::size_t sleepy_task_cadence, const std::size_t task_number)
{
    if (sleepy_task_cadence == 0)
        return false;
    return ((task_number) % sleepy_task_cadence) == 0;
}

//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------

static void submit_task_common_threadpool(const std::chrono::nanoseconds task_duration,
    tools::threadpool &threadpool,
    tools::threadpool::waiter &waiter,
    std::shared_ptr<int> &dummy)
{
    // prepare task
    auto task =
        [
            l_dummy         = dummy,  //include a dummy shared ptr so perf results are comparable with other tests
            l_task_duration = task_duration
        ]()
        {
            if (l_task_duration > std::chrono::nanoseconds{0})
                std::this_thread::sleep_for(l_task_duration);
        };

    // otherwise submit to the threadpool
    threadpool.submit(&waiter, std::move(task), true);
}

/// threadpool from src/common/threadpool.h
class test_common_threadpool
{
public:
    static const size_t loop_count = 10;

    bool init(const ParamsShuttleAsync &params)
    {
        if (params.description.size())
            std::cout << params.description << '\n';

        // save the test parameters
        m_params = params;

        // create the threadpool
        m_threadpool = std::unique_ptr<tools::threadpool>{
                tools::threadpool::getNewForUnitTests(params.num_extra_threads + 1)
            };

        return true;
    }

    bool test()
    {
        // prepare waiter
        tools::threadpool::waiter waiter{*m_threadpool};

        // submit tasks
        std::chrono::nanoseconds task_duration;
        std::shared_ptr<int> dummy{std::make_shared<int>()};

        for (std::size_t task_id{0}; task_id < m_params.num_tasks; ++task_id)
        {
            // base-level task length
            task_duration = m_params.task_duration;

            // periodically include the sleep duration
            if (is_sleepy_task(m_params.sleepy_task_cadence, task_id + 1))
                task_duration += m_params.sleepy_task_sleep_duration;

            // submit the task
            submit_task_common_threadpool(task_duration, *m_threadpool, waiter, dummy);
        }

        // join
        waiter.wait();

        return true;
    }

private:
    ParamsShuttleAsync m_params;
    std::unique_ptr<tools::threadpool> m_threadpool;
};

//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------

static void submit_task_async_threadpool(const std::chrono::nanoseconds task_duration,
    async::join_token_t &join_token,
    async::Threadpool &threadpool)
{
    // prepare task
    auto task =
        [
            l_join_token    = join_token,
            l_task_duration = task_duration
        ]() -> async::TaskVariant
        {
            if (l_task_duration > std::chrono::nanoseconds{0})
                std::this_thread::sleep_for(l_task_duration);
            return boost::none;
        };

    // submit to the threadpool
    threadpool.submit(async::make_simple_task(0, std::move(task)));
}

static void submit_sleepy_task_async_threadpool(const std::chrono::nanoseconds task_duration,
    const std::chrono::nanoseconds sleep_duration,
    async::join_token_t &join_token,
    async::Threadpool &threadpool)
{
    // prepare task whose continuation will sleep until 'sleep_duration' after the task is done
    auto task =
        [
            l_join_token     = join_token,
            l_task_duration  = task_duration,
            l_sleep_duration = sleep_duration
        ]() mutable -> async::TaskVariant
        {
            if (l_task_duration > std::chrono::nanoseconds{0})
                std::this_thread::sleep_for(l_task_duration);
            return async::make_sleepy_task(0,
                std::chrono::steady_clock::now() + l_sleep_duration,
                [
                    ll_join_token = std::move(l_join_token),
                    x             = 5  //force the task to allocate instead of using small-object optimization
                ]() -> async::TaskVariant
                {
                    (void) x;
                    return boost::none;  //do nothing
                });
        };

    // submit to the threadpool
    threadpool.submit(async::make_simple_task(0, std::move(task)));
}

/// threadpool from src/async/threadpool.h
class test_async_threadpool
{
public:
    static const size_t loop_count = 10;

    bool init(const ParamsShuttleAsync &params)
    {
        if (params.description.size())
            std::cout << params.description << '\n';

        // save the test parameters
        m_params = params;

        // create the threadpool
        // - note: use 3 priority levels {0, 1, 2} for realism
        m_threadpool = std::make_unique<async::Threadpool>(
                2, params.num_extra_threads, 20, std::chrono::seconds{1}
            );

        return true;
    }

    bool test()
    {
        // 1. make join signal
        async::join_signal_t join_signal{m_threadpool->make_join_signal()};

        // 2. get join token
        async::join_token_t join_token{m_threadpool->get_join_token(join_signal)};

        // 3. submit tasks to join on
        for (std::size_t task_id{0}; task_id < m_params.num_tasks; ++task_id)
        {
            if (is_sleepy_task(m_params.sleepy_task_cadence, task_id + 1))
            {
                submit_sleepy_task_async_threadpool(m_params.task_duration,
                    m_params.sleepy_task_sleep_duration,
                    join_token,
                    *m_threadpool);
            }
            else
                submit_task_async_threadpool(m_params.task_duration, join_token, *m_threadpool);
        }

        // 4. get join condition
        async::join_condition_t join_condition{
                m_threadpool->get_join_condition(std::move(join_signal), std::move(join_token))
            };

        // 5. join the tasks
        m_threadpool->work_while_waiting(std::move(join_condition));

        return true;
    }

private:
    ParamsShuttleAsync m_params;
    std::unique_ptr<async::Threadpool> m_threadpool;
};


//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------

static void submit_task_async_threadpool_with_fanout(const std::chrono::nanoseconds task_duration,
    async::join_token_t &join_token,
    async::Threadpool &threadpool)
{
    // prepare task
    auto task =
        [
            l_join_token    = join_token,
            l_task_duration = task_duration,
            &threadpool
        ]() -> async::TaskVariant
        {
            // use fanout for task
            async::fanout_token_t fanout_token{threadpool.launch_temporary_worker()};

            if (l_task_duration > std::chrono::nanoseconds{0})
                std::this_thread::sleep_for(l_task_duration);

            return boost::none;
        };

    // submit to the threadpool
    threadpool.submit(async::make_simple_task(0, std::move(task)));
}

static void submit_sleepy_task_async_threadpool_with_fanout(const std::chrono::nanoseconds task_duration,
    const std::chrono::nanoseconds sleep_duration,
    async::join_token_t &join_token,
    async::Threadpool &threadpool)
{
    // prepare task whose continuation will sleep until 'sleep_duration' after the task is done
    auto task =
        [
            l_join_token     = join_token,
            l_task_duration  = task_duration,
            l_sleep_duration = sleep_duration,
            &threadpool
        ]() mutable -> async::TaskVariant
        {
            if (l_task_duration > std::chrono::nanoseconds{0})
                std::this_thread::sleep_for(l_task_duration);

            // use fanout for sleepy task
            if (l_sleep_duration > std::chrono::nanoseconds{0})
            {
                async::fanout_token_t fanout_token{threadpool.launch_temporary_worker()};
                std::this_thread::sleep_for(l_sleep_duration);
            }

            return boost::none;
        };

    // submit to the threadpool
    threadpool.submit(async::make_simple_task(0, std::move(task)));
}

/// threadpool from src/async/threadpool.h
class test_async_threadpool_with_fanout
{
public:
    static const size_t loop_count = 10;

    bool init(const ParamsShuttleAsync &params)
    {
        if (params.description.size())
            std::cout << params.description << '\n';

        // save the test parameters
        m_params = params;

        // create the threadpool
        // - note: use 3 priority levels {0, 1, 2} for realism
        m_threadpool = std::make_unique<async::Threadpool>(
                2, params.num_extra_threads, 20, std::chrono::seconds{1}
            );

        return true;
    }

    bool test()
    {
        // 1. make join signal
        async::join_signal_t join_signal{m_threadpool->make_join_signal()};

        // 2. get join token
        async::join_token_t join_token{m_threadpool->get_join_token(join_signal)};

        // 3. submit tasks to join on
        for (std::size_t task_id{0}; task_id < m_params.num_tasks; ++task_id)
        {
            if (is_sleepy_task(m_params.sleepy_task_cadence, task_id + 1))
            {
                submit_sleepy_task_async_threadpool_with_fanout(m_params.task_duration,
                    m_params.sleepy_task_sleep_duration,
                    join_token,
                    *m_threadpool);
            }
            else
                submit_task_async_threadpool_with_fanout(m_params.task_duration, join_token, *m_threadpool);
        }

        // 4. get join condition
        async::join_condition_t join_condition{
                m_threadpool->get_join_condition(std::move(join_signal), std::move(join_token))
            };

        // 5. join the tasks
        m_threadpool->work_while_waiting(std::move(join_condition));

        return true;
    }

private:
    ParamsShuttleAsync m_params;
    std::unique_ptr<async::Threadpool> m_threadpool;
};

//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------

static void submit_task_parent_threadpool(const std::chrono::nanoseconds task_duration,
    parent::ThreadPool &threadpool,
    std::shared_ptr<std::promise<void>> &done_signal)
{
    // prepare task
    auto task =
        [
            l_signal        = done_signal,
            l_task_duration = task_duration
        ]()
        {
            if (l_task_duration > std::chrono::nanoseconds{0})
                std::this_thread::sleep_for(l_task_duration);
        };

    // submit to the threadpool
    threadpool.submit(std::move(task));
}

/// reference threadpool from src/async/parent.h
class test_parent_threadpool
{
public:
    static const size_t loop_count = 10;

    bool init(const ParamsShuttleAsync &params)
    {
        if (params.description.size())
            std::cout << params.description << '\n';

        // save the test parameters
        m_params = params;

        // create the threadpool
        m_threadpool = std::make_unique<parent::ThreadPool>(
                params.num_extra_threads + 1
            );

        // sleep one of the threads to emulate our main thread
        m_main_pause_signal = std::make_unique<std::promise<void>>();
        m_threadpool->submit(
            [
                pause_flag = std::make_shared<std::future<void>>(m_main_pause_signal->get_future())
            ]() mutable
            {
                try { pause_flag->get(); } catch (...) {}
            });

        return true;
    }

    bool test()
    {
        // make done signal to synchronize with the join
        std::shared_ptr<std::promise<void>> done_signal{std::make_shared<std::promise<void>>()};

        // submit tasks
        std::chrono::nanoseconds task_duration;

        for (std::size_t task_id{0}; task_id < m_params.num_tasks; ++task_id)
        {
            // base-level task length
            task_duration = m_params.task_duration;

            // periodically include the sleep duration
            if (is_sleepy_task(m_params.sleepy_task_cadence, task_id + 1))
                task_duration += m_params.sleepy_task_sleep_duration;

            submit_task_parent_threadpool(task_duration, *m_threadpool, done_signal);
        }

        // release the paused pseudo-main thread to emulate 'work while joining'
        m_main_pause_signal = std::make_unique<std::promise<void>>();

        // synchronize the join
        std::future<void> flag{done_signal->get_future()};
        done_signal = nullptr;
        try { flag.get(); } catch (...) {}

        // pause the pseudo-main thread again
        m_threadpool->submit(
            [
                pause_flag = std::make_shared<std::future<void>>(m_main_pause_signal->get_future())
            ]() mutable
            {
                try { pause_flag->get(); } catch (...) {}
            });

        return true;
    }

private:
    ParamsShuttleAsync m_params;
    std::unique_ptr<parent::ThreadPool> m_threadpool;

    // pause signal (must be defined last so the threadpool won't hang)
    std::unique_ptr<std::promise<void>> m_main_pause_signal;
};

//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------
