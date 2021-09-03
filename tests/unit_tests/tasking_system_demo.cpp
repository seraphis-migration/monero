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

#include "async/misc_utils.h"
#include "common/expect.h"
#include "misc_log_ex.h"

#include <gtest/gtest.h>

#include <future>
#include <iostream>
#include <memory>
#include <queue>
#include <stdexcept>

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
class ThreadPool
{
public:
    void add_task(std::packaged_task<void()> new_task)
    {
        m_pending_tasks.push(std::move(new_task));
    }

    bool try_run_next_task()
    {
        // check if there are any tasks
        if (m_pending_tasks.size() == 0)
            return false;

        // run the oldest task
        auto task_to_run{std::move(m_pending_tasks.front())};
        m_pending_tasks.pop();
        task_to_run();

        return true;
    }

private:
    std::queue<std::packaged_task<void()>> m_pending_tasks;
};
//-------------------------------------------------------------------------------------------------------------------
// the thread pool itself should not be exposed, otherwise someone could move the pool and cause issues
//-------------------------------------------------------------------------------------------------------------------
namespace detail
{
static ThreadPool& get_demo_threadpool()
{
    static ThreadPool threadpool{};
    return threadpool;
}
} //namespace detail
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void add_task_to_demo_threadpool(std::packaged_task<void()> new_task)
{
    detail::get_demo_threadpool().add_task(std::move(new_task));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename T>
static void add_task_to_demo_threadpool(T&& new_task)
{
    add_task_to_demo_threadpool(static_cast<std::packaged_task<void()>>(std::forward<T>(new_task)));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_run_next_task_demo_threadpool()
{
    return detail::get_demo_threadpool().try_run_next_task();
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void print_int(const int i)
{
    std::cerr << "print int: " << i << '\n';
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void add_int(const int x, int &i_inout)
{
    i_inout += x;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void mul_int(const int x, int &i_inout)
{
    i_inout *= x;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename T>
struct Task final
{
    unsigned char id;
    T task;
};
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename T>
Task<T> make_task(const unsigned char id, T &&task)
{
    return Task<T>{.id = id, .task = std::forward<T>(task)};
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
/// declare the monitor builder
template <typename>
class TaskGraphMonitorBuilder;

/// monitor a task graph
/// - destroying the monitor will immediately cancel the graph (i.e. it assumes the graph has no desired side effects
///   other than setting the future result)
template <typename R>
class TaskGraphMonitor final
{
    friend class TaskGraphMonitorBuilder<R>;

public:
    bool is_canceled() const { return async::future_is_ready(m_cancellation_flag); }
    bool has_result()  const { return async::future_is_ready(m_final_result);      }

    void cancel()
    {
        if (!this->is_canceled() && m_cancellation_handle)
        {
            try { m_cancellation_handle->set_value(); } catch (...) { /* already canceled */ }
        }
    }
    expect<R> expect_result() { return async::unwrap_future(m_final_result); }

protected:
    std::shared_ptr<std::promise<void>> m_cancellation_handle;
    std::shared_future<void> m_cancellation_flag;
    std::future<R> m_final_result;
};
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename R>
class TaskGraphMonitorBuilder final
{
    void check_state() const
    {
        if(!m_monitor.m_cancellation_flag.valid())
            throw std::runtime_error{"task graph monitor builder: already extracted monitor."};
    }
public:
    /// construct from the future result
    TaskGraphMonitorBuilder()
    {
        m_monitor.m_cancellation_handle = std::make_shared<std::promise<void>>();
        m_monitor.m_cancellation_flag   = m_monitor.m_cancellation_handle->get_future().share();
        m_monitor.m_final_result        = m_final_result_promise.get_future();
    }

    /// add a task
    void add_task(const unsigned char task_id, std::future<void> task_completion_flag)
    {
        this->check_state();
        //todo: track the task
    }

    /// get a weak handle to the cancellation flag that can be used to force cancel the graph
    std::weak_ptr<std::promise<void>> get_weak_cancellation_handle()
    {
        this->check_state();
        return m_monitor.m_cancellation_handle;
    }

    /// get the cancellation flag
    std::shared_future<void> get_cancellation_flag()
    {
        this->check_state();
        return m_monitor.m_cancellation_flag;
    }

    /// cancel the task graph (useful if a failure is encountered while building the graph)
    void cancel()
    {
        this->check_state();
        m_monitor.cancel();
    }

    /// extract the result promise
    std::promise<R> extract_result_promise()
    {
        if (m_promise_extracted_flag)
            throw std::runtime_error{"task graph monitor builder: already extracted result promise."};
        m_promise_extracted_flag = true;

        return std::move(m_final_result_promise);
    }

    /// extract the monitor
    TaskGraphMonitor<R> extract_monitor()
    {
        this->check_state();
        return std::move(m_monitor);
    }

private:
    std::promise<R> m_final_result_promise{};
    bool m_promise_extracted_flag{false};
    TaskGraphMonitor<R> m_monitor;
};
//-------------------------------------------------------------------------------------------------------------------
// type tokens for overload resolution in the task graph builder
//-------------------------------------------------------------------------------------------------------------------
struct DetachableGraphTerminatorToken final {};
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void force_set_cancellation_flag_noexcept(std::weak_ptr<std::promise<void>> &weak_cancellation_handle)
{
    try         { if (auto cancellation_handle{weak_cancellation_handle.lock()}) cancellation_handle->set_value(); }
    catch (...) { /* failure to set the flag means it's already set */ }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void force_set_cancellation_flag_noexcept(std::shared_ptr<std::promise<void>> &strong_cancellation_handle)
{
    try         { if (strong_cancellation_handle) strong_cancellation_handle->set_value(); }
    catch (...) { /* failure to set the flag means it's already set */ }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <bool>
struct get_cancellation_handle_t final {};

template <>
struct get_cancellation_handle_t<false> final
{
    std::weak_ptr<std::promise<void>> operator()(std::weak_ptr<std::promise<void>> cancellation_handle) const
    {
        return cancellation_handle;
    }
};

template <>
struct get_cancellation_handle_t<true> final
{
    std::shared_ptr<std::promise<void>> operator()(std::weak_ptr<std::promise<void>> cancellation_handle) const
    {
        return cancellation_handle.lock();
    }
};
//-------------------------------------------------------------------------------------------------------------------
// note: do not use a try-catch in this function because we want to let the caller handle exceptions as needed
//-------------------------------------------------------------------------------------------------------------------
template <typename I, typename T>
static auto initialize_future_task(I &&initial_value, T &&task)
{
    static_assert(std::is_same<decltype(task(std::declval<I>())), void>::value, "");

    return
        [
            l_val     = std::forward<I>(initial_value),
            l_task    = std::forward<T>(task)
        ] () mutable -> void
        {
            l_task(std::move(l_val));
        };
}
//-------------------------------------------------------------------------------------------------------------------
// end case: set the promise from the final task's result
// - detachable graphs: the last task shares ownership of its graph's cancellation handle so if the graph monitor
//   is destroyed the graph can continue to run
//-------------------------------------------------------------------------------------------------------------------
template <typename R, typename S, typename T, bool detachable = false>
static auto build_task_graph(TaskGraphMonitorBuilder<R> &graph_monitor_builder_inout, S, Task<T> &&final_task)
{
    std::promise<void> completion_handle{};
    graph_monitor_builder_inout.add_task(final_task.id, completion_handle.get_future());
    std::shared_future<void> cancellation_flag{graph_monitor_builder_inout.get_cancellation_flag()};

    return
        [
            l_final_task          = std::forward<Task<T>>(final_task).task,
            l_result_promise      = graph_monitor_builder_inout.extract_result_promise(),
            l_completion_handle   = std::move(completion_handle),
            l_cancellation_handle = get_cancellation_handle_t<detachable>{}(
                                            graph_monitor_builder_inout.get_weak_cancellation_handle()
                                        ),
            l_cancellation_flag   = std::move(cancellation_flag)
        ] (auto&& this_task_val) mutable -> void
        {
            try
            {
                // check for cancellation
                if (async::future_is_ready(l_cancellation_flag))
                    return;

                // execute the final task
                l_result_promise.set_value(l_final_task(std::forward<decltype(this_task_val)>(this_task_val)));
                l_completion_handle.set_value();
            }
            catch (...)
            {
                try
                {
                    l_result_promise.set_exception(std::current_exception());
                    l_completion_handle.set_exception(std::current_exception());
                } catch (...) { /*can't do anything*/ }
                force_set_cancellation_flag_noexcept(l_cancellation_handle);  //set cancellation flag for consistency
            }
        };
}
//-------------------------------------------------------------------------------------------------------------------
// detachedable graph: build the final task in detachable mode
//-------------------------------------------------------------------------------------------------------------------
template <typename R, typename S, typename T>
static auto build_task_graph(TaskGraphMonitorBuilder<R> &graph_monitor_builder_inout,
    S scheduler,
    Task<T> &&final_task,
    DetachableGraphTerminatorToken)
{
    return build_task_graph<R, S, T, true>(graph_monitor_builder_inout, scheduler, std::forward<Task<T>>(final_task));
}
//-------------------------------------------------------------------------------------------------------------------
// fold into task 'a' its continuation 'the rest of the task graph'
//-------------------------------------------------------------------------------------------------------------------
template <typename R, typename S, typename T, typename... Ts>
static auto build_task_graph(TaskGraphMonitorBuilder<R> &graph_monitor_builder_inout,
    S scheduler,
    Task<T> &&this_task,
    Ts &&...continuation_tasks)
{
    std::promise<void> completion_handle{};
    graph_monitor_builder_inout.add_task(this_task.id, completion_handle.get_future());
    std::weak_ptr<std::promise<void>> cancellation_handle{graph_monitor_builder_inout.get_weak_cancellation_handle()};
    std::shared_future<void> cancellation_flag{graph_monitor_builder_inout.get_cancellation_flag()};

    return
        [
            l_scheduler           = scheduler,
            l_this_task           = std::forward<Task<T>>(this_task).task,
            l_completion_handle   = std::move(completion_handle),
            l_next_task           = build_task_graph<R>(
                                        graph_monitor_builder_inout,
                                        scheduler,
                                        std::forward<Ts>(continuation_tasks)...
                                    ),
            l_cancellation_handle = std::move(cancellation_handle),
            l_cancellation_flag   = std::move(cancellation_flag)
        ] (auto&& this_task_val) mutable -> void
        {
            try
            {
                // check for cancellation
                if (async::future_is_ready(l_cancellation_flag))
                    return;

                // this task's job
                auto this_task_result =
                    [&]() -> expect<decltype(l_this_task(std::declval<decltype(this_task_val)>()))>
                    {
                        try { return l_this_task(std::forward<decltype(this_task_val)>(this_task_val)); }
                        catch (...)
                        {
                            try { l_completion_handle.set_exception(std::current_exception()); }
                            catch (...) { /*can't do anything*/ }
                            return std::error_code{};
                        }
                    }();

                // give up if this task failed
                // - force-set the cancellation flag so all dependents in other branches of the graph will be cancelled
                if (!this_task_result)
                {
                    force_set_cancellation_flag_noexcept(l_cancellation_handle);
                    return;
                }

                // check for cancellation again (can discard the task result if cancelled)
                if (async::future_is_ready(l_cancellation_flag))
                    return;

                // pass the result of this task to the continuation
                auto continuation = initialize_future_task(
                        std::forward<typename decltype(this_task_result)::value_type>(
                                std::move(this_task_result).value()
                            ),
                        std::move(l_next_task)
                    );

                // mark success
                // - do this before scheduling the next task in case the scheduler immediately invokes the continuation
                try { l_completion_handle.set_value(); } catch (...) { /* don't kill the next task */ }

                // submit the continuation task to the scheduler
                l_scheduler(std::move(continuation));
            } catch (...) { force_set_cancellation_flag_noexcept(l_cancellation_handle); }
        };
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename R, typename S, typename I, typename... Ts>
static TaskGraphMonitor<R> schedule_task_graph(S scheduler, I &&initial_value, Ts &&...tasks)
{
    // build task graph
    TaskGraphMonitorBuilder<R> monitor_builder{};

    try
    {
        auto task_graph_head = initialize_future_task(
                std::forward<I>(initial_value),
                build_task_graph<R>(monitor_builder, scheduler, std::forward<Ts>(tasks)...)
            );

        // schedule task graph
        scheduler(std::move(task_graph_head));
    }
    catch (...)
    {
        // assume if launching the task graph failed then it should be canceled
        monitor_builder.cancel();
        LOG_ERROR("scheduling a task graph failed.");
    }

    // return monitor
    return monitor_builder.extract_monitor();
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename S>
static auto basic_tasking_system_demo_test(S scheduler)
{
    // set up the basic task sequence
    int initial_val{10};
    int add_five{5};
    int mul_three{3}; (void)mul_three;
    int mul_ten{10}; (void)mul_ten; (void)mul_int;
    // task 1: print
    // task 2: add 5
    // task 3: print
    // task 4 SPLIT: divide in half for each branch
    //   task 4a-1: print    task 4b-1: print
    //   task 4a-2: mul10
    // task 4 JOIN: add together each branch
    // task 5 print
    auto job1 = make_task(1,
            [](int val) -> int
            {
                print_int(val);
                return val;
            }
        );
    auto job2 = make_task(2,
            [
                addor = std::move(add_five)
            ] (int val) -> int
            {
                add_int(addor, val);
                return val;
            }
        );
    auto job3 = make_task(3,
            [](int val) -> int
            {
                print_int(val);
                return val;
            }
        );/*
    auto job4 =
        [
            multiplier = std::move(mul_three)
        ] (int val) -> int
        {
            mul_int(multiplier, val);
            return val;
        };
    auto job4_split =
        [] (int val) -> std::tuple<int, int>
        {
            return {val/2, val/2};
        };
    auto job4a_1 =
        [] (int val) -> int
        {
            print_int(val);
            return val;
        };
    auto job4a_2 =
        [
            multiplier = std::move(mul_ten)
        ] (int val) -> int
        {
            mul_int(multiplier, val);
            return val;
        };
    auto job4b_1 =
        [] (int val) -> int
        {
            print_int(val);
            return val;
        };
    auto job4_join =
        [] (std::tuple<int, int> val) -> int
        {
            return std::get<0>(val) + std::get<1>(val);
        };
    auto job5 =
        [](int val) -> int
        {
            print_int(val);
            return val;
        };*/

    // build task graph and schedule it
    return schedule_task_graph<int>(
            scheduler,
            std::move(initial_val),
            std::move(job1),
            std::move(job2),
            std::move(job3)/*,
            task_graph_openclose(
                std::move(job4_split),
                std::make_tuple(std::move(job4a_1), std::move(job4a_2)),
                std::make_tuple(std::move(job4b_1)),
                std::move(job4_join)
            ),
            std::move(job5)*/
        );

    // problems with a full task graph
    // - when joining, the last joiner should schedule the continuation (can use an atomic int with fetch_add() to
    //   test when all joiners are done)

    // todo
    // - is_canceled() callback for tasks that can cancel themselves
    // - make detached task graph by moving the task graph monitor into the last task's lambda capture
    //   - detached graphs should have void return type (last task returns nothing)
    //   - detached graphs can be built sideways within a large graph construction, using a fresh monitor builder
    //   - detached graphs are not cancellable; if a cancellable process is desired, don't use a detached graph, just
    //     use a normal graph and keep track of the graph monitor (which will auto-cancel the graph when destroyed)
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename S>
static auto basic_detached_tasking_system_demo_test(S scheduler)
{
    // set up the basic task sequence
    int initial_val{10};
    int add_five{5};
    int mul_three{3}; (void)mul_three;
    int mul_ten{10}; (void)mul_ten; (void)mul_int;
    // task 1: print
    // task 2: add 5
    // task 3: print
    // task 4 SPLIT: divide in half for each branch
    //   task 4a-1: print    task 4b-1: print
    //   task 4a-2: mul10
    // task 4 JOIN: add together each branch
    // task 5 print
    auto job1 = make_task(1,
            [](int val) -> int
            {
                print_int(val);
                return val;
            }
        );
    auto job2 = make_task(2,
            [
                addor = std::move(add_five)
            ] (int val) -> int
            {
                add_int(addor, val);  //throw std::runtime_error{"abort"};  //test that the graph gets cancelled
                return val;
            }
        );
    auto job3 = make_task(3,
            [](int val) -> int
            {
                print_int(val);
                return val;
            }
        );/*
    auto job4 =
        [
            multiplier = std::move(mul_three)
        ] (int val) -> int
        {
            mul_int(multiplier, val);
            return val;
        };
    auto job4_split =
        [] (int val) -> std::tuple<int, int>
        {
            return {val/2, val/2};
        };
    auto job4a_1 =
        [] (int val) -> int
        {
            print_int(val);
            return val;
        };
    auto job4a_2 =
        [
            multiplier = std::move(mul_ten)
        ] (int val) -> int
        {
            mul_int(multiplier, val);
            return val;
        };
    auto job4b_1 =
        [] (int val) -> int
        {
            print_int(val);
            return val;
        };
    auto job4_join =
        [] (std::tuple<int, int> val) -> int
        {
            return std::get<0>(val) + std::get<1>(val);
        };
    auto job5 =
        [](int val) -> int
        {
            print_int(val);
            return val;
        };*/

    // build task graph and schedule it
    schedule_task_graph<int>(
            scheduler,
            std::move(initial_val),
            std::move(job1),
            std::move(job2),
            std::move(job3)/*,
            task_graph_openclose(
                std::move(job4_split),
                std::make_tuple(std::move(job4a_1), std::move(job4a_2)),
                std::make_tuple(std::move(job4b_1)),
                std::move(job4_join)
            ),
            std::move(job5)*/,
            DetachableGraphTerminatorToken{}  //add terminator
        );

    // problems with a full task graph
    // - when joining, the last joiner should schedule the continuation (can use an atomic int with fetch_add() to
    //   test when all joiners are done)

    // todo
    // - is_canceled() callback for tasks that can cancel themselves
    // - make detached task graph by moving the task graph monitor into the last task's lambda capture
    //   - detached graphs should have void return type (last task returns nothing)
    //   - detached graphs can be built sideways within a large graph construction, using a fresh monitor builder
    //   - detached graphs are not cancellable; if a cancellable process is desired, don't use a detached graph, just
    //     use a normal graph and keep track of the graph monitor (which will auto-cancel the graph when destroyed)
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(tasking_system_demo, basic_autorun)
{
    // run the test with a scheduler that immediately invokes tasks
    TaskGraphMonitor<int> task_graph_monitor = basic_tasking_system_demo_test(
            [](auto&& task)
            {
                task();
            }
        );

    // extract final result
    EXPECT_TRUE(task_graph_monitor.has_result());
    const expect<int> final_result{task_graph_monitor.expect_result()};
    EXPECT_TRUE(final_result);
    EXPECT_NO_THROW(final_result.value());
    std::cerr << "final result: " << final_result.value() << '\n';
}
//-------------------------------------------------------------------------------------------------------------------
TEST(tasking_system_demo, basic_threadpool)
{
    // run the test with a scheduler that sends tasks into the demo threadpool
    TaskGraphMonitor<int> task_graph_monitor = basic_tasking_system_demo_test(
            [](auto&& task)
            {
                add_task_to_demo_threadpool(std::forward<decltype(task)>(task));
            }
        );

    // run tasks in the threadpool to completion
    int num_tasks_completed{0};
    while (try_run_next_task_demo_threadpool())
    {
        ++num_tasks_completed;
        std::cerr << "completed task #" << num_tasks_completed << '\n';
    }

    // extract final result
    EXPECT_TRUE(task_graph_monitor.has_result());
    const expect<int> final_result{task_graph_monitor.expect_result()};
    EXPECT_TRUE(final_result);
    EXPECT_NO_THROW(final_result.value());
    std::cerr << "final result: " << final_result.value() << '\n';
}
//-------------------------------------------------------------------------------------------------------------------
TEST(tasking_system_demo, basic_threadpool_detached)
{
    // run the test with a scheduler that sends tasks into the demo threadpool
    // - do not save the graph monitor (i.e. detach the graph immediately)
    basic_detached_tasking_system_demo_test(
            [](auto&& task)
            {
                add_task_to_demo_threadpool(std::forward<decltype(task)>(task));
            }
        );

    // run tasks in the threadpool to completion
    int num_tasks_completed{0};
    while (try_run_next_task_demo_threadpool())
    {
        ++num_tasks_completed;
        std::cerr << "completed task #" << num_tasks_completed << '\n';
    }

    std::cerr << "detached graph done\n";
}
//-------------------------------------------------------------------------------------------------------------------
