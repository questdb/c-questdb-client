/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2022 QuestDB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <thread>
#include <mutex>
#include <condition_variable>		
#include <queue>
#include <optional>
#include <iostream>

extern "C"
{
#include "../src/build_env.h"
#include "../src/qdb_thread_id.h"
}

// Blocking first-in first-out single-producer single-consumer message queue.
// Designed for simplicity of testing, not performance.
// See: https://www.justsoftwaresolutions.co.uk/threading/
//          implementing-a-thread-safe-queue-using-condition-variables.html
template <typename T>
class msg_q
{
public:
    void push(const T& msg)
    {
        std::unique_lock<std::mutex> lock{_m};
        const bool was_empty = _q.empty();
        _q.push(msg);
        lock.unlock();
        if (was_empty)
            _cv.notify_one();
    }

    T pop()
    {
        // Yes, yes.. API should ideally be `T& front()` and `void pop()`,
        // but it's good enough for testing here. ~T Shall not throw.
        std::unique_lock<std::mutex> lock{_m};
        while (_q.empty())
            _cv.wait(lock);
        T value = _q.front();
        _q.pop();
        return value;
    }

private:
    std::mutex _m;
    std::condition_variable _cv;
    std::queue<T> _q;
};

class test_thread
{
public:
    test_thread()
    {
        qdb_thread_id_init();
        start();
    }

    void start()
    {
        if (_t)
            throw std::runtime_error("Thread already started");
        _t = std::thread{[&](){
                fprintf(stderr, "test_thread :: (A) %d\n", GetCurrentThreadId());
                bool run = true;
                while (run)
                {
                    switch (_req_q.pop())
                    {
                        case req::id:
                            _res_q.push(qdb_thread_id());
                            break;
                        
                        case req::stop:
                            run = false;
                            break;
                    }
                }
                fprintf(stderr, "test_thread :: (Z) %d\n", GetCurrentThreadId());
            }};
    }

    int id()
    {
        check_started();
        _req_q.push(req::id);
        return _res_q.pop();
    }

    void stop()
    {
        if (!_t)
            return;
        _req_q.push(req::stop);
        _t->join();
        _t.reset();
    }

    ~test_thread()
    {
        stop();
    }

private:
    void check_started()
    {
        if (!_t)
            throw std::runtime_error("Thread not started");
    }

    enum class req { id, stop };
    
    msg_q<req> _req_q;
    msg_q<int> _res_q;
    std::optional<std::thread> _t;
};

extern "C" void qdb_thread_id_reset_for_testing();

// TEST_CASE("2 threads, 2 ids")
// {
//     qdb_thread_id_reset_for_testing();

//     test_thread tt1;
//     test_thread tt2;

//     CHECK(tt1.id() == 0);
//     CHECK(tt1.id() == 0);
//     CHECK(tt2.id() == 1);
//     CHECK(tt2.id() == 1);
//     CHECK(tt1.id() == 0);
//     CHECK(tt1.id() == 0);
//     CHECK(tt2.id() == 1);
//     CHECK(tt2.id() == 1);
// }

TEST_CASE("2 threads, 2 ids   (B)")
{
    fprintf(stderr, "2 threads, 2 ids   (B)\n");
    qdb_thread_id_reset_for_testing();

    test_thread tt1;
    test_thread tt2;

    CHECK(tt1.id() == 0);
    CHECK(tt2.id() == 1);
    CHECK(tt1.id() == 0);

    tt1.stop();
    tt2.stop();
}

// TEST_CASE("0 id reused across threads")
// {
//     qdb_thread_id_reset_for_testing();

//     test_thread tt1;
//     CHECK(tt1.id() == 0);

//     test_thread tt2;
//     tt1.stop();

//     CHECK(tt2.id() == 0);
//     tt2.stop();
// }


#if defined(PLATFORM_WINDOWS)


#else  // pthread supported platforms

TEST_CASE("Stack of ids behaviour")
{
    qdb_thread_id_reset_for_testing();

    test_thread tt0;
    CHECK(tt0.id() == 0);
    test_thread tt1;
    CHECK(tt1.id() == 1);
    test_thread tt2;
    CHECK(tt2.id() == 2);
    test_thread tt3;
    CHECK(tt3.id() == 3);

    tt1.stop();
    tt0.stop();
    tt2.stop();

    test_thread tt4;
    CHECK(tt4.id() == 2);  // The latest value pushed on the stack.

    test_thread tt5;
    CHECK(tt5.id() == 0);  // The next value pushed on the stack.

    test_thread tt6;
    CHECK(tt6.id() == 1);  // The next value pushed on the stack.

    test_thread tt7;
    CHECK(tt7.id() == 4);  // A new value, all buckets are busy.
}

TEST_CASE("Resize")
{
    qdb_thread_id_reset_for_testing();

    std::vector<test_thread> ttv1{32};
    for (size_t index = 0; index < ttv1.size(); ++index)
        CHECK(ttv1[index].id() == static_cast<int>(index));

    // Stopping threads backwards.
    for (size_t index = ttv1.size(); index-- > 0; )
        ttv1[index].stop();

    std::vector<test_thread> ttv2{4};
    for (size_t index = 0; index < ttv2.size(); ++index)
        CHECK(ttv2[index].id() == static_cast<int>(index));

    // Stopping threads forwards.
    for (size_t index = 0; index < ttv2.size(); ++index)
        ttv2[index].stop();

    std::vector<test_thread> ttv3{4};
    for (size_t index = 0; index < ttv3.size(); ++index)
        CHECK(ttv3[index].id() == static_cast<int>(ttv3.size() - 1 - index));
}
#endif
