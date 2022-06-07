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

#include "qdb_call_once.h"
#include "build_env.h"

#include <stdbool.h>

#if defined(PLATFORM_WINDOWS)
#    include <Windows.h>
#    include <processthreadsapi.h>
#    define ATOMIC_LOAD(flag) *flag
#    define ATOMIC_STORE(flag, value) *flag = value
#    define YIELD_THREAD SwitchToThread
#else
#    include <stdatomic.h>
#    include <sched.h>
#    define ATOMIC_LOAD atomic_load
#    define ATOMIC_STORE atomic_store
#    define YIELD_THREAD sched_yield
#endif

static const qdb_call_once_flag_state state_not_called = qdb_not_called;

void qdb_call_once(qdb_call_once_flag* flag, qdb_call_once_callback cb)
{
    if (((qdb_call_once_flag_state) ATOMIC_LOAD(flag)) == qdb_called)
        return;

#if defined(PLATFORM_WINDOWS)
    const bool exchanged =
        InterlockedCompareExchange(
            flag,
            qdb_calling,
            qdb_not_called
        ) == qdb_not_called;
#else
    const bool exchanged = atomic_compare_exchange_strong(
        flag,
        &state_not_called,
        qdb_calling);
#endif
    if (exchanged)
    {
        // This thread won the lock. It gets to call the function.
        cb();
        // and then set the "called" flag.
        ATOMIC_STORE(flag, qdb_called);
    }
    else
    {
        while (((qdb_call_once_flag_state) ATOMIC_LOAD(flag)) == qdb_calling)
        {
            YIELD_THREAD();
        }
    }
}
