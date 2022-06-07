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

#pragma once

#include "build_env.h"
typedef enum
{
    qdb_not_called = 0,
    qdb_calling,
    qdb_called
} qdb_call_once_flag_state;

typedef
#if defined(PLATFORM_WINDOWS)
    volatile long
#else
    _Atomic enum qdb_call_once_flag_state
#endif
  qdb_call_once_flag;
typedef void(*qdb_call_once_callback)();

/**
 * Call the function only once.
 *
 * This is guarded by the provided flag.
 * This is implemented with a series of atomic spinlocks.
 *
 * This implementation guarantees that any competing calls wait until
 * the the first called has completed its call.
 */
void qdb_call_once(qdb_call_once_flag*, qdb_call_once_callback);
