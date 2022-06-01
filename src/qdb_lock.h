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

#if defined(PLATFORM_WINDOWS)
#    include <synchapi.h>
typedef CRITICAL_SECTION qdb_lock_t;
#    define QDB_LOCK_INIT InitializeCriticalSection
#    define QDB_LOCK_ACQUIRE EnterCriticalSection
#    define QDB_LOCK_RELEASE LeaveCriticalSection
#else
#    include <pthread.h>
typedef pthread_mutex_t qdb_lock_t;
#    define QDB_LOCK_INIT(lock)
#    define QDB_LOCK_ACQUIRE pthread_mutex_lock
#    define QDB_LOCK_RELEASE pthread_mutex_unlock
#endif
