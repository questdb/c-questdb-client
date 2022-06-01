#include "qdb_thread_id.h"
#include "qdb_call_once.h"
#include "qdb_lock.h"
#include "aborting_malloc.h"

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>


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

#if defined(PLATFORM_WINDOWS)

void qdb_thread_id_init()
{

}

int qdb_thread_id()
{
    return 42;  // TODO whole impl, needs to a complete different approach.
}

#else  // pthread supported platforms.

// A stack of size_t values:
// The logic uses the bucket indices as thread ids.
// The bucket values themselves only track the next available bucket
// for when a thread exits.
// This forms an intrusive stack of available slots.
// The mapping between threads and their ID is held as a thread local:
// as such this logic does not need to keep any hashmap between thread IDs
// and the counters we return.
static size_t buckets_size;
static size_t* buckets = NULL;

// Points to the first available slot, or `buckets_size` if none
// are available.
static size_t first_avail;

// A lock for accessing or mutating the buckets.
// This is only needed at thread creation / destruction.
static qdb_lock_t lock;

// pthread thread local key for the thread ID value.
static pthread_key_t thread_id_key;

// Ensures the init function is only called once.
static qdb_call_once_flag init_flag = qdb_not_called;

static void buckets_init(size_t old_size, size_t new_size)
{
    for (size_t index = old_size; index < new_size; ++index)
        buckets[index] = index + 1;
}

static void buckets_grow()
{
    const size_t old_size = buckets_size;
    buckets_size *= 2;
    buckets = aborting_realloc(buckets, buckets_size * sizeof(size_t));
    buckets_init(old_size, buckets_size);
}

static void release_thread_id(void* value)
{
    size_t id = (size_t)value - 1;
    QDB_LOCK_ACQUIRE(&lock);
    fprintf(stderr, "release_thread_id :: (A) id: %zu, first_avail: %zu, buckets[id]: %zu\n",
        id, first_avail, buckets[id]);
    for (size_t index = 0; index < buckets_size; ++index)
        fprintf(stderr, "    [%zu]: %zu\n", index, buckets[index]);
    // Push-front free bucket into linked list "stack", headed by "first_avail".
    buckets[id] = first_avail;
    first_avail = id;
    fprintf(stderr, "release_thread_id :: (B) id: %zu, first_avail: %zu, buckets[id]: %zu\n",
        id, first_avail, buckets[id]);
    QDB_LOCK_RELEASE(&lock);
}

static void init_impl()
{
    QDB_LOCK_INIT(&lock);

    buckets_size = 8;
    buckets = aborting_malloc(buckets_size * sizeof(size_t));
    buckets_init(0, buckets_size);
    first_avail = 0;

    // We leak the key this until application end by never calling `tss_delete`.
    // We clean up any associated IDs (and buckets) each time a thread exits.
    const int error = pthread_key_create(&thread_id_key, release_thread_id);
    if (error)
    {
        fprintf(stderr, "Failed to create thread local key. Error: %d.", error);
        abort();
    }
}

void qdb_thread_id_reset_for_testing()
{
    free(buckets);
    init_impl();
}

void qdb_thread_id_init()
{
    qdb_call_once(&init_flag, init_impl);
}

int qdb_thread_id()
{
    void* cached = pthread_getspecific(thread_id_key);
    if (cached != NULL)
    {
        fprintf(stderr, "qdb_thread_id :: (A) %d\n", (int)(size_t)cached - 1);
        return (int)(size_t)cached - 1;
    }

    QDB_LOCK_ACQUIRE(&lock);
    const size_t id = first_avail;
    if (id == buckets_size)
        buckets_grow();
    const size_t next_avail = buckets[id];
    first_avail = next_avail;
    QDB_LOCK_RELEASE(&lock);

    // We need to avoid the value `0` (NULL), so we bump up by 1.
    int error = pthread_setspecific(thread_id_key, (void*)(id + 1));
    if (error)
    {
        fprintf(stderr, "Failed setting thread ID local. Error: %d", error);
        abort();
    }
    fprintf(stderr, "qdb_thread_id :: (B) %d\n", (int)id);
    return (int)id;
}
#endif
