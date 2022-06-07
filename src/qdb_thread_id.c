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

// Ensures the init function is only called once.
static qdb_call_once_flag init_flag = qdb_not_called;

#if defined(PLATFORM_WINDOWS)

#include <Windows.h>
#include <synchapi.h>
#include <tlhelp32.h>
#include <stdlib.h>

SRWLOCK lock;

typedef struct
{
    DWORD os_thread_id;
    qdb_thread_id_t mapped_id;
} map_entry_t;

size_t map_len;
size_t map_capacity;
static map_entry_t* map;

size_t id_stack_len;
size_t id_stack_capacity;
static qdb_thread_id_t* id_stack;

static void init_impl()
{
    InitializeSRWLock(&lock);

    map_len = 0;
    map_capacity = 8;
    map = aborting_malloc(map_capacity * sizeof(map_entry_t));

    id_stack_len = 0;
    id_stack_capacity = 8;
    id_stack = aborting_malloc(id_stack_capacity * sizeof(qdb_thread_id_t));
}

static void id_stack_push(qdb_thread_id_t id)
{
    if (id_stack_capacity <= id_stack_len)
    {
        id_stack_capacity *= 2;
        id_stack = aborting_realloc(id_stack, id_stack_capacity * sizeof(size_t));
    }
    id_stack[id_stack_len] = id;
    ++id_stack_len;
}

static qdb_thread_id_t next_id()
{
    if (id_stack_len > 0)
    {
        --id_stack_len;
        fprintf(stderr, "next_id :: (A) %d\n", id_stack[id_stack_len]);
        return id_stack[id_stack_len];
    }
    else
    {
        fprintf(stderr, "next_id :: (B) %d\n", (qdb_thread_id_t)map_len);
        return (qdb_thread_id_t)map_len;
    }
}

static int compare_win32_thread_id(const void* lhs, const void* rhs)
{
    const DWORD* left = lhs;
    const DWORD* right = rhs;
    return *left - *right;
}

static DWORD* list_active_thread_ids(size_t* len_out)
{
    size_t len = 0;
    size_t capacity = 8;
    DWORD curr_proc_id = GetCurrentProcessId();
    DWORD* active = aborting_malloc(capacity * sizeof(DWORD));

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        fprintf(
            stderr,
            "Could not CreateToolhelp32Snapshot. GetLastError(): %d\n",
            GetLastError());
        abort();
    }

    THREADENTRY32 thread;
    thread.dwSize = sizeof(THREADENTRY32);
    if (!Thread32First(snapshot, &thread))
    {
        fprintf(
            stderr,
            "Could not begin listing process ids. GetLastError(): %d\n",
            GetLastError());
        abort();
    }

    if (thread.th32OwnerProcessID == curr_proc_id)
        active[++len] = thread.th32ThreadID;

    while (Thread32Next(snapshot, &thread))
    {
        if (len == capacity)
        {
            capacity *= 2;
            active = aborting_realloc(active, capacity * sizeof(DWORD));
        }
        if (thread.th32OwnerProcessID == curr_proc_id)
            active[++len] = thread.th32ThreadID;
    }

    DWORD last_err = GetLastError();
    if (last_err != ERROR_NO_MORE_FILES)
    {
        fprintf(
            stderr,
            "Failed to list thread. GetLastError(): %d\n",
            last_err);
        abort();
    }

    CloseHandle(snapshot);

    qsort(active, len, sizeof(DWORD), compare_win32_thread_id);

    *len_out = len;
    return active;
}

static void gc_dead_thread_ids()
{
    fprintf(stderr, "gc_dead_thread_ids :: (A) map_len: %" PRIu64 "\n", map_len);
    // Get a sorted list of windows thread ids for the current process.
    size_t active_len;
    DWORD* active = list_active_thread_ids(&active_len);
    fprintf(stderr, "gc_dead_thread_ids :: (B) active: ");
    for (size_t index = 0; index < active_len; ++index)
        fprintf(stderr, "%d ", active[index]);
    fprintf(stderr, "\n");

    // build a consolidated map that doesn't contain old entries..
    size_t map2_len = 0;
    map_entry_t* map2 = malloc(map_capacity * sizeof(map_entry_t));
    fprintf(stderr, "gc_dead_thread_ids :: (C)\n");

    // ..by walking both lists together.
    size_t map_index = 0;
    for (size_t active_index = 0;
         (map_index < map_len) && (active_index < active_len);)
    {
        const map_entry_t* entry = &map[map_index];
        DWORD entry_tid = entry->os_thread_id;
        DWORD active_tid = active[active_index];
        if (entry_tid < active_tid)
        {
            // Iterating entry for an exited thread. Clean up.
            id_stack_push(entry->mapped_id);
            ++map_index;
        }
        else if (entry_tid == active_tid)
        {
            // Iterating active entry. Keep it.
            map2[++map2_len] = *entry;
        }
        else  // (entry_tid > active_tid)
        {
            ++active_index;
        }
    }

    // Clean up after any entries that are larger than those of the active list.
    for (; map_index < map_len; ++map_index)
        id_stack_push(map[map_index].os_thread_id);

    // Swap it out.
    map_len = map2_len;
    free(map);
    map = map2;
    fprintf(stderr, "gc_dead_thread_ids :: (Z) map_len: %" PRIu64"\n", map_len);
}

static int compare_map_entry(const void* lhs, const void* rhs)
{
    const map_entry_t* left = lhs;
    const map_entry_t* right = rhs;
    return (int)left->os_thread_id - (int)right->os_thread_id;
}

static const map_entry_t* find_mapping(DWORD os_thread_id)
{
    map_entry_t sought;
    sought.os_thread_id = os_thread_id;
    return bsearch(
        &sought,
        map,
        map_len,
        sizeof(map_entry_t),
        compare_map_entry);
}

static void register_mapping(DWORD os_thread_id, qdb_thread_id_t mapped_id)
{
    if (map_len == map_capacity)
    {
        map_capacity *= 2;
        map = aborting_realloc(map, map_capacity * sizeof(map_entry_t));
    }
    map[map_len].os_thread_id = os_thread_id;
    map[map_len].mapped_id = mapped_id;
    ++map_len;
    qsort(map, map_len, sizeof(map_entry_t), compare_map_entry);
}

qdb_thread_id_t qdb_thread_id()
{
    DWORD os_thread_id = GetCurrentThreadId();
    fprintf(stderr, "qdb_thread_id :: (A) %d\n", os_thread_id);

    // First, we attempt to find an existing entry in the map.
    {
        AcquireSRWLockShared(&lock);
        const map_entry_t* result = find_mapping(os_thread_id);
        if (result)
        {
            qdb_thread_id_t value = result->mapped_id;
            ReleaseSRWLockShared(&lock);
            return value;
        }

        // Note: Can't "upgrade" lock from shared to exclusive.
        ReleaseSRWLockShared(&lock);
    }

    fprintf(stderr, "qdb_thread_id :: (B)\n");

    // If there isn't one, we add one in.
    AcquireSRWLockExclusive(&lock);
    
    fprintf(stderr, "qdb_thread_id :: (C)\n");
    gc_dead_thread_ids();
    fprintf(stderr, "qdb_thread_id :: (D)\n");
    qdb_thread_id_t mapped_id = next_id();
    fprintf(stderr, "qdb_thread_id :: (E)\n");
    register_mapping(os_thread_id, mapped_id);
    fprintf(stderr, "qdb_thread_id :: (F)\n");
    ReleaseSRWLockExclusive(&lock);
    fprintf(stderr, "qdb_thread_id :: (G) os_thread_id: %d, mapped_id: %d\n", os_thread_id, mapped_id);

    return mapped_id;
}

void qdb_thread_id_reset_for_testing()
{
    AcquireSRWLockExclusive(&lock);
    free(map);
    free(id_stack);
    init_impl();
    ReleaseSRWLockExclusive(&lock);
}

#else  // pthread supported platforms.

// A lock for accessing or mutating the buckets.
// This is only needed at thread creation / destruction.
static qdb_lock_t lock;

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

// pthread thread local key for the thread ID value.
static pthread_key_t thread_id_key;

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
    QDB_LOCK_ACQUIRE(&lock);
    free(buckets);
    init_impl();
    QDB_LOCK_RELEASE(&lock);
}

qdb_thread_id_t qdb_thread_id()
{
    void* cached = pthread_getspecific(thread_id_key);
    if (cached != NULL)
    {
        fprintf(stderr, "qdb_thread_id :: (A) %d\n", (int)(size_t)cached - 1);
        return (qdb_thread_id_t)(size_t)cached - 1;
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
    return (qdb_thread_id_t)id;
}
#endif

void qdb_thread_id_init()
{
    qdb_call_once(&init_flag, init_impl);
}