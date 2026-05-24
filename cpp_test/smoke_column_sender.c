/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2025 QuestDB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 ******************************************************************************/

/*
 * Hand-runnable smoke test for the column-major sender C ABI.
 *
 * Not wired into CMake — the in-tree CMake build does not yet build the
 * column-sender ABI surface as a C test (the existing `smoke_line_reader`
 * pattern wires through ctest; we'll follow it once the C test matrix
 * for the column sender is fleshed out).
 *
 * Build manually against a real QuestDB instance, e.g.:
 *
 *   gcc -std=c11 cpp_test/smoke_column_sender.c \
 *       -I include -L target/debug -lquestdb_client \
 *       -o smoke_column_sender
 *
 *   ./smoke_column_sender "qwpws::addr=localhost:9000;"
 *
 * Round-trips a single 3-row chunk with mixed i64, f64, varchar, and a
 * designated timestamp. Prints any client-side error to stderr and
 * exits non-zero; on success exits 0 after flushing and returning the
 * sender to the pool.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "questdb/ingress/column_sender.h"

static int die(line_sender_error* err, const char* what)
{
    if (err) {
        size_t msg_len = 0;
        const char* msg = line_sender_error_msg(err, &msg_len);
        fprintf(stderr, "%s: %.*s\n", what, (int)msg_len, msg);
        line_sender_error_free(err);
    } else {
        fprintf(stderr, "%s\n", what);
    }
    return 1;
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        fprintf(stderr,
                "usage: %s 'qwpws::addr=host:port;[options]'\n",
                argv[0]);
        return 2;
    }
    const char* conf = argv[1];

    line_sender_error* err = NULL;
    questdb_db* db = questdb_db_connect(conf, strlen(conf), &err);
    if (!db)
        return die(err, "questdb_db_connect failed");

    column_sender* sender = questdb_db_borrow_sender(db, &err);
    if (!sender) {
        questdb_db_close(db);
        return die(err, "questdb_db_borrow_sender failed");
    }

    const char* table = "smoke_column_sender";
    column_sender_chunk* chunk =
        column_sender_chunk_new(table, strlen(table), &err);
    if (!chunk) {
        questdb_db_return_sender(db, sender);
        questdb_db_close(db);
        return die(err, "column_sender_chunk_new failed");
    }

    const char* qty_name = "qty";
    const int64_t qty[3] = { 10, 20, 30 };
    if (!column_sender_chunk_column_i64(
            chunk, qty_name, strlen(qty_name),
            qty, 3, NULL, &err))
    {
        column_sender_chunk_free(chunk);
        questdb_db_return_sender(db, sender);
        questdb_db_close(db);
        return die(err, "column_i64(qty) failed");
    }

    const char* price_name = "price";
    const double price[3] = { 1.1, 2.2, 3.3 };
    if (!column_sender_chunk_column_f64(
            chunk, price_name, strlen(price_name),
            price, 3, NULL, &err))
    {
        column_sender_chunk_free(chunk);
        questdb_db_return_sender(db, sender);
        questdb_db_close(db);
        return die(err, "column_f64(price) failed");
    }

    /* Arrow Utf8: 3 rows of varchar with one null in the middle.
       offsets length = row_count + 1; null row's slice is ignored by
       the encoder (we set it to zero length here to keep offsets
       monotonic). */
    const char* msg_name = "msg";
    const int32_t msg_offsets[4] = { 0, 5, 5, 10 };
    const uint8_t msg_bytes[] = { 'a','l','p','h','a',
                                  'g','a','m','m','a' };
    const uint8_t msg_validity_bits = 0x05u; /* rows 0 + 2 valid, row 1 null */
    const column_sender_validity msg_validity = {
        &msg_validity_bits, 3
    };
    if (!column_sender_chunk_column_varchar(
            chunk, msg_name, strlen(msg_name),
            msg_offsets, msg_bytes, sizeof(msg_bytes),
            3, &msg_validity, &err))
    {
        column_sender_chunk_free(chunk);
        questdb_db_return_sender(db, sender);
        questdb_db_close(db);
        return die(err, "column_varchar(msg) failed");
    }

    const int64_t ts_nanos[3] = {
        (int64_t)1700000000000000000LL,
        (int64_t)1700000000000001000LL,
        (int64_t)1700000000000002000LL
    };
    if (!column_sender_chunk_designated_timestamp_nanos(
            chunk, ts_nanos, 3, &err))
    {
        column_sender_chunk_free(chunk);
        questdb_db_return_sender(db, sender);
        questdb_db_close(db);
        return die(err, "designated_timestamp_nanos failed");
    }

    if (!column_sender_flush(
            sender, chunk, column_sender_ack_level_ok, &err))
    {
        column_sender_chunk_free(chunk);
        questdb_db_return_sender(db, sender);
        questdb_db_close(db);
        return die(err, "column_sender_flush failed");
    }

    column_sender_chunk_free(chunk);
    questdb_db_return_sender(db, sender);
    questdb_db_close(db);
    fprintf(stdout, "ok\n");
    return 0;
}
