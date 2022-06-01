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

void qdb_thread_id_init();

/**
 * A temporarily unique thread ID.
 *
 * Provided IDs are only unique for at a given point in time.
 * IDs are re-used once a thread exits.
 * This is designed to give threads low numbers.
 *
 * In other words, if 4 threads invoke this functions in sequence,
 * their IDs are going to be 0, 1, 2, 3.
 *
 * If thread 1 exits and another one is started, the new thread will be
 * assigned id 1 again.
 */
int qdb_thread_id();
