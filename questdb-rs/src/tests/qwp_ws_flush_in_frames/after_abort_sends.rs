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
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

//! What a sender sends of a flush in frames that failed part way: no frame of
//! it from the moment it failed, on its connection and on a new one, and
//! whether a frame of it was sent before is what its error says with
//! `in_doubt`.

use std::sync::Arc;

use super::{
    ConfirmationHold, ConfirmationStoredHookGuard, FIRST, FRAME_LIMIT, LaterFrameHookGuard,
    Progress, QwpWsModelServer, RECONNECT_SOON, SCHEMA_MISMATCH, TABLE, WAIT,
    assert_rejected_for_good, assert_table_holds, buffer_of_symbols, frame_of_a_sender,
    frames_of_a_sender, let_it_work, on_disk, rows_of, sender_with, stopped_by_a_full_dictionary,
    symbols_held_before, wait_for_no_connection, wait_until,
};
use crate::ErrorCode;
use crate::ingress::{AckLevel, Sender, SymbolGlobalDict, TestDictCapGuard};

/// A sender whose dictionary holds `symbols` symbols, which tries a server
/// that went away again soon. A `hold` parks its network thread.
fn sender_of(
    server: &QwpWsModelServer,
    progress: Progress,
    symbols: usize,
    hold: Option<&Arc<ConfirmationHold>>,
) -> Sender {
    // The dictionary and the hook of a sender are taken when it is built.
    let _cap = TestDictCapGuard::new(symbols);
    let _hook = hold.map(|hold| ConfirmationStoredHookGuard::new(hold.hook()));
    sender_with(server.port, progress, RECONNECT_SOON)
}

/// Lets the sender work until it has connected again `reconnects` times.
fn wait_for_reconnects(sender: &mut Sender, progress: Progress, reconnects: u64) {
    wait_until(WAIT, || {
        let done = sender.qwp_ws_totals().unwrap().reconnects_succeeded >= reconnects;
        if !done {
            let_it_work(sender, progress);
        }
        done
    });
    assert_eq!(
        sender.qwp_ws_totals().unwrap().reconnects_succeeded,
        reconnects
    );
}

/// Two flushes before, and a flush in frames of a table of its own that
/// fails part way before the sender has handed any of its frames to the
/// transport: in background progress mode its network thread is parked at
/// the confirmation of the first flush, in manual progress mode nobody
/// drives it. The error is not in doubt, and the sender sends no frame of
/// the failed flush once it goes on: neither on its connection, which the
/// server ends once it has taken the second flush, before it answers it,
/// nor on the new one, on which it sends the second flush again.
fn a_flush_that_fails_part_way_before_its_frames_are_sent_is_not_in_doubt_and_none_is_sent_after(
    progress: Progress,
) {
    let server = QwpWsModelServer::start_cutting_first_connection(FRAME_LIMIT, 2);
    let first_before = buffer_of_symbols(TABLE, 0..10);
    let second_before = buffer_of_symbols(TABLE, 10..20);
    let large = buffer_of_symbols(FIRST, 20..1220);
    let mut sender_symbols = SymbolGlobalDict::new();
    frame_of_a_sender(&first_before, false, &mut sender_symbols);
    frame_of_a_sender(&second_before, false, &mut sender_symbols);
    let frames = frames_of_a_sender(&large, FRAME_LIMIT, &mut sender_symbols);
    let failing = frames.len() / 2;
    assert!(failing > 2, "{} frames", frames.len());
    let symbols = symbols_held_before(&frames[failing]);
    let hold = Arc::new(ConfirmationHold::default());
    hold.arm();
    let background = matches!(progress, Progress::Background);
    let mut sender = sender_of(&server, progress, symbols, background.then_some(&hold));

    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&first_before).unwrap(),
        Some(0)
    );
    if background {
        assert_eq!(hold.wait_until_parked(), Some(0));
    } else {
        sender.wait(AckLevel::Ok, WAIT).unwrap();
    }
    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&second_before).unwrap(),
        Some(1)
    );
    let err = sender.flush_and_keep(&large).unwrap_err();
    assert_eq!(err.code(), ErrorCode::FlushAborted, "{}", err.msg());
    assert!(!err.in_doubt());
    assert_eq!(err.msg(), stopped_by_a_full_dictionary(symbols, false));
    assert_eq!(server.frames_taken(), 1);
    hold.release();

    // The sender sends the second flush, which ends its first connection,
    // and sends it again on the second.
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_eq!(sender.completed_fsn(AckLevel::Ok).unwrap(), Some(1));
    assert_eq!(sender.published_fsn().unwrap(), Some(1));
    assert_eq!(sender.qwp_ws_totals().unwrap().reconnects_succeeded, 1);
    sender.close_drain().unwrap();
    drop(sender);
    // The server has taken everything the sender wrote.
    wait_for_no_connection(&server);
    assert_eq!(server.model.frames_with_rows_of(FIRST), 0);
    assert!(server.model.table(FIRST).is_none());
    // The second flush is committed on both connections: the first ended
    // after the commit and before its answer.
    assert_table_holds(
        &server,
        TABLE,
        3,
        &[&first_before, &second_before, &second_before],
    );
    server.finish();
}

/// The server commits a table by itself once it holds this many rows of it.
const ROW_LIMIT: usize = 300;

/// A flush before, and a flush in frames of a table of its own whose frames
/// before the one that fails part way the server has all taken when it
/// fails: more rows of its table than its row limit, so the server has
/// committed a part of them by itself. The error is in doubt and says so.
/// The sender sends no frame of the failed flush again, also on the new
/// connection it makes after the server went away.
fn a_flush_that_fails_part_way_after_its_frames_are_sent_is_in_doubt_and_none_is_sent_again(
    progress: Progress,
) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    server.model.commit_by_itself_at(ROW_LIMIT);
    let before = buffer_of_symbols(TABLE, 0..10);
    let large = buffer_of_symbols(FIRST, 10..1210);
    let mut sender_symbols = SymbolGlobalDict::new();
    frame_of_a_sender(&before, false, &mut sender_symbols);
    let frames = frames_of_a_sender(&large, FRAME_LIMIT, &mut sender_symbols);
    let failing = frames.len() / 2;
    let symbols = symbols_held_before(&frames[failing]);
    let mut sender = sender_of(&server, progress, symbols, None);

    assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    let err = {
        // Before the flush cuts the frame that fails, the server has taken
        // the flush before and every frame of this one that it published.
        let published = 1 + failing;
        let (frames_taken, mut later_frames) = (server.frames_taken_reader(), 0);
        let _hook = LaterFrameHookGuard::new(Box::new(move || {
            later_frames += 1;
            if later_frames == failing {
                wait_until(WAIT, || frames_taken() >= published);
            }
        }));
        sender.flush_and_keep(&large).unwrap_err()
    };
    assert_eq!(err.code(), ErrorCode::FlushAborted, "{}", err.msg());
    assert!(err.in_doubt());
    assert_eq!(err.msg(), stopped_by_a_full_dictionary(symbols, true));
    assert_eq!(server.model.frames_with_rows_of(FIRST), failing);
    // What the server committed by itself is the first rows of the flush,
    // and more than its row limit holds.
    let committed = server.model.table(FIRST).unwrap().rows_as_text();
    let rows = rows_of(FIRST, &large);
    assert!(
        (ROW_LIMIT..rows.len()).contains(&committed.len()),
        "{} rows committed",
        committed.len()
    );
    assert_eq!(committed, rows[..committed.len()]);

    server.go_down();
    wait_for_no_connection(&server);
    server.come_back();
    wait_for_reconnects(&mut sender, progress, 1);
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_eq!(sender.completed_fsn(AckLevel::Ok).unwrap(), Some(0));
    assert_eq!(sender.published_fsn().unwrap(), Some(0));
    sender.close_drain().unwrap();
    drop(sender);
    wait_for_no_connection(&server);
    assert_eq!(server.model.frames_with_rows_of(FIRST), failing);
    assert_eq!(server.model.table(FIRST).unwrap().rows_as_text(), committed);
    assert_table_holds(&server, TABLE, 1, &[&before]);
    server.finish();
}

/// A flush before, and a flush in frames of a table of its own whose frames
/// before the one that fails part way the server has all taken, more rows of
/// its table than its row limit, so it has committed a part of them by
/// itself. The server rejects the last of those frames for good, and the
/// sender stops for that reason before the flush cuts the frame that fails.
/// The flush fails with that rejection, which is in doubt: frames of the
/// flush were sent.
fn a_flush_that_fails_part_way_after_the_sender_stopped_for_a_frame_of_it_is_in_doubt(
    progress: Progress,
) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    server.model.commit_by_itself_at(ROW_LIMIT);
    let before = buffer_of_symbols(TABLE, 0..10);
    let large = buffer_of_symbols(FIRST, 10..1210);
    let mut sender_symbols = SymbolGlobalDict::new();
    frame_of_a_sender(&before, false, &mut sender_symbols);
    let frames = frames_of_a_sender(&large, FRAME_LIMIT, &mut sender_symbols);
    let failing = frames.len() / 2;
    let symbols = symbols_held_before(&frames[failing]);
    let mut sender = sender_of(&server, progress, symbols, None);

    assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    // The last frame of the flush published before the one that fails:
    // frame `failing` of the sender, the server's frame `failing + 1`.
    server.reject_frame(failing + 1, SCHEMA_MISMATCH);
    let err = {
        let published = 1 + failing;
        let frames_taken = server.frames_taken_reader();
        let open_connections = server.open_connections_reader();
        let mut later_frames = 0;
        let _hook = LaterFrameHookGuard::new(Box::new(move || {
            later_frames += 1;
            if later_frames == failing {
                wait_until(WAIT, || frames_taken() >= published);
                // A sender that stops ends its connection once it has
                // stopped; the error below tells that the rejection is why.
                wait_until(WAIT, || open_connections() == 0);
            }
        }));
        sender.flush_and_keep(&large).unwrap_err()
    };
    assert_rejected_for_good(&err, failing as u64);
    assert!(err.in_doubt());
    let committed = server.model.table(FIRST).unwrap().rows_as_text();
    assert!(
        committed.len() >= ROW_LIMIT,
        "{} rows committed",
        committed.len()
    );
    assert_eq!(committed, rows_of(FIRST, &large)[..committed.len()]);
    drop(sender);
    server.finish();
}

mod a_flush_that_fails_part_way_before_its_frames_are_sent_is_not_in_doubt_and_none_is_sent_after {
    use super::a_flush_that_fails_part_way_before_its_frames_are_sent_is_not_in_doubt_and_none_is_sent_after as test;
    use super::{Progress, on_disk};

    #[test]
    fn background() {
        test(Progress::Background);
    }

    #[test]
    fn manual() {
        test(Progress::Manual);
    }

    #[test]
    fn on_disk_background() {
        on_disk(test, Progress::Background);
    }

    #[test]
    fn on_disk_manual() {
        on_disk(test, Progress::Manual);
    }
}

/// Only a sender in background progress mode sends during a flush that has
/// room in its queue.
mod a_flush_that_fails_part_way_after_its_frames_are_sent_is_in_doubt_and_none_is_sent_again {
    use super::a_flush_that_fails_part_way_after_its_frames_are_sent_is_in_doubt_and_none_is_sent_again as test;
    use super::{Progress, on_disk};

    #[test]
    fn background() {
        test(Progress::Background);
    }

    #[test]
    fn on_disk_background() {
        on_disk(test, Progress::Background);
    }
}

/// Only a sender in background progress mode sends during a flush that has
/// room in its queue.
mod a_flush_that_fails_part_way_after_the_sender_stopped_for_a_frame_of_it_is_in_doubt {
    use super::a_flush_that_fails_part_way_after_the_sender_stopped_for_a_frame_of_it_is_in_doubt as test;
    use super::{Progress, on_disk};

    #[test]
    fn background() {
        test(Progress::Background);
    }

    #[test]
    fn on_disk_background() {
        on_disk(test, Progress::Background);
    }
}
