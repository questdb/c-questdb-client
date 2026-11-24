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

//! What a sender does with the answers of the server about the frames of a
//! flush in frames that failed part way, once the flush has failed.
//!
//! The error of the flush already says what of it the server may hold. So
//! an answer about one of its frames is reported as an error of the server
//! and changes nothing else: the sender does not stop, does not connect
//! again, and goes on confirming the flushes before it, at every ack level.

use super::*;
use crate::tests::qwp_ws::{MOCK_DURABLE_LOCAL, MOCK_DURABLE_ON, MockDurableTier};

/// The durable acks a sender requests.
#[derive(Clone, Copy)]
enum DurableAcks {
    /// `request_durable_ack=on`: acks once a commit is replicated.
    On,
    /// `request_durable_ack=local`: acks once a commit is on the server's
    /// own disk.
    Local,
}

impl DurableAcks {
    fn setting(self) -> &'static str {
        match self {
            DurableAcks::On => "request_durable_ack=on;",
            DurableAcks::Local => "request_durable_ack=local;",
        }
    }

    fn tier(self) -> MockDurableTier {
        match self {
            DurableAcks::On => MOCK_DURABLE_ON,
            DurableAcks::Local => MOCK_DURABLE_LOCAL,
        }
    }

    fn level(self) -> AckLevel {
        match self {
            DurableAcks::On => AckLevel::Durable,
            DurableAcks::Local => AckLevel::LocalDurable,
        }
    }
}

/// A flush before, of one frame, and a buffer whose flush in frames finds
/// the dictionary of its sender full at a middle frame: the number of that
/// frame in the flush, and the size of the dictionary.
fn a_flush_before_and_one_that_fails_at_a_middle_frame() -> (Buffer, Buffer, usize, usize) {
    let before = buffer_of_symbols(TABLE, 0..10);
    let large = buffer_of_symbols(TABLE, 10..1210);
    let mut sender_symbols = SymbolGlobalDict::new();
    frame_of_a_sender(&before, false, &mut sender_symbols);
    let frames = frames_of_a_sender(&large, FRAME_LIMIT, &mut sender_symbols);
    let failing = frames.len() / 2;
    assert!(failing > 2, "{} frames", frames.len());
    let symbols = symbols_held_before(&frames[failing]);
    (before, large, failing, symbols)
}

/// Flushes `large`, which fails at its frame `failing`. In background
/// progress mode the flush cuts that frame only once the server has taken
/// `taken` frames of the sender, so that the network thread has sent the
/// frames of the flush before them.
fn flush_that_fails_part_way(
    sender: &mut Sender,
    progress: Progress,
    server: &QwpWsModelServer,
    large: &Buffer,
    failing: usize,
    taken: usize,
) -> crate::Error {
    let (frames_taken, mut later_frames) = (server.frames_taken_reader(), 0);
    let _hook = matches!(progress, Progress::Background).then(|| {
        LaterFrameHookGuard::new(Box::new(move || {
            later_frames += 1;
            if later_frames == failing {
                wait_until(WAIT, || frames_taken() >= taken);
            }
        }))
    });
    let err = sender.flush_and_keep(large).unwrap_err();
    assert_eq!(err.code(), ErrorCode::FlushAborted, "{}", err.msg());
    err
}

/// Waits until `sender` has read the OK of its first flush. A sender in
/// manual progress mode that requests durable acks reports one watermark,
/// the durable one, so only its count of acks tells.
fn wait_for_the_first_ok(sender: &mut Sender, progress: Progress) {
    match progress {
        Progress::Background => sender.wait(AckLevel::Ok, WAIT).unwrap(),
        Progress::Manual => wait_until(WAIT, || {
            sender.drive_once().unwrap();
            sender.qwp_ws_totals().unwrap().acks >= 1
        }),
    }
}

/// The settings of a new sender on the slot of the first sender that
/// [`on_disk`] gave a slot. None with the queues in memory.
fn the_slot_of_the_first_sender() -> Option<String> {
    SF_DIR.with(|sf_dir| {
        let sf_dir = sf_dir.borrow();
        let (dir, _) = sf_dir.as_ref()?;
        Some(format!(
            "sf_dir={};sender_id=sender1;",
            dir.path().display()
        ))
    })
}

/// A sender that requests durable acks: flush A gets its OK, and its
/// durable ack comes only after the server has rejected for good a frame of
/// flush B, a flush in frames that failed part way. The rejection is about
/// the failed flush, whose error already says what of it may be held. So
/// the sender goes on reading answers: A becomes durable, the calls about A
/// succeed at every ack level, `close_drain` empties the slot, and the next
/// sender on the slot sends nothing of A again.
///
/// In background progress mode the flush cuts its failing frame only once
/// the server has taken the rejected one: its error is in doubt. A sender in
/// manual progress mode drives nothing during a flush that has room, and
/// sends no frame of the flush once it has failed: the server takes none,
/// and has nothing to reject.
fn a_rejection_of_a_frame_of_a_flush_that_failed_part_way_leaves_the_flush_before_it_durable(
    progress: Progress,
    durable_acks: DurableAcks,
) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    server.grant_durable_acks(durable_acks.tier());
    let (before, large, failing, symbols) = a_flush_before_and_one_that_fails_at_a_middle_frame();
    let mut sender = {
        let _cap = crate::ingress::TestDictCapGuard::new(symbols);
        sender_with(server.port, progress, durable_acks.setting())
    };
    let level = durable_acks.level();

    assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
    wait_for_the_first_ok(&mut sender, progress);
    // The server takes A as its first frame. It rejects the second frame of
    // B, which is frame 2 of the sender, and tells so once B has failed.
    server.reject_frame(3, SCHEMA_MISMATCH);
    server.hold_answers();
    let err = flush_that_fails_part_way(&mut sender, progress, &server, &large, failing, 3);
    server.let_answers_go();

    match progress {
        Progress::Background => {
            assert_rejection_for_good(&the_server_error_read_by(&mut sender, progress), 2);
            assert_eq!(sender.poll_qwp_ws_error().unwrap(), None);
        }
        Progress::Manual => {
            for _ in 0..10 {
                sender.drive_once().unwrap();
            }
            assert_eq!(sender.poll_qwp_ws_error().unwrap(), None);
            assert_eq!(server.frames_taken(), 1);
        }
    }
    assert_eq!(sender.completed_fsn(level).unwrap(), None);
    server.send_durable_ack(&[(TABLE, 1)]);
    sender.wait(level, WAIT).unwrap();
    assert_eq!(sender.completed_fsn(level).unwrap(), Some(0));
    assert_eq!(sender.published_fsn().unwrap(), Some(0));
    assert_eq!(sender.acked_fsn().unwrap(), Some(0));
    assert_eq!(sender.completed_fsn(AckLevel::Ok).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_eq!(sender.qwp_ws_terminal_error().unwrap(), None);
    assert_stopped_by_a_full_dictionary(&sender, progress, &err, symbols);
    assert_eq!(err.in_doubt(), matches!(progress, Progress::Background));
    let later = sender.flush_and_keep(&before).unwrap_err();
    assert_refused_after_a_full_dictionary(&later, symbols);
    sender.close_drain().unwrap();
    assert_eq!(files_in_the_slots(), Vec::<String>::new());
    assert_table_holds(&server, TABLE, 1, &[&before]);
    drop(sender);

    if let Some(slot) = the_slot_of_the_first_sender() {
        wait_for_no_connection(&server);
        let taken = server.frames_taken();
        let mut next = sender_with(
            server.port,
            progress,
            &format!("{slot}{}", durable_acks.setting()),
        );
        assert_eq!(next.published_fsn().unwrap(), None);
        // A frame of A that the slot still held would go out before C.
        let c = buffer_of_symbols(TABLE, 5000..5001);
        assert_eq!(next.flush_and_keep_and_get_fsn(&c).unwrap(), Some(0));
        wait_for_the_first_ok(&mut next, progress);
        assert_eq!(server.frames_taken(), taken + 1);
        assert_table_holds(&server, TABLE, 2, &[&before, &c]);
        server.send_durable_ack(&[(TABLE, 2)]);
        next.wait(level, WAIT).unwrap();
        next.close_drain().unwrap();
        assert_eq!(files_in_the_slots(), Vec::<String>::new());
    }
    server.finish();
}

mod a_rejection_of_a_frame_of_a_flush_that_failed_part_way_leaves_the_flush_before_it_durable {
    use super::a_rejection_of_a_frame_of_a_flush_that_failed_part_way_leaves_the_flush_before_it_durable as test;
    use super::{DurableAcks, Progress, on_disk};

    fn on(progress: Progress) {
        test(progress, DurableAcks::On);
    }

    fn local(progress: Progress) {
        test(progress, DurableAcks::Local);
    }

    #[test]
    fn on_background() {
        on(Progress::Background);
    }

    #[test]
    fn on_manual() {
        on(Progress::Manual);
    }

    #[test]
    fn on_on_disk_background() {
        on_disk(on, Progress::Background);
    }

    #[test]
    fn on_on_disk_manual() {
        on_disk(on, Progress::Manual);
    }

    #[test]
    fn local_background() {
        local(Progress::Background);
    }

    #[test]
    fn local_manual() {
        local(Progress::Manual);
    }

    #[test]
    fn local_on_disk_background() {
        on_disk(local, Progress::Background);
    }

    #[test]
    fn local_on_disk_manual() {
        on_disk(local, Progress::Manual);
    }
}

/// The server rejects with `status` frame `rejected` of the sender, a frame
/// of a flush in frames that failed part way, and tells so once the flush
/// has failed. The first frame of the flush, which brings the first block of
/// a table, is where a schema mismatch shows. The sender reports the
/// rejection, which names the frame, as an error of the server, whatever the
/// policy of `status`, and nothing else changes: it does not stop, does not
/// connect again, confirms the flush before, and refuses a later flush. A
/// close drain empties its slot.
///
/// With `durable_acks`, the durable ack of the flush before comes after the
/// rejection, on the same connection: the sender reads it, which it could
/// not have done had the rejection made it stop or connect again. Without,
/// a ping after the rejection does the same: a sender that connects again
/// after a rejection waits first, and does not read the connection it
/// leaves, so it answers the ping only if it stayed.
///
/// Only a sender in background progress mode can have sent a frame of the
/// flush before the flush failed: the flush cuts its failing frame once the
/// server has taken the rejected one and the one after it. The server never
/// answers that one, so the sender keeps reading its connection: without
/// durable acks it reads only while a frame waits for an answer, and would
/// not answer the ping although it stayed.
fn a_rejection_of_a_frame_of_a_flush_that_failed_part_way_is_reported_and_changes_nothing_else(
    progress: Progress,
    (status, category, policy): (u8, QwpWsErrorCategory, QwpWsErrorPolicy),
    rejected: u64,
    durable_acks: Option<DurableAcks>,
) {
    assert!(matches!(progress, Progress::Background));
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    if let Some(durable_acks) = durable_acks {
        server.grant_durable_acks(durable_acks.tier());
    }
    let (before, large, failing, symbols) = a_flush_before_and_one_that_fails_at_a_middle_frame();
    // Frame 0 is the flush before, and the failing frame is not queued.
    assert!((1..failing as u64).contains(&rejected));
    let mut sender = {
        let _cap = crate::ingress::TestDictCapGuard::new(symbols);
        sender_with(
            server.port,
            progress,
            durable_acks.map_or("", DurableAcks::setting),
        )
    };

    assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    // The server counts the frames it takes from 1.
    let rejected_taken = rejected as usize + 1;
    server.reject_frame(rejected_taken, status);
    server.hold_answers();
    let err = flush_that_fails_part_way(
        &mut sender,
        progress,
        &server,
        &large,
        failing,
        rejected_taken + 1,
    );
    server.let_answers_go();

    let rejection = the_server_error_read_by(&mut sender, progress);
    assert_eq!(
        (
            rejection.category,
            rejection.applied_policy,
            rejection.status
        ),
        (category, policy, Some(status))
    );
    assert_eq!((rejection.from_fsn, rejection.to_fsn), (rejected, rejected));
    assert_eq!(sender.poll_qwp_ws_error().unwrap(), None);
    server.ping_and_wait_for_a_pong();
    assert_eq!(server.connections_taken(), 1);
    if let Some(durable_acks) = durable_acks {
        server.send_durable_ack(&[(TABLE, 1)]);
        sender.wait(durable_acks.level(), WAIT).unwrap();
        assert_eq!(sender.completed_fsn(durable_acks.level()).unwrap(), Some(0));
    }
    assert_eq!(sender.published_fsn().unwrap(), Some(0));
    assert_eq!(sender.acked_fsn().unwrap(), Some(0));
    assert_eq!(sender.completed_fsn(AckLevel::Ok).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_eq!(sender.qwp_ws_terminal_error().unwrap(), None);
    let totals = sender.qwp_ws_totals().unwrap();
    assert_eq!(
        (totals.reconnect_attempts, totals.reconnects_succeeded),
        (0, 0),
        "{totals:?}"
    );
    let later = sender.flush_and_keep(&before).unwrap_err();
    assert_refused_after_a_full_dictionary(&later, symbols);
    assert_stopped_by_a_full_dictionary(&sender, progress, &err, symbols);
    assert!(err.in_doubt());
    sender.close_drain().unwrap();
    assert_eq!(files_in_the_slots(), Vec::<String>::new());
    drop(sender);
    wait_for_no_connection(&server);
    assert_eq!(server.connections_taken(), 1);
    assert_table_holds(&server, TABLE, 1, &[&before]);
    server.finish();
}

/// Makes the tests of
/// [`a_rejection_of_a_frame_of_a_flush_that_failed_part_way_is_reported_and_changes_nothing_else`]
/// for a rejection of a frame of the sender: `<rejection>::background`, with
/// durable acks `<rejection>::background_with_durable_acks`, and both once
/// more with the queue on disk.
macro_rules! for_each_rejection {
    ($($rejection:ident: $status:ident, $category:ident, $policy:ident, frame $frame:literal;)*) => {$(
        mod $rejection {
            use super::super::{
                DurableAcks, Progress, QwpWsErrorCategory, QwpWsErrorPolicy, on_disk,
            };
            use super::super::a_rejection_of_a_frame_of_a_flush_that_failed_part_way_is_reported_and_changes_nothing_else as test;

            const REJECTION: (u8, QwpWsErrorCategory, QwpWsErrorPolicy) =
                (super::super::$status, QwpWsErrorCategory::$category, QwpWsErrorPolicy::$policy);

            fn without_durable_acks(progress: Progress) {
                test(progress, REJECTION, $frame, None);
            }

            fn with_durable_acks(progress: Progress) {
                test(progress, REJECTION, $frame, Some(DurableAcks::On));
            }

            #[test]
            fn background() {
                without_durable_acks(Progress::Background);
            }

            #[test]
            fn background_with_durable_acks() {
                with_durable_acks(Progress::Background);
            }

            #[test]
            fn on_disk_background() {
                on_disk(without_durable_acks, Progress::Background);
            }

            #[test]
            fn on_disk_background_with_durable_acks() {
                on_disk(with_durable_acks, Progress::Background);
            }
        }
    )*};
}

mod a_rejection_of_a_frame_of_a_flush_that_failed_part_way_is_reported_and_changes_nothing_else {
    for_each_rejection! {
        rejected_for_good: SCHEMA_MISMATCH, SchemaMismatch, Terminal, frame 2;
        rejected_as_not_written: WRITE_ERROR, WriteError, Retriable, frame 2;
        rejected_as_not_writable: NOT_WRITABLE, NotWritable, RetriableOther, frame 2;
        first_frame_rejected_for_good: SCHEMA_MISMATCH, SchemaMismatch, Terminal, frame 1;
    }
}
