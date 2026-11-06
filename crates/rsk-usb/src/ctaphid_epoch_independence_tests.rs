// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

thread_local! {
    static RESET_AFTER_READ: Cell<bool> = const { Cell::new(false) };
}

#[derive(Default)]
struct ResetBetweenReads {
    calls: usize,
}

impl MsgHandler for ResetBetweenReads {
    fn session_epoch() -> u32 {
        let epoch = EPOCH.with(Cell::get);
        if RESET_AFTER_READ.with(|armed| armed.replace(false)) {
            EPOCH.with(|current| current.set(epoch + 1));
        }
        epoch
    }

    async fn handle_msg(&mut self, _: u32, _: &[u8], out: &mut [u8]) -> usize {
        self.calls += 1;
        out[..2].copy_from_slice(&[0x90, 0]);
        2
    }

    async fn handle_cbor(&mut self, cid: u32, data: &[u8], out: &mut [u8]) -> usize {
        self.handle_msg(cid, data, out).await
    }

    fn reset_app_selection(&mut self) {}
}

#[test]
fn a_reset_between_epoch_reads_discards_a_held_frame_before_dispatch() {
    with_hid_handler(ResetBetweenReads::default(), [], |hid, trace| {
        let frame = TxFrames::new(OWNER, CTAPHID_CBOR, &[1]).next().unwrap();
        hid.pending_bytes.expose_mut().copy_from_slice(&frame);
        hid.pending_frame = Some(0);
        RESET_AFTER_READ.with(|armed| armed.set(true));
        drain_ready(hid.run());
        assert_eq!(hid.handler.calls, 0, "the old frame reached the worker");
        assert_eq!(hid.session_epoch, 1);
        assert_eq!(hid.pending_frame, None);
        assert!(hid.pending_bytes.expose().iter().all(|&byte| byte == 0));
        assert!(responses(trace).is_empty());
    });
}

#[test]
fn a_reset_cannot_complete_the_previous_sessions_message_with_a_continuation() {
    let mut old = frames(OWNER, CTAPHID_CBOR, &[0xa5; 100]).into_iter();
    with_hid([old.next().unwrap()], |hid, trace| {
        {
            let mut run = core::pin::pin!(hid.run());
            let mut cx = Context::from_waker(Waker::noop());
            assert!(core::future::Future::poll(run.as_mut(), &mut cx).is_pending());
            EPOCH.with(|epoch| epoch.set(1));
            trace.borrow_mut().reads.push_back(old.next().unwrap());
            assert!(core::future::Future::poll(run.as_mut(), &mut cx).is_pending());
            trace
                .borrow_mut()
                .reads
                .extend(frames(OTHER, CTAPHID_PING, &[7]));
            assert!(core::future::Future::poll(run.as_mut(), &mut cx).is_pending());
        }
        assert!(
            hid.handler.requests.is_empty(),
            "a stale continuation reached the worker"
        );
        assert_eq!(responses(trace), [(OTHER, CTAPHID_PING, vec![7])]);
        assert!(!hid.asm.in_progress());
    });
}

#[test]
fn a_reset_during_fragment_timeout_drops_the_old_message_and_lock() {
    let first = frames(OWNER, CTAPHID_CBOR, &[1; 100]).remove(0);
    with_hid([first], |hid, trace| {
        hid.lock
            .arm(OWNER, LOCK_MAX_SECONDS, Instant::now().as_millis());
        {
            let mut run = core::pin::pin!(hid.run());
            let mut cx = Context::from_waker(Waker::noop());
            assert!(core::future::Future::poll(run.as_mut(), &mut cx).is_pending());
            EPOCH.with(|epoch| epoch.set(1));
            std::thread::sleep(std::time::Duration::from_millis(RX_TIMEOUT_MS + 20));
            assert!(core::future::Future::poll(run.as_mut(), &mut cx).is_pending());
            trace
                .borrow_mut()
                .reads
                .extend(frames(OTHER, CTAPHID_PING, &[7]));
            assert!(core::future::Future::poll(run.as_mut(), &mut cx).is_pending());
        }
        assert_eq!(responses(trace), [(OTHER, CTAPHID_PING, vec![7])]);
        assert!(hid.handler.requests.is_empty());
        assert_eq!(hid.session_epoch, 1);
        assert!(!hid.asm.in_progress());
        assert!(hid.pending_bytes.expose().iter().all(|&byte| byte == 0));
    });
}

#[test]
fn scrubbing_an_oversized_verification_prestate_clears_its_declared_length() {
    let mut posed = Reassembler::mid_transaction(OWNER, 0, 0, CTAP_MAX_MESSAGE + 1);
    posed.scrub();
    assert!(posed.message().is_empty());
    assert_eq!(posed.tx_view().need, 0);
    posed.abort();
    assert_eq!(posed.tx_view().owner, None);
}
