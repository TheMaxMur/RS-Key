// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use std::{cell::Cell, rc::Rc};

struct HeldReply {
    released: Rc<Cell<bool>>,
    calls: usize,
}

impl HeldReply {
    async fn reply(&mut self, data: &[u8], out: &mut [u8]) -> usize {
        self.calls += 1;
        assert_eq!(data, [0xa5; 4]);
        core::future::poll_fn(|_| {
            if self.released.get() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        out[..2].copy_from_slice(&[0x90, 0]);
        2
    }
}

impl ApduHandler for HeldReply {
    fn session_epoch() -> u32 {
        EPOCH.with(Cell::get)
    }

    async fn handle_apdu(&mut self, data: &[u8], out: &mut [u8]) -> usize {
        self.reply(data, out).await
    }

    async fn handle_secure(&mut self, data: &[u8], out: &mut [u8]) -> SecureResult {
        SecureResult {
            len: self.reply(data, out).await,
            status: SECURE_STATUS_OK,
            error: 0,
        }
    }
}

#[test]
fn a_revoked_epoch_suppresses_time_extensions_and_the_eventual_reply() {
    for secure in [false, true] {
        let released = Rc::new(Cell::new(false));
        with_ccid_handler(
            HeldReply {
                released: Rc::clone(&released),
                calls: 0,
            },
            1,
            [],
            |ccid, trace| {
                ccid.status = STATUS_ACTIVE;
                ccid.rx[HEADER..HEADER + 4].fill(0xa5);
                {
                    let operation = async {
                        if secure {
                            ccid.run_secure(HEADER, HEADER + 4).await;
                        } else {
                            ccid.run_xfr(HEADER, HEADER + 4).await;
                        }
                    };
                    let mut operation = core::pin::pin!(operation);
                    let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
                    assert!(core::future::Future::poll(operation.as_mut(), &mut cx).is_pending());
                    EPOCH.with(|epoch| epoch.set(1));
                    std::thread::sleep(std::time::Duration::from_millis(WTX_INTERVAL_MS + 20));
                    assert!(core::future::Future::poll(operation.as_mut(), &mut cx).is_pending());
                    assert!(bulk_packets(trace).is_empty(), "a revoked WTX escaped");
                    released.set(true);
                    assert!(core::future::Future::poll(operation.as_mut(), &mut cx).is_ready());
                }
                assert_eq!(ccid.handler.calls, 1);
                assert!(bulk_packets(trace).is_empty(), "a revoked reply escaped");
                assert_eq!(ccid.status, STATUS_INACTIVE);
                assert!(ccid.tx.iter().all(|&byte| byte == 0));
                assert!(ccid.rx[HEADER..HEADER + 4].iter().all(|&byte| byte == 0));
            },
        );
    }
}

#[test]
fn reading_in_a_new_epoch_revokes_the_previous_slot_before_accepting_a_header() {
    let next = message(CCID_XFR_BLOCK, 9, &[0, 0xa4, 4, 0]);
    with_ccid(0, [Read::Packet(next.clone())], |ccid, _| {
        ccid.status = STATUS_ACTIVE;
        EPOCH.with(|epoch| epoch.set(1));
        assert_eq!(complete(ccid.read_message()), Some(next.len()));
        assert_eq!(ccid.session_epoch, 1);
        assert_eq!(ccid.status, STATUS_INACTIVE);
        assert_eq!(&ccid.rx[..next.len()], next);
    });
}
