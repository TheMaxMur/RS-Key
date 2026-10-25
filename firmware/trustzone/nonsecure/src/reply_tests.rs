// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn all_alignments_lengths_and_byte_edges_preserve_canaries() {
    for offset in 0..16 {
        for length in (0..80).chain([3062, 3065, 7609, 7612]) {
            let mut bytes = vec![0xa5; offset + length + 16];
            {
                let mut guard = ReplyGuard::new(&mut bytes[offset..offset + length]);
                assert_eq!(guard.len(), length);
                guard.fill(0x5a);
            }
            assert!(bytes[..offset].iter().all(|&x| x == 0xa5));
            assert!(bytes[offset..offset + length].iter().all(|&x| x == 0));
            assert!(bytes[offset + length..].iter().all(|&x| x == 0xa5));
        }
    }
}

fn early_error(bytes: &mut [u8]) -> Result<(), ()> {
    let mut guard = ReplyGuard::new(bytes);
    guard.fill(0x5a);
    Err(())?;
    Ok(())
}
#[test]
fn early_error_clears_the_full_reply() {
    for length in [3, 3065, 7612] {
        let mut bytes = vec![0xa5; length];
        assert_eq!(early_error(&mut bytes), Err(()));
        assert!(bytes.iter().all(|&x| x == 0));
    }
}
#[test]
fn dropping_pending_future_clears_the_full_reply() {
    use core::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    for length in [3, 3065, 7612] {
        let mut bytes = vec![0xa5; length];
        {
            let mut pending = Box::pin(async {
                let mut guard = ReplyGuard::new(&mut bytes);
                guard.fill(0x5a);
                core::future::pending::<()>().await;
            });
            let mut context = Context::from_waker(Waker::noop());
            assert!(matches!(pending.as_mut().poll(&mut context), Poll::Pending));
        }
        assert!(bytes.iter().all(|&x| x == 0));
    }
}
