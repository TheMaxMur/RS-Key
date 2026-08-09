// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The three flags the socket threads and the device thread share.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

#[derive(Default)]
pub struct Signals {
    /// Set while the device thread waits for a touch, so the CTAPHID connection
    /// streams `STATUS_UPNEEDED` rather than `STATUS_PROCESSING` — that is what
    /// makes a client say "touch your security key".
    up_pending: AtomicBool,
    /// The CTAPHID channel whose command the device thread is running; 0 = idle.
    active_cid: AtomicU32,
    /// The channel a `CTAPHID_CANCEL` was last seen on.
    ///
    /// Both are channel ids, and the touch is aborted only when they match, so a
    /// second process on its own channel cannot cancel this one's ceremony. A
    /// single global "cancel requested" boolean is exactly the bug audit run-31
    /// filed as HIGH.
    cancel_cid: AtomicU32,
}

impl Signals {
    pub fn set_up_pending(&self, v: bool) {
        self.up_pending.store(v, Ordering::Release);
    }

    pub fn up_pending(&self) -> bool {
        self.up_pending.load(Ordering::Acquire)
    }

    /// Claim the device for `cid`, clearing any cancel left over from before this
    /// command — a CANCEL that arrived while the device was idle is not an answer
    /// to a ceremony that had not started.
    pub fn begin(&self, cid: u32) {
        self.cancel_cid.store(0, Ordering::Release);
        self.active_cid.store(cid, Ordering::Release);
    }

    pub fn end(&self) {
        self.active_cid.store(0, Ordering::Release);
        self.up_pending.store(false, Ordering::Release);
    }

    pub fn request_cancel(&self, cid: u32) {
        self.cancel_cid.store(cid, Ordering::Release);
    }

    /// Cancel whatever command is in flight.
    ///
    /// `CtapHid`'s cancel hook is a `fn()` and carries no channel, but it is only
    /// called for a `CTAPHID_CANCEL` whose cid it has already matched against the
    /// in-flight one — so this is the same scoping the per-channel form gives, and
    /// with nothing in flight (`active_cid` 0) it cancels nothing.
    pub fn cancel_active(&self) {
        self.cancel_cid
            .store(self.active_cid.load(Ordering::Acquire), Ordering::Release);
    }

    /// Whether the in-flight command has been cancelled by its *own* channel.
    pub fn cancelled(&self) -> bool {
        let active = self.active_cid.load(Ordering::Acquire);
        active != 0 && self.cancel_cid.load(Ordering::Acquire) == active
    }
}
