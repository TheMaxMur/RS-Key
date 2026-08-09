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
    /// An OTP frame command owns the presence wait.
    ///
    /// One presence backend serves every transport, so without a scope a FIDO
    /// `CTAPHID_CANCEL` would end an OTP challenge's touch wait and the OTP dummy
    /// write would end a FIDO ceremony. `firmware/src/presence.rs` splits them the
    /// same way, for the same reason.
    otp_wait: AtomicBool,
    /// The host asked to end that wait — the dummy write, or the next command.
    otp_cancel: AtomicBool,
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

    /// Claim the presence wait for an OTP frame command, dropping any cancel left
    /// over from before it.
    pub fn begin_otp(&self) {
        self.otp_cancel.store(false, Ordering::Release);
        self.otp_wait.store(true, Ordering::Release);
    }

    pub fn end_otp(&self) {
        self.otp_wait.store(false, Ordering::Release);
    }

    /// End the OTP wait, if one is what is running.
    pub fn cancel_otp(&self) {
        if self.otp_wait.load(Ordering::Acquire) {
            self.otp_cancel.store(true, Ordering::Release);
        }
    }

    /// Whether the in-flight command has been cancelled by its own transport: a
    /// FIDO `CTAPHID_CANCEL` on the channel that owns the ceremony, or the OTP
    /// host moving on from a challenge waiting for its press.
    pub fn cancelled(&self) -> bool {
        let active = self.active_cid.load(Ordering::Acquire);
        if active != 0 && self.cancel_cid.load(Ordering::Acquire) == active {
            return true;
        }
        self.otp_wait.load(Ordering::Acquire) && self.otp_cancel.load(Ordering::Acquire)
    }
}
