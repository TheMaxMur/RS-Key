// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Cross-CTAPHID-message FIDO state: the firmware owns one [`FidoState`] per
//! power cycle and threads `&mut` into each [`crate::Ctx`]. The authenticator's
//! ephemeral ECDH key is held as its 32-byte scalar and regenerated on first
//! use and on PIN mismatch.

use zeroize::Zeroize;

use rsk_crypto::pinproto::{self, PinProto, public_xy};

use crate::Rng;
use crate::consts::{
    CTAP_CREDENTIAL_MGMT, CTAP_GET_NEXT_ASSERTION, CTAP_LARGE_BLOBS, MAX_CREDENTIAL_COUNT_IN_LIST,
    MAX_LARGE_BLOB_SIZE, MAX_RESIDENT_CREDENTIALS, PUAT_INITIAL_USAGE_LIMIT_MS,
    PUAT_MAX_USAGE_PERIOD_MS, STATEFUL_WALK_IDLE_MS,
};
use crate::hmacsecret::{SALT_AUTH_MAX, SALT_ENC_MAX};

// pinUvAuthToken permission bits.
pub const PERM_MC: u8 = 0x01; // makeCredential
pub const PERM_GA: u8 = 0x02; // getAssertion
pub const PERM_CM: u8 = 0x04; // credentialManagement
pub const PERM_BE: u8 = 0x08; // bioEnrollment (unsupported)
pub const PERM_LBW: u8 = 0x10; // largeBlobWrite
pub const PERM_ACFG: u8 = 0x20; // authenticatorConfiguration
pub const PERM_PCMR: u8 = 0x40; // per-credential-management read-only

/// Max credentials tracked for `getNextAssertion` (`MAX_CREDENTIAL_COUNT_IN_LIST`).
pub const MAX_ASSERTION_CREDS: usize = MAX_CREDENTIAL_COUNT_IN_LIST as usize;

/// State carried between `getAssertion` and `getNextAssertion` when resident
/// discovery finds more than one credential. Holds EF_CRED slot offsets (newest
/// first) rather than the credentials themselves; `getNextAssertion` re-reads them.
pub struct AssertionState {
    pub active: bool,
    /// The [`FidoState::channel`] the opening `getAssertion` arrived on. A walk
    /// carries that request's clientDataHash and its presence/UV decision, so a
    /// second process asking for the next leg on its own channel would collect an
    /// assertion over a hash it never sent, behind a touch it never gave — the
    /// scoping `mse_cid` below already applies, for the same reason.
    pub channel: u32,
    pub rp_id_hash: [u8; 32],
    pub client_data_hash: [u8; 32],
    pub uv: bool,
    /// The originating request's user-presence decision (honoring `up:false`
    /// unless the `strict-up` build forces it true) — getNextAssertion reuses it
    /// so a silent discovery stays silent across the whole walk.
    pub up: bool,
    pub slots: [u16; MAX_ASSERTION_CREDS],
    pub total: u8,
    pub counter: u8,
    /// Uptime at the originating getAssertion — the 30 s validity window.
    pub started_ms: u64,
    /// The originating request's extension inputs, re-evaluated per credential
    /// for each getNextAssertion response.
    pub hmac_present: bool,
    pub hmac_proto: u64,
    pub hmac_peer_x: [u8; 32],
    pub hmac_peer_y: [u8; 32],
    pub hmac_salt_enc: [u8; SALT_ENC_MAX],
    pub hmac_salt_enc_len: u8,
    pub hmac_salt_auth: [u8; SALT_AUTH_MAX],
    pub hmac_salt_auth_len: u8,
    pub ext_cred_blob: bool,
    pub ext_third_party_payment: bool,
}

impl AssertionState {
    const fn new() -> Self {
        Self {
            active: false,
            channel: 0,
            rp_id_hash: [0; 32],
            client_data_hash: [0; 32],
            uv: false,
            up: true,
            slots: [0; MAX_ASSERTION_CREDS],
            total: 0,
            counter: 0,
            started_ms: 0,
            hmac_present: false,
            hmac_proto: 1,
            hmac_peer_x: [0; 32],
            hmac_peer_y: [0; 32],
            hmac_salt_enc: [0; SALT_ENC_MAX],
            hmac_salt_enc_len: 0,
            hmac_salt_auth: [0; SALT_AUTH_MAX],
            hmac_salt_auth_len: 0,
            ext_cred_blob: false,
            ext_third_party_payment: false,
        }
    }

    pub fn reset(&mut self) {
        self.active = false;
        self.total = 0;
        self.counter = 0;
        self.hmac_present = false;
        self.ext_cred_blob = false;
        self.ext_third_party_payment = false;
    }
}

/// State carried across `credentialManagement` enumerate begin/next calls.
/// The *Begin* subcommands reset the counters; the *Next* variants read them.
/// `FidoState::reset` clears it.
pub struct CredMgmtState {
    /// The [`FidoState::channel`] whose *Begin* opened the walk. §6.8 exempts the
    /// *Next* subcommands from carrying a pinUvAuthParam of their own — they
    /// inherit the Begin's authorization — so without this a second process reads
    /// the relying-party ids that authorization bought, having shown no token.
    pub channel: u32,
    /// `now_ms` of the last leg this walk served, its *Begin* included — the
    /// idle window in [`FidoState::expire_stale_sequences`] measures from here. It is
    /// the only bound a walk opened under the persistent `pcmr` token has: that
    /// token carries no usage timer of its own (CTAP 2.2 §6.8.2).
    pub last_leg_ms: u64,
    // u16 so a fully-provisioned store (MAX_RESIDENT_CREDENTIALS = 256) can be
    // counted and walked to the last slot; a u8 saturated at 255, hiding the
    // 256th RP/credential from enumeration.
    pub rp_counter: u16,
    pub rp_total: u16,
    pub cred_counter: u16,
    pub cred_total: u16,
    pub rp_id_hash: [u8; 32],
    /// Enumerate cursor: the EF_RP / EF_CRED slot to resume the sweep from on the
    /// next getNextRP / getNextCredential, so each getNext is O(gap-to-next-match)
    /// rather than re-scanning from slot 0 (which made a full walk O(n^2)). The
    /// matching Begin resets it to 0. RP and credential enumerations keep separate
    /// cursors, though only one walk is ever live: a Begin of either retires the
    /// other (§6 "exclusively preceded", `retire_sequences_except`), so the split
    /// buys isolation between consecutive walks rather than concurrent ones.
    pub rp_next_slot: u16,
    pub cred_next_slot: u16,
    /// Per-EF_CRED-slot cache of the credential's rpId-hash prefix (its first 4
    /// bytes as LE `u32`), so `enumerateCredentials` filters slots in RAM and reads
    /// flash only for the target rp — without it each per-rp Begin re-read every
    /// slot, making a many-distinct-rp walk O(rps·creds). Built lazily on the first
    /// enumerate and reused across the walk; `rp_index_gen` / `rp_index_valid` gate
    /// staleness against [`Fs::write_gen`](rsk_fs::Fs::write_gen). Entries for empty
    /// slots are don't-care (the occupancy bitmap skips them first), and a prefix
    /// hit is always confirmed by the full 32-byte compare, so a 4-byte collision
    /// only costs a read, never a wrong match.
    pub rp_index: [u32; MAX_RESIDENT_CREDENTIALS as usize],
    pub rp_index_gen: u32,
    pub rp_index_valid: bool,
}

impl CredMgmtState {
    const fn new() -> Self {
        Self {
            channel: 0,
            last_leg_ms: 0,
            rp_counter: 1,
            rp_total: 0,
            cred_counter: 1,
            cred_total: 0,
            rp_id_hash: [0; 32],
            rp_next_slot: 0,
            cred_next_slot: 0,
            rp_index: [0; MAX_RESIDENT_CREDENTIALS as usize],
            rp_index_gen: 0,
            rp_index_valid: false,
        }
    }

    /// Whether `channel` may take the next leg of the RP walk: it opened it, and
    /// the walk has not run out. Both halves in one place because a *Next* carries
    /// no authorization of its own (§6.8) — the pair IS the authorization check.
    pub fn may_walk_rps(&self, channel: u32) -> bool {
        self.channel == channel && self.rp_counter <= self.rp_total
    }

    /// [`Self::may_walk_rps`] for the credential walk.
    pub fn may_walk_creds(&self, channel: u32) -> bool {
        self.channel == channel && self.cred_counter <= self.cred_total
    }

    /// Whether either walk still has a leg to serve — the counter half of the two
    /// above, so [`FidoState::expire_stale_sequences`] can tell a live cursor from a
    /// spent one and leave `last_leg_ms` alone when there is nothing to retire.
    fn walking(&self) -> bool {
        self.rp_counter <= self.rp_total || self.cred_counter <= self.cred_total
    }

    /// Drop the enumerate cursor back to its fail-closed start (`rp_counter >
    /// rp_total`), so a *Next* answers `NotAllowed` until the next authorized
    /// *Begin*. The slot→rpId-prefix cache stays: it is a `write_gen`-guarded perf
    /// index, holds no authorization, and never leaves the device.
    pub fn reset(&mut self) {
        self.rp_counter = 1;
        self.rp_total = 0;
        self.cred_counter = 1;
        self.cred_total = 0;
        self.rp_id_hash = [0; 32];
        self.rp_next_slot = 0;
        self.cred_next_slot = 0;
    }
}

/// Multi-fragment `authenticatorLargeBlobs` write buffer. The platform sends
/// the serialized large-blob array in fragments across separate commands; they
/// accumulate in `temp` until the whole array (length fixed by the first
/// fragment) has arrived, then commit to EF_LARGEBLOB.
pub struct LargeBlobState {
    pub expected_length: usize,
    pub expected_next_offset: usize,
    /// `now_ms` of the last fragment accepted into `temp` — the idle window in
    /// [`FidoState::expire_stale_sequences`] measures from here. Meaningful only
    /// while [`Self::in_flight`]; an arming fragment that is then rejected leaves
    /// it stale, which expires the abandoned transfer rather than preserving it.
    pub last_fragment_ms: u64,
    pub temp: [u8; MAX_LARGE_BLOB_SIZE],
}

impl LargeBlobState {
    const fn new() -> Self {
        Self {
            expected_length: 0,
            expected_next_offset: 0,
            last_fragment_ms: 0,
            temp: [0; MAX_LARGE_BLOB_SIZE],
        }
    }

    /// Whether a multi-fragment write is part-way through. `expected_length` is
    /// armed by the `offset == 0` fragment and cleared when the array commits, so
    /// it is the whole in-flight condition; a `largeblob-ext` build never arms it
    /// (it borrows only `temp`), which is why the timer is inert there.
    fn in_flight(&self) -> bool {
        self.expected_length != 0
    }

    /// Abandon a part-written array. Only the two counters: `temp` is refilled
    /// wholesale by the `offset == 0` fragment that starts the next transfer, and
    /// wiping 2 KiB on every unrelated command would cost more than it protects
    /// (the buffer holds platform-supplied blob bytes, not device secrets).
    fn reset(&mut self) {
        self.expected_length = 0;
        self.expected_next_offset = 0;
    }
}

/// The session pinUvAuthToken plus its presence/permission flags.
pub struct PinUvAuthToken {
    pub token: [u8; 32],
    pub in_use: bool,
    pub permissions: u8,
    pub rp_id_hash: [u8; 32],
    pub has_rp_id: bool,
    pub user_present: bool,
    pub user_verified: bool,
    /// `now_ms` when the token was issued; the absolute-lifetime cap measures
    /// from here and never moves.
    pub issued_at_ms: u64,
    /// `now_ms` of the token's most recent use; the rolling inactivity window
    /// measures from here and is pushed out by [`FidoState::mark_token_used`].
    pub last_used_ms: u64,
}

impl PinUvAuthToken {
    const fn new() -> Self {
        Self {
            token: [0; 32],
            in_use: false,
            permissions: 0,
            rp_id_hash: [0; 32],
            has_rp_id: false,
            user_present: false,
            user_verified: false,
            issued_at_ms: 0,
            last_used_ms: 0,
        }
    }
}

/// The clientPIN soft lock as the firmware persists it across a warm reset: the
/// engaged flag *and* the mismatch batch that arms it. They move as one — carrying
/// the flag alone let a host stop at two mismatches and reboot to restart the
/// batch, spending the whole flash retry budget with no power cycle (CTAP 2.1
/// §6.5.5.6).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PinLock {
    /// clientPIN is locked until the authenticator is really power-cycled.
    pub engaged: bool,
    /// Consecutive wrong PINs this power cycle; the lock arms at
    /// [`PIN_MISMATCH_LIMIT`].
    pub mismatches: u8,
}

/// All clientPIN state that must survive between CBOR commands within one power
/// cycle.
pub struct FidoState {
    ephemeral: [u8; 32],
    ephemeral_set: bool,
    /// Cached `getKeyAgreement` public key `d·G` for the current `ephemeral`
    /// scalar, computed once in [`Self::regenerate`] so each getKeyAgreement need
    /// not recompute the scalar multiply (~40 ms on the M33). Public — it is what
    /// getKeyAgreement returns — so no zeroize.
    ephemeral_pub: ([u8; 32], [u8; 32]),
    pub paut: PinUvAuthToken,
    // Not `pub`: the firmware must move the pair through [`FidoState::pin_lock`] /
    // [`FidoState::restore_pin_lock`], never one half of it.
    pub(crate) needs_power_cycle: bool,
    pub(crate) new_pin_mismatches: u8,
    /// `getNextAssertion` carry-over.
    pub gna: AssertionState,
    /// `credentialManagement` enumerate carry-over.
    pub cm: CredMgmtState,
    /// `authenticatorLargeBlobs` multi-fragment write buffer. Cleared by
    /// `reset()`; a write resuming across an interleaved reset (no real platform
    /// does this) restarts from `offset == 0`.
    pub lba: LargeBlobState,
    /// MSE seed-backup channel: once a `VENDOR_MSE` key agreement succeeds,
    /// `mse_active` is set and `mse_key`/`mse_pub` hold the derived
    /// ChaCha20-Poly1305 channel key and the device ephemeral public key (the
    /// AEAD AAD). RAM-only; the key is zeroized on `Drop` and a reset.
    ///
    /// **One-shot.** `MSE` and its consumer are separate CTAPHID transactions, so
    /// the worker lock does not span them, and the channel id cannot identify the
    /// party in between. A second `MSE` while this is set therefore refuses *and*
    /// drops the channel, and every gated consumer spends it — so an interloper
    /// can deny a handshake but can never redirect one. Fail closed both ways.
    pub mse_active: bool,
    /// The channel [`Self::channel`] held when that handshake ran — defence in
    /// depth only, **not** the boundary. A CTAPHID channel id is a routing label
    /// the sender writes into its own frame header (CTAP 2.1 §11.2.5), so it
    /// cannot tell the owner from an interloper forging it; what actually keeps
    /// the seed from being encrypted to a second process is that the channel is
    /// one-shot ([`Self::mse_active`]). Checked through [`Self::mse_ready`].
    pub mse_cid: u32,
    pub mse_key: [u8; 32],
    pub mse_pub: [u8; 65],
    /// Soft-lock: the seed decrypted by a vendor `UNLOCK`. RAM-only — held until
    /// power-off, a reset, or an `AUT_DISABLE`; zeroized on `Drop` and on overwrite.
    pub keydev_dec: Option<[u8; 32]>,
    /// How to fetch the OTP DEVK (the reset-stable attestation root), rather than
    /// the key itself: it is wanted by one opt-in command, and holding it would
    /// park an unrotatable signing key in RAM for the whole power cycle. `None` on
    /// an unprovisioned device and in most tests. A bare `fn` because there is no
    /// state to carry — the same shape the transport's touch/cancel hooks use.
    /// Device identity, not session state — it survives [`Self::reset`].
    pub devk_source: Option<fn() -> Option<[u8; 32]>>,
    /// Whether this power cycle's `EV_BOOT` journal entry has been written
    /// ([`crate::journal`]). Survives [`Self::reset`] — the cycle did not end.
    pub audit_boot_logged: bool,
    /// This power cycle started from a **warm** reset (`sys_reset`), not a power-on
    /// reset — set by the firmware from a register a power-on reset clears. The
    /// host can request a warm reset ungated, so anything that keys on "just powered
    /// up" (the CTAP 2.1 §6.6 reset window) must refuse to trust the restarted
    /// uptime. Power-cycle fact, not session state: survives [`Self::reset`].
    pub warm_boot: bool,
    /// Transport channel of the request being dispatched — the CTAPHID CID, or 0
    /// for a transport with no channel concept. A property of the in-flight
    /// request like `Ctx::now_ms`, stamped by the firmware before each dispatch;
    /// survives [`Self::reset`] because the request outlives the state it clears.
    pub channel: u32,
}

impl Default for FidoState {
    fn default() -> Self {
        Self::new()
    }
}

impl FidoState {
    pub const fn new() -> Self {
        Self {
            ephemeral: [0; 32],
            ephemeral_set: false,
            ephemeral_pub: ([0; 32], [0; 32]),
            paut: PinUvAuthToken::new(),
            needs_power_cycle: false,
            new_pin_mismatches: 0,
            gna: AssertionState::new(),
            cm: CredMgmtState::new(),
            lba: LargeBlobState::new(),
            mse_active: false,
            mse_cid: 0,
            mse_key: [0; 32],
            mse_pub: [0; 65],
            keydev_dec: None,
            devk_source: None,
            audit_boot_logged: false,
            warm_boot: false,
            channel: 0,
        }
    }

    /// Whether the seed-backup channel is live **and** owned by the channel this
    /// request arrived on. Every consumer of `mse_key`/`mse_pub` gates on this,
    /// never on `mse_active` alone.
    pub fn mse_ready(&self) -> bool {
        self.mse_active && self.mse_cid == self.channel
    }

    /// Spend or drop the seed-backup channel, zeroizing the key.
    ///
    /// Called after every gated consumer (whatever its outcome) and on a refused
    /// re-key, so a channel is usable exactly once by the party that established it.
    pub fn clear_mse(&mut self) {
        self.mse_active = false;
        self.mse_cid = 0;
        self.mse_key.zeroize();
        self.mse_pub = [0; 65];
    }

    /// Drop the unlocked seed copy (disable / reset), zeroizing it first.
    pub fn clear_keydev_dec(&mut self) {
        if let Some(k) = self.keydev_dec.as_mut() {
            k.zeroize();
        }
        self.keydev_dec = None;
    }

    /// Clear all session state after a reset (the `Drop` impl zeroizes the old
    /// token / session key / ephemeral scalar). The DEVK, the journal's boot-entry
    /// flag and the warm-boot origin are device/power-cycle facts, not session
    /// state — they carry across, as does the in-flight request's channel.
    pub fn reset(&mut self) {
        let devk_source = self.devk_source;
        let audit_boot_logged = self.audit_boot_logged;
        let warm_boot = self.warm_boot;
        let channel = self.channel;
        *self = Self::new();
        self.devk_source = devk_source;
        self.audit_boot_logged = audit_boot_logged;
        self.warm_boot = warm_boot;
        self.channel = channel;
    }

    /// The clientPIN soft lock to persist across a warm reset (see [`PinLock`]).
    pub fn pin_lock(&self) -> PinLock {
        PinLock {
            engaged: self.needs_power_cycle,
            mismatches: self.new_pin_mismatches,
        }
    }

    /// Restore a [`pin_lock`](Self::pin_lock) taken before a warm reset. Run once at
    /// boot, any time after [`Self::new`]: nothing else writes these fields at
    /// start-up, and [`Self::ensure_initialized`] leaves them alone.
    pub fn restore_pin_lock(&mut self, lock: PinLock) {
        self.needs_power_cycle = lock.engaged;
        self.new_pin_mismatches = lock.mismatches;
    }

    /// `initialize`: on the first clientPIN command, generate the ephemeral ECDH
    /// key and a fresh pinUvAuthToken.
    pub fn ensure_initialized(&mut self, rng: &mut impl Rng) {
        if !self.ephemeral_set {
            self.regenerate(rng);
            self.reset_pin_uv_auth_token(rng);
        }
    }

    /// `regenerate`: draw a new ephemeral ECDH scalar (in range `[1, n)`) and
    /// cache its public key `d·G` — the same multiply that validates the scalar,
    /// so [`Self::ephemeral_public`] (called on every getKeyAgreement) reuses it
    /// instead of recomputing.
    pub fn regenerate(&mut self, rng: &mut impl Rng) {
        loop {
            rng.fill(&mut self.ephemeral);
            if let Some(xy) = public_xy(&self.ephemeral) {
                self.ephemeral_pub = xy;
                break;
            }
        }
        self.ephemeral_set = true;
    }

    pub fn ephemeral_scalar(&self) -> &[u8; 32] {
        &self.ephemeral
    }

    /// The ephemeral public key `(x, y)` returned by `getKeyAgreement` — the value
    /// cached by [`Self::regenerate`] (consistent with `ephemeral` by construction).
    pub fn ephemeral_public(&self) -> Option<([u8; 32], [u8; 32])> {
        self.ephemeral_set.then_some(self.ephemeral_pub)
    }

    /// `resetPinUvAuthToken`: new random token, cleared permissions / flags. The
    /// credMgmt cursor goes with it, like [`Self::stop_using_token`].
    pub fn reset_pin_uv_auth_token(&mut self, rng: &mut impl Rng) {
        self.cm.reset();
        rng.fill(&mut self.paut.token);
        self.paut.permissions = 0;
        self.paut.in_use = false;
        self.paut.has_rp_id = false;
        self.paut.rp_id_hash = [0; 32];
        self.paut.user_present = false;
        self.paut.user_verified = false;
        self.paut.issued_at_ms = 0;
        self.paut.last_used_ms = 0;
    }

    /// `beginUsingPinUvAuthToken` — marks the token in use and starts its usage
    /// timer at `now_ms` (CTAP 2.1 §6.5.5.7).
    pub fn begin_using_token(&mut self, user_is_present: bool, now_ms: u64) {
        self.paut.user_present = user_is_present;
        self.paut.user_verified = true;
        self.paut.in_use = true;
        self.paut.issued_at_ms = now_ms;
        self.paut.last_used_ms = now_ms;
    }

    /// Refresh the rolling inactivity window after a successful token use
    /// (CTAP 2.1 §6.5.5.7): each use defers the inactivity deadline, bounded by
    /// the absolute [`PUAT_MAX_USAGE_PERIOD_MS`] which `issued_at_ms` still caps.
    pub fn mark_token_used(&mut self, now_ms: u64) {
        if self.paut.in_use {
            self.paut.last_used_ms = now_ms;
        }
    }

    /// The CTAP 2.1 §6.5.5.7 post-user-presence triad — `clearUserPresentFlag()`,
    /// `clearUserVerifiedFlag()`, `clearPinUvAuthTokenPermissionsExceptLbw()` — run
    /// once a makeCredential / getAssertion user-presence test succeeds. Spends the
    /// in-use token down to largeBlobWrite and drops its UP/UV flags so a follow-on
    /// authenticatorConfig can't ride the touch (GHSA-wqjm-653g-hgw3). The token
    /// stays `in_use` (lbw is deliberately retained); it retires on its usage timer.
    pub fn consume_after_user_presence(&mut self) {
        if self.paut.in_use {
            self.paut.permissions &= PERM_LBW;
            self.paut.user_present = false;
            self.paut.user_verified = false;
        }
    }

    /// [`Self::consume_after_user_presence`], run only when `user_present`. The
    /// getAssertion call sites key on the raw `up`, so a silent up:false pre-flight
    /// stays inert (GHSA-wqjm-653g-hgw3); folding the guard in here keeps the caller
    /// (`get_assertion_inner`) under the cognitive-complexity ceiling.
    pub fn consume_after_user_presence_if(&mut self, user_present: bool) {
        if user_present {
            self.consume_after_user_presence();
        }
    }

    /// `stopUsingPinUvAuthToken` — drop the in-use state, permissions, and
    /// presence/rpId binding. The token bytes stay put; `in_use == false` and
    /// zero permissions make every downstream check fail closed.
    pub fn stop_using_token(&mut self) {
        self.paut.in_use = false;
        self.paut.permissions = 0;
        self.paut.has_rp_id = false;
        self.paut.rp_id_hash = [0; 32];
        self.paut.user_present = false;
        self.paut.user_verified = false;
        // The credMgmt *Next* walkers carry no pinUvAuthParam of their own (CTAP 2.1
        // §6.8 exempts them) — they inherit the *Begin* call's authorization, so the
        // cursor must die with the token that granted it.
        self.cm.reset();
    }

    /// Abandon every multi-call sequence `cmd` does not continue — the assertion
    /// walk, both credential-management enumerate cursors, and a part-written
    /// large blob.
    ///
    /// CTAP 2.2 §6 lets an authenticator "maintain state based on the assumption
    /// that each stateful command is exclusively preceded by either another
    /// instance of the same command, or by the corresponding state initializing
    /// command", where *exclusively preceded* means "no other authenticator
    /// operation occurs in between", and fail the sequence with
    /// `CTAP2_ERR_NOT_ALLOWED` when that is violated. The clause is a MAY, so the
    /// permissive reading is conformant too; taking it up buys a smaller state
    /// surface. It is the command half of the rule — the same clause's 30-second
    /// half is [`Self::expire_stale_sequences`], which the large-blob buffer needs
    /// most: on a PIN-less key it has no token bounding it either.
    ///
    /// Each slot names its own continuation, so an unrelated command retires all
    /// three while a continuation retires only the other two. The enumerate cursor
    /// is continued by just two of credentialManagement's subcommands, which this
    /// cannot see — [`crate::credmgmt::cred_mgmt`] retires that one itself once it
    /// has parsed the subcommand.
    pub fn retire_sequences_except(&mut self, cmd: u8) {
        if cmd != CTAP_GET_NEXT_ASSERTION {
            self.gna.reset();
        }
        if cmd != CTAP_CREDENTIAL_MGMT {
            self.cm.reset();
        }
        if cmd != CTAP_LARGE_BLOBS {
            self.lba.reset();
        }
    }

    /// Expire an in-use token once its usage timer has run out (CTAP 2.1
    /// §6.5.5.7), checked before every CBOR command. Retires on either the
    /// rolling inactivity window or the absolute lifetime cap, whichever first.
    pub fn expire_stale_token(&mut self, now_ms: u64) {
        if !self.paut.in_use {
            return;
        }
        let since_issue = now_ms.saturating_sub(self.paut.issued_at_ms);
        let since_use = now_ms.saturating_sub(self.paut.last_used_ms);
        if since_issue >= PUAT_MAX_USAGE_PERIOD_MS || since_use >= PUAT_INITIAL_USAGE_LIMIT_MS {
            self.stop_using_token();
        }
    }

    /// Retire a stateful sequence left idle past [`STATEFUL_WALK_IDLE_MS`], checked
    /// before every CBOR command beside [`Self::expire_stale_token`]. CTAP 2.3 §6
    /// also *requires* the state to die with the token that authorized the opening
    /// call, which [`Self::stop_using_token`] does — but a `pcmr` token never
    /// expires and a PIN-less key's large-blob write has no token at all, so that
    /// MUST alone left both live for the whole power cycle.
    ///
    /// The assertion walk is absent because it times itself, per §6.3 step 7, inside
    /// [`crate::getassertion::get_next_assertion`].
    pub fn expire_stale_sequences(&mut self, now_ms: u64) {
        if self.cm.walking() && idle_past(now_ms, self.cm.last_leg_ms) {
            self.cm.reset();
        }
        if self.lba.in_flight() && idle_past(now_ms, self.lba.last_fragment_ms) {
            self.lba.reset();
        }
    }

    /// `getUserVerifiedFlagValue` — false unless a token is in use.
    pub fn user_verified(&self) -> bool {
        self.paut.in_use && self.paut.user_verified
    }

    /// `getUserPresentFlagValue` — false unless a token is in use, and in practice
    /// always false: no ceremony here mints a token carrying presence (see
    /// [`crate::clientpin`]'s `issue_token` for why). The §6.1.2 step 14 / §6.2.2
    /// step 9 presence gates deliberately do not consult it — reading it there is
    /// only correct together with the decision that would set it.
    pub fn user_present(&self) -> bool {
        self.paut.in_use && self.paut.user_present
    }

    /// Verify a `pinUvAuthParam` MAC over `data` under the current token.
    pub fn verify_token(&self, proto: PinProto, data: &[u8], param: &[u8]) -> bool {
        pinproto::verify(proto, &self.paut.token, data, param)
    }
}

/// Whether the gap since `since_ms` has reached the window CTAP 2.3 §6 lets an
/// authenticator assume between the legs of a stateful command.
fn idle_past(now_ms: u64, since_ms: u64) -> bool {
    now_ms.saturating_sub(since_ms) >= STATEFUL_WALK_IDLE_MS
}

/// Build the pinUvAuthParam message `0xff×32 ‖ cmd ‖ subcommand ‖ params` into
/// `buf`, returning its length (CTAP 2.1 §6.5.5.7).
pub(crate) fn puat_subcommand_msg(buf: &mut [u8], cmd: u8, subcommand: u8, params: &[u8]) -> usize {
    buf[..32].fill(0xff);
    buf[32] = cmd;
    buf[33] = subcommand;
    buf[34..34 + params.len()].copy_from_slice(params);
    34 + params.len()
}

impl Drop for FidoState {
    fn drop(&mut self) {
        self.ephemeral.zeroize();
        self.paut.token.zeroize();
        self.mse_key.zeroize();
        if let Some(k) = self.keydev_dec.as_mut() {
            k.zeroize();
        }
    }
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod tests;
