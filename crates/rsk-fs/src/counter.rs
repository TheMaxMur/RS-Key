// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The records the store keeps in its counter partition, written down once.
//!
//! A counter is rewritten on every operation that bumps it, so the store keeps
//! it in a partition of its own and its churn never reclaims a page that holds a
//! key or a credential; `rsk_store::is_counter_fid` routes by [`COUNTER_FIDS`].
//! A FID on the wrong side reads absent while its old value stays live in the
//! other ring, and the set has drifted twice while it was spelled out in more
//! than one place — so it is spelled here only, and each counter is a
//! [`CounterFid`], not a `u16`: the plaintext [`Fs::put`](crate::Fs::put) cannot
//! write one, and the typed [`Fs::put_counter`](crate::Fs::put_counter) is the
//! route in (this must NOT build):
//!
//! ```compile_fail,E0308
//! # fn f<S: rsk_fs::Storage>(fs: &mut rsk_fs::Fs<S>) {
//! let _ = fs.put(rsk_fs::counter::EF_COUNTER, &[0; 4]);
//! # }
//! ```
//!
//! and its twin does:
//!
//! ```
//! # fn f<S: rsk_fs::Storage>(fs: &mut rsk_fs::Fs<S>) {
//! let _ = fs.put_counter(rsk_fs::counter::EF_COUNTER, &[0; 4]);
//! # }
//! ```

/// A FID the store routes to its counter partition. The field is private, so
/// the constants below are the only values; [`COUNTER_FIDS`] lists every one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CounterFid(u16);

impl CounterFid {
    /// The underlying 16-bit FID — an explicit, greppable escape hatch.
    #[inline]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// FIDO's global signature counter: U2F's, and the seed of each credential's own.
pub const EF_COUNTER: CounterFid = CounterFid(0xC000);
/// FIDO's per-credential signature counters, rewritten on every getAssertion.
pub const EF_CRED_CTR: CounterFid = CounterFid(0xC001);
/// OpenPGP's digital-signature counter, DO 0x93.
pub const EF_SIG_COUNT: CounterFid = CounterFid(0x0093);
/// The vendor interface's test counter.
pub const COUNTER_FID: CounterFid = CounterFid(0xCC01);

/// Every counter record. One declared above and left out of this list is read
/// from and written to the main partition, a split nothing else would notice.
pub const COUNTER_FIDS: [CounterFid; 4] = [EF_COUNTER, EF_CRED_CTR, EF_SIG_COUNT, COUNTER_FID];

#[cfg(test)]
#[path = "counter_tests.rs"]
mod tests;
