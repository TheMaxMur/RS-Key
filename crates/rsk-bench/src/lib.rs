// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![cfg_attr(not(test), no_std)]

//! Robust summary statistics for the on-device latency harness.
//!
//! The firmware `bench` feature times a crypto primitive over many iterations
//! and hands the raw per-iteration samples here. Why this and not a mean:
//! steady-state EC latency on the RP2350 is **XIP-cache / code-layout sensitive**
//! — the hot working set (e.g. the variable-base P-256 scalar-mul, ~34 KB) is
//! bigger than the 16 KB XIP cache, so which lines collide and evict depends on
//! where the linker placed the code. A naive mean of host-timed round-trips then
//! swings ±~30 ms from an innocent code move and fakes a regression. The honest
//! read is:
//!
//! - **`cold`** — the first sample (a cold XIP cache if the bench is the first
//!   crypto op after a power-cycle); this is the ~1.4× cold-boot penalty.
//! - **`median` + `mad`** over the warm samples — robust to the occasional
//!   cache-refill outlier, so cross-build A/B compares the steady state, not the
//!   noise.
//!
//! The device computes the [`Summary`] here (not the host) so the reported number
//! comes from this gated, Kani-proved code, then ships the 20-byte [`Summary`] to
//! the host for display and A/B comparison. `no_std`, no alloc, no deps.

/// Serialized [`Summary`] length: five little-endian `u32`s.
pub const SUMMARY_LEN: usize = 20;

/// A robust summary of one bench run's per-iteration samples (units are whatever
/// the caller measured — the firmware harness uses microseconds). The `median`,
/// `min` and `mad` are over the warm samples (`samples[warmup..]`); `cold` is the
/// first sample regardless of `warmup`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Summary {
    /// Warm sample count (`samples.len() - warmup`, clamped at 0).
    pub n: u32,
    /// The first sample — cold XIP cache when the bench is the first op after a
    /// power-cycle.
    pub cold: u32,
    /// Warm minimum (the best case: fully cache-resident).
    pub min: u32,
    /// Warm median (upper median for even counts — always an observed value).
    pub median: u32,
    /// Warm median absolute deviation: `median(|x - median|)`. Small = tight /
    /// layout-stable; large = the run straddled cache-refill boundaries.
    pub mad: u32,
}

impl Summary {
    /// Little-endian serialization, field order `[n, cold, min, median, mad]`.
    pub fn to_le_bytes(&self) -> [u8; SUMMARY_LEN] {
        let mut b = [0u8; SUMMARY_LEN];
        b[0..4].copy_from_slice(&self.n.to_le_bytes());
        b[4..8].copy_from_slice(&self.cold.to_le_bytes());
        b[8..12].copy_from_slice(&self.min.to_le_bytes());
        b[12..16].copy_from_slice(&self.median.to_le_bytes());
        b[16..20].copy_from_slice(&self.mad.to_le_bytes());
        b
    }

    /// Inverse of [`Summary::to_le_bytes`].
    pub fn from_le_bytes(b: &[u8; SUMMARY_LEN]) -> Self {
        let u = |i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        Summary {
            n: u(0),
            cold: u(4),
            min: u(8),
            median: u(12),
            mad: u(16),
        }
    }
}

/// Summarize per-iteration `samples`. `cold` is `samples[0]`; the warm statistics
/// are over `samples[warmup..]` (pass `warmup = 1` to exclude the cold sample from
/// the steady-state median). Reorders `samples` in place (the caller no longer
/// needs their order once summarized). An empty warm range collapses every warm
/// field onto `cold` with `n = 0`.
pub fn summarize(samples: &mut [u32], warmup: usize) -> Summary {
    let cold = samples.first().copied().unwrap_or(0);
    let w = warmup.min(samples.len());
    let warm = &mut samples[w..];
    if warm.is_empty() {
        return Summary {
            n: 0,
            cold,
            min: cold,
            median: cold,
            mad: 0,
        };
    }
    let n = warm.len();
    // `min` is order-independent; take it before the sort mutates `warm`.
    let min = warm.iter().copied().min().unwrap();
    warm.sort_unstable();
    let median = warm[n / 2];
    // MAD: overwrite the (no-longer-needed) warm slice with absolute deviations,
    // re-sort, take their median. `abs_diff` avoids the signed detour.
    for x in warm.iter_mut() {
        *x = x.abs_diff(median);
    }
    warm.sort_unstable();
    let mad = warm[n / 2];
    Summary {
        n: n as u32,
        cold,
        min,
        median,
        mad,
    }
}

#[cfg(kani)]
#[path = "kani.rs"]
mod proofs;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
