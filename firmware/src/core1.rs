// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The RP2350's second core as a prime-search engine for RSA keygen.
//!
//! RSA generation is the longest operation the device ever runs (each prime is
//! hundreds of rejected candidates), and the search is embarrassingly
//! parallel: candidates are independent random draws. Core1 runs a bare loop —
//! no executor: it sleeps in WFE until core0 posts a job, then draws and tests
//! candidates with its own per-job HMAC-DRBG, posting found primes back.
//! Core0 keeps testing its own candidates between polls and feeds both streams
//! through one [`RsaKeygen`] pool, so the cores race for `p` and `q` — the
//! expected wall time roughly halves (and with it the longest CCID transaction
//! a host ever has to sit through).
//!
//! Safety boundaries:
//! - **Flash/XIP**: embassy-rp's flash driver brackets every erase/program
//!   with `multicore::pause_core1()` (a RAM-resident FIFO-IRQ handshake), so
//!   this loop's XIP fetches can never collide with a flash write. The
//!   inter-core FIFO stays reserved for that protocol — this mailbox is
//!   critical-section statics plus SEV/WFE.
//! - **Heap**: both cores allocate bignums; the global allocator is
//!   critical-section-guarded (a cross-core hardware spinlock), so
//!   allocations serialize.
//! - **Secrets**: the DRBG seed and every prime in transit are zeroized at
//!   each hand-off, and `BUSY` is raised in the same critical section that
//!   takes the job — `run_rsa_search`'s wind-down ("job gone ∧ ¬BUSY ⇒ core1
//!   is out, nothing more will be posted") has no window for a late find.

use core::cell::RefCell;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use embassy_rp::Peri;
use embassy_rp::multicore::{Stack, spawn_core1};
use embassy_rp::peripherals::CORE1;
use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use rsk_crypto::HmacDrbg;
use rsk_openpgp::Rng;
use rsk_openpgp::keys::{RsaKeygen, RsaPrivateKey, RsaStep};
use rsk_rsa::IncrementalSieve;
use static_cell::StaticCell;
use zeroize::Zeroize;

extern crate alloc;
use alloc::boxed::Box;

/// One prime in transit, little-endian (an RSA-4096 half = 256 bytes).
const MAX_HALF: usize = 256;

/// Core1's per-job DRBG seed: 40 bytes of entropy from the main TRNG-backed
/// RNG ‖ an 8-byte domain tag — the entropy ‖ nonce ‖ personalization
/// concatenation of SP 800-90A 10.1.2.3, sized like `FidoRng`'s 48-byte seed.
const SEED_LEN: usize = 48;
const SEED_TAG: &[u8; 8] = b"rsk-rsa2";

struct Job {
    half_bytes: usize,
    seed: [u8; SEED_LEN],
}

/// A found prime in transit from core1 to core0.
struct Found {
    le: [u8; MAX_HALF],
    len: usize,
}

/// The core0 ↔ core1 mailbox: the posted job and up to two found primes.
struct Mailbox {
    job: Option<Job>,
    found: [Option<Found>; 2],
}

static MAILBOX: Mutex<CriticalSectionRawMutex, RefCell<Mailbox>> =
    Mutex::new(RefCell::new(Mailbox {
        job: None,
        found: [None, None],
    }));
/// Core0 → core1: the pool is complete, abandon the current search.
static STOP: AtomicBool = AtomicBool::new(false);
/// Core1 → core0: a search is running (raised atomically with taking the job).
static BUSY: AtomicBool = AtomicBool::new(false);
/// Core0 → core1: a job sits in the mailbox. The idle loop polls ONLY this
/// atomic — embassy's executors on core0 broadcast SEV constantly, so WFE
/// falls through ~continuously and the idle loop is effectively a spin; one
/// SRAM load per spin keeps it off the spinlock and (nearly) off XIP, instead
/// of hammering both through the Mutex on every spurious wake.
static JOB_PENDING: AtomicBool = AtomicBool::new(false);
/// Latched after core1 misses the entry deadline twice running: from then on
/// every search runs single-core. A halted core1 (panic, fault) must degrade
/// keygen, never hang the worker — the worker is the device. One lone miss
/// does NOT latch: a genuine in-flight candidate at RSA-4096 (strong MR + a
/// software Lucas) can hold BUSY for a few seconds, and that core is alive.
static DEGRADED: AtomicBool = AtomicBool::new(false);
/// Consecutive entry-deadline misses; reset on any clean engage. Two in a row
/// is a core that is not coming back.
static MISSES: AtomicU32 = AtomicU32::new(0);

/// Core1's stack. The deep frame is `passes_fermat_base2` → `modexp_priv`
/// (~6 KiB of fixed buffers); 16 KiB leaves comfortable headroom for the
/// Baillie-PSW bignum work on top.
static CORE1_STACK: StaticCell<Stack<16384>> = StaticCell::new();

/// One running small-prime sieve per core (each ~5 KiB — too large to sit on
/// core1's stack next to the modexp frames, hence static). They are
/// SINGLE-CORE-EXCLUSIVE: `CORE0_SIEVE` is touched only from `run_rsa_search`
/// (core0), `CORE1_SIEVE` only from `search` (core1). Since each `&mut` lives
/// on exactly one core and the two cores never touch the same sieve, there is
/// no aliasing and no cross-core race — no atomics or lock needed.
static mut CORE0_SIEVE: IncrementalSieve = IncrementalSieve::new();
static mut CORE1_SIEVE: IncrementalSieve = IncrementalSieve::new();

/// Liveness counters, readable over the vendor applet (INS 0x12) on a
/// `core1-stats` build — the only window into core1, which has no debugger and no
/// UART: idle-loop wakes and jobs taken on core1, then candidates tried / primes
/// found per core (the per-core rates expose cross-core XIP/bus contention).
/// Relaxed throughout — monotonic telemetry, not synchronization.
static WAKES: AtomicU32 = AtomicU32::new(0);
static JOBS: AtomicU32 = AtomicU32::new(0);
static C1_TRIES: AtomicU32 = AtomicU32::new(0);
static C1_FINDS: AtomicU32 = AtomicU32::new(0);
static C0_TRIES: AtomicU32 = AtomicU32::new(0);
static C0_FINDS: AtomicU32 = AtomicU32::new(0);

/// The seven counters plus the live flags (busy, stop, job-pending, degraded),
/// little-endian packed for the vendor read.
#[cfg(feature = "core1-stats")]
pub fn stats() -> [u8; 32] {
    let mut out = [0u8; 32];
    let counters = [
        &WAKES, &JOBS, &C1_TRIES, &C1_FINDS, &C0_TRIES, &C0_FINDS, &MISSES,
    ];
    for (slot, c) in out.chunks_exact_mut(4).take(7).zip(counters) {
        slot.copy_from_slice(&c.load(Ordering::Relaxed).to_le_bytes());
    }
    let flags = [&BUSY, &STOP, &JOB_PENDING, &DEGRADED];
    for (b, f) in out[28..].iter_mut().zip(flags) {
        *b = f.load(Ordering::Relaxed) as u8;
    }
    out
}

/// Boot the engine (idle in WFE until the first job). Called once from `main`;
/// from that point embassy-rp's flash driver pauses/resumes core1 around every
/// erase/program.
pub fn spawn(core1: Peri<'static, CORE1>) {
    let stack = CORE1_STACK.init_with(Stack::new);
    let floor = stack.mem.as_ptr() as u32;
    spawn_core1(core1, stack, move || core1_main(floor));
}

/// Scrub and drop any primes still sitting in the mailbox.
///
/// Zeroize *through* the slot, never after moving out of it: `Option::take()`
/// copies the payload to a local and writes back only the `None` discriminant, so
/// wiping the local leaves a full RSA prime resident in this static — which
/// `worker::reboot`'s BOOTSEL drop does not clear either (audit run-33).
fn scrub_found(mb: &mut Mailbox) {
    for slot in &mut mb.found {
        if let Some(f) = slot.as_mut() {
            f.le.zeroize();
        }
        *slot = None;
    }
}

/// Zeroize the job's DRBG seed through the slot, then drop it. Same hazard as
/// [`scrub_found`]: the seed replays core1's entire candidate stream.
fn scrub_job(mb: &mut Mailbox) {
    if let Some(j) = mb.job.as_mut() {
        j.seed.zeroize();
    }
    mb.job = None;
}

/// Move the posted job out, wiping the copy the slot keeps. Copy the fields by
/// value first, *then* zeroize through the `&mut` — a `take()` followed by a
/// zeroed write-back would be a dead store the optimiser is free to drop.
fn take_job(mb: &mut Mailbox) -> Option<Job> {
    let j = mb.job.as_mut()?;
    let out = Job {
        half_bytes: j.half_bytes,
        seed: j.seed,
    };
    j.seed.zeroize();
    mb.job = None;
    Some(out)
}

/// Move one found prime out, wiping the copy the slot keeps (see [`take_job`]).
fn take_found(slot: &mut Option<Found>) -> Option<Found> {
    let f = slot.as_mut()?;
    let out = Found {
        le: f.le,
        len: f.len,
    };
    f.le.zeroize();
    *slot = None;
    Some(out)
}

/// Wipe the primes in transit and the keygen DRBG seed from the mailbox, before
/// dropping to BOOTSEL. Measured 2026-08-05 on RP2350 A4 with secure boot off
/// (`tests/54_sram_residue.py`): main SRAM reads back all zeros after that drop,
/// so this is depth against a silicon revision that stops clearing it, not the
/// only thing between a live prime and a reflash.
///
/// The mailbox, plus a bounded wait for core1 to finish scrubbing its own sieve.
///
/// `CORE1_SIEVE` is not touched from here: `STOP` does not wait for core1 — it can
/// still be inside `try_candidate_le` — so writing it from core0 would alias a live
/// `&mut` across cores. Each core scrubs its own sieve on its own STOP edge, which
/// also closes the window immediately rather than only at reboot. But `scrub` used
/// to return without giving core1 a chance to *reach* that edge, so a reboot issued
/// while a search was live dropped to BOOTSEL with the last window — up to
/// `SIEVE_WINDOW` candidates, one of which is the prime that was found — still
/// resident (audit run-34 #23).
///
/// A core1 that never answers is faulted, and that is exactly what latches
/// `DEGRADED`; its sieve stays resident and cannot be cleared soundly from here.
pub fn scrub() {
    MAILBOX.lock(|mb| {
        let mb = &mut mb.borrow_mut();
        scrub_found(mb);
        scrub_job(mb);
    });
    // Ask core1 to wind down, then wait for it to go idle. Bounded: the caller is
    // on the reboot path and must not hang if core1 is wedged.
    STOP.store(true, Ordering::Release);
    cortex_m::asm::sev();
    for _ in 0..SCRUB_WAIT_ITERS {
        if !BUSY.load(Ordering::Acquire) {
            break;
        }
        cortex_m::asm::nop();
    }
}

/// Spin budget for [`scrub`]'s wait on core1. A candidate test is microseconds and
/// the reboot path already sleeps ~200 ms for the USB flush, so this is generous
/// for the live case and still bounded for a wedged one.
const SCRUB_WAIT_ITERS: u32 = 2_000_000;

// --------------------------------------------------------------- core1 side --

/// Core1 entry: wait for a job, search until satisfied or told to stop, repeat.
fn core1_main(stack_floor: u32) -> ! {
    // This stack is a plain array in `.bss`, so an overflow lands in whatever the
    // linker put below it — flip-link only guards core0's, the one at the edge of
    // RAM. MSPLIM traps the SP decrement itself, so a frame big enough to step
    // over a guard band cannot slip past.
    // SAFETY: writes the stack-limit register of the core that owns this stack,
    // before anything has pushed; the value is that stack's own base.
    unsafe { cortex_m::register::msplim::write(stack_floor) };

    // Whether the late-find scrub already ran for the current STOP edge.
    let mut stop_scrubbed = false;
    loop {
        // The cheap idle gate: one SRAM atomic, no lock (see JOB_PENDING).
        if !JOB_PENDING.load(Ordering::Acquire) {
            // STOP up means core0 has assembled and drained: anything still
            // in the found slots is OUR late post — scrub it (once per edge).
            if STOP.load(Ordering::Acquire) && !stop_scrubbed {
                MAILBOX.lock(|mb| scrub_found(&mut mb.borrow_mut()));
                // …and our own sieve: its last candidate IS the prime we just
                // delivered, and it would otherwise sit here until the next
                // search reseeds. SAFETY: unchanged ownership — CORE1_SIEVE is
                // touched only from core1, and the search that used it has ended.
                unsafe { (*core::ptr::addr_of_mut!(CORE1_SIEVE)).scrub() };
                stop_scrubbed = true;
            }
            cortex_m::asm::wfe();
            continue;
        }
        stop_scrubbed = false;
        WAKES.fetch_add(1, Ordering::Relaxed);
        // Take the job and raise BUSY in ONE critical section — the wind-down
        // in `run_rsa_search` relies on never observing "job taken, BUSY not
        // yet visible".
        let job = MAILBOX.lock(|mb| {
            let job = take_job(&mut mb.borrow_mut());
            if job.is_some() {
                BUSY.store(true, Ordering::Relaxed);
                JOB_PENDING.store(false, Ordering::Relaxed);
            }
            job
        });
        let Some(mut job) = job else {
            // Raced with the wind-down's un-post: nothing to do after all.
            cortex_m::asm::wfe();
            continue;
        };
        JOBS.fetch_add(1, Ordering::Relaxed);
        search(&job);
        job.seed.zeroize();
        BUSY.store(false, Ordering::Release);
        cortex_m::asm::sev();
    }
}

/// Core1's RNG: the per-job HMAC-DRBG (state zeroizes on drop).
struct DrbgRng(HmacDrbg);
impl Rng for DrbgRng {
    fn fill(&mut self, buf: &mut [u8]) {
        self.0.fill(buf);
    }
}

/// Draw and test candidates until the pool is satisfied or core0 says stop.
fn search(job: &Job) {
    // The same paranoia as core0's gate: if the asm modexp known-answer test
    // fails on THIS core, contribute nothing (core0's own `usable()` gate has
    // already refused the whole operation if its KAT failed).
    if !RsaKeygen::new(job.half_bytes * 16).usable() {
        return;
    }
    let mut rng = DrbgRng(HmacDrbg::new(&job.seed));
    // SAFETY: CORE1_SIEVE is touched only here, on core1. Scrub forces a fresh
    // window (new job → new size/RNG) and wipes any prime left from the last.
    let sieve = unsafe { &mut *core::ptr::addr_of_mut!(CORE1_SIEVE) };
    sieve.scrub();
    while !STOP.load(Ordering::Acquire) {
        C1_TRIES.fetch_add(1, Ordering::Relaxed);
        let mut le = [0u8; MAX_HALF];
        let Some(len) = RsaKeygen::try_candidate_le(sieve, &mut rng, job.half_bytes, &mut le)
        else {
            continue;
        };
        C1_FINDS.fetch_add(1, Ordering::Relaxed);
        let pool_full = MAILBOX.lock(|mb| {
            let mut mb = mb.borrow_mut();
            if let Some(slot) = mb.found.iter_mut().find(|s| s.is_none()) {
                *slot = Some(Found { le, len });
            }
            mb.found.iter().all(|s| s.is_some())
        });
        le.zeroize();
        if pool_full {
            // Two primes delivered from this side alone — the pool is complete
            // whatever core0 found; stop burning cycles and wait for the next job.
            break;
        }
    }
}

// --------------------------------------------------------------- core0 side --

/// Run the RSA prime search on both cores and assemble the key. Blocks the
/// worker exactly like the old single-core loop did (the interrupt executor
/// keeps USB + keepalives flowing); core1 is parked again by the time this
/// returns. `None` is the old `RsaStep::Failed`: an unusable size / failed
/// modexp self-test, or key assembly failure.
pub fn run_rsa_search(nbits: usize, rng: &mut dyn Rng) -> Option<Box<RsaPrivateKey>> {
    run_rsa_search_progress(nbits, rng, &mut || {})
}

/// As [`run_rsa_search`], with an `on_tick` hook invoked once at the top of every
/// search iteration. It is a pure observation point (it never touches the keygen,
/// the core1 mailbox, or `rng`), so the trusted display can spin its "generating"
/// indicator from it while the search blocks the panel — the only way to animate,
/// since the search owns this core. The hook must time-gate its own work: it runs
/// on the keygen's hot path, so anything expensive (a panel repaint) slows the
/// search if not throttled.
pub fn run_rsa_search_progress(
    nbits: usize,
    rng: &mut dyn Rng,
    on_tick: &mut dyn FnMut(),
) -> Option<Box<RsaPrivateKey>> {
    let mut kg = RsaKeygen::new(nbits);
    if !kg.usable() {
        return None;
    }

    // The PREVIOUS search's core1 tail may still be running — one candidate at
    // most, but at RSA-4096 that candidate can be a strong-MR plus a software
    // Lucas, several seconds of work (STOP is only checked between
    // candidates). Wait it out here, off this keygen's critical path, before
    // reusing the mailbox. The wait is BOUNDED so a core1 that never releases
    // BUSY (panicked / faulted) costs the speedup, never the worker: a lone
    // miss just skips core1 for this search, and only two misses running latch
    // permanent single-core mode (a core that is genuinely gone).
    let engaged = !DEGRADED.load(Ordering::Relaxed) && {
        let deadline = embassy_time::Instant::now() + embassy_time::Duration::from_secs(6);
        let mut timed_out = false;
        while BUSY.load(Ordering::Acquire) {
            if embassy_time::Instant::now() > deadline {
                timed_out = true;
                break;
            }
            core::hint::spin_loop();
        }
        if timed_out {
            if MISSES.fetch_add(1, Ordering::Relaxed) + 1 >= 2 {
                DEGRADED.store(true, Ordering::Relaxed);
            }
            false
        } else {
            MISSES.store(0, Ordering::Relaxed);
            true
        }
    };

    if engaged {
        // Post the job: stale finds scrubbed, fresh DRBG seed for core1.
        let mut job = Job {
            half_bytes: kg.half_bytes(),
            seed: [0u8; SEED_LEN],
        };
        rng.fill(&mut job.seed[..SEED_LEN - SEED_TAG.len()]);
        job.seed[SEED_LEN - SEED_TAG.len()..].copy_from_slice(SEED_TAG);
        STOP.store(false, Ordering::Release);
        MAILBOX.lock(|mb| {
            let mut mb = mb.borrow_mut();
            scrub_found(&mut mb);
            mb.job = Some(job);
        });
        JOB_PENDING.store(true, Ordering::Release);
        cortex_m::asm::sev();
    }

    // SAFETY: CORE0_SIEVE is touched only here, on core0. Scrub forces a fresh
    // window for this keygen and wipes any prime from the previous one.
    let sieve = unsafe { &mut *core::ptr::addr_of_mut!(CORE0_SIEVE) };
    sieve.scrub();

    // `Some(Some(key))` = assembled, `Some(None)` = the old `Failed`.
    let mut outcome: Option<Option<Box<RsaPrivateKey>>> = None;
    while outcome.is_none() {
        // Observation hook (display spinner); time-gated by the caller, off the keygen state.
        on_tick();
        // Core1's finds first (cheap to drain) — but only when we actually
        // engaged it this keygen. If the entry gate timed out (engaged=false),
        // core1 is still on the PRIOR job, so anything in `found` is a stale
        // prime for a different (possibly different-size) key; feeding it to this
        // keygen would corrupt the modulus. Leave it for the wind-down scrub.
        let mut batch = if engaged {
            MAILBOX.lock(|mb| {
                let mb = &mut mb.borrow_mut();
                let [a, b] = &mut mb.found;
                [take_found(a), take_found(b)]
            })
        } else {
            [None, None]
        };
        let mut had_finds = false;
        for f in batch.iter_mut().filter_map(Option::as_mut) {
            had_finds = true;
            if outcome.is_none() {
                match kg.offer_le(&mut f.le[..f.len]) {
                    RsaStep::More => {}
                    RsaStep::Done(k) => outcome = Some(Some(k)),
                    RsaStep::Failed => outcome = Some(None),
                }
            } else {
                // A find that arrived after the verdict — scrub, don't use.
                f.le.zeroize();
            }
        }
        if had_finds {
            continue; // re-poll before sinking into a slow own candidate
        }
        // …then one own candidate (the slow part, one Baillie-PSW).
        C0_TRIES.fetch_add(1, Ordering::Relaxed);
        let mut le = [0u8; MAX_HALF];
        if let Some(len) = RsaKeygen::try_candidate_le(sieve, rng, kg.half_bytes(), &mut le) {
            C0_FINDS.fetch_add(1, Ordering::Relaxed);
            match kg.offer_le(&mut le[..len]) {
                RsaStep::More => {}
                RsaStep::Done(k) => outcome = Some(Some(k)),
                RsaStep::Failed => outcome = Some(None),
            }
        }
        le.zeroize();
    }

    // Wind down — OFF the critical path: un-post the job if core1 never took
    // it, drain-scrub what is posted right now, raise STOP, and return the key
    // immediately. A candidate still in flight on core1 finishes in the
    // background; core1 scrubs its own late find when it notices STOP, and the
    // next job's entry gate (the BUSY wait above) keeps the mailbox exclusive.
    MAILBOX.lock(|mb| {
        let mut mb = mb.borrow_mut();
        scrub_job(&mut mb);
        JOB_PENDING.store(false, Ordering::Relaxed);
        scrub_found(&mut mb);
    });
    // Our own sieve holds the last candidate — the prime this key was built
    // from. `sieve` is the same `&mut` the loop above used, so this stays inside
    // core0's exclusive borrow.
    sieve.scrub();
    STOP.store(true, Ordering::Release);
    cortex_m::asm::sev();
    outcome.flatten()
}
