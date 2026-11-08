<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# MC/DC const, macro and worker measurements

The follow-up combines the const-function and EC macro adapters from the
[MC/DC report](mcdc-independence.md) in one fresh host measurement. It also
extends the isolated ARM runtime from boot/getInfo to real SG, USB, OTP,
button and reboot paths. These are source measurements with explicit
frontend and fault boundaries. They do not establish whole-firmware MC/DC.

The [2026-11-06 source-decision extension](mcdc-source-decisions.md) measures
previously omitted let-else, equality assertions and predicate callbacks. Its
host results and separate ARM campaigns retain their expanded denominators
and source-bound residuals.

## Combined host measurement

The source snapshot contains the final assertion-component test. All 132
const functions in the 51 adapter files retain identical bodies in their
const and runtime helpers. Four EC macro invocations are expanded from their
existing templates: the two Brainpool modules and the P-256/secp256k1 comb
functions. Parenthesizing the substituted `$double` expression preserves
both the function-path and closure call forms. Product sources are unchanged.

This isolated copy uses `RUSTC_BOOTSTRAP=1` with the pinned compiler's
`const_eval_select`; it changes no toolchain pin. The UI crate also needs
`allow(long_running_const_eval)` in the measurement copy: its fixed glyph
generator otherwise exceeds the compiler's diagnostic budget. The initial
lint refusal is retained and receives no coverage credit. The ordinary
adapted suite and the subsequent instrumented suite pass.

The default run `run_bc5dfeefea035e71` passes **4,820 tests, five skipped**.
It records **4,244/4,388 conditions with tool pairs (96.72%)**, with all 3,248
decisions executed and 3,119 fully paired. Compared with the native-source
default, the adapters expose 102 additional conditions and witness 96 of them.
The denominator grew; a lower percentage does not mean lost native pairs.
These raw workspace counts retain verification helpers alongside product code.

All 138 native residual identities have one corresponding residual in this
run. Matching uses file, expression, condition occurrence and decision ID;
line shifts from the adapters do not establish identity on their own. The
[native residual annex](mcdc-residuals.md) retains their source-bound reviews.
The six additional raw residuals are:

| Original source | Missing outcome | Boundary |
|---|---|---|
| `crates/rsk-ec/src/lib.rs:101`, both comb instantiations | `n >= 256` true | `n = j * 64 + t`, with `j` in `0..4` and `t` in `0..64`; the largest value is 255. The closure has no other caller. |
| `crates/rsk-ui/src/glyph.rs:283,293` | Capacity assertions false | The argument-free generator reads fixed glyph tables and fixed sizes. The successful compile-time and runtime executions produce the same bounded output. Corrupting those tables would be a different input source. |
| `crates/rsk-ui/src/glyph.rs:292` | `run != 0` false | Every selected fixed size has a positive pixel count. The loop increments `run` after each possible flush, including its final pixel. |
| `crates/rsk-ui/src/glyph.rs:302` | Final size assertion false | The same fixed generator fills the declared table exactly; this is an integrity check of fixed build data, not a variable command input. |

The raw result still has 144 residuals, `complete=false` and
`structurallyComplete=false`. The 79 frontend limitation records remain.
Source-bound explanations do not turn missing vectors into measured pairs.
The whole-library tool pairs also retain the semantic coupling boundary in
the original report; every defensive condition has not been reviewed as an
independently observable security check.

## Isolated const/EC profiles

All eighteen profiles use the same transformed Rust snapshot, including the
final assertion-component test. Each profile has a fresh source and Cargo
target; no depinfo or vector is shared between profile builds. The guarded
`matches!` expansion described below belongs to a separate default run.

| Profile | Tests passed / skipped | Conditions with tool pairs | Raw residuals |
|---|---:|---:|---:|
| `default` | 4,820 / 5 | 4,244/4,388 (96.72%) | 144 |
| `advertise-pqc` | 4,820 / 5 | 4,244/4,388 (96.72%) | 144 |
| `fips-profile` | 4,806 / 5 | 4,232/4,388 (96.44%) | 156 |
| `fips-profile,advertise-pqc` | 4,806 / 5 | 4,232/4,388 (96.44%) | 156 |
| `strong-pin` | 4,824 / 5 | 4,238/4,388 (96.58%) | 150 |
| `strong-pin,advertise-pqc` | 4,824 / 5 | 4,238/4,388 (96.58%) | 150 |
| `always-uv` | 4,820 / 5 | 4,244/4,388 (96.72%) | 144 |
| `always-uv,advertise-pqc` | 4,820 / 5 | 4,244/4,388 (96.72%) | 144 |
| `strict-up` | 4,818 / 5 | 4,234/4,388 (96.49%) | 154 |
| `strict-up,advertise-pqc` | 4,818 / 5 | 4,234/4,388 (96.49%) | 154 |
| `display` | 4,825 / 5 | 4,246/4,390 (96.72%) | 144 |
| `strict-config` | 4,801 / 5 | 4,226/4,369 (96.73%) | 143 |
| `largeblob-ext` | 4,813 / 5 | 4,237/4,388 (96.56%) | 151 |
| `preview-sign` | 4,859 / 5 | 4,280/4,426 (96.70%) | 146 |
| `preview-sign,largeblob-ext` | 4,853 / 5 | 4,273/4,426 (96.54%) | 153 |
| `display,strong-pin` | 4,829 / 5 | 4,240/4,390 (96.58%) | 150 |
| `display,fips-profile` | 4,811 / 5 | 4,234/4,390 (96.45%) | 156 |
| `fido-conformance` | 4,818 / 5 | 4,234/4,388 (96.49%) | 154 |

Every report is valid and unstale, with zero failed tests or evidence
corruptions. Each retains `complete=false`, `structurallyComplete=false`
and the 79 frontend limitation records. Every native residual has a unique
source correspondence; each profile adds exactly the same six const/EC
residuals listed above. The older native profile annex retains the
profile-specific policy and producer arguments.

The raw runs, full paginated queries, depinfo archives, source hashes and
per-profile residual correspondence are in
`target/mcdc-expansion-20261105/` for the default and
`target/mcdc-unified-profiles-20261105/` for the seventeen alternatives.
Their checks are summarized in
`target/mcdc-expansion-20261105/unified-profile-review.json`.

## Frontend inventory

The retained AST inventory enumerates all 79 limitation identities (59 const
and 20 macro records) in their
75 source files, hashes each file, and identifies the same 132 const
functions as the adapter. It also records const/static initializers, const
arguments, the const block and macro calls. This is a source inventory;
cfg-disabled syntax and nested const syntax are not additional runtime
coverage obligations counted from that inventory.

The eight local macro definitions were read directly. AST descendants of a
macro's token tree do not expose its executable syntax: an empty AST control
list would also miss the EC templates' real branches. The four AES templates
contain no explicit Boolean decisions; their `?` paths and dependency
implementations remain separate. The two SHA-256 templates contain straight
line integer operations, including bitwise operations. The four AST-visible
`OUT_DIR` includes and the two further table includes expanded with the
Brainpool modules contain coordinate data. The two literal Brainpool includes
contain runtime code already measured in their own source files.

Configuration and environment macros produce fixed build inputs; their
feature arms belong to separate profiles. `matches!` needs an additional
qualification: the tool records its aggregate result and scrutinee, while
its pattern guard can contain further Boolean conditions. That boundary is
not removed by expanding the four EC invocations or by the const adapter.

An additional inventory finds 117 AST-visible `matches!` calls in 66 crate
source files, including 13 guarded calls in ten files. Calls nested inside
opaque outer macro arguments are a separate boundary. The guarded-call
experiment substitutes the standard `match` expansion in another fresh source
copy, preserving a single scrutinee evaluation, pattern bindings and guard
ordering. Its calibration gives 1/2 for an incomplete AND guard and 2/2 after
adding the missing row; ordinary tests also assert single evaluation for
matching and nonmatching patterns.

The subsequent full default, `run_3d39c6cb54d41600`, passes the same 4,820 tests
with five skipped and records **4,255/4,399 conditions (96.73%)**. All 13 guards
have tool pairs for their 19 conditions. The net source denominator grows by
11 conditions, all witnessed; the same 144 residual identities remain. This
is a separate source snapshot from the const/EC profile matrix.

Three first operands require the same coupling distinction as FIDO UV:

| Guard | Actual-state constraint |
|---|---|
| `crates/rsk-devconf/src/lib.rs:429`, `c == want.len() && cur.get(..c) == Some(want)` | Slice equality implies equal lengths. The content predicate independently changes the decision; the length predicate cannot do so while actual content equality remains true. |
| `crates/rsk-fido/src/clientpin.rs:1091`, `n >= 2 && buf[1] & FORCE_CHANGE != 0` | An honest read shorter than two bytes leaves the zero-initialized second byte untouched. A set flag implies the width predicate. |
| `crates/rsk-openpgp/src/info.rs:145`, `n >= 1 && uif[0] != 0` | An empty honest read leaves the zero-initialized first byte zero. A nonzero byte implies the width predicate. |

The tool's skipped-operand pairs remain credited in its raw report; they do
not establish independent enforcement by those three first operands. These
constraints do not cover arbitrary writes outside a read's admitted prefix.
The other operand has an actual `TF`/`TT` pair in each conjunction.

Separate controls remove only the first predicate from each original
conjunction. The uninstrumented const/EC baseline retains the original
conjunctions and passes all three package suites. The controls
also pass: 72 devconf, 1,181 FIDO and 490 OpenPGP unique tests respectively; the latter
two retain one ignored test each. Each modified source is restored and hashed.
These expected green results support the coupling qualification and receive
no mutation-kill credit. Logs and exact substitutions are retained under
`guard-coupling-controls/`.
The FIDO log also contains one child-process repeat, counted separately from
the primary suite's unique tests.

OpenPGP's `n < 3 || rec[0] == 0` is independently observable: short nonzero
records supply `T-` with the skipped byte predicate actually false; ordinary
nonzero verifiers supply `FF`; full zero-length-byte records supply `FT`.
The focused 88-test PIN run alone lacks `FF`; the full suite supplies it through
the command tests. Coverage credit belongs to the run that actually observes
the pair, rather than to a passing narrower filter.

## ARM worker measurements

The Secure worker has 29 declared decisions and 35 declared conditions. The
existing `rsk_tz_test_delay` configuration is false in these images. Applying
Supercov's own cfg settlement removes its three decisions and four conditions,
leaving **26 compiled decisions and 31 conditions**. The original pilot's
4/35 declaration count therefore corresponds to **4/31 compiled conditions**.

The follow-up retains separate ELF identities for four profiles. Vectors
from different images never form a pair. Within an image, boot sessions and
campaigns may contribute vectors only after checking the exact ELF hash,
manifest and probe layout. Each raw region must have the expected token and
length, zero overflow/loss flags and no pending decision slot before witness
search. Negative controls corrupt the token, length, overflow, loss and pending
properties individually and are refused. The cfg settlement and witness
arithmetic remain upstream's.

| Image profile | Conditions with tool pairs | Raw residuals |
|---|---:|---:|
| No-touch, existing NS gateway startup probes | 18/31 | 13 |
| No-touch, additional NS SG ABI fixtures | 23/31 | 8 |
| Physical BOOTSEL button, existing NS gateway probes | 20/31 | 11 |
| Physical BOOTSEL button, additional NS SG ABI fixtures | 25/31 | 6 |
| Button/ABI, fault fencing and real reseed failure | 29/31 | 2 |

The additional NS fixtures call the actual SG gateways. An oversized request
occupies a valid complete NS-readable span and is refused by the Secure length
guard. A real getInfo ticket is polled into a valid three-byte NS buffer,
which remains unchanged on refusal; polling the same ticket into a sufficient
buffer then retrieves the actual response. These are explicitly custom ABI
fixtures, rather than claims that ordinary USB input can supply such a buffer.

The command campaign checks CTAPHID CBOR/MSG/vendor and INIT transitions,
CCID framing and GET RESPONSE, applet capability refusals, card power cycles
and USB reset. USB/IP carries real OTP feature reports. The HMAC-SHA1 answer
is checked independently. BOOTSEL input drives the emulated GPIO, and USB/IP
reads the resulting keyboard press/release reports. The Yubico OTP output is
decoded and independently checked by AES decryption, UID and CRC.

The BOOTSEL reboot command obtains consent in the button profile; warm reboot
retains its ungated policy. A
read-only emulator observer saves the coverage region at the actual reboot
boundary, after the worker's mode decision and before the emulator replaces
the chip/RAM. It does not replace the firmware reboot with an ordinary return.
The isolated observer patch and binary identity are retained with the evidence.

USB reset during an actual ML-DSA-87 makeCredential records both successful
and revoked `Session::finish` outcomes. The physical-button campaign supplies
a real press after reset to release the old wait; a fresh CCID connection and
getInfo then succeed. Recovery checks require getInfo's version list and
16-byte AAGUID, so a late makeCredential map cannot satisfy them. A separate
image with product-identical, uninstrumented
Secure worker/main reproduces the initial delayed CCID response and recovers
after the same physical press. This delay therefore cannot be attributed only
to coverage probes. The first PROCESSING keepalive can precede the operation's
presence wait, and a host socket timeout is not an emulated-time deadline.
The failed, shorter recovery attempts remain recorded as failed attempts.
A later run also waits beyond the 30-second presence timeout on the emulated
clock, then reconnects without pressing the button. CCID and getInfo succeed,
with both finish outcomes recorded. This establishes delayed recovery in that
run, rather than a permanent firmware deadlock.

The later fault campaign uses a fresh button/ABI ELF. Eight validated regions
from that exact image supply **29/31** conditions. A laboratory observer redirects
Secure core1 to the existing panic entry and explicitly wakes it. Core1 then
executes the real fault fence and terminal wait; it is not an architectural
HardFault injection. The observer permits core0 to continue after this explicit
injection. An already-running NS fixture calls the real SG entries after fencing,
without setting `FAILED` itself.

An enhanced NS fixture checks a previously ready ticket as well as a new submit:
control and submit return `INVALID`, poll returns `ABANDONED`, and the response
buffer stays unchanged. Its separate ELF corroborates the fault path; its vectors
are not merged into the 29/31 image. Removing each of the three worker guards in
an isolated copy fails the corresponding assertion: control returns `1`, submit
returns `PENDING`, or poll returns a 577-byte response and changes the buffer.

The RNG campaign consumes the actual 65,536-byte reseed interval through OpenPGP
GET CHALLENGE, then presses emulated BOOTSEL for a configured Yubico OTP. A
measurement-only observer publishes the byte count. A transient peripheral fault
makes real TRNG EHR reads return zero; the failed entropy draws queue a reboot,
which the worker's timer arm consumes. The pre-reset region contains its pair.
A fresh typed getInfo succeeds after reboot. The healthy control consumes the
same interval, produces an OTP independently checked by AES, UID and CRC, and
continues without reboot. These tests exercise owned emulators and temporary
stores.

The two residual conditions remain visible:

| Worker source | Disposition |
|---|---|
| `firmware/src/worker.rs:300` | The same ticket must first produce `Poll::Ready`. The serialized synchronous copy/release has no await; reset changes Reply to DiscardReply, and release accepts both. Wrong tickets are refused earlier. This producer/state invariant explains the missing refusal. |
| `firmware/src/worker.rs:456` | The legacy Secure OTP signal's only producer belongs to an uninstantiated USB handler. The TrustZone image's actual NS OTP traffic uses the SG exchange path instead. |

No-touch additionally leaves the button-only outcomes unmeasured. Coverage in
the button profile is separate evidence, not a cross-image pair for no-touch.
Full-image instrumentation, full display-path execution, dependency scopes,
timing/layout equivalence and silicon correspondence remain separate
obligations. A 16 KiB worker region is not a full-image resource estimate.

## ARM C and assembly follow-up

The later component campaign compiles the original RSA C source with Clang
21.1.8 source-based MC/DC instrumentation and retains GCC's unchanged assembly.
It adds bounded laboratory SG fixtures to supply operands and reads actual ARM
counters from SRAM. LLVM's own `llvm-profdata` and `llvm-cov` perform coverage
analysis. A freestanding raw-profile transport is checked against the exact
LLVM 21.1.8 format; an actual ARM `a && b` calibration observes 0/2, 1/2 and 2/2.
The reporting ELF adds only a nonloaded profile-name alias. Loaded bytes and
coverage-mapping sections must remain identical to the executed image.

One hundred passing arithmetic cases compare results with independent host
modular exponentiation, CRT and endian expectations. Little-endian operands are
typed word arrays, matching the Rust callers. The C report gives **8/8** conditions
in four compound decisions, with both branch counts for all **31** source
predicates, including single-condition decisions and loops. The actual SG C
wrappers separately give Clang pairs for **4/4** compound conditions. The poll
wrapper's zero-capacity term is coupled to writability: a zero-length span is
never writable. Its Clang short-circuit pair does not establish a feasible
unique-cause pair for that redundant term; the range-check contract supplies
the coupling disposition.

A separate read-only emulator observer records actual conditional-instruction
outcomes, after pending-exception arbitration and around instruction dispatch.
The linked assembly bytes must equal the original GCC object's section bytes.
All **19/19** compiled assembly predicates show both outcomes, including the
`IT EQ`-predicated ADD. The source's two other conditional sites are excluded
by `CONSTANT_MEMORY_ACCESS_PATTERN=0`. Witness checks independently evaluate
the saved ISA flags/registers and verify the resulting PC or LR change. Empty
boot traces have no pairs; corrupt outcome, next-PC and invalid-event records
are refused. These are assembly predicate observations, separate from Clang's
C source-condition analysis.

Direct public-exponent-one calls expose a pre-existing C API defect: the result
can remain in Montgomery form. GCC and Clang both reproduce it. The only
production Rust caller supplies the fixed exponent 65537 for blinding and
Bellcore checking; the C big-endian public wrapper has no Rust caller. Eight
exponent-one rows are explicitly excluded from the fresh passing component
campaign. The C coverage denominator stays unchanged, and the API defect stays
recorded. This is neither complete C API correctness verification nor a claim
that changing the C compiler preserves every timing or layout property.

The follow-up evidence is in `target/mcdc-closure-20261105/`:
`worker-verified.json`, `worker-union.json`, `fault-controls.json`,
`core1-fault-v4/`, `trng-button-2/`, `trng-healthy-3/` and
`rsa-c-arm-5/verified.json`. The C/assembly driver, raw counters, per-case traces,
observer source and binary hashes are retained there. Original product source,
toolchain pins and gate wiring are unchanged by these measurement fixtures.

## Firmware component follow-up

File-sized ARM batches avoid allocating the full firmware's probe region at
once. The selector chooses complete original decision expressions before
emission. A calibration runs the excluded expression normally while only the
selected expression publishes vectors. Per-image records retain source hashes,
features, selected ranges, loaded ELF and counter-region identities. Inactive
display/probe modules in a button image receive no execution credit.

The ARM adapter serializes complete decision publication. Secure counters use
the existing multicore critical section; Non-secure counters use a local
PRIMASK guard to avoid recursing through the probed critical-section release.
This is not a general NMI/HardFault-safe recorder. Single-condition caching is
limited to canonical Boolean vectors. Its recording, cache publication and
clear share one lock. The corrected adapter repeats cold, partial, complete,
clear, re-record and 100-command stages on ARM; the earlier serial calibration
did not test a concurrent clear.

The display profile boots and completes ordinary USB commands and reset. A
separate constructor fixture calls the original panel methods with clipped and
empty rectangles, short sources, DMA-band boundaries and retained scenes.
Changing the laboratory PIO divider produces real FIFO-full and drain waits.
The resulting image supplies **39/40** declared condition pairs. The remaining
`!source_done` term cannot become false at a loop test: assigning true immediately
breaks `fill`, and every caller exits when its returned `done` is true. This
also holds for non-fused iterators. The denominator stays 40.

An earlier fixture presented an unfinalized empty scene. A fresh panic-location
diagnostic identifies `crates/rsk-ui/src/scene.rs:687`; finalizing that scene
repairs the fixture's violated contract. The failed image and runs remain
recorded. Panel vectors already exist at boot, so their attribution is the
component fixture, not subsequent USB traffic. The original campaign driver's
hardcoded button-profile label is corrected by explicit attribution metadata.
No panel-pixel correctness claim follows from branch traces or USB recovery.

An LED component image (`LED_KIND=ws2812`, `MAX_LEDS=8`) supplies **32/44**
declared pairs. A separate Python implementation checks a SHA-256 chain of
1,200 effect frames for the specified white-colour input grid. Actual vendor
setters and persisted PHY changes exercise steady mode, GRB order and GPIO
brightness across reboots of that same ELF. Brightness 0/128/255 produces
`on_us=0/1003/2000`. The constructor's zero-count and direct `StatusHandler`
calls are component inputs; normal PHY loading filters a zero LED count.
Six fixed const/build checks and six geometric guards retain no raw pair.
For flow, `dist=k` implies `n>=k+1` and the corresponding trail bound. For
bounce, `half_pos<=2n-3` makes the checked right neighbour exist. The GRB run
uses white and therefore establishes branch execution rather than functional
red/green permutation; physical waveforms are not checked.

Actual RSA-2048 generation exercises both cores and independently verifies a
signature from the generated key. One ordinary run has **7/29** declared pairs;
core0 supplied both primes, while core1's find arrived late. A separate image
uses the existing observation-only progress hook to wait for two real core1
finds. It also has **7/29** pairs, with `C1_FINDS=2`, `C0_FINDS=0`, one core0
candidate and a verified signature. This establishes core1's contribution under
that explicit schedule. These different ELFs are not combined into a pair.

A later component image records **26/29** pairs in one ELF. Scheduling hooks
delay execution before mailbox take, before park acknowledgement, and between
the park-loop test and cancellation. They do not assign the product's BUSY,
JOB_PENDING or pause state. Real producers and transitions exercise an unposted
job, successful timeout cancellation, acknowledgement winning cancellation,
solo search while the other core is occupied, and an extra prime arriving after
assembly. Generated RSA-512 component keys perform the real blinded private
operation; the host independently checks `signature^65537 mod modulus == 42`.
This does not establish protocol permission to generate RSA-512. One additional
internal job has invalid width zero and witnesses core1's refusal; production
posts validated widths. The remaining three outcomes would violate pause
ownership (`release`/`finish`) or the producer's free-slot invariant. Their raw
pairs remain absent.

Rust probes in the Non-secure time driver fail ordinary transport workloads;
those runs receive no completion credit. A separate emulator observer instead
records the native branch instructions. Two runs of the same ELF observe both
outcomes for **2/2** source conditions and all three selected inlined machine
predicates. The laboratory model explicitly advances TIMER1 across a low-word
rollover after a selected actual raw-high read. The verifier binds the adjacent
CMP/SUBS/SBCS and branch bytes, independently checks registers, flags and next
PC, and rejects three corrupt witnesses. Typed getInfo and OpenPGP GET CHALLENGE
succeed afterward. This is accelerated counter-rollover evidence, not elapsed
silicon time or timing equivalence.

The DMA policy's two compound readback assertions supply **5/5** pairs from one
ELF. Five independent, one-shot bus-read response faults clear channel S, P or
LOCK, or IRQ S or P, while preserving the other returned bits. Each reaches
the intended assertion at `security_policy.rs:101` or `:109`, fences USB and
halts before Non-secure entry. Fault selection binds the actual post-write LDR
to the ELF. Earlier address-only selection hit the modify read before the write
and did not test the guard; those failed attempts remain recorded. The experiment
corrupts the read response, while the model's actual DMA permissions stay set.
An isolated control preserves each volatile read and instrumented condition but
disables the assertion's panic. All five corresponding read-response faults
then reach USB and pass typed getInfo. This checks that the intended fail-stop
assertion, rather than an unrelated exception, supplies the negative outcome.

The TrustZone span/vector component image records **14/17** pairs. Direct
zero-length helper inputs, temporary nonoverlapping Secure MPU regions, and
five one-shot vector-read response faults exercise the real implementations.
Read-only and denied spans produce the expected helper refusals; a two-byte
span crossing different regions exercises `check_range` returning `None`.
Every temporary map is restored and read back before ordinary getInfo succeeds.
Invalid initial stack bounds, alignment, entry Thumb bit and entry range reach
their intended assertions before Non-secure entry. Two first operands are
coupled to NS permissions; the third missing pair is a fixed linked image
length. The model ignores MAIR writes and reads zero, so these experiments make
no memory-type enforcement claim. Earlier fixtures stopped at an incorrect
MAIR readback expectation before performing permission checks.
Two separate guard-removal controls leave the other checks intact: removing
the readable predicate wrongly permits the denied span, while removing the
writable predicate wrongly permits the read-only span. The original MPU map
is restored and getInfo succeeds in each control. These changed images receive
no production coverage credit.

A further vector control observes the actual `MSR MSP_NS` instruction in the
changed image. Healthy, out-of-bounds, misaligned and invalid-entry inputs all
reach that protected write when the assertions are removed. Clearing the entry
Thumb bit also reaches ordinary getInfo. The observer records registers directly
after instruction execution, before synchronous fault arbitration; it establishes
the protected action, not any later exception or terminal state. Earlier polling
attempts could not inspect the invalid-stack runs and receive no completion credit.

The GPIO presence component supplies **3/3 runtime pairs**: input polarity,
constructor pin bounds and pull polarity. Pins 14, 15 and 29 exercise the real
constructor and sample; their results agree with stable SIO input readings.
Pin 30 reaches the intended assertion and fences USB. A fourth declared
condition is the fixed `TICK_HZ` assertion. This all-file selection also exposes
two decisions omitted by the initial cfg-filtered manifest; the original two
constructor identities remain. These are reserved-pin component calls, not
evidence that an ordinary BOOTSEL profile selects GPIO at boot.

The PIN-lock const/runtime adapter preserves all four original helper bodies.
An independent Python oracle agrees with a digest of **1,536 processed rows**
over tag/low-byte inputs and encode/decode combinations. They include repeated
raw words and are not 1,536 distinct inputs. The result is **7/18 component
pairs**: five codec predicates and two in the compile-only `round_trips` helper.
Some component states violate the normal producer's mismatch bound. Eleven
fixed compile-time assertion conditions retain no raw pair. This measurement
does not establish seven ordinary command-runtime predicates.

The existing emulator boot-seal suite passes all **19 named cases** for both
the main and OTP-key measurement images. It checks provisioned and partially
programmed OTP files, replay refusal and flash-program cuts during migration.
The main and OTP-key repeats also capture and validate raw regions immediately
before modeled software resets. Each ELF retains its own union; successful
scenario counts alone establish neither independent pairs nor completion.

A separate main-image component writes authenticated marker values `[1]`,
`[1,0]` and `[0]`, reads them back and enters the unchanged boot decision through
real warm reboots. Five same-ELF regions supply its marker-length/value pairs.
The ordinary marker writer emits only `[1]`; malformed values are component
inputs. These unprovisioned-page cases are not latch-burn removal controls.

The RNG-handler image supplies **3/3** declared source pairs. Ordinary challenge
requests consume the unchanged 65,536-byte interval. A healthy reseed produces
an independently checked keyboard OTP; zero EHR responses instead cause the
actual timer-driven reboot, followed by successful getInfo. A separate fault
returns zero only for Secure firmware EHR reads during initial seeding. The
48-byte seed is refused before NS entry and USB attach, with the fatal fence
set. The same observer and ELF boot normally with that mode disabled. Hardware
block counts alone do not distinguish the boot and reseed instantiations;
their callpaths and pre-NS versus command-time outcomes do.

The SHA accelerator component supplies **26/26** declared pairs in one image.
Python hashlib checks 28 digest geometries, including padding boundaries and
unaligned erased/non-erased tails. A private SG calls the unchanged digest body
after boot. Explicit CSR-response faults exercise error, single-poll recovery
and 1,024-poll readiness failures. Each selected read is bound to actual ELF
instruction bytes; a fault must affect the corresponding published result.
The real `Engine::new` constructor also sees 1,024 missing RESET_DONE responses;
its separate component-owned engine refuses digest, while the ordinary engine
still hashes correctly. Guest memory, CPU registers and native bus side effects
are not changed by the response observer. Earlier stack-constrained placements
receive no credit. The accepted measurement copy separates the storage boot
frame from its large constructor; it makes no stack or timing equivalence claim.

The real Non-secure keyboard handlers supply **10/10** pairs in one image through
USBIP Feature/non-Feature reports, malformed/reset frames, HMAC challenges,
Yubico OTP typing and padded static-password scancodes. The host checks the HMAC
and OTP AES/UID/CRC independently. Pausing an ordinary GET_REPORT immediately
before OTP_STATUS and fencing Secure through its real panic path supplies
INVALID and the original None refusal. A valid touch-required HMAC frame is
paused after the original PENDING poll; native USB reset changes the epoch,
producing the abandoned zero-length reply and missing-status refusal. Reports
and ordinary traffic recover after re-enumeration. No SG result is substituted.
The Secure legacy `OtpHidHandler`
is not instantiated by this builder; its queue consumer is active and is paired
by actual ticket typing. RTC read-before-set/refusal and read-after-set/time
verification supply **1/1**. Real LED APDUs with payload lengths zero, one and
two pair both optional effect/speed decisions in the vendor module. A persisted
LED record supplies the loader's third pair: four actual native payload-word
responses are corrupted during boot, the loader refuses the record and the
public GET command returns the independently captured default block. The
backing word stays unchanged; a wrong-PC control loads the saved block. One
corrupted response alone recovers through a repeat read and receives no refusal
credit. The completed same-image vendor union is **3/3**.

The worker V1 source is reconstructed from its original ARM baseline and three
creation-time archived overlays. All before/after hashes agree, alongside 1,449
unchanged source/build inputs. This repairs the attribution of a later copy
that already contained V2 diagnostic fields. It neither replaces the recorded
V1 ELF nor claims a fresh bit-identical rebuild.

A Non-secure diagnostic fixture forwards bounded laboratory requests through
the real USB SG. Oversize lengths, invalid spans, flags, allocation descriptors,
epochs and identity ranges, followed by ordinary commands and reset, supply
**46/71** declared pairs in the Secure USB entry/controller module. Separate
USBIP standard control transfers exercise configuration loss and successful
reconfiguration; their same-image union with the SG campaign supplies **49/71**.
The default command campaign alone supplied 30/71. A halted
endpoint experiment has not completed its subsequent CCID oracle and receives
no completion credit.

Extended SG inputs, exact empty/nonempty IN packets and a delay of only the NS
CCID reader supply **32/32** endpoint pairs in one ELF. A real host OUT remains
full while READY, nonempty WRITE and empty Interrupt/Bulk writes provide actual
state controls for the precomputed request-waiting terms. Repeated native
EP_ABORT_DONE response faults preserve actual retirement; EP_WRITE then returns
PENDING. Removing that response fault restores the exact CCID reply and normal
traffic. No controller field is planted. A separate control image supplies
**14/16**, including disabled-endpoint refusal and malformed EP0 OUT. Its NS-only setup delay lets
the real SG poll an actual host SETUP into capacities zero, seven and eight;
short outputs stay unchanged, the eight-byte output is exact, and the ordinary
control exchange and FIDO traffic recover. The delay changes neither Secure
session fields nor controller buffers. A native USB reset after the original
control future poll but before observe/session recheck supplies the second
cancellation-check pair. The canceled request is refused; re-enumeration,
OpenPGP challenge and FIDO getInfo recover. The two unpaired input-empty terms
are constrained by the SG entry's no-data-operation length check.
A DATA packet of two bytes against wLength one reaches the actual overflow;
the host unlinks the unacknowledged status stage and a new SETUP recovers.
Real 64/128-byte CCID replies, consumed versus unconsumed IN ZLPs, and a real
zero-length Bulk OUT supply seven bulk pairs. Holding core0 between the actual
ZLP observation and abort lets the native host consume that ZLP or leave it
pending. A separate one-read response fault clears the actual EP_ABORT_DONE
result after the controller read. Both scenarios require the correct CCID reply
and a subsequent challenge. Their same-ELF union supplies **10/10**. The response
fault is not a model of a physically delayed controller acknowledgement.

The NS lifecycle image also exercises real busy submit after abandoning a
long RSA command, configuration loss during that wait, and reset between the
actual pending-poll return and epoch check. A real Secure panic/fence before
submit yields INVALID and the intended NS assertion. Persisted interface masks
and VID settings are checked against actual USB descriptors, available protocol
exchanges and card activation. A separate GPIO build checks persisted LED pin
overrides against presence, power and user-LED reservations. These are separate
ELFs and profiles, with no cross-image vector union.

A nested NS critical-section calibration exposed an apparatus defect: the
emulator's CPS decoder interchanged the I and F selector bits. Actual B672
therefore changed FAULTMASK instead of PRIMASK, and an inner release could
unmask the modeled outer section. The opcode regression fails for that exact
reason in the retained baseline and passes after correcting the isolated
observer; 35 security regression tests also pass. The selector encoding follows
[Armv8-M ARM C2.4.43](https://community.arm.com/cfs-file/__key/communityserver-discussions-components-files/471/DDI0553B_5F00_y_5F00_armv8m_5F00_arm.pdf).
Old raw vectors remain evidence for their recorded emulator versions. They
do not establish architectural nested-mask or interrupt-scheduling equivalence;
the corrected observer separately repeats nested masking (`0x11`), the six-stage
recorder/cache/clear calibration, pending-poll/reset, submit/fence, busy-submit
revocation, both bulk schedules and SHA **26/26**. The correction and actual-opcode
regression are retained as an [isolated emulator patch](../../third_party/mcdc-picoem-cps.patch).
Product dependency pins are unchanged.

Further same-ELF Secure USB scenarios supply **62/71** tool pairs: actual entry
and admission fences, full Bulk IN retry, native host consumption, reset and
fence during retry, control-owner refusal, BUS_DISABLE, disabled OUT observation,
Reset/Suspend deduplication and SETUP replacement. The latter sends a new token
through the original host_setup API while cached SETUP remains marked seen;
a wrong address times out, the saved Controller state stays unchanged until
resume, and a real reset restores ordinary exchanges. Exact HAL response faults distinguish an event
seen by both observers from one seen only by the HAL. The retry scenarios
explicitly fault only the next time-read responses to the captured native
start value; all limits stay unchanged. This separates functional branch
evidence from an ordinary 64-microsecond timing claim. A one-read Resume fault
also supplies actual progress, with exact packets and protocol recovery.
The endpoint-slot let-chain still needs its semantic producer constraints;
a tool pair alone does not establish independence of an absent slot's enable bit.

A separate host source component executes **4,294,967,290** actual revocations
through the original BusEpoch module, without seeding its private state. The
exact repeated firmware guard has independent FF, TF and FT input states;
exhaustion then refuses configuration and admission across further revocations
and resume. Removing its exhaustion term fails after the full history because
it admits an epoch that must be refused. These are source-component witnesses
for the two exhaustion terms, outside the ARM raw-pair count and without a
physical USB-reset workload claim.

Standard host CONFIGURATION and SET/CLEAR_FEATURE HALT requests pair the NS
endpoint enable and stall decisions. GET_STATUS values are exact; FIDO and CCID
recovery is checked after an explicit USB reset. A disabled CCID write is also
paused before its real EPOCH query, with the actual endpoint and DISABLED result
checked. Resuming with an unchanged epoch versus native USB reset supplies both
epoch outcomes, followed by re-enumeration and protocol recovery. An earlier raw
disable/re-enable experiment timed out before its reply oracle and is excluded.

The original NS CTRL_SETUP queue is paused before its SG call. Healthy, native
USB reset and real Secure panic/fence produce the actual success, DISABLED and
INVALID results, including the outer setup-error refusal. Holding the NS entry
after its first successful identity chunk lets a real Secure fence invalidate
the next chunk; the original identity read returns None before USB startup.
The first chunk is identical to the healthy control. A separate component polls
the private NS control future while the ordinary task owns the real SETUP;
it observes busy without acquiring a ticket. That component does not establish
concurrent control requests from the ordinary serialized USB task.

Quad flash measurements use the existing waveshare-one/4MiB profile and an
isolated Puya P25Q32H observer. Its bounded model covers the non-D, unlocked
volatile-QE sequence and checks 12 QMI tests; the product pins remain unchanged.
The model follows the [P25Q32H V1.4 data sheet](https://www.puyasemi.com/download_path/%E6%95%B0%E6%8D%AE%E6%89%8B%E5%86%8C/Flash/P25Q32H_Datasheet_V1.4.pdf),
including the D-ordering restriction on command 31h. This is not a qualification
of other ordering codes, hardware timing or nonvolatile status persistence.
Each native fault changes only an actual bus-read response after its normal
effects. The startup selector is initialized at the first response hook,
after that first native read, rather than before the first bus access.

Startup command/Prepare failures take the ordinary fallback; OmitPrefix,
cleanup and all three Release timeouts reach the native fence before NS starts.
Each bounded timeout retains exactly 100,000 substituted CSR responses against
the unchanged firmware limit. Probe independence is checked from actual
128-byte arrays: a final-progress fault yields Err with zero XOR difference,
while one FIFO response fault yields Ok with nonzero difference. Independent
XOR recomputation agrees with the paused native registers. Four separate
ensure-mode register responses vary prefix, suffix, format and clock while
the remaining registers stay native. A real RSA-2048 job held after BUSY
publication makes with_xip_idle return None; readiness is preserved, the same
job resumes and its signature verifies independently. No Engine field, BUSY
flag or sampled array is planted.
The same-image quad union is **24/28**. Three missing terms are fixed BOARD/size
expressions per ELF. The fourth is the concrete constructor's read error:
the preceding guard fixes 4MiB capacity, offset is 256, length is 128, and the
pinned BlockingAsync/Flash backend has READ_SIZE one. Its only Result error
check is bounds/alignment before a raw copy and Ok; a bus fault traps rather
than returning this Err. Source hashes and four rejecting arithmetic controls
retain this justification. It is not an executed error pair.

The OTP lock component supplies **7/14** pairs in one image. A separate boot
quarantine image pairs PROVISIONING_BLOCKED, giving eight source conditions
with per-image witnesses; no vectors are combined between those ELFs. The six
remaining terms are build-fixed fake-key tests and the build-validated hex
parser result. Original
Page58 lock calls see extra/missing policy bits, a successful native ROM burn,
and a real read-only permission refusal. Rollback handles empty and already
programmed copies, plus native ROM refusal. A one-read response fault hides
the first successful rollback burn from its readback; the original function
refuses before programming the other copies. A wrong-PC control programs all
three, and the native backing rows verify both effects. Only owned emulator
files are provisioned or fused.

At boot, a separate main-image schedule pauses after genuine latch validation
but before the late MKEK read. Exactly sixteen raw presence-scan responses
become zero, with native rows and ECC reads unchanged. The original Blank-if-
latched guard produces Unreadable and public pre-OTP status FFFE. Blank and
healthy sealed controls report FFFF and 0000; all three OTP files stay byte
identical to their inputs. This is late raw-read response corruption, with no
claim of physical OTP fault qualification.

An actual pending-seal boot also receives bounded corruption of one persisted
flash word after the late Fused result. Forty native memcpy responses change
one bit; the public pre-OTP mask becomes `0009` (FIDO and OATH pending), auto-seal
reports MigrationPending and the emulator latch remains zero. A wrong-PC
control completes migration and sealing. This supplies the `seal_pending` /
zero-migration-mask decision's missing second pair. A separate native power-cut
checkpoint captures the committed scrub marker and its actual TTT decision
before the provisioning recheck and every latch burn, with unchanged unlatched
OTP. That checkpoint is reached by original code, without clearing a sealed
image's latch or manufacturing a marker.

That reachable checkpoint also supplies the final scrub-ready pair. The boot
is held after metadata deletion and immediately before the original marker
remove. One actual RP2350 XIP status response changes from `2` to `6`, reporting
both FIFO flags. The original remove fails before its tombstone, the healthy
medium probe still sees the old marker, and the boot reports ScrubPending with
zero migration mask and byte-identical unlatched OTP. A negative-control ELF
differs only by replacing the native branch over the subsequent marker checks
with a NOP. It retains actual `scrub_ready=false`; those unchanged checks pass
and it wrongly seals. This establishes the condition's independent protection,
rather than inferring the skipped marker operands. The control contributes no
coverage vectors. The original main ELF now supplies **26/65** pairs; separate
main-profile images witness four other source conditions without cross-image
vector unions.

The Non-secure session image supplies **11/12** pairs. A real RSA-2048 APDU
produces WTX before control ABORT, CMD_ABORTED and the matching bulk acknowledgement;
subsequent APDU and FIDO exchanges succeed. This verifies transport cancellation,
not rollback of key-generation side effects. The remaining data-empty term is
coupled to its current producer: wLength zero makes Embassy receive zero chunks.
Likewise, the current 64-byte control buffer admits at most one OUT chunk, whose
first/last flags are both true. Oversized requests are rejected before that call.

An isolated SG calls the actual fault fence twice. Its first-entry/repeated-entry
pair and native USB disconnect/packet-clearing check give **1/1**. This component
test does not claim architectural exception entry or NMI-safe instrumentation.

The sweep component supplies **3/3** declared pairs. An additional call to the
unchanged dead-region function before the first stack-limit arm observes the
native MSPLIM value zero and publishes `[0,0,0,1]`. Ordinary post-arm calls
supply the other result and both loop directions. The extra pre-arm caller is
a component fixture; the production startup does not call sweep at that point.

Tool declarations remain a measurement boundary. For example, let-else at
`core1.rs:213,225,375` and `display_panel.rs:400` is absent from the declared
decision denominator and is not automatically classified as a limitation.
Executing both directions in a workload is insufficient to claim measured
coverage for those omitted decisions. An instruction observer separately binds
both directions of the panel's `RepeatN<Rgb565>` instantiation at
`display_panel.rs:400` to its actual load, comparison and branch bytes. Registers,
flags and next PC agree, and three corrupted witnesses are rejected. This
constructor-fixture evidence covers that monomorph only and does not enlarge
the Supercov denominator. File-batch and component results do not establish
whole-firmware MC/DC completion.

Evidence remains in `target/mcdc-closure-20261105/`: `batches/`,
`firmware-obligations.json`, `native-time-verified.json`, and the corresponding
observer sources, instruction bindings, raw regions and logs. The C-profile
transport also retains controls in `clang-transport-controls/`: the same LLVM
tool accepts the actual ARM profile and rejects an unsupported raw version and
truncated records for their intended format errors.

## Remaining firmware conditions

The successful batch inventory has 548 declared source-condition identities.
It retains 134 without a raw pair in those batches. Each has an explicit
source-hashed row in `firmware-residual-review.json`; no row is removed from a
raw denominator. Twenty-one have separate same-image worker witnesses, and
two have the full BusEpoch host-history witnesses described above. Neither
kind is combined with another ELF's vectors. The other 111 are:

| Count | Source boundary | Reason |
|---:|---|---|
| 64 | Build constants and const assertions | Fixed environment text, pin policy, fake-key selection, USB strings, tick rate and layout checks cannot change within one ELF. Invalid build inputs fail compilation. |
| 12 | Inactive producers/features | Eight conditions belong to the uninstantiated Secure OTP handler/reboot path; four belong to the hostile-access diagnostic feature. The active NS keyboard has separate 10/10 evidence. |
| 15 | Ownership, producer, typed and entry invariants | Pause/ticket owners, the core1 prime pool, panel iterator completion, default oscillator configuration, MPU array widths, retry eligibility, transport buffer sizes, NS entry and typed transport indices constrain the missing values. |
| 5 | Linker geometry and concrete backend | Fixed partition/image/MPU ranges and the quad constructor's concrete read contract described above. |
| 6 | LED arithmetic | Bounce's right neighbour exists; a selected flow distance implies its trail bound. An independent bounded check covers all LED counts through 255 and 129,540 bounce positions. |
| 9 | Permission and entry couplings | NS permission depends on the configured attribution, and no-data SG operations are rejected before their inner empty-input checks. |

The full manifest also has six identities outside successful batch reports:
the two NS time conditions have the separate native instruction witnesses;
four worker conditions are inside the inactive `rsk_tz_test_delay` diagnostic
block. They retain explicit supplementary rows. The inventory is broader than
one build and includes additional all-file selections, so its counts are not
a single-image coverage denominator. Tool-omitted decisions and frontend
limitations remain outside this review; it does not establish whole-firmware
MC/DC completion.

## Evidence and reproduction

The final gate exposed a socket-test setup race in
`tools/emu/src/hid_tests.rs`. Its fake worker's five-second cancellation
deadline started before the client's `connect` returned. A diagnostic run
spent 2.55 seconds there, then processed CANCEL within 28 milliseconds of
its writes. Preparing the connected socket pair before starting the worker
preserves the deadline and all framing assertions. The fake worker now
refuses to report cancellation on timeout. A six-second setup delay fails
the old fixture and passes the repaired one; disabling its CANCEL watch
still fails at the original deadline. These controls receive no MC/DC credit.
The retained measurement sources are unchanged. Verification of the closure's
931-file Rust inventory records this test-only amendment separately from the
other 930 files; the host expansion has its own broader source inventory.

The local evidence root is `target/mcdc-expansion-20261105/`. It retains the
source hashes, exact const and macro substitutions, ordinary and instrumented
logs, paginated reports, raw SRAM regions, image hashes, observer patch and
decoded vectors. `arm-verified-summary.json` lists every input region and hash;
`arm-union-negative-controls.json` records the corruption controls. The
underlying tool versions and three external patches remain in the
[main report](mcdc-independence.md#reproduction).

The measurement copy is prepared only once in a fresh directory. Existing
raw evidence must not be overwritten to obtain a new source snapshot. The
retained drivers run inside the existing Nix shell:

```sh
nix develop -c python target/mcdc-expansion-20261105/reconcile_profiles.py
nix develop -c python target/mcdc-expansion-20261105/verify_other_inputs.py
nix develop -c python target/mcdc-expansion-20261105/collect_arm.py
nix develop -c python target/mcdc-expansion-20261105/verify_expansion.py
```

These verify source/residual correspondence, manifests and data inputs,
same-image regions and upstream witness search, then check the combined
evidence. They do not build or flash a device or change the gate. The remaining
unknown scopes receive no coverage credit.
