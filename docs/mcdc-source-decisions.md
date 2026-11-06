<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# MC/DC source-decision extension

The 2026-11-06 follow-up measures Rust syntax omitted by the earlier frontend:
`let-else`, guarded `matches!`, equality assertions and reviewed predicate
callbacks. The compiler and production firmware are unchanged. This closes the
reviewed omissions in the current source inventory. It does not establish
literal whole-firmware MC/DC. The [current-source review](#current-source-completion-review)
reconciles declared macro/const warnings and retained C/assembly evidence;
raw residuals, dependencies and physical-device evidence remain explicit.

## Frontend and qualification

The [source-decision patch](mcdc-supercov-source-decisions.patch) applies to
Supercov 4.22.0 at `bd6c9d76426d446fb57bcbe5df7791820c97fac1`, after the
[anonymous-const](mcdc-supercov-anonymous-const.patch) and
[pin-expression](mcdc-supercov-pin-expression.patch) patches. Exact application
and reversal were checked by file hashes, not by exit status alone. Its SHA-256
is `3cae0ffe20f59ce8033b561189296d59ff61f8acf5dfbc8f8e30c0b9fb1c693a`.
The existing Nix compiler is Rust 1.99.1 (58cf8f9c3 2026-10-13), with
`aarch64-apple-darwin` host tests and `thumbv8m.main-none-eabihf` ARM images.
The host executable SHA-256 is
`c37b914b785fa307ae79e0844d6211cecbcb8bceda8a164dddd8cb3c520ceec2`.
The evaluated-vector criterion, pair arithmetic and runtime record layout are
unchanged from the [original measurement](mcdc-independence.md).

- `let-else` records actual pattern success. Initializers, bindings, scope and
  temporary lifetimes stay intact; probes run inside the else arm or after the
  statement. Its cfg/cfg_attr predicate gates both probes.
- Guarded `matches!` exposes its guard to discovery while executing the original
  macro once. Compound guards do not acquire a duplicate value decision.
- `assert_eq!`/`assert_ne!` retain the standard macro. A borrowed wrapper records
  the original equality comparison once, preserving right-operand evaluation,
  lazy messages, Debug and panic text. The standard `assert_ne!` uses equality;
  a type with a deliberately panicking overridden `ne` verifies this distinction.
- The reviewed standard Iterator/Option/Result predicate callbacks record the
  returned Boolean, including their own early returns. Nested functions,
  closures and async blocks do not donate returns to the enclosing callback.
  Existing compound expressions are deduplicated. Function-item predicates are
  evaluated once. The current consumer policy excludes custom `find(key)` data
  lookups; it is not general Rust type inference. A future iterator
  `find(local_predicate)` needs renewed source review.
- Delayed closure/async/non-const-function bodies inside const/static
  initializers are runtime code. Actual compile-time evaluation stays outside
  the runtime denominator. Active cfg sites, recursive cfg_attr and release
  debug-assert settings determine the corresponding limitation records.

Qualification passes 62 existing frontend tests and seven added integration
tests. Ordinary and measured debug/release fixtures check exact full/partial
vectors, omitted operands, cfg exclusion, callback calls, Drop order, panic
text, hygiene and the custom-find boundary. A selected-range calibration runs
the complete functional fixture while admitting only the selected let-else
condition. The actual ARM collector accepts an intact raw region and refuses
separate token, length, overflow, loss and pending-record corruptions.

The initial ARM campaigns used the frozen v8 frontend. The host uses v9's custom-find
correction. Across all 47 firmware input files, their complete generated Rust and
manifest bytes agree: 527 declared decisions, 662 conditions, 4,444 hits and
28 limitation records. This establishes correspondence for these firmware
inputs, not a merged execution denominator or universal frontend correctness.

## Host measurement

The initial extended default `run_05d481757f2a6577` passes 4,820 tests,
five skipped, and records 4,775/5,029 paired conditions. Twenty added tests
produce the final default `run_ca3cc7a656f04845`: **4,840 passed, five skipped;
4,806/5,029 paired conditions (95.57%)**. All 3,883 decisions execute; 3,675
are fully paired. Workspace counts include verification helpers alongside
product code.

The denominator is unchanged between these two runs. Full residual queries
and source-identity comparison confirm exactly the 31 intended new pairs;
each new false outcome is attributed to an added test. The remaining **223
raw missing conditions are the earlier 144 plus 79 newly exposed invariants**.
Both runs are valid and unstale, with zero evidence corruptions. The final
run retains `complete=false`, `structurallyComplete=false` and 79 declared
frontend limitation records.

Four Authority decision queries exceed the unmodified CLI's 64 KiB JSON limit
inside one nested phase-attribution record. Their ordinary text queries expose
both global atomic vectors; narrow JSON queries retain complete attribution
to the new lifecycle test. The full raw archive is retained. This workaround
changes neither evidence nor pair arithmetic; global attribution from a
truncated JSON page is never treated as complete.

The same 132 const-function and four EC-template adapters from the
[previous follow-up](mcdc-expansion.md) are retained in the isolated measurement
copy. Production sources keep their original const/macro forms. All source
hashes, adapter metadata, raw evidence and paginated queries are retained.
The fresh ordinary adapted suite also passes.

The 31 newly tested conditions cover:

| Scope | Missing outcomes exercised | Oracle |
|---|---:|---|
| Authenticated Authority / ReadTags | 5 / 3 | Calls in the wrong lifecycle order refuse without replacing admitted authority; distinct admitted bounds clear stale cache state. Tags are component inputs, not a cryptographic-validity claim. |
| Bound storage | 1 | An absent PIN owner returns None, reports no storage error, performs only reads and leaves media/output unchanged. |
| Import backup verification | 1 | A wrong same-width backup is recovered from the real legacy record before activation; after activation it produces MemoryFatal and byte-identical media. |
| ML-DSA packing / output contracts | 4 / 2 | Exact size panics; short public/signature outputs preserve every byte. Debug-only assertions are measured in the debug profile. |
| Power-cut model / read-fault probe | 5 / 2 | Public Fs overwrites expose the exact length/content assertion; nondeterministic provisioning and changed first-read FID expose the intended apparatus check. These are verification-helper controls. |
| PIV import / management-head recovery | 1 / 2 | Authenticated empty-scalar import returns WRONG_DATA and preserves the stored canary; genuine short legacy heads recover default NEVER touch through both scan and protect paths. Canary retention does not establish usability of a prior key. |
| FIDO cached point / credential enumeration | 1 / 1 | Valid point prefix with wrong coordinate width returns the exact encoding error without output; a present 31-byte RP hash with protocol and MAC returns MissingParameter without writes/output. |
| SDK dispatcher / OATH rename / OTP record | 1 / 1 / 1 | Disabling an applet during an open chain refuses and clears its body; rename skips an unrelated TLV and retains a known HMAC result; an authenticated empty slot first unseals as Some(0), then is filtered to None without writes. |

A pair for a defensive check does not prove that deleting it changes the public
result: a later scalar-width check can also refuse PIV's empty scalar. These
measurements retain component contracts, public command paths and apparatus
controls as distinct evidence scopes.

## Fresh feature matrix

All eighteen profiles now use the same current Rust snapshot, frozen v9
frontend, 132 const-function adapters and four EC-template expansions. Each
ordinary adapted suite and its measured full suite passes. Every row retains
its own raw archive and complete paginated residual queries; no vector crosses
a profile boundary. All 31 newly tested conditions have pairs in every profile.

| Profile | Passed | Paired conditions | Raw missing | Run |
|---|---:|---:|---:|---|
| `default` | 4,840 | 4,806/5,029 | 223 | `run_ca3cc7a656f04845` |
| `advertise-pqc` | 4,840 | 4,806/5,029 | 223 | `run_b2030fe432f31088` |
| `fips-profile` | 4,826 | 4,793/5,029 | 236 | `run_becf193d6a15d429` |
| `fips-profile,advertise-pqc` | 4,826 | 4,793/5,029 | 236 | `run_ce91020c1702df24` |
| `strong-pin` | 4,844 | 4,799/5,029 | 230 | `run_e08676ca09596e5a` |
| `strong-pin,advertise-pqc` | 4,844 | 4,799/5,029 | 230 | `run_e791c0df5730b113` |
| `always-uv` | 4,840 | 4,806/5,029 | 223 | `run_089a6fc9b4440633` |
| `always-uv,advertise-pqc` | 4,840 | 4,806/5,029 | 223 | `run_978f4607ecdc2463` |
| `strict-up` | 4,838 | 4,796/5,029 | 233 | `run_580b39d1fae5b668` |
| `strict-up,advertise-pqc` | 4,838 | 4,796/5,029 | 233 | `run_350992b6934d0a5a` |
| `display` | 4,845 | 4,808/5,031 | 223 | `run_1787753a4a75658a` |
| `strict-config` | 4,821 | 4,781/5,003 | 222 | `run_1d70062d8cac5d5b` |
| `largeblob-ext` | 4,833 | 4,799/5,029 | 230 | `run_f04b3e0ba690dd20` |
| `preview-sign` | 4,879 | 4,845/5,070 | 225 | `run_ed1621fdf6cba712` |
| `preview-sign,largeblob-ext` | 4,873 | 4,838/5,070 | 232 | `run_f2be47b20f4532ce` |
| `display,strong-pin` | 4,849 | 4,801/5,031 | 230 | `run_afbe68f5ad84d3b3` |
| `display,fips-profile` | 4,831 | 4,795/5,031 | 236 | `run_32fba98bae015ed9` |
| `fido-conformance` | 4,838 | 4,796/5,029 | 233 | `run_ce419e8f90ea1067` |

Every row has five skipped tests, valid and unstale evidence, zero reported
evidence corruptions, and 79 declared frontend warnings. The raw reports keep
complete=false and structurallyComplete=false. Every residual is matched to
its existing profile-specific source argument or a newly reviewed invariant.

The complexity callback at `crates/rsk-fido/src/pinpolicy.rs:33` has one further
profile-specific exclusion: strong-pin/fips-profile makes PIN_COMPLEXITY_POLICY
true, so the outer OR never calls record.get(1).is_some_and. Its absent outcomes
are not feasible callback invocations in those builds. The default has both
outcomes separately; its vectors are not donated to the stricter profiles.

Disk-full attempts are retained separately. Some failed publication or probe
header validation; one reported valid evidence while missing known new test
witnesses. It is excluded from this table despite that flag. A cached retry
also failed on an unknown obligation and receives no credit. Replacements use
fresh frontend preparation. Admission requires all 31 known pairs and a full
residual-identity reconciliation, as well as successful tests and raw validation.

All twenty added test functions also pass in every ordinary adapted suite,
including the expected-panic apparatus controls. Resource scheduling limits
concurrent evidence writers; these runs establish functional/coverage results,
not wall-clock performance comparisons.

The fresh matrix and its source hashes, failed attempts and per-profile reviews
are retained under `target/mcdc-completion-20261106/profiles/`.

## Host residuals exposed by this frontend

All 79 additional residual identities have the following current-source
arguments. They remain missing in raw evidence. They are not synthetic pairs
or universal unreachability proofs. A producer, supported target, buffer size,
curve set or encoded format change requires reviewing the corresponding row.
The 144 earlier residuals retain their [existing dispositions](mcdc-expansion.md)
and [native annex](mcdc-residuals.md).

| Original source | Why the missing outcome has no current producer |
|---|---|
| `crates/rsk-piv/src/keygen.rs:270`, `crates/rsk-piv/src/keygen.rs:426` | The selected curve is supported; rejection sampling supplies its exact scalar width. A rejected scalar is retried, not returned as None. |
| `crates/rsk-piv/src/keygen.rs:278`, `crates/rsk-piv/src/keygen.rs:738`, `crates/rsk-piv/src/keygen.rs:767` | public_point returns the selected curve's fixed 65/97/32-byte encoding within the supplied buffer. |
| `crates/rsk-piv/src/keygen.rs:301` | The public-key DO contains at most the fixed 141-byte EC encoding and fits its output buffer. |
| `crates/rsk-piv/src/keygen.rs:342` | The current RSA sizes are 1024..4096 bits; the modulus and at-most-five-byte exponent fit the 533-byte DO buffer. |
| `crates/rsk-piv/src/keygen.rs:525` | The preceding curve-specific check supplies exactly 32/48 scalar bytes. from_scalar refuses oversize input; zero is represented and is refused later by public_point. |
| `crates/rsk-piv/src/keygen.rs:579` | The preceding Ed25519/X25519 check supplies exactly 32 bytes to the constructor. |
| `crates/rsk-piv/src/keygen.rs:709` | modulus_be returns Err for insufficient capacity; its successful reported length is bounded by the buffer it received. |
| `crates/rsk-piv/src/lib.rs:781`, `crates/rsk-piv/src/lib.rs:992`, `crates/rsk-piv/src/lib.rs:1051` | The object/meta readers clamp their returned lengths; the public-key DO builder bounds its output by the same supplied buffer. |
| `crates/rsk-piv/src/lib.rs:810` | Management-key lengths are 16/24/32, fitting the 36-byte body and u8. |
| `crates/rsk-piv/src/lib.rs:1027`, `crates/rsk-piv/src/lib.rs:1036` | The validated metadata is nonempty; public_point/modulus_be bounds the public bytes. The largest public key is 512 bytes, fitting u16. |
| `crates/rsk-piv/src/lib.rs:1713` | The fixed PIVMAN fields and bounded timestamp fit the admin buffer; admin_len is produced by that same builder. |
| `crates/rsk-oath/src/lib.rs:517` | The current entry length is bounded by ResBuf. skip/take are clamped against that same entry before slicing. |
| `crates/rsk-oath/src/lib.rs:605`, `crates/rsk-oath/src/lib.rs:608` | The same algorithm/key already produced a successful HMAC. Its SHA-1/256/512 result is 20/32/64 bytes, fitting u8. |
| `crates/rsk-oath/src/lib.rs:644`, `crates/rsk-oath/src/lib.rs:799`, `crates/rsk-oath/src/lib.rs:854`, `crates/rsk-oath/src/lib.rs:938`, `crates/rsk-oath/src/lib.rs:1005`, `crates/rsk-oath/src/lib.rs:1879` | The successful seal/open operation bounds its reported length by the same supplied scratch buffer. |
| `crates/rsk-oath/src/lib.rs:694` | The recorded IMF offset came from this same blob with at least eight remaining bytes; the blob has not been resized. |
| `crates/rsk-oath/src/lib.rs:752` | The parser bounds the challenge at 64 bytes before this copy and u8 conversion. |
| `crates/rsk-oath/src/lib.rs:1468` | The range was parsed from the same live blob; no intervening mutation changes its length. |
| `crates/rsk-oath/src/seal.rs:80` | The preceding plaintext bound establishes nonce/ciphertext/tag ranges in the fixed blob buffer. |
| `crates/rsk-devconf/src/lib.rs:225`, `crates/rsk-devconf/src/lib.rs:229` | n starts at one; the bounded push path cannot exceed the 128-byte configuration buffer. |
| `crates/rsk-devconf/src/lib.rs:520` | The input is a safe byte slice, its offset is bounded by isize::MAX, and the TLV length is u8. Neither checked addition can overflow usize on the supported 32/64-bit targets. |
| `crates/rsk-devconf/src/lib.rs:532` | Only nine writable tags can reach this duplicate-rejecting loop; seen has sixteen slots. |
| `crates/rsk-devconf/src/lib.rs:781` | The producer allocates each entry as two header bytes plus its value. |
| `crates/rsk-sdk/src/applet.rs:59`, `crates/rsk-sdk/src/applet.rs:72` | The preceding capacity/end guards establish len <= capacity <= buf.len() and end <= capacity. |
| `crates/rsk-sdk/src/applet.rs:354` | The preceding chain-length guard bounds chain_len + apdu.nc by the same chain buffer. |
| `crates/rsk-sdk/src/applet.rs:456` | i is the position found in this exclusively borrowed applet slice; its length cannot change between lookup and dispatch. |
| `crates/rsk-fido/src/getassertion.rs:528` | The parser bounds allow_len by the fixed descriptor array. |
| `crates/rsk-fido/src/getassertion.rs:860`, `crates/rsk-fido/src/getassertion.rs:1182` | The extension CBOR writer bounds ext_len by its supplied buffer; authenticator data reserves the same extension capacity after its 37-byte prefix. |
| `crates/rsk-fido/src/makecredential.rs:1281` | The preceding reader clamps n by the same record buffer. |
| `crates/rsk-fido/src/clientpin.rs:1005` | The code-point count advances only after successful access to the same fixed array. |
| `crates/rsk-fido/src/cbordec.rs:116` | The descriptor parser checks its count against out.len() before requesting the next slot. |
| `crates/rsk-mldsa/src/sign.rs:372` | The public-key input has the fixed encoded width. Each decoded t1 coefficient is ten bits and every ten-bit pattern is admissible. |
| `crates/rsk-otp/src/hid.rs:101` | The sequence is checked at 0..=9; the fixed frame has ten seven-byte data chunks. |
| `crates/rsk-otp/src/ticket.rs:54` | The HMAC has twenty bytes; dynamic truncation uses an offset at most fifteen and reads four bytes. |
| `crates/rsk-otp/src/record.rs:104` | The preceding CONFIG_SIZE..=SLOT_SIZE check bounds both slices. |
| `crates/rsk-otp/src/seal.rs:91`, `crates/rsk-otp/src/seal.rs:167` | The preceding plaintext/stored-record checks bound nonce/ciphertext/tag and plaintext ranges. |
| `crates/rsk-usb/src/ctaphid.rs:488`, `crates/rsk-usb/src/ctaphid.rs:577` | The payload length is min-clamped to 57 in a fixed 64-byte frame and to the supplied message/data buffer. |
| `crates/rsk-usb/src/ctaphid.rs:592` | off < total and the continuation length is min-clamped to 59 and the remaining payload; both slices use those same bounds. |
| `crates/rsk-phy/src/lib.rs:545` | The name length is clamped to the name and remaining output room; end cannot exceed output capacity. |
| `crates/rsk-ui/src/scene.rs:282` | start is a private u16 stream offset, while a safe slice length is at most isize::MAX. Their sum cannot overflow usize on either supported target. |
| `crates/rsk-ui/src/scene.rs:991`, `crates/rsk-ui/src/scene.rs:992` | RasterEncoder publishes only complete, bounded pixel/run streams. Failed writes roll back before publication; flush consumes exactly that stream. |
| `crates/rsk-openpgp/src/dobj.rs:115`, `crates/rsk-openpgp/src/dobj.rs:118`, `crates/rsk-openpgp/src/dobj.rs:526` | These callers select fixed ATTR_* tables or the RSA-2048 fallback. These are not the reader of arbitrary persisted algorithm attributes. |
| `crates/rsk-openpgp/src/retries.rs:52` | Both returned lengths were clamped to their respective eight-byte buffers. |
| `crates/rsk-piv/src/seal.rs:86`, `crates/rsk-piv/src/seal.rs:140` | The preceding plaintext and record bounds establish the nonce/ciphertext/tag and plaintext slices. |
| `crates/rsk-piv/src/seal.rs:244` | The PrivKey serializer supplies a fixed scalar encoding with at least the algorithm byte. |
| `crates/rsk-piv/src/seal.rs:340` | parse_rsa_blob accepts a half width derived as n/2 or n/5; both prime ranges fit the same accepted blob. |
| `crates/rsk-piv/src/objects.rs:109` | The preceding MAX_OBJECT check reserves the object-ID prefix and body in the same record buffer. |
| `crates/rsk-store/src/authenticated/bank.rs:23` | A typed 32-byte group has exactly eight four-byte chunks. |
| `crates/rsk-usb/src/bulk_retry.rs:27` | The address is masked to 0xff before conversion to u8. |
| `crates/rsk-store/src/authenticated/main.rs:751`, `crates/rsk-store/src/authenticated/main.rs:798` | Successful resolution requires Complete journal scans with no pending transition. The exclusive Current owner and its cache/history helpers preserve those postconditions. |
| `crates/rsk-store/src/authenticated/managed.rs:168` | The preceding any-Otp test is false. RootArm has only Otp and PreOtp variants, so every remaining header is PreOtp. |
| `crates/rsk-store/src/authenticated/managed.rs:391`, `crates/rsk-store/src/authenticated/managed.rs:452` | ready is established only with Some(active); no ready-state transition removes that active owner. |
| `crates/rsk-store/src/authenticated/counter_bank.rs:47` | The counter-location producer maps the FID injectively to its bank entry; the returned entry carries the requested FID. |
| `crates/rsk-mldsa/src/round.rs:27` | The bounded coefficient decomposition reconstructs its input exactly without arithmetic overflow. |
| `crates/rsk-mldsa/src/round.rs:49` | The current valid gamma2 values make the quotient/remainder decomposition reconstruct the input modulo Q. |
| `crates/rsk-piv/src/chuid.rs:58` | The CHUID builder uses a fixed layout; the serial hash changes bytes, not field widths. Those encoded lengths sum to CHUID_LEN. |
| `crates/rsk-fido/src/cert.rs:144` | The fixed certificate TBS fields sum to TBS_LEN. |

## ARM image campaigns

The independent AST inventory maps all 60 firmware let-else sites: 59 runtime
sites and one build-script site. The newly admitted set has **84 unique source
identities**: 59 let-else, ten closure predicates, three function predicates,
two guarded matches, nine equality assertions and one inequality assertion.
All are single-condition decisions. Repeated syntax in different images is
counted once in this inventory, while its evidence stays image-specific.

There are **45 identities with a pair in at least one admitted single image**
and **39 with a source-bound explanation below**. The 42 feasible pair gaps
identified after the baseline campaigns now have measured opposite outcomes;
three pairs already existed in those baselines. This is not a 45/84 firmware coverage
percentage. The 31 separate ELF reports retain 183 raw regions after the
[display admission/cancellation follow-up](#display-execution). Vectors may be
combined only when the exact ELF SHA-256 agrees; different profile or fixture
images never form a pair.

| Campaign | Executed path and oracle |
|---|---|
| Core1 | Real RSA-2048 prime jobs, another core1 prime, cancellation/take schedules and RSA-512 private operation; independently checked signatures. All six newly exposed core1 decisions have pairs in the admitted schedule image. |
| Display panel | Empty, short and full RepeatN inputs enter the actual panel conversion. The fixed clock contract remains in the residual table. |
| Main boot | Persisted PHY changes exercise LED count, GPIO and timeout filters. The owned boot-seal suite retains pre-reset snapshots for both guarded matches. |
| Main migration | An owned fused/pending migration boot pauses after the late fused-key result at PC 0x10032f90. A bounded read-response corruption targets persisted word 0x10280810 (observed native PC 0x20020c2a). Rescue/pending and latch oracles distinguish it from the healthy boot; a wrong-PC control stays healthy. No private guest state is planted. |
| OTP keys | One permission-word LDR at PC 0x10048878, after the presence scan, returns 0xffffffff. The real HAL read_ecc_word refusal changes PRE_OTP_LEFT from 0x0000 to 0xfffe; the OTP backing file is unchanged. |
| Sweep | Real INS 0x15 zero/0xaa scans reach the predicate; scanned > nonzero confirms execution over zero bytes. |
| ACCESSCTRL | Five bounded read-response corruptions reach the exact ROM grant, GPIO0, GPIO1, FORCE_NS and lock assertions. Each halts before NS entry; a wrong-PC control boots normally. |
| USB SG / endpoints | Actual pre-START STALL, identity offset/length bounds, repeated START and real IN/OUT allocation exhaustion exercise refusal paths. Ordinary traffic then checks protocol recovery. |
| NS USB / control | Allocated Endpoint trait calls reject 65-byte transfers before SG. Real CTRL_OUT length64/65 and repeated accept exercise control capacity; valid OTP feature traffic executes its successful OUT path. |
| Bulk waiting | Delaying only the real NS CCID read leaves an actual host OUT pending; interrupt-empty/bulk-ZLP behavior and exact first CCID reply verify the waiting branch and recovery. |
| Worker | Real RSA-2048 CCID ABORT then FIDO while busy; owned getInfo exchange held across a second submit and complete decode after drain; OTP feature lengths0/64/65 plus HMAC/keyboard result; display Secure prefix parsing. |
| NS submit fence | Healthy RSA/ABORT reaches PENDING. A fenced Secure panic makes the original valid submit return INVALID at the verified BL, producing the intended NS assertion in the same ELF. A wrong-register control stays healthy. |
| QMI | In the 4 MiB Puya profile, the first startup JEDEC LDR at PC 0x2001e7fe receives one extra bit (0x85→0x185). Healthy quad-ready1 and faulted serial-fallback-ready0 both retain working getInfo/OpenPGP; a wrong-PC control remains healthy. |

The Puya serial runtime-command attempt after quad enable returned 0xff JEDEC
bytes in the emulator model and is excluded. Only the later startup-read
campaign supplies the QMI pair. Component fixtures call the real routines with
explicit inputs or delay their real consumers. Their image hashes, source
changes and scopes remain separate from unmodified command-path campaigns.
None of these observations is a physical fault-injection result.

## ARM residuals exposed by this frontend

These 39 identities remain raw missing outcomes. Thirty-eight have one-sided
execution evidence, including the later real CCID Secure request at worker:701.
Worker:773 has no current producer and is inactive. This pair-gap review does
not establish complete execution coverage. Width conversions below are
specific to the 32-bit ARM image; ownership arguments refer to the reviewed
actual callers. A direct private-state overwrite is not a feasible producer.

| Original source | Current boundary |
|---|---|
| `firmware/src/display_panel.rs:73` | The sole production constructor receives the configured clock/frequency ratio. No current caller supplies a different ratio. |
| `firmware/src/flash_storage/sha256.rs:76` | A typed &[u8; 64] has exactly sixteen four-byte chunks. |
| `firmware/src/trustzone/mod.rs:20`, `firmware/src/trustzone/mod.rs:35`, `firmware/src/trustzone/mod.rs:56` | u32 and usize both have 32 bits on this target. |
| `firmware/src/trustzone/mpu.rs:34`, `firmware/src/trustzone/mpu.rs:35` | All configure callers use fixed aligned regions, RamCode validation, or linker ranges aligned/rounded to 32 bytes. |
| `firmware/src/trustzone/usb.rs:271`, `firmware/src/trustzone/usb.rs:388`, `firmware/src/trustzone/usb.rs:426` | The u32/usize conversions are lossless on this target. |
| `firmware/src/trustzone/usb.rs:179` | observe establishes Some(bus) before this path; the Controller is exclusively owned throughout. |
| `firmware/src/trustzone/usb.rs:268` | Main installs IDENTITY before launching NS; no later path clears it. |
| `firmware/src/trustzone/usb.rs:416`, `firmware/src/trustzone/usb.rs:429` | Packet64 bounds the supplied buffer; the successful endpoint read count cannot exceed that supplied length. |
| `firmware/src/trustzone/usb/control.rs:27` | The task pool has one slot, START is installed once, and the task never exits. |
| `firmware/src/trustzone/usb/control.rs:109`, `firmware/src/trustzone/usb/control.rs:175`, `firmware/src/trustzone/usb/control.rs:193` | The sole owned command queue bounds input and capacity to the fixed 64-byte packet. |
| `firmware/src/trustzone/usb/control.rs:167`, `firmware/src/trustzone/usb/control.rs:190` | The fixed 64-byte packet always contains eight bytes and a first byte; actual OTP OUT traffic executes the latter path. |
| `firmware/src/trustzone/usb/control.rs:218` | The preceding operation-mask guard bounds the address to 127. |
| `firmware/src/trustzone/usb/control.rs:287`, `firmware/src/trustzone/usb/control.rs:290` | The prior length check bounds the requested output; HAL bounds received length by the same at-most-64-byte buffer. |
| `firmware/src/trustzone/usb/endpoints.rs:47`, `firmware/src/trustzone/usb/endpoints.rs:57` | HAL allocation indices are 1..15 and ENDPOINTS is sixteen. |
| `firmware/src/trustzone/usb/endpoints.rs:66`, `firmware/src/trustzone/usb/endpoints.rs:87` | The value is masked to 0xff before conversion to u8. |
| `firmware/src/trustzone/usb/endpoints.rs:128`, `firmware/src/trustzone/usb/endpoints.rs:158` | The preceding allocated-endpoint guard establishes the slot; exclusive ownership prevents intervening removal. |
| `firmware/src/worker.rs:229`, `firmware/src/worker.rs:285` | The u32/usize conversions are lossless on this target. |
| `firmware/src/worker.rs:282` | Ready is visible only after the Dispatch EXCHANGE guard drops. Polling is serialized and core1 does not own EXCHANGE. |
| `firmware/src/worker.rs:701` | pin_ref_ready accepts exactly P2 0x80..0x83, the same set accepted by secure_pin_meta. A real selected-OpenPGP Secure request executes its true path; native CCID ABORT cancels the ceremony. |
| `firmware/src/worker.rs:773` | The legacy SecureOtpHidHandler is never instantiated by the current producer. This is inactive source, not an executed true-only condition. |
| `firmware/trustzone/nonsecure/src/keyboard.rs:76` | Frame sets req_ready before signaling. The sole consumer shares the NS executor, with no await between wait and take; reset preserves the request. |
| `firmware/trustzone/nonsecure/src/keyboard.rs:104` | The character is masked to 0xff before conversion to u8. |
| `firmware/trustzone/nonsecure/src/main.rs:130` | The valid producer reserves full FIDO/CCID reply capacity plus status, or three bytes for reset. ABANDONED is handled first. No valid caller supplies a private undersized exchange. |
| `firmware/trustzone/nonsecure/src/usb.rs:23` | The allocated slice fits u32 on this target. |
| `firmware/trustzone/nonsecure/src/usb.rs:202` | capacity is min(buffer.len(), 64), and the slice immediately uses that same buffer. |

## Retained evidence and remaining scope

The initial laboratory artifacts are under `target/mcdc-whole-fw-20261106/`:
`patch-qualification.json`, frozen tool sources/binaries, debug/release/range
calibrations, `firmware-v8-v9-correspondence.json`, `batch-plan.json`,
`new-firmware-evidence.json`, per-image sources/ELFs/depinfo/raw regions,
`host/full-queries/`, and the fresh `host-final/` source and run. The earlier
measurements and their raw evidence are retained unchanged. Rebuildable
half-image Cargo caches were pruned only after retaining the combined image,
S/NS ELFs and
depinfo archives with hashes. The completed tool Cargo cache was also pruned
after checking all five frozen v9 executables and archiving its depinfo.

The 28 firmware and 79 host frontend limitation records remain declared.
Their [current-source review](#declared-frontend-warnings) distinguishes existing
adapters, compile-time evaluation and macro bodies without owned Boolean
control. The consumer policy is bound to current source. Earlier profile
measurements retain their original frontend; fresh profiles are recorded
separately. The [C/assembly correspondence](#owned-c-and-assembly-correspondence)
is a separate component scope. Source pairs and invariants do not replace
independence review for coupled conditions, hardware faults or timing.

## Verification

The final Rust tree passes both mandatory gates on 2026-11-06:

```sh
nix develop -c env RUST_TEST_THREADS=4 ./scripts/check.sh
nix develop -c ./scripts/check-assurance.sh
nix develop -c ./scripts/docs.sh check
```

The main gate uses four host test threads, matching the earlier qualified
[gate setting](mcdc-independence.md#verification). All twenty new test functions
appear in its log. Its interop row passes 1,281 tests, two skipped; assurance
passes 2,729 tests. Both full gates return zero. The final formatting check,
book build and link check pass. Logs and observed exit codes are retained as
`check-final.*`, `assurance-final.*` and `docs-final*` in the laboratory folder.

The prescribed `mutants-container.sh --in-diff HEAD` initially encounters a
container name owned by another run. A scratch copy uses a dedicated name and
output directory, retaining the same runner and resource limits. The image's
dangling `/usr/bin/env` is repaired only inside that disposable container.
The completed run returns zero and lists **zero in-diff mutants**: the crate
diff adds tests, with no production Rust lines to mutate. This is not a
mutation-kill result. Failed environment attempts and the successful
`mutants-env-fixed.log` remain separate.

The frontend patch hashes and all foreign working changes match their saved
baselines. Production Rust, compiler pins, firmware behavior and device release
are unchanged. The source/test additions were committed as `cd540fab`.
No push or hardware operation was performed.

The later documentation-only completion composes those full-gate results for
the unchanged Rust/checker tree with fresh documentation build/link checks and
all current prose/registry rows from check-assurance.sh. The unchanged assurance
pytest suite is not repeated for this documentation update.

## Current-source completion review

The follow-up reconciles the finite owned firmware-source inventory, including every
declared frontend warning. Measured pairs and reviewed missing outcomes remain
distinct. The default still reports 4,806/5,029 pairs and 223 raw residuals;
no source argument is substituted for a vector. This is completion of this
source-inventory work, with explicit exceptions, rather than literal 100%
MC/DC of the complete delivered binary.

### Declared frontend warnings

The review retains all 79 host and 28 firmware records, including their exact
original IDs, reasons and source hashes. Its join uses record identity and
path; a warning's reported line may belong to the adapted measurement copy.
No additional unadapted owned runtime Boolean control decision was found
inside these 107 records in the current source.

| Declared records | Current-source disposition |
|---:|---|
| 51 host const records | All 132 original const functions have retained adapters; all original file hashes match. Adapter presence does not imply that every path executed. |
| 8 other host const records | Fixed table geometry, feature expressions, FID assertions, const-generic dimensions and the compile-time flash read-size assertion. |
| 12 host macro records | cfg/env values fixed for each build; their surrounding runtime predicates are measured separately. |
| 5 EC macro records | Generated coordinate constants or followed literal includes; four Boolean-bearing runtime template expansions retain their separate adapters. |
| 2 other host macro records | AES templates delegate operations and errors; SHA templates perform integer arithmetic and bitwise operations. Neither hides an owned Rust Boolean control predicate. |
| 1 host fixture record | Included Wycheproof text is data. |
| 9 firmware const records | Build validation, const-generic dimensions and aggregate initialization. |
| 1 firmware PIN record | The separately measured runtime codec described below. |
| 1 allocator record | Arithmetic, three for loops and dependency delegation; no explicit Boolean control predicate in the owned body. |
| 8 firmware macro records | Static addresses, direct register writes, pinning an existing future, GPIO constructors or unconditional PIO output/wrap. |
| 5 firmware macro records | Build cfg/env values. |
| 2 firmware macro records | Straight-line assembly or generated diagnostic constants. |
| 2 firmware macro records | Pinned critical-section/Embassy expansions emit direct wrappers; owned implementation bodies remain ordinary measured source. |

Actual compile-time assertions remain compile-time assertions. Artificially
executing them after rewriting them as runtime code would not establish a
production runtime pair. The allocator's for loops, AES error propagation,
integer bit operations, dependency internals and generated machine branches
remain distinct from this Rust Boolean MC/DC criterion.

### Firmware inventory reconciliation

The complete current frontend manifest contains 527 decisions and 662
conditions. Matching exact decision IDs and condition indices gives:

| Conditions | Evidence inventory |
|---:|---|
| 530 | Earlier native firmware batch conditions, with their original image-specific evidence and dispositions. |
| 6 | Earlier supplementary obligations, including the independent native timer observer. |
| 84 | Newly admitted source forms described above. |
| 42 | Previously unaccounted display/bench and compile-time conditions. |

The last 42 conditions comprise 24 compile-time conditions, 15 feasible runtime
conditions and three runtime exceptions. They were absent from both earlier
batch inventories; empty vectors do not establish their infeasibility.
The compile-time set consists of display GPIO, clock, backlight and presence
assertions, plus loops and the contains helper inside main's const block.
Its exact identities and original source hashes remain in the reconciliation
record. The display/LED collision checks additionally belong to a configuration
rejected by the existing compile_error. They receive no runtime pair credit.

A single feature manifest also omits 13 real conditions retained by the older
inventory: flash_storage's two debug assertions; six non-display compile-time
conditions in main; presence's timer-frequency const assertion; main's
build-fixed presence selection; and three presence GPIO component conditions.
The latter retain their original same-image constructor/input pairs. Keeping
these conditions gives a **537-decision, 675-condition firmware-directory Rust
source union**. Target-specific library variants are reviewed separately below.
This is a source inventory across configurations, not a merged execution report.

Five other earlier keys are explicitly excluded as laboratory calibration:
two conditions at Non-secure diagnostics:36 and three at Non-secure main:456/457.
Neither repeated expression text nor a matching line alone transfers evidence;
identities, indices and current source hashes are checked. In particular,
main:354's const BUILD_LED_POWER_ENABLED must not inherit main:912's runtime
observation merely because their expression text agrees.

### PIN codec adapter

A fresh button/TrustZone image uses the frozen v9 frontend and current sources.
The four original const bodies remain available for compile-time evaluation;
const_eval_select sends runtime consumers through the corresponding measured
bodies. A separate Rust compiler wrapper enables the laboratory intrinsic only
for firmware. Dependencies compile without RUSTC_BOOTSTRAP, preserving the
ordinary ARM cfg selection. A clean build excludes reuse of bootstrap-dependent
Cargo artifacts. Product sources, dependency versions and compiler pins are
unchanged.

All 1,536 typed codec rows match an independent Python SHA-256 chain over decoded
state, clamping, encoded words and round-trip results. All **five production
codec conditions** have measured pairs. The two conditions in the round_trips
verification helper are separately paired; they are not two more production
conditions. Eleven compile-time assertion conditions remain raw unpaired in the
18-condition source manifest. This component result does not cover every RAM
lock lifecycle or physical reboot schedule.

### Display execution

The reachable worker:701 path now executes in the retained display ELF
`18c9c0652c620b8083f372d4c6110069bff9417d1b51dd25416f4d475ac36bbc`.
A real CCID Secure request first refuses without a selected applet. After
selecting OpenPGP, its valid PIN-verify prefix passes the actual readiness check
and reaches secure_pin_meta. Native CCID CONTROL ABORT cancels the pending
ceremony, followed by its matching bulk acknowledgement. The PIN status and
retry count remain unchanged; OpenPGP challenge and FIDO getInfo work afterward.

The three added raw regions bring the 31 separate source-extension ELF reports
to **183 regions**. Of the 39 source-bound missing outcomes, 38 now have their
reachable side observed. Worker:773 remains inactive because its legacy handler
has no current producer. Worker:701 still has no feasible false outcome: its
preceding readiness check accepts the same P2 set as secure_pin_meta. These
earlier observations cover request admission and cancellation, without claiming
successful PIN typing or complete display-ceremony coverage.

### Remaining display and bench decisions

Four further image reports, prepared with the frozen v9 frontend, close the
15 feasible runtime gaps found by the full inventory reconciliation. Each
report joins only regions from its own ELF.

| Image selection | Measured conditions | Result |
|---|---|---|
| worker-display-no-wake | worker:108 first operand; both worker:121 operands; worker:686/698; both worker:704 IDs; worker:720 | 8/9 raw pairs; the other worker:108 operand has no active OTP_REQ producer. |
| sweep-bench-remaining | sweep:37/114 and both sweep:117 operands | 4/4 raw pairs, with the bounds-domain qualification below. |
| vendor-bench-remaining | vendor:170/195/208 | 3/3 raw pairs. |
| main-display-remaining | main:1107/1109 | Each decision's configured outcome executes; 0/2 pairs, retained as configuration exceptions. |

The worker image is
`01aa29c4bb66566675dc19bd9b8efeb8a00a53102ffefee482c12a06382a7c94`,
with the supported display/TrustZone configuration WAKE_PIN=none, LED_KIND=none
and FLASH_SIZE=16M. A laboratory TouchPad adapter supplies only Point/None input.
All 35 rsk-display source files are byte-identical to the product. Original
debounce, 800 ms hold, PIN layout, Presence and PinEntry results execute unchanged;
an RAII guard disables the input script on every ordinary return. Fresh owned
flash retains the default unscrambled layout. No physical CST328/I2C claim follows.

Actual USB/IP CCID Secure requests refuse an unsupported operation and an
unselected PIN reference without reading touch input. Deny consumes release
and the Deny point. Both approval cases consume the hold, six digit/release
gestures for 123456 and OK/release. An INS 0x21 template fails assembly with
the PIN status still 63C3; the normal INS 0x20 template runs the real VERIFY,
returns 9000 and leaves PIN status 9000. A following OpenPGP challenge succeeds.
These checks distinguish an actual Deny or entered PIN from a generic cancellation.

For worker:121, a real queued request gives pending=true before and after the
2,500 ms UI floor. After the worker fully drains it, a boot timestamp already
older than that floor gives actual pending=false with elapsed>=floor. Thus the
first operand's pair does not rely only on an omitted second operand whose
actual value was false. The legacy OTP_REQ operand remains false: the actual
Non-secure keyboard producer submits through abi::OTP and Secure REQ.

Native vendor commands stop and restart the sweep, scan real zero/nonzero dead
stack bytes, and exercise matching zero and nonmatching 0xAA patterns of equal
length. At sweep:117, the final seven addresses fail the eight-byte bounds
guard; an eight-byte pattern matches and mismatches inside the bounds. The tool
credits both operands under its evaluated-vector criterion. Holding the second
operand actually true beyond top would leave its valid read domain: the bounds
term therefore retains a safety-domain coupling qualification, rather than a
counterfactual out-of-bounds read or an unconstrained unique-cause claim.
Vendor selectors 4/3 exercise refusal/OTP admission, selectors 3/2 produce the
expected 24/20-byte OTP/HKDF summaries, and pattern lengths 7/8 exercise refusal
and scan admission.

The first display attempts are retained without pair credit. The emulator does
not model the wake GPIO's pull-up; default active-low GP25 therefore cancelled
both attempted gestures after only the release sample. The supported
WAKE_PIN=none configuration removes that unmodelled input, without replacing
the ceremony's result. Failed disk-full builds and report writes are also
separate from the four completed reports.

### Target-specific library variants

The current crate-source cfg review finds one additional ARM-only runtime
Boolean condition outside the firmware-directory inventory:
`crates/rsk-rsa/src/lib.rs:606`, the public-modexp wrapper's if ok. Its host
fallback always returns true and cannot supply this pair. Other target-specific
RSA wrappers contain FFI, conversions and for loops without additional Boolean
control. The crypto target dependency selects an external SHA backend; the
pointer-width sites are tests, and display's not(test) changes its external
sleep implementation. Their source hashes and cfg sites are retained separately.

A fresh button/TrustZone image, SHA-256
`d609c4b7781b3e25113dfcce88eebb6518430334b5a70db05aa7e4430005fef2`,
measures the actual ARM Rust wrapper with a runtime owned by rsk-rsa. Both
outcomes form **one same-image runtime pair**. With modulus 2^255+67, base 2
and exponent 65537, all 32 result bytes match independent Python pow. A second
call with base equal to the modulus receives the real C precondition refusal;
the wrapper returns false and preserves every byte of its 0xA5 output canary.
No FFI return or private Boolean state is substituted. Buffer widths remain
valid; base<n is deliberately violated for this negative component input.
Ordinary signature callers reduce their bases modulo n, so this is not a
healthy wire-producer witness for that refusal.

Six ARM-only debug assertions contribute twelve further source conditions:
lib.rs:383, 481, 482, 483, 580 and 581. Release compilation excludes them;
they receive no runtime pair credit. These target-library dispositions remain
separate from the 675 firmware-directory conditions and the host denominator.
The retained S/NS/combined images, raw 4 KiB region, independent oracle,
current-source hashes and dependency identities are checked. The only extra
RSA dependency edge is the laboratory runtime's already-pinned critical-section;
production dependencies and Rust sources are unchanged.

### Owned C and assembly correspondence

The complete current inventory is five files: gateway.c and the RSA C,
assembly, declaration header and configuration header. Current source bytes
match the retained measured originals; only the documented uninstrumented
fixtures and naked-entry profiling exclusion differ in the laboratory copy.
The independent arithmetic/ISA witness verifier passes again against the
retained image and records.

The existing results therefore apply to these current sources: **8/8 RSA C
compound conditions, 4/4 gateway compound conditions, both branch counts for
31/31 C predicates and both outcomes for 19/19 compiled assembly predicates**.
The two other assembly sites are build-excluded by the unchanged configuration.
The gateway's zero-capacity/writability coupling retains its separate argument;
Clang's short-circuit pair is not a feasible unique-cause pair for that redundant
term. Direct C wrappers and the unconditional register-wiping NS entry introduce
no additional Boolean control predicate. The unused exponent-one C API defect
and its eight diagnostic exclusions remain recorded in the
[C/assembly report](mcdc-expansion.md#arm-c-and-assembly-follow-up).

### Evidence boundary

The additional evidence is retained in `target/mcdc-completion-20261106/`:
source-scope-review.json, host-raw-manifest.json, owned-c-source-correspondence.json,
owned-c-verified.json, arm-completion.json, the image-specific unions and raw
display regions, and the fresh PIN image, adapter, compiler wrapper and independent
codec oracle. The firmware-inventory-reconciliation.json and
remaining-source-correspondence.json records retain the complete inventory and
the four later image reports, with their original source and dependency hashes.
The target-library-variant-review.json record and batches/rsa-target-wrapper
retain the separate ARM-only Rust wrapper measurement and cfg review.
Failed environment/build attempts remain separate from admitted
measurements. Completed Cargo caches may be removed after retaining depinfo;
raw records, source snapshots and loaded images remain.

The reviewed exceptions depend on today's producers, types, arithmetic bounds,
configuration and pinned expansions. A relevant source change reopens its
argument. The raw reports keep complete=false and structurallyComplete=false.
Compiler-native coverage, dependency internals, arbitrary future macro expansion,
general match/?/for branch coverage, timing/layout equivalence and physical-device
fault correspondence are separate obligations. The standalone rsk-wipe eraser
image and host-tool workspaces retain their separate scopes. No cross-profile or cross-image
vectors are used to manufacture a pair.
