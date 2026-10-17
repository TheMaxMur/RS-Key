<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Stateful USB oracle recorder

`oracle.py` records requests, responses, state observations, checks, and host
latency. It uses raw CTAPHID and OTP HID feature reports and recorded PC/SC APDU calls. Captures can
be inspected and compared offline. The scenario inventory is derived from
[oracle-plan.md](oracle-plan.md); a family link means a tested portion, never
completion of every variation in that family.

## Expand the catalog without devices

```sh
nix develop -c python tests/interop/oracle.py plan \
  --profile rsk --out /tmp/oracle-catalog.json
```

`plan` expands the normal suite dispatcher in memory. It does not enumerate,
open, query, reset, or capture a device. The JSON contains stable case IDs,
revisions, effects, family links, and unimplemented families. Algorithm expansion
lists potential cases; it is not evidence of support on an attached device.
Use `--suite` to inspect a subset or `--profile trezor` to inspect routing exclusions.

## Select a device

Run commands from the repository root in the pinned development environment:

```sh
nix develop -c python tests/interop/oracle.py list
```

Copy an exact `hid` ID and/or PC/SC reader name from this output. HID IDs bind
the current OS path and can change after replugging. A serial is accepted only
when it identifies exactly one enumerated FIDO interface. There is no implicit
first-device selection. Supplying both interfaces records the binding evidence;
it does not prove that two same-model devices are the same physical key.

`list` also exposes `otp_hid` selectors for known Yubico-compatible OTP
interfaces. Select one explicitly with `--otp-hid OTP_ID_FROM_LIST` to run OTP
fixtures over feature reports. Without it, OTP fixtures use the selected card
transport. There is no automatic retry on another interface after a refusal.
On macOS, feature access uses nonexclusive IOKit calls bound to the same registry
entry ID; other platforms use hidapi. Both run in a bounded worker process.

```sh
nix develop -c python tests/interop/oracle.py capture \
  --hid HID_ID_FROM_LIST --reader 'EXACT READER NAME' \
  --out /tmp/oracle-reference-001
```

The output directory must be new. Default runs omit fixture writes and operator
confirmation. Use `--suite fido`, `--suite oath`, etc. to narrow a run; the flag
can be repeated. Omit a transport when it is unavailable: dependent scenarios
report their precondition rather than opening another key.

## Exercise test applets

`--exercise` permits fixture writes. `--touch` declares that an operator can
confirm requests; it does not simulate presence on hardware. The runner prints
each interactive scenario to stderr. `--timeout` bounds each exchange, including
the operator's wait. The default is 15 seconds. `--samples` repeats suites in
the same session; these are stateful repetitions, not independent cold boots.

PIN changes, applet resets, and configuration changes additionally require their
respective `--allow-effect pin_change`, `--allow-effect applet_reset`, or
`--allow-effect config_change` flag. A broad suite selection does not grant
these permissions. The flags and declared case effects are retained in the
manifest and journal. The OATH reset case erases **all OATH state**; it does
not restore preexisting records, access codes, or OTP-PIN state.
OTP swap cases additionally require `--allow-effect otp_both_slots` and replace
then clear slots 1 and 2. RS-Key slots 3 and 4 require
`--allow-effect otp_extra_slots` and the explicitly selected card path. Their
previous secrets cannot be restored. Selecting an OTP feature interface never
silently falls back to the card path for these extra-slot cases.

Pass actual fixture secrets through environment variables. Values are never
guessed, and a refused PIN stops further attempts for that PIN domain in the
run. Do not paste secret values into a command argument:

```sh
nix develop -c python tests/interop/oracle.py capture \
  --hid HID_ID_FROM_LIST --reader 'EXACT READER NAME' \
  --out /tmp/oracle-reference-exercise-001 --exercise --touch \
  --pin-env ORACLE_FIDO_PIN --piv-pin-env ORACLE_PIV_PIN \
  --management-key-env ORACLE_PIV_MANAGEMENT_KEY_HEX \
  --openpgp-pin-env ORACLE_OPENPGP_PIN \
  --openpgp-admin-env ORACLE_OPENPGP_ADMIN \
  --oath-password-env ORACLE_OATH_PASSWORD
```

Only supply the flags needed for selected suites. An unset named environment
variable is an argument error; omitting the flag records a blocked precondition
when an authenticated scenario needs it. The PIV management key is hex. The
OATH password uses the applet's PBKDF2 derivation and mutual authentication.

These fixture effects are intentional:

- FIDO: sets the supplied PIN only when it is unset; creates wrapped credentials
  and, with PIN plus credential management, resident credentials that it deletes.
  Wrapped credential IDs and U2F handles remain usable and are retained privately.
- OATH: creates names in a seed-derived `oracle-…` namespace, verifies HOTP/TOTP,
  renames records, and deletes them. Existing fixture names block replacement.
- OTP: **replaces then clears slot 2** (`--otp-slot 1` selects slot 1). Its old
  secret cannot be restored. Fixtures use challenge-response, not keyboard typing.
- PIV: **replaces retired slot 82**, verifies its key operations, then deletes
  the key on profiles supporting DELETE KEY. On older profiles it records that
  the last fixture remains. Existing certificates are not restored or rewritten.
- OpenPGP: **replaces SIG, DEC and AUT keys**, checks their operations, then
  deletes the fixture keys. The SDK's deletion path restores RSA2048 attributes;
  it does not restore previous keys or attributes.
- `large-blobs`: replaces the shared serialized array, checks fragmented writes
  and rejection of a bad digest, then restores and verifies the original bytes.

Cleanup is itself recorded and timed. A transport deadline or disconnect makes
the session state unknown: subsequent operations and mutation retries stop.
An active HID request receives a recorded, best-effort CANCEL on close; sending
CANCEL does not establish whether an earlier write committed. Recovery requires
a new run and explicit readback, not automatic write replay.

Trezor devices are automatically bound to the `trezor` profile. This profile
opens the FIDO interface, permits standard CTAP/U2F requests, and refuses card,
vendor/wallet commands and host PIN changes. The detected wallet profile cannot
be overridden. No wallet management transport is opened. This is an accidental
command-routing guard, not a sandbox for arbitrary Python extensions.

## Implemented scenarios and remaining scope

| Suite | Current checks |
| --- | --- |
| `fido` | PING framing boundaries, getInfo, PIN retries/key agreement, malformed CBOR and missing-field refusals; optional PIN setup, wrapped/resident makeCredential and getAssertion for advertised algorithms with an available verifier, wrong RP/handle, counters, selection; credProtect level 1, credBlob, hmac-secret one/two salts and advertised PIN protocols, largeBlobKey, unknown extension |
| `credential-management` | Three resident fixtures over two RPs; metadata deltas, RP/credential walks and past-end refusals, update user, discoverable assertions/getNextAssertion, deletion and restored count |
| `large-blobs` | Read, multi-fragment write/readback, invalid digest, preservation after refusal, original array restoration |
| `u2f` | VERSION, REGISTER with attestation verification, check-only, enforced and non-enforced presence authentication with verified signatures |
| `select` | Known shared, RS-Key and additional device AIDs, retaining refusal statuses |
| `oath` | LIST and refusal probes; SHA1/SHA256/SHA512 TOTP with 6/8 digits, repeated/boundary challenges, full HMAC, CALCULATE ALL and continuation, RENAME/DELETE, sequential HOTP |
| `otp` | Status, serial/config reads; explicit card or OTP HID feature path, raw feature-report polling and CRC checks; HMAC-SHA1 variable/fixed-length challenges, access-code refusal followed by a valid control, AES challenge-response and deletion |
| `otp-states` | Bad config CRC with key-preservation witness, UPDATE with/without allow-update, original-key preservation and access-code change/removal, separately permitted empty/empty, empty/full and full/full swaps, RS-Key slots 3/4 and legacy-slot isolation |
| `piv` | Metadata, objects and parser refusals; import/generate P256, P384, RSA2048, Ed25519 and X25519 fixtures, signatures, RSA decryption, ECDH/X25519 and deletion where supported |
| `openpgp` | DO catalog, PIN-status queries and challenge lengths; P256 import/generate/read for SIG/DEC/AUT, independently checked signature/ECDH, signature-counter scope and fixture deletion |
| `management` | Shared config reads over CCID and profiled CTAPHID vendor command |
| `rsk` | Profile-restricted vendor/rescue identity, status, config, counter, LED, backup and attestation-state reads |
| `negative` | Required fields, wrong scalar/container types, clientDataHash lengths, malformed CBOR/APDU, invalid subcommands and options, selected combined defects; explicit valid control after each refusal |
| `oath-states` | Record preservation after refused PUT/RENAME/DELETE; binary/UTF-8/name boundaries, duplicate/reordered/unknown TLVs; increasing challenges; access-code set/change/restore, locked LIST, wrong proof and replay; separately permitted OATH reset |
| `fido-states` | PIN protocols 1/2 token MAC and permission controls, RP-walk restart/interruption/exhaustion, fragmented-blob offset/authentication faults with original-array restoration, separately permitted PIN change with existing-key signature and old-token invalidation |
| `card-states` | Same/different/invalid/prefix/suffix selection, cross-applet recovery, populated PIV key PIN policies and one-shot grant consumption, object length/chaining/rollback, OpenPGP PW1.81/PW1.82 isolation and counter scope, DO ACL and restoration, separately permitted PIN change/restore |
| `transport` | Invalid INIT lengths, malformed/absent/duplicate/reordered continuations, excessive declared length, exact HID errors, valid PING after each error, INIT resynchronization; raw faults excluded on Trezor |
| `management-states` | Invalid/read-only tags; set/change/clear config lock through each selected writer, then missing/wrong/short unlock through every selected writer; shared lock readback and unchanged configuration |
| `vendor` | RS-Key classical/hybrid MSE, decrypted export when unsealed, repeated/consumed-channel refusals, malformed MSE points/KEM, config identity rewrite/rejection/readback, audit window/chain and nonce-bound signature checks |

Unsupported algorithms, absent secrets, missing transports and mode exclusions
are separate from failed assertions. Successful cryptographic cases also require
that a damaged signature be rejected by the host verifier. Packed attestation
checks the statement signature using the leaf certificate or credential key;
this does **not** establish manufacturer trust or validate a certification chain.

The executable corpus remains smaller than the entire matrix. Coverage reports
retain `not_implemented` for unrepresented families. In particular, automatic
blocking/unblocking, PIV/OpenPGP/FIDO resets, bio enrollment,
capacity exhaustion, power-cycle fault injection, concurrent-CID/cancellation
experiments, OTP keyboard input-report capture, most vendor mutation workflows,
OnlyKey-specific commands and CanoKey administration/NDEF are not implemented.
PIN/PUK and reset-code lifecycle variants, persistent read-only tokens, optional
FIDO extension/build profiles, OpenPGP KDF/UIF/AES/certificate lifecycles, PIV
management-key replacement/attestation, seed replacement and recovery-mode
mutations also remain incomplete. Section 14's external vendor catalogs require
confirmed models and firmware; selecting their AID alone does not implement them.
Even a family with implemented cases is partial until its remaining variants
have evidence. Offline catalog expansion reports `implemented_not_run`, never
hardware verification or complete family coverage.
Hardware USB packet capture, internal applet calls and device CPU execution
traces are not observable through these adapters. PC/SC captures APDUs, not raw
CCID USB packets. None of the scenarios flashes firmware or writes OTP fuses.

## Artifacts and time measurements

The capture directory is mode `0700`; its files are `0600`. Raw traces can
contain PINs in APDUs, private fixture keys and reusable credential IDs. Keep
captures outside the repository. There is no sanitized share/export command yet.

| File | Content |
| --- | --- |
| `manifest.json` | Run UUID, profile, exact selectors, OS/clock, dependency versions, runner hash, seed, modes and explicit fixture effects |
| `events.jsonl` | Append-only source evidence: session/scenario events, durable exchange intent, raw I/O, response, decoded CBOR, checks, bindings, state transitions and final outcome |
| `results.json` | Derived exchanges, scenario verdicts, latency statistics and matrix coverage |

This is schema version 1 of the implementation; it is not a claim to implement
every optional field in the planning document. `inspect` and `compare` rebuild
results from the manifest and event log, ignoring a stale `results.json`.
An interrupted final line is reported; pending exchanges remain unfinished.
Earlier malformed complete records, changed request bytes, mismatched lengths,
duplicate exchange IDs and inconsistent timing are rejected.

Every exchange records an operation ID, sample, scenario, phase, session,
observation layer, request/response hex and lengths, execution/protocol outcomes,
status and timing. Setup, SDK chaining and cleanup requests are separate timed
exchanges. Decoding never replaces raw bytes. CBOR maps retain entry order and
duplicate keys in the decoded event; raw bytes retain noncanonical encodings.
Bytes, sets, nonfinite numbers and integers outside JSON's exact numeric range
have tagged representations. Unsupported decoding is an event, not missing raw
evidence. Bindings name generated handles and their producing exchange.
Witnessed transitions identify a triggering exchange and explicit witness IDs
from the same case. Inferred selection events remain distinguishable by their
`basis`. Scenario timing brackets the full operation separately from individual
transport API intervals; it includes checks, setup, cleanup, and host work.

All nanosecond timestamps are offsets from a host monotonic origin. Intent is
flushed before starting the measured call. I/O observations are buffered and
JSON serialization/fsync occur after the call. Per exchange:

- `api_duration_ns`: recorder call start to return/error. It includes Python,
  OS/transport scheduling, keepalives and human confirmation time.
- `response_latency_ns`: that duration when a response is obtained. It is null
  for deadlines, disconnects, host rejection and a send-only CANCEL.
- HID records `tx_complete_ns`, `first_rx_ns` (including keepalive),
  `first_final_rx_ns`, and `final_rx_ns`, plus every observed report.
- PC/SC records `backend_api_duration_ns` around `transmit()` inside an isolated
  worker. The outer duration also includes IPC. Killing a timed-out worker bounds
  host waiting; it does not prove that the device aborted the operation.
- TCP emulator timings describe the socket adapter, not physical USB.
- OTP HID captures each feature read/write and poll. Its backend duration covers
  the SDK protocol operation, including polling and worker instrumentation.

PC/SC and OTP feature calls are isolated so the parent can terminate a blocked
worker. Raw CTAPHID reads use bounded polls and check the deadline between
writes; a native HID driver blocked inside `write()` cannot be interrupted by
this adapter's Python deadline.

These are host response measurements, not device-only execution times. Grouped
statistics separate scenario, step, command, status, execution/protocol outcome
and observation layer. They report sample IDs, response and censored counts,
minimum, median and MAD. p95 requires 100 responses and p99 requires 1,000.
No-response timeouts never become zero-latency successes. Cold boots, physical
power cycles and the time of a physical touch are not inferred.

## Inspect and compare offline

```sh
nix develop -c python tests/interop/oracle.py inspect /tmp/oracle-reference-001
nix develop -c python tests/interop/oracle.py compare \
  /tmp/oracle-reference-001 /tmp/oracle-rsk-001 --out /tmp/oracle-diff.json
```

Comparison aligns scenario/sample and exchange order. It checks protocol status,
assertion names/verdicts, declared observations, counts and runner/fixture
provenance. Raw bytes remain available, while dynamic signatures/handles are
checked cryptographically rather than required to be byte-equal. Observations
explicitly marked `presence` compare availability; their values may differ.
Both-side mode/profile exclusions or confirmed unsupported scenarios are counted
as excluded. Other unexecuted or failed scenarios are not comparable; a run with
no matched executed scenarios cannot pass comparison.

Different captures commonly expose firmware/identity/capability differences.
Optional JSON rules are an array of objects with a narrow glob `path`, `mode`
(`ignore`, `presence`, or `tolerance`) and a nonempty `reason`. Numeric tolerance
also needs a finite nonnegative `absolute` bound. Rules are not applied to failed
cryptographic assertions. Do not suppress a whole response to hide a defect.

The comparison includes right/left median latency ratios and counts for matching
groups. `--max-slowdown 2` optionally fails on a ratio greater than 2. Without
that flag, time differences are descriptive. Compare manifests, sample state,
operator involvement and observation layers before interpreting a speed ratio.

Exit codes: capture/compare `0` means its requested checks passed, `1` indicates
failed checks or a non-comparable requested comparison, `2` indicates an argument
or runner failure, and `130` indicates interruption. Capture prints inconclusive
counts separately; exit `0` alone never certifies full matrix coverage.

## Emulator and extension scenarios

Start an isolated emulator using the invocation in
[tools/emu/README.md](../../tools/emu/README.md), then select its endpoints:

```sh
nix develop -c python tests/interop/oracle.py capture \
  --emu-hid 127.0.0.1:7799 --emu-card 127.0.0.1:7800 \
  --out /tmp/oracle-emulator-001 --suite fido
```

Hardware and emulator transports cannot be mixed in one run; socket failure
never falls back to USB. `--script PATH` additionally loads a trusted Python
file with `run(session)`. Use `session.case(name, families, effects, touch)`;
all device I/O must use `session.ctap`, `session.hid_call` or `session.apdu`.
Use `session.check`, `observe`, `bind`, `state` and deterministic `fixture`
values for predicates and references. This extension interface is trusted code
with the normal permissions of the Python process, not a restricted language.

```sh
nix develop -c python -m pytest tests/interop -q
```

The oracle tests use functional synthetic peers. Deliberate defects include accepted
bad MACs, permission/ACL/lock bypass, replay, partial writes on refusal, invalid
assembly error codes, reused MSE channels, a wrong hybrid KDF domain, and audit
signatures that omit the nonce. They do not establish that unrun physical-device
scenarios work, and no hardware/reference capture is needed to run them.
Refusal checks also reject an unrelated status as evidence: credential-ID tests
use otherwise valid authorization and require `NO_CREDENTIALS`; card ACL tests
submit valid object data and require the authentication status word.
