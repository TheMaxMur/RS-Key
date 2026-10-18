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
it does not cryptographically authenticate a device. Selected HID/card pairs
must expose matching protocol serials before any scenario runs. A mismatch
aborts capture. Reconnection checks that both serials retain the original
identity; a disappearing or ambiguous serial never selects a neighboring key.

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

Unsolicited keyboard reports need the separately selected `--keyboard-hid`
interface and `--operator`. The receiver records key reports and press edges
under a declared US layout. Gesture start and gesture-to-first-report latency
remain unknown unless independently observed.

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

Intentional failures require `--allow-effect pin_attempts`. Each such case names
its PIN domain and an explicit bounded attempt budget; default one-failure
stopping remains in force elsewhere. These cycles can block the reference and
recover it through its PUK, reset code or explicitly permitted factory reset.
Seed migration, organization identity replacement, reboot and capacity filling
respectively require `seed_change`, `replace_identity`, `reboot` and `capacity`.
Storage initialization/import requires `--allow-effect storage_setup` and
`--allow-effect reboot`, plus `--recovery-layout empty` or `legacy`. This names
an independently prepared recovery fixture; the recorder does not damage active
storage to manufacture one. Use `--suite rescue` for a recovery-only run. The
resulting active store is retained and the recovery fixture is consumed.
`rescue-recovery` runs the full recovery whitelist and refusal paths first in
the default catalog. For a dedicated prepared-media run, select
`--suite rescue-recovery --suite rescue` in that order. Its `occupied` profile
means surviving authenticated authority that blocks initialization/import;
`incompatible` means an authenticated authority/partition contradiction that
returns a storage error. Those negative profiles do not initialize the medium.
The public ready bit does not establish either layout or flash-image identity.
The manifest lists potential effects from the selected cases; the journal shows
which cases actually ran.

The semantic matrices are separately selectable: `pin-matrix`,
`pin-setup-matrix`, `credential-matrix`, `registration-matrix`, `token-matrix`,
`reset-tokens`, `blob-matrix`, `config-matrix`, `piv-matrix`, `piv-objects`,
`piv-pool-capacity`, `piv-moves`, `card-pin-matrix`, `openpgp-matrix`,
`openpgp-catalog`, `openpgp-catalog-reset`, `oath-semantics`, `oath-access`,
`oath-gates`, `vendor-matrix`, `management-matrix`, `otp-transport`,
`pcsc-sharing`, `u2f-semantics`, `cbor-matrix` and `cross-reset`. Additional
stateful suites include `info-matrix`, `uv-matrix`, `uv-block`, `reset-matrix`,
`selection-matrix`, `bio-matrix`, `cursor-matrix`, `store-state`,
`hid-operations`, `pinpad-matrix`, `pinpad-properties`, `pinpad-headless`,
`piv-escrow`, `piv-policies`, `oath-pin-matrix`, `oath-commands`,
`oath-rename`, `oath-presence`, `oath-challenges`, `oath-pages`,
`assertion-matrix`, `extension-matrix`, `piv-references`, `openpgp-mse`,
`openpgp-references`, `openpgp-recovery`, `openpgp-operations`,
`openpgp-decipher`, `openpgp-operation-state`, `openpgp-kdf`, `openpgp-uif`,
`openpgp-uif-fixed`, `openpgp-certificates`, `openpgp-aes`,
`openpgp-attestation` and `openpgp-reset-profile`.
OTP command expansion also includes `otp-commands`, `otp-swap`,
`otp-challenges`, `otp-lifetime`, `otp-waits`, `keyboard-matrix` and
`keyboard-counters`.
Their case effects still control execution independently of suite selection.
Quota measurements and reset/grant witnesses can reset the relevant applet;
cross-reset fixtures also replace PIV/OpenPGP/OTP keys and arm a known config
lock, prove private operations on each neighbor, then clear owned fixtures.
An existing unknown config lock blocks that fixture before replacement.

OpenPGP key fixtures read DO FA and use its actual attributes on RS-Key. The
raw APDU path includes advertised RSA-1024 even though yubikit's RSA enum omits
it, and preserves the advertised exponent width. A host SDK gate is never
recorded as an on-card rejection. Early inventory/selector/open failures have
their own journaled host-API cases. Raw OTP feature-report SET operations have
no invented device-response latency; subsequent GET reports retain their own
timestamps.

`--operator` permits physical replug and secure-entry instructions. A reported
replug is recorded as an interval with uncertainty, not an exact power-cut time.
`--feature` records known build features supplied by the operator, independently
of observed support. For example `preview-sign`, `largeblob-ext`, `bench`,
`strict-config` and `pin-complexity` describe different contracts.
`display` and `headless` are mutually exclusive positive build declarations.
Omitting `display` does not establish that a secure-entry device has no screen.
`phy-records` stages malformed/range-boundary records through rescue and restores
them before any reboot. When a numeric tag was absent, supply `--phy-defaults`
with a per-device JSON object of known boot-default wire values, for example
`{"04":"11","0c":"03"}` for an independently confirmed GPIO 17 / driver 3
profile. The runner never guesses an absent wiring default. Numeric tags have
no deletion API, so cleanup records any retained explicit default override;
existing fields are restored exactly. String clear uses a NUL value.
Local PIN-change cases verify the operator-reported replacement through a
read-only issuance before testing old grants. Pinpad cases stop on an
unexpected retry decrease and retain fixture state for explicit recovery.
The PW1-SIG pinpad fixture replaces the OpenPGP SIG key and temporarily enables
reusable signature-PIN mode; its additional `config_change` permission is
required and the original mode is restored during cleanup.

Pass actual fixture secrets through environment variables. Values are never
guessed, and a refused PIN stops further attempts for that PIN domain in the
run, outside explicitly permitted bounded failure cycles. Do not paste secret
values into a command argument:

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
Recovery cases also accept `--piv-puk-env`, `--oath-pin-env` and
`--openpgp-reset-code-env`; an empty reset-code value means known unset.

These fixture effects are intentional:

- FIDO: sets the supplied PIN only when it is unset; creates wrapped credentials
  and, with PIN plus credential management, resident credentials that it deletes.
  Wrapped credential IDs and U2F handles remain usable and are retained privately.
- OATH: creates names in a seed-derived `oracle-…` namespace, verifies HOTP/TOTP,
  renames records, and deletes them. Existing fixture names block replacement.
- OTP: **replaces then clears slot 2** (`--otp-slot 1` selects slot 1). Its old
  secret cannot be restored. Keyboard suites additionally type fixture data;
  swap and extra-slot cases have their own permissions.
- PIV: ordinary fixtures **replace retired slot 82**, verify its key operations, then delete
  the key on profiles supporting DELETE KEY. On older profiles it records that
  the last fixture remains. Existing certificates are not restored or rewritten.
- OpenPGP: **replaces SIG, DEC and AUT keys**, checks their operations, then
  deletes the fixture keys. RS-Key's recorded attribute transitions restore RSA2048;
  it does not restore previous keys or attributes.
- `large-blobs`: replaces the shared serialized array, checks fragmented writes
  and rejection of a bad digest, then restores and verifies the original bytes.
- `card-keys` expands PIV's 24 ordinary key slots, supported algorithms, origin,
  PIN and touch policies as a complete product; OpenPGP expands SIG/DEC/AUT,
  compatible algorithms, import/generate, MSE and UIF. It replaces previous
  private keys and cannot restore them. Fixed UIF cleanup resets OpenPGP.
- Lifecycle suites change retry policies, PINs, management keys, certificates,
  KDF and applet state. Resets retain the resulting factory store. FIDO reset
  can reprovision the supplied fixture PIN only after observing factory state.
  OpenPGP's write-only AES key remains installed. Scan-map cleanup installs the
  default US map because the previous map has no read API. RTC writes retain
  the selected test time. Seed cleanup restores exported seed bytes but cannot
  roll back credential-store state or a removed device certificate.
  Rescue certificate installation retains its fixture certificate because that
  record has no read/export command; the device public-key binding is checked.

Cleanup is itself recorded and timed. A transport deadline or disconnect makes
the session state unknown: subsequent operations and mutation retries stop.
An active HID request receives a recorded, best-effort CANCEL on close; sending
CANCEL does not establish whether an earlier write committed. Recovery requires
an explicitly declared recovery case and readback, or a new run. The lost-write
case interrupts response delivery, reconnects and distinguishes a complete old
value from a complete committed value before restoring it. It never replays
the uncertain mutation automatically.

Trezor devices are automatically bound to the `trezor` profile. This profile
opens the FIDO interface, permits standard CTAP/U2F requests, and refuses card,
vendor/wallet commands and host PIN changes. The detected wallet profile cannot
be overridden. No wallet management transport is opened. This is an accidental
command-routing guard, not a sandbox for arbitrary Python extensions.

## Executable scenarios and observation limits

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
| `fido-extensions`, `fido-lists` | credProtect levels and UV visibility; credBlob lengths/update preservation; hmac-secret-mc protocols/salts/invalid inputs; separate largeBlob extension; payment/uvm; algorithm preference and alternative identifiers; allow/exclude list size and matching-position boundaries; foreign ID lengths and options |
| `fido-sequences`, `fido-lifetimes` | Three independently signed resident assertions under one RP; complete/restarted/interrupted/expired cursors; token idle expiry, persistent read-only lifetime and replacement; 600-second absolute cap under periodic use |
| `fido-lifecycle`, `fido-reset-bio` | Persistent read-only mutation refusals, encrypted identifier/store-state decryption and changes; built-in UV and profiled preview commands; separately gated biometric enrollment/rename/removal and FIDO reset with old-credential invalidation |
| `fido-reconnect`, `enterprise-attestation` | Persistent read-only grants across USB rebinding/power cycle; enterprise enable/type 1/type 2, eligible/unrelated RPs and attestation-format preferences, fixture certificate and signature verification, identity removal and factory-policy cleanup |
| `fido-policy`, `fido-pin-cycles`, `preview-sign` | alwaysUv restoration; minPINLength/RP disclosure/complexity/force-change; temporary and permanent PIN blocking with power-cycle/reset recovery; previewSign signatures against independently derived ARKG keys and malformed parameters |
| `oath-records` | VERIFY CODE with counter witnesses; password/login/metadata boundaries and preservation; OTP-PIN set/change/verify/block/reset and missing-authorization controls |
| `piv-lifecycle`, `piv-moves`, `card-keys` | PUK unblock, retry totals, management-key algorithms/touch rotation and invalid-key controls; required reset preconditions; source/destination MOVE pairs and occupied/protected refusals; slot/algorithm/policy matrices, signatures, decryption, ECDH and attestation restricted to generated keys |
| `openpgp-lifecycle`, `openpgp-objects`, `card-chaining` | Reset-code/PW3 recovery; retry policies; certificate occurrence and GET NEXT walks; AES known answers, KDF enable/disable, terminate/activate; DO ACLs/lengths/readback/rollback through proper composite templates; valid and interrupted command chains |
| `hid-sequences`, `ccid`, `pcsc-sessions`, `connections` | Presence/cancel ownership, foreign CID busy and recovery, WINK/LOCK/expiry; raw emulator CCID power/slot/status/XfrBlock and native secure PIN entry; PC/SC transactions, dispositions and second client; explicit reset/reconnect/power actions and serial rebinding |
| `keyboard`, `otp-admin` | Yubico OTP decryption/CRC/counters, HOTP known answers, static text, CR and pacing; profiled admin-slot lengths, independent key preservation and scan-map effect on real input reports |
| `management-enforcement`, `cross` | Application bit combinations with actual dispatch and reachable restoration; service commands and lock persistence; populated cross-applet authorization, HID/card token/cursor/retry scope, lost-response readback, capacity neighbor and concurrent RSA/HID operation |
| `vendor-lifecycle`, `vendor-properties`, `rescue`, `u2f-matrix` | Seed LOAD/restore with old-key witnesses, finalize, soft lock and organization U2F identity; audit/config/counter/LED pairwise boundaries and measurement builds; device signatures, PHY/RTC, setup/refusal, reboot and safe fuse-selector refusals; U2F encodings and invalid-handle/parameter controls |
| `field-matrix` | Per-field and nested-field type defects for the profiled CTAP parsers, exact type errors, unchanged PIN retries and public state; stop on an unexpected result or state change; explicit CBOR null differs from an absent body |
| `transport-boundaries` | Scheduled continuation before/at/after the RS-Key assembly deadline, actual host write intervals, foreign-CID continuation isolation, post-completion unsolicited reports and valid recovery controls |
| `apdu-matrix` | Explicit short/extended APDU cases 1-4, Lc/Le and OpenPGP challenge bounds; complete, exhausted and interrupted GET RESPONSE chains with exact object preservation |
| `apdu-dispatch`, `pcsc-grants` | Every applet's full CLA byte range, raw empty CCID blocks, malformed Lc, unsupported INS and distinct chain/object ceilings; every protected PIV/OpenPGP/OATH grant subset across PC/SC transaction/reconnect dispositions |
| `fido-properties`, `fido-property-reconnect` | Unknown versus wrongly typed known extensions, absent/non-UV credBlob, independent per-credential HMAC secrets and malformed HMAC fields, largeBlobKey opt-in/update/reconnect stability and unsolicited-output refusal, resident/stateless counter semantics |
| `oath-matrix`, `oath-reconnect` | Initial HOTP moving-factor boundaries and counter preservation through malformed/bulk/repeated requests; increasing-mark equality/bulk/persistence; complete and interrupted LIST/CALCULATE ALL paging |
| `rescue-matrix` | Status selectors and their refusals, civil calendar normalization, weekday and leap-second behavior, epoch overflow, malformed-write preservation and unset clock after power loss |
| `info-matrix`, `store-state` | Discovery consistency and key-agreement lifetimes; encrypted identifier/store-state IVs, successful/refused mutations, deletion and reset transitions |
| `uv-matrix`, `uv-block` | Local permission bytes, signed provenance, MC/GA option products and extension-secret consistency; explicit local PIN change, shared retry budget, temporary/permanent blocks and reset recovery |
| `selection-matrix`, `reset-matrix`, `bio-matrix` | Confirmation/refusal/timeout/cancel/competition, reset window and display exemption, biometric sequence/authorization/duplicate/full-store cases with owned-template cleanup |
| `cursor-matrix`, `hid-operations` | Owned RP/credential/assertion walk counts, exact results, expiry, interruptions and CID ownership; outstanding INIT, reserved CIDs and processing/UP/final-response cancellation races |
| `pinpad-matrix`, `pinpad-properties`, `pinpad-headless` | Part 10 structures/properties, driver refusals, actual PIV/OpenPGP protected-operation grants, standing-grant preservation and raw Secure refusal without a display |
| `piv-escrow`, `piv-policies` | Management-key escrow opt-in/ACL/storage/rotation and immutable objects; slot/PIN/touch products with private operations after refusal, idle and connection actions |
| `piv-references` | Exact metadata/attestation references; binary PIN/PUK grammar, validation precedence and retained grants; retry-policy authorization/limits/cold-power persistence and blocked-PUK recovery; protected F9 identity and management-touch refusal |
| `openpgp-mse` | Both templates/references with distinct actual DEC/AUT private keys, independent signatures/ECDH, password/UIF policy ownership, malformed grammar, same/refused/different SELECT and connection lifetimes |
| `openpgp-references`, `openpgp-recovery` | Every PW reference, status/logout and CHANGE grammar; binary/byte-length boundaries, shared/independent retries and latches; reset-code grammar, blocked references and authenticated recovery; all reference budgets and retained keys across connection actions |
| `openpgp-operations`, `openpgp-decipher`, `openpgp-operation-state` | Raw RSA/EC/EdDSA inputs and independent signatures, one-shot and counter scope; RSA padding/integers/indicators and EC/X25519 point/TLV grammar; missing keys, operation parameters, counter persistence and SIG-only counter reset on import/generation |
| `openpgp-kdf` | Exact single/three-salt fixed layouts, opaque host metadata, incompatible old verifiers and reset-code retirement; rejection beside any owner key; KDF installed before key import retains private access across every connection action |
| `openpgp-uif`, `openpgp-uif-fixed`, `openpgp-attestation` | Disabled/enabled/permanent UIF, confirmation/decline/timeout, each password grant and one-shot boundary; generated/imported/empty subjects, class/body/reference precedence, issued certificates, preserved subject keys and counters; fixed policy cleanup requires applet reset |
| `openpgp-certificates`, `openpgp-aes`, `openpgp-reset-profile` | Exact certificate selection and walk grammar/lifetimes; AES known answers, key/block/ACL/UIF grammar and DEC/MSE independence; populated routed reset defaults, permanent UIF, blocked PW3 escape and terminated command/persistence gates |
| `assertion-matrix`, `extension-matrix` | getAssertion field presence, RP/hash/authorization boundaries and counter witnesses; payment/UV/output products, certificate format lists, largeBlob grammar/size/delete/replacement/connection lifetimes |
| `oath-pin-matrix` | Opaque/empty/binary PIN bytes, first-match TLV semantics and malformed-input grants, authorization retirement after PIN change, private record and access-code persistence across all connection actions |
| `oath-commands`, `oath-rename`, `oath-presence` | Known command CLA/P1/P2/grant combinations, rename TLV/name grammar with used HOTP/private-field preservation, CALCULATE/VERIFY CODE touch outcomes and code-less PIN-install consent |
| `oath-challenges`, `oath-pages` | Individual versus bulk challenge TLV grammars and byte bounds under both grants; exact page reconstruction, dispatch/refusal/mutation/SELECT retirement and HOTP/private-field preservation |
| `otp-commands`, `otp-swap` | Explicit CCID/feature routes; mode/flag products, exact status and HMAC/AES controls; CONFIGURE/UPDATE/DELETE lengths, CRC/RFU/access-code precedence and UPDATE masks; all offset swap pairs/layouts/code states with both identities checked |
| `otp-challenges`, `otp-lifetime`, `otp-waits` | Fixed versus variable padded challenge bounds, consent/refusal/timeout/panel cancel; binary access-code set/replacement/removal and connection persistence; raw UP-needed, owner abort, incomplete/bad-CRC incoming frames and complete command supersession |
| `keyboard-matrix` | Every RS-Key slot's raw static material, modifiers, shifted punctuation, TAB/CR, length/fixed-size/flag products, empty output and release reports; exact key presses and observed report intervals, without inferred physical gesture timestamps |
| `keyboard-counters` | HOTP initial/moving-factor boundaries, Yubico private block/CRC/use/session positions, connection persistence, successful/refused UPDATE/CONFIGURE/DELETE, swaps with unequal histories, partial observation followed by connection action and every position through the 8-bit Yubico session wrap |
| `otp-disabled`, `otp-admin-matrix` | Immediate disabled dispatch, live identify/re-enable routes, cached feature status, silent gestures with unchanged HOTP counters; global admin-code/length/strict-build behavior and scan-map output/persistence in each slot |
| `management-state` | Identical locked writes and real mutation controls under every owner/writer/code combination; confirmation/refusal, strict-build disabled writers and witnessed cleanup |
| `config-factory` | Unset-PIN configuration authorization, protocol/authentication presence and width products, preserved policy and private credential, with witnessed factory reset and known-PIN recovery |
| `phy-records` | Every PHY field's one-byte TLV overlay, widths/values/strings/duplicates/truncation, complete stored-value controls and retained device-key signatures; explicit restoration defaults for previously absent numeric fields |
| `phy-persistence`, `rescue-presence`, `rescue-recovery`, `rescue-reboot` | Persisted PHY and device-key controls; shared-lock and consent/grammar refusal; prepared recovery whitelist and distinct administration refusals; native ACK-before-disconnect observations with exact rebinding |
| `vendor-measurements` | Shipping exclusions versus explicit measurement profiles, complete selector/body/warmup/pattern bounds, device-timer layouts and declared divisors; always restart an acknowledged measurement sweep stop |

OTP-HID always supplies a 64-byte command body. The current RS-Key SWAP parser
accepts only 0/2/6/8-byte bodies, so that route is expected to refuse SWAP;
the CCID layouts are checked separately. A missing OTP slot answers CCID
`9000` with an empty body, while the feature protocol reports `No data`.
An occupied-slot program-sequence wrap from 255 to 0 can also make the SDK
report `No data` after a committed write. The cases distinguish that outcome
with status and private-operation readback. Feature DeviceInfo/extended-status
reads validate CRC and padding before parsing their payloads.

Unsupported algorithms, absent secrets, missing transports and mode exclusions
are separate from failed assertions. Successful cryptographic cases also require
that a damaged signature be rejected by the host verifier. Packed attestation
checks the statement signature using the leaf certificate or credential key;
this does **not** establish manufacturer trust or validate a certification chain.

The offline catalog represents all 182 numbered families in the matrix. Case
IDs, effects, explicit parameters and generation methods are recorded. The PIV
matrix uses the slot/algorithm/origin/PIN/touch product; LED variations use a
bounded seeded pairwise covering array. These
finite expansions do not establish every possible input/history combination.
`plan --seed VALUE` makes the generated portion reproducible and opens no device.

Scenario contract revision 3 identifies the expanded semantic controls and
corrected fixture behavior. Comparisons reject differing scenario revisions,
parameters or generation methods and omit their timing ratios. Original raw
captures remain intact; a contract change needs a fresh run for comparison.

Family reports distinguish `implemented_not_run`, `partially_exercised`, blocked
or unimplemented families. They never infer complete coverage from a family tag
or a successful selection. The [requirement audit](oracle-plan.md#requirement-audit-2026-10-18)
records implementation clauses separately. Any unchecked clause produces
`matrix_completion: incomplete` and `unresolved_requirements`, even when
`unimplemented_families` is empty;
`variant_coverage` is never promoted to complete by catalog membership. The
bounded implementation audit is closed; `not_certified` still distinguishes
unperformed physical execution and reference verification from implementation.
Section 14's OnlyKey, CanoKey and other external vendor catalogs remain unknown
until model and firmware are identified; shared FIDO/card cases do not substitute
for those vendor workflows. Wallet operations remain outside the Trezor profile.

Idle tests require a sufficiently large `--timeout`: above 31 seconds for the
30-second windows and above 601 seconds for the absolute token cap. Physical
power actions, keyboard gestures and pinpad cases require their explicit modes.
Unavailable raw CCID/USB actions cannot be inferred from a PC/SC APDU result.
PC/SC transaction/busy results belong to the driver layer. A secondary-client
deadline is retained as such and does not establish a firmware rejection.
Hardware USB packet capture, internal applet calls and device CPU execution
traces are not observable through these adapters. PC/SC captures APDUs, not raw
CCID USB packets. None of the scenarios flashes firmware or writes OTP fuses.

## Artifacts and time measurements

The capture directory is mode `0700`; its files are `0600`. Raw traces can
contain PINs in APDUs, private fixture keys and reusable credential IDs. Keep
captures outside the repository. There is no sanitized share/export command yet.

| File | Content |
| --- | --- |
| `manifest.json` | Run UUID, profile, exact selectors, OS/clock, dependency versions, runner/input-corpus hashes, seed, modes and potential fixture effects |
| `events.jsonl` | Append-only source evidence: session/scenario events, durable exchange intent, raw I/O, response, decoded CBOR, checks, bindings, state transitions and final outcome |
| `results.json` | Derived exchanges, scenario verdicts, latency statistics and matrix coverage |

This is schema version 1 of the implementation; it is not a claim to implement
every optional field in the planning document. `inspect` and `compare` rebuild
results from the manifest and event log, ignoring a stale `results.json`.
An interrupted final line is reported; pending exchanges remain unfinished.
Earlier malformed complete records, changed request bytes, mismatched lengths,
duplicate exchange IDs and inconsistent timing are rejected.

APDU `61xx` is `response_continuation`, distinct from `applet_error`. A pending
tail must not satisfy a refusal check. Existing captures retain their original
classification; the comparator reports the difference and the runner hash.
Idle HID observations have no fabricated request or response latency. Scheduled
HID tests retain each host write's start/end and requested delay; these are
host-side intervals, not device arrival timestamps.

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
JSON serialization/fsync occur after that exchange's call. Scheduled overlap
can invoke a nested recorded exchange from a keepalive or backend-start hook;
the outer interval then includes that nested call and its journal overhead.
`capture_detail_mode` records this buffering policy. Each exchange has a
separate `exchange_capture_overhead` event with monotonic start/end/duration
for request and response journaling, including their fsync, and an estimate of
runner observer-callback time inside the API. The overhead event's own write
and flush are excluded from its measurement. Child-process/driver overhead
is not separately observable. Recovery validates these intervals and attaches
them to the exchange; none is subtracted to invent device-only compute time.
Per exchange:

- `api_duration_ns`: recorder call start to return/error. It includes Python,
  OS/transport scheduling, keepalives and human confirmation time.
- `response_latency_ns`: that duration when a response is obtained. It is null
  for deadlines, disconnects, host rejection and a send-only CANCEL.
- HID records `tx_complete_ns`, `first_rx_ns` (including keepalive),
  `first_final_rx_ns`, and `final_rx_ns`, plus every observed report and the
  keepalive status/timestamp timeline.
- PC/SC records `backend_api_duration_ns` around `transmit()` inside an isolated
  worker. The outer duration also includes IPC. Killing a timed-out worker bounds
  host waiting; it does not prove that the device aborted the operation.
- TCP emulator timings describe the socket adapter, not physical USB.
- OTP HID captures each feature read/write and poll. Its backend duration covers
  the SDK protocol operation, including polling and worker instrumentation.
- Keyboard events have no synthetic host exchange. They record first/last report
  and output duration; unobserved gesture latency stays null. Host wait and
  connection-control intervals are separate from authenticator execution time.

PC/SC and OTP feature calls are isolated so the parent can terminate a blocked
worker. Raw CTAPHID reads use bounded polls and check the deadline between
writes; a native HID driver blocked inside `write()` cannot be interrupted by
this adapter's Python deadline.

These are host response measurements, not device-only execution times. Grouped
statistics separate scenario, step, command, status, execution/protocol outcome
and observation layer. They report sample IDs, response and censored counts,
minimum, median and MAD. p95 requires 100 responses and p99 requires 1,000.
`--warmups N` adds N full fixture cycles before `--samples N` measured cycles;
all raw events remain saved with their role. Statistics separate warmup and
measured samples and first-session versus subsequent requests. Reconnect,
card-reset, operator-reported power and emulator-power boundaries are distinct;
an operator report cannot establish an actual physical cold-boot timestamp.
Each scenario reruns its setup/cleanup; global counters, write-only defaults and
irreversible policy changes retain their observed state effects. Select those
operations individually when repeated cycles cannot establish matched state.
Comparison omits warmup ratios and rejects known mismatched host/backend,
fixture, sampling and result contexts.
No-response timeouts never become zero-latency successes. Cold boots, physical
power cycles and the time of a physical touch are not inferred.

## Inspect and compare offline

`usb-identity` is a separate native transition suite. It needs the exact native
CCID and FIDO HID selectors of one serial-bearing RS-Key, an unlocked shared
configuration, an unwrapped seed, FIDO enabled and an ordinary UV policy. Run
it without OTP/keyboard handles: it owns rebuilding its selected transports
across all 256 mask bytes and both rescue-staged and FIDO auto-reboot paths.
The operating system must leave native CCID access available for the tested
identities; the adapter never detaches a driver or resets USB configuration.

Every target is declared before writing. The runner checks descriptor classes,
interface order and HID usages, observes removal after the acknowledgment and
rebinds only the unique declared VID/PID/serial/string state. A fresh private-key
challenge proves continuity before the new endpoint can receive PIN material
or a restoration write. It checks VID-dependent ATR/OpenPGP manufacturer and
stable OpenPGP serial/version, restores complete PHY/USB state through whichever
FIDO or CCID path remains, and stops after unverified restoration. If a numeric
VID/PID or mask override was originally absent, the protocol cannot delete it;
its observed baseline/default remains explicitly stored and is reported.
Enumeration is a host API observation, not a claim to capture every USB packet
the operating system used during discovery.

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

The remaining vendor matrices have separate suites: `config-grammar` MACs the
original nested CBOR bytes; `config-vendor` stages numeric PHY vendor IDs without
booting them; `mse-lifetimes` exercises consuming versus parser-refused requests
on owner/foreign CIDs and both FIDO routes. `vendor-records` compares raw LED
records with normalized live values and checks default/strict configuration
gates. `vendor-counter` records shared persistent increments and uncertain
response recovery without replay. `audit-access` checks journal authorization,
nonce-bound checkpoint signatures and persistent opt-in/history.

`identity-chain` uses populated organization keys to distinguish DER framing,
PIN authorization and scalar errors, and witnesses the exact configured leaf
and signer through U2F. The current import checks sequence framing rather than
X.509 semantics or scalar/leaf coherence. Accepted mismatches and opaque framed
bytes are reported explicitly; they are not treated as valid trusted chains.

`seed-matrix` expands host authorization and actual AEAD/scalar/length failures,
the independent named PIN-less LOAD confirmations and the FIPS import-only
policy. Its FIPS witness verifies the rebuilt certificate and actual attestation
signature against the imported scalar; it retains that known fixture seed because
the original cannot be exported. `seed-lifetimes` separates stored lock/seal state
from RAM unlock and channel ownership over SELECT, session/card/USB connection
changes, observed warm reboot and physical power cycle. It verifies the exact
loaded seed and old/new private credentials, then restores its known seed.
FINALIZE recovery uses a real FIDO reset and reprovisions the supplied host PIN;
other FIDO reset-owned records stay reset. `identity-reset` provisions an absent
organization fixture around the ordinary applet reset handlers and requires the
completed reset exchange before verifying its retained private signing identity.

`cross-walks` starts populated RP, credential and assertion continuations in both
HID/CCID directions under both protocols. A foreign continuation cannot consume
the owner's walk, while the device-wide read-only token remains usable on both
routes. `cross-processing` sends PIV/OpenPGP/OATH requests after actual PROCESSING
KEEPALIVEs during ML-DSA-44/65/87 creation and assertion and verifies both results.
This schedules overlap from host observations; nested API time includes callback
work and does not reveal parallel device execution or its exact completion time.

`numeric-matrix` rejects signed and overflowing values at every declared integer
reader, including signed COSE algorithm overflow. `cbor-matrix` walks every byte
truncation and nested integer/length/map/UTF-8 encoding variant. Its generic
semantic templates require a known configured host PIN; PIN-less controls live
in their explicit owning suites. Invalid vendor target templates prevent a
permissive PHY write or audit policy change from becoming a parser baseline.

The enterprise suite covers both protocols' vendor RP-list count and raw-byte
limits, replacement/empty/duplicate lists, Unicode/NUL strings, rejected MACs
and connection persistence through actual attestation signatures. CONFIG may
hash an RP string that makeCredential separately refuses by length/grammar;
that acknowledged write is not presented as direct readback of an unreachable
hash. Positive CONFIG fixtures require a known configured host PIN.

RS-Key's separate display PIN is not the clientPIN/UV reference advertised by
getInfo. `--device-pin-state set|unset` records a known fixture precondition; it
is not inferred from `clientPin: false` or `uv: false`. An unknown state keeps
the local-entry attempt guard conservative. `vendor-local-pin` needs the `set`
profile without a host PIN, explicit display/headless availability, controlled
operator input and a bounded PIN-attempt effect. Its public controls verify the
host PIN's separate retry record; the device PIN's private retry count is not
exported over CTAP. Existing host Rust tests check that private counter. Audit
PIN-unset consent cases require the `unset` profile. Neither declaration
authorizes changing a PIN, and no wallet interface is used.

Start an isolated emulator using the invocation in
[tools/emu/README.md](../../tools/emu/README.md), then select its endpoints:

```sh
nix develop -c python tests/interop/oracle.py capture \
  --emu-hid 127.0.0.1:7799 --emu-card 127.0.0.1:7800 \
  --out /tmp/oracle-emulator-001 --suite fido
```

Hardware and emulator transports cannot be mixed in one run; socket failure
never falls back to USB. `--script PATH` additionally loads a trusted Python
file with `run(session)` and optional `configure(session)`. Setup runs once
after interface binding and before samples; `run` follows each sample's suites.
Trezor profiles reject extension scripts before loading their code or opening
an interface. Use `session.case(name, families, effects, touch)`;
all device I/O must use `session.ctap`, `session.hid_call` or `session.apdu`.
Use `session.check`, `observe`, `bind`, `state` and deterministic `fixture`
values for predicates and references. This extension interface is trusted code
with the normal permissions of the Python process, not a restricted language.

`button-gestures` needs `configure(session)` to attach an identified external
sensor/actuator adapter as `session.button_stimulus`. The runner does not assume
a GPIO controller or manufacture physical input from a software keyboard.
The adapter contract is:

| Operation | Required behavior |
|---|---|
| `describe()` | Pure metadata: `source` is `electrical_sensor` or `device_samples`, nonempty `instrument_id`, `host_clock: trace.monotonic_origin`, and calibrated `schedule_tolerance_ns` in 0..100,000,000 |
| `start(edges, start_ns, deadline_ns)` | Arm asynchronously; `edges` contains `(offset_ms, pressed)` pairs; return a job without waiting for all edges |
| `job.wait_edge(ordinal, deadline_ns)` | Wait for the numbered observed sensor edge, rather than a controller ACK |
| `job.release(deadline_ns)` | Request release of an open-ended held press |
| `job.finish(deadline_ns)` | Return actual input evidence by the deadline: `source`, observed `initial_pressed`/`final_pressed`, and ordered `edges` with `pressed`, `lower_ns`, `upper_ns` against the trace origin |
| `job.cancel()` / adapter `close()` | Stop pending schedules and release the actuator; safe to repeat; close runs before device interfaces close |

Exact boundary evidence additionally supplies `sampled_edge_ms`: actual
monotonic device-sample times corresponding to the observed edges. Their clock
is separate from host time and is never subtracted from USB timestamps. A rig
without that evidence still captures the 999/1000/1001-ms electrical cases,
checks the bounded possible slot outputs and reports exact sampling as
inconclusive. Requested edge times and API returns never become sensor times.
Long click-count cases need a timeout over their full schedule (up to about
54 seconds). Each case owns four confirmed-empty OTP slots and cleans them up;
it requires both OTP slot effects, operator availability and explicit keyboard
selection. Keyboard capture runs independently throughout busy/presence tests;
trace writing stays on the runner thread. It measures host observation times,
with source intervals retained, rather than claiming device emission instants.

```sh
nix develop -c python -m pytest tests/interop -q
```

The oracle tests use functional synthetic peers. Deliberate defects include accepted
bad MACs, permission/ACL/lock bypass, replay, partial writes on refusal, invalid
assembly error codes, reused MSE channels, a wrong hybrid KDF domain, audit
signatures that omit the nonce, seed-load no-ops, old credentials surviving seed
replacement, broken certificate cursors, wrong AES keys, unexpected PIN unblock,
expired read-only tokens and duplicate assertion continuations. The binding
tests reject mixed interfaces, changed serials and ambiguous replug candidates;
reset-scope tests detect deletion of neighboring public state. They do not
establish that unrun physical-device
scenarios work, and no hardware/reference capture is needed to run them.
Refusal checks also reject an unrelated status as evidence: credential-ID tests
use otherwise valid authorization and require `NO_CREDENTIALS`; card ACL tests
submit valid object data and require the authentication status word.

`extended-lifetimes` enumerates every PIV PIN/management, OpenPGP PW81/PW82/PW83
and OATH code/PIN grant subset across same/different/invalid SELECT, native USB
bus reset and CPU warm reboot. The native path needs positively matched FIDO
and CCID USB serials and no other open interface handles. It sends warm reboot
through the independent HID MSG selection, observes actual disconnect, reopens
the exact interfaces and proves the retained private credential with a fresh
nonce before any PIN/configuration request. No card SELECT is inserted before
grant measurement. USB reset/reopen includes ICC power-on; this records the
whole observable boundary, not an isolated device-internal reset instant.
`config-lifetimes` separately owns a disabled OATH mask, changed flags and a
known shared lock through every enabled writer and all nine connection/SELECT
boundaries; it verifies all selected readers and actual dispatch enforcement.

`cross-walks` crosses both route directions, both PIN protocols, ordinary and
persistent tokens, all three populated walks and same/different/invalid card
selection. `cross-presence` checks every supported foreign cancel-scope pair
among FIDO, CCID and OTP HID, with four CCID applet owners. Injections follow
actual UP-needed, OTP pending reports or CCID time extensions while the
operator withholds input. Each owner then has its own cancellation or separate
confirmation and private/counter control. Time-extension callbacks are host
scheduling boundaries, not exact device presence-start or CPU-overlap times.

`unknown-slots`, `unknown-secrets`, `unknown-fido` and `unknown-admin` complement
`uncertain-writes` and `vendor-uncertain`: every injected mutation is sent once,
then explicitly read back before known-state recovery. Whole slot/configuration
and private-key observations distinguish complete old/new states from partial
results. Bounded old/new PIN candidates require an available recovery retry;
PUK's missing VERIFY API is recorded and uses explicit CHANGE-to-original
recovery, which differs from the lost CHANGE-to-new request. A failed readback
or private control halts subsequent requests and cleanup rather than guessing
which secret/configuration is current. Opaque device certificates, NDEF and
legacy-mode records without export/effect stay unknown after neighbor controls.
SELECT resets the OTP program sequence, so it cannot prove durable commitment.
Scan-map output proves the effective digits that were observed, not unused
write-only entries; prior custom maps/certificates cannot be exported/restored.

`cm-matrix` starts every subcommand with owned resident keys and correctly
scoped authorization. It tests mandatory/empty/extra fields, both protocols,
MAC widths, ordinary/persistent/revoked/expired grants, RP/hash/reference/user
bounds, exact raw subparameter limits and name/display-name UTF-8 truncation.
Next requests start from real two-row cursors; typed protocol overflow is still
a parser failure, while supported-width protocol/MAC values are ignored by
Next as the profile defines. Refusals preserve exact resident users, private
keys and retry counts. This suite needs an initially empty resident fixture
store and a timeout above 31 seconds for the idle-expiry rows.

`foreign-references` never opens a source device. Supply `--foreign-references`
with a JSON array of at most 32 previously captured public proof objects.
Every object has `kind` (`fido2` or `u2f`), `source_serial`, and `seed_relation`
(`distinct`, `same` or `unknown`). FIDO2 adds `rp` and hexadecimal
`credential_id`, `cose_key` (CBOR), `auth_data`, `client_hash` and `signature`
from a registration and successful assertion. U2F adds hexadecimal `handle`,
`application`, `challenge`, `public_key` (uncompressed P-256), `auth_head`
(flags plus counter) and `signature`. The bundle is bounded and its private-key
possession signatures are verified before device discovery. USB serial and
opaque ID pairing remain supplied capture metadata, not claims that an
assertion cryptographically attests those fields. The target serial must be
observed and different. Declared distinct identities must reject the reference;
same/unknown seed relations record portability and verify the original key if
the target accepts it. Missing source proofs remain a named fixture
precondition for a later capture, not an invented second-device observation.

`unknown-resets` adds whole applet reset/TERMINATE/ACTIVATE response loss with
private neighbor, old-key/grant and factory-state witnesses. `unknown-boot`
records prepared storage setup and rescue/vendor reboot losses. Readiness does
not prove an entire storage migration, and rebinding after a lost reboot ACK
does not prove a CPU/BOOTSEL transition. Those outcomes stay unknown. Reboot
recovery verifies the original private FIDO credential before PIN/config use;
an unknown setup or reboot is never automatically repeated.

`oath-sequences` generates 16 seed-derived histories of 12 typed steps (PUT,
CALCULATE, DELETE, SELECT, parser refusal), choosing only valid state
transitions. Each history starts with absent owned names, preserves all
preexisting records, and checks the exact names, independent neighboring HMAC
and HOTP moving factor after every step. Its recipe and step events are saved.
Single-defect command matrices remain separate from this bounded generation.

`minimize CAPTURE --scenario ID --factory offline.py --out DIRECTORY` reduces
a saved `oath-v1` recipe without discovering devices or replaying raw requests.
Use `--sample INDEX` when the selected scenario failed in several invocations.
The explicitly trusted Python factory exports `make_session(trace, seed)` and
returns a new RS-Key Session with only a synthetic `offline=True` or emulator
card backend for each trial. Factory code executes with ordinary Python
permissions; its offline declaration is the adapter author's contract, not a
sandbox. Physical adapters and wallet profiles are excluded before replay;
wallet source captures are rejected before loading the factory. Each trial
reconstructs the named fixture and authenticated operations from the recipe.
All trial traces, the original source hash/seed, factory hash and shortened
recipe are retained. Only the original failed assertion, triggering action and
protocol evidence count as reproduction; arbitrary failures do not. The final
recipe is confirmed twice in fresh sessions. The report distinguishes a
bounded result from one whose valid single-step deletions have all been tried;
it does not claim a globally shortest history. Default trial budget is 128.
