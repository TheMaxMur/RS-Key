<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# USB applet oracle scenario matrix and trace format

Status: scenario contract, 2026-10-17. The executable catalog represents every
numbered family; its bounded expansions and observation limits are documented
in [oracle.md](oracle.md). Catalog presence does not establish device coverage
or measurement of every variation below. The requirement audit below records
implementation gaps independently of family presence.

The oracle runs stateful scenarios against physical reference keys and
RS-Key, records every observable request and response with timing, and compares
their behavior. Recorded reference runs must also support later comparisons
without the reference device attached.

The RS-Key scope follows the current [host protocol](../../docs/protocol.md)
and [architecture](../../docs/architecture.md). The existing
[interop harness](README.md) provides capability snapshots, comparison rules,
and a frozen YubiKey baseline. The additional `oracle.py` recorder expands
executable scenarios from the contract specified here.

External devices need profiles keyed by manufacturer, model, firmware, and
available interfaces. A device family name alone does not establish support.
The exact external-device inventory remains to be supplied before captures.

## 1. Scope and scenario contract

Capture externally observable behavior: requests, responses, intermediate
messages, latency, and observable state changes. Ordinary USB access cannot
trace internal firmware function calls on a closed reference device.

Each matrix row below is a scenario family. Expand it into concrete cases with
explicit inputs and preconditions. A rejection column identifies inputs to
investigate; it does not invent a reference device's actual status word.
Keep the specification expectation and measured reference outcome separate.

| Scenario field | Required contents |
|---|---|
| Identity | Stable case ID, case revision, and matrix family ID |
| Applicability | Protocol, device profile, and required capabilities |
| Initial state | Required records, keys, PINs, policies, and objects |
| Setup | Exact sequence establishing the initial state |
| Inputs | Fixed values, boundary values, or a generator with a recorded seed |
| Steps | Requests, waits, operator actions, and connection changes |
| Checks | Responses, cryptography, side effects, and subsequent usability |
| Cleanup | What to remove or restore, and what cannot be restored |
| Effects | Writes, PIN-attempt consumption, reset, identity replacement, power interruption |
| Repetition | How each sample obtains a comparable initial state |

Authentication rejection tests require an existing object and otherwise valid
inputs. A signing attempt against an empty slot cannot establish whether an
authentication guard ran.

The logger must not issue hidden diagnostic requests. In current RS-Key,
`getInfo` can retire an active credential enumeration. State observations are
explicit scenario steps placed where their effects are permitted.

Model state as independent components rather than one global status string:

| Component | States or properties to distinguish |
|---|---|
| Connection | Detached, enumerated, open session, reset, reconnected; transport and session identity |
| Selection | No applet, selected applet, failed selection, same-app reselect, different-app select |
| Authentication | Unauthenticated, authenticated, one-shot grant, cached grant, revoked, expired |
| PIN | Unset, set, change required, temporarily blocked, permanently blocked; retries remaining |
| Token | Protocol, permissions, RP binding, lifetime, ordinary or persistent read-only |
| Objects | Absent, present, replaced, deleted; origin, algorithm, policy, occupancy |
| Sequence | Idle, request assembling, awaiting continuation, awaiting presence, cancelled, expired |
| Lifecycle | Active, terminated, recovery required, reset in progress |

For each concrete transition record the established precondition, triggering
step, expected postcondition, observed postcondition, and evidence step IDs.
Unknown internal state stays unknown; a host observation does not expose a
complete device-state snapshot.

## 2. Common input matrix

Apply each relevant dimension to every command and subcommand.

| ID | Dimension | Required variants |
|---|---|---|
| G01 | Field presence | Absent, empty, valid, extra |
| G02 | Type | Correct type, another format-valid type, null, container instead of scalar |
| G03 | Length | 0, 1, minimum minus one, minimum, minimum plus one, maximum minus one, maximum, maximum plus one |
| G04 | Numeric value | Zero, valid boundaries, reserved values, negative instead of unsigned, overflow |
| G05 | Encoding | Valid, truncated, incorrect declared length, trailing bytes |
| G06 | CBOR | Key order and duplicates, unknown keys, non-shortest integers, indefinite lengths, multiple top-level items |
| G07 | TLV | Unknown and duplicate tags, reordered tags, nesting, incorrect length, alternative length encodings |
| G08 | Strings | ASCII, multibyte UTF-8, invalid UTF-8, NUL, byte and code-point boundaries |
| G09 | Object reference | Existing, absent, deleted, replaced, from another device or applet |
| G10 | Authorization | Missing, valid, invalid, revoked, expired, wrong permission |
| G11 | Repetition | Identical request, repeat after success, rejection, or lost response |
| G12 | Interruption | Cancel, deadline, connection close, reconnect, incomplete transfer |
| G13 | Multiple defects | Each defect alone, then together to measure validation precedence |
| G14 | Recovery after rejection | Valid control request; check data, counters, authorization, and pending sequences |

Require all listed single-defect cases, defined state transitions, and explicitly
selected interacting defects. Use pairwise combinations and seeded sequence
generation for the remaining combinations. Record the coverage method and
generation bounds. Do not describe this finite matrix as exhaustive coverage
of every possible input or history.

Malformed command probes must belong to a known protocol profile. Blindly
sweeping instruction bytes on an unidentified vendor applet is outside this
plan's ordinary capture mode.

## 3. Transport matrix

Transport failures and applet rejections are separate observations.

| ID | Surface | Successful cases | Rejections and transitions |
|---|---|---|---|
| T01 | USB discovery | Enumerate interfaces and endpoints; open the intended physical instance | Two identical keys, claimed interface, disappearance, reappearance |
| T02 | CTAPHID INIT | Allocate CID; resynchronize | Invalid length or nonce, unknown CID, INIT during an operation |
| T03 | CTAPHID PING | Empty, single-frame, multi-frame, maximum-size echo | Oversize message, inconsistent declared length |
| T04 | CTAPHID assembly | Every initial and continuation frame boundary | Missing, duplicated, reordered frames; incorrect sequence; different CID mid-message |
| T05 | Assembly timeout | Completion before the boundary | Completion at or after the boundary; a valid request after timeout |
| T06 | KEEPALIVE | All status changes and intervals | Missing events, status transitions, events after completion |
| T07 | CANCEL | Cancel an outstanding operation | Before a request, during processing, after completion, from another CID |
| T08 | CID concurrency | Sequential and overlapping requests | Busy behavior, foreign cancellation, continuation of another CID's sequence |
| T09 | WINK and LOCK | Supported operations | Unknown parameters, lock expiry, another CID |
| T10 | CCID | Power on/off, ATR, status, XfrBlock, time extensions | Invalid slot, sequence or length; abort; removal during a request |
| T11 | APDU | Cases 1-4, short and extended encodings, Le variants | Truncated header, inconsistent Lc, unsupported CLA or INS |
| T12 | Command chaining | Complete a valid chain | Different INS, P1, P2 or AID mid-chain; overflow; abandoned chain |
| T13 | Response chaining | Complete GET RESPONSE or protocol-specific continuation | No pending response, repeat final continuation, intervening command |
| T14 | PC/SC session | Connect, transaction, reconnect, disconnect | Different dispositions, second client, reader busy, card reset |
| T15 | OTP HID | Feature reports, polling, response retrieval | CRC, sequence, missing reports, busy, cancellation |
| T16 | Secure PIN entry | Supported pinpad operations | Invalid structures or lengths, operator refusal, timeout, unavailable display |

Each capture declares its observation layer: `pcsc_apdu`, `hid_report`,
`ccid_message`, or `usb_transfer`. A PC/SC APDU capture does not establish the
contents or timing of all underlying CCID messages or USB transfers. Record
backend limitations, hidden retry behavior, and whether lower-layer events
are observable. A request refused by an SDK or driver before transmission
does not establish a device rejection.

## 4. FIDO2 commands

Select the applicable CTAP version and options from the device profile.
The [CTAP 2.3 command definitions](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html)
also distinguish optional and superseded commands.

| ID | Operation | Successful cases | Rejections and transitions |
|---|---|---|---|
| F01 | getInfo | All fields, types, values, capability consistency | Extra body; repeated reads; changes after PIN, configuration, reset, credential creation |
| F02 | clientPIN.getPINRetries | Counters before and after operations | PIN unset, temporary block, permanent block |
| F03 | getKeyAgreement | PIN/UV protocols 1 and 2; usable ECDH point | Unknown protocol; repeats within a session and after power cycle |
| F04 | setPIN | Minimum and maximum PINs; permitted Unicode | Already set; length and policy; padding; MAC; invalid EC point |
| F05 | changePIN | New PIN accepted; old PIN refused | Wrong old PIN, invalid new PIN, same PIN, existing credential usability |
| F06 | Obtain token using PIN | Legacy getPinToken; token with permissions | Wrong PIN; empty or unknown permissions; required or mismatching RP |
| F07 | Obtain token using built-in UV | Verification on the device | Cancel, timeout, wrong local PIN or UV, blocked verification |
| F08 | getUVRetries | Where built-in UV exists | UV absent; before and after errors and power cycle |
| F09 | Token lifetime | Authorized operation with correct RP | Wrong MAC, operation or RP; expiry; PIN change; reset; replacement token |
| F10 | Persistent read-only token | Metadata and enumeration | Delete or update attempt; reconnect; PIN change; reset |
| F11 | makeCredential | Resident and nonresident; every algorithm; preference order; same and different RP and user IDs | Required fields; unsupported algorithm; excludeList; capacity; UV and UP |
| F12 | getAssertion | allowList and discoverable; one or multiple credentials; up and uv variants | No match; different RP; damaged, foreign or deleted ID; invalid token |
| F13 | getNextAssertion | Complete walk; order; binding to the initiating request | No initializer; past end; intervening command; idle timeout; different CID |
| F14 | Credential metadata | Empty, partial, full storage | Missing permission; read-only and ordinary tokens |
| F15 | Enumerate RPs | Zero, one, many RPs; complete walk | Continuation without initializer; expiry; intervening command |
| F16 | Enumerate credentials | Different list sizes and user data | Unknown RP; deletion or creation during walk; foreign continuation |
| F17 | Delete credential | Delete selected object; reclaim capacity | Repeated deletion; unknown ID; read-only token; subsequent use of deleted ID |
| F18 | Update user information | Change permitted fields | Inconsistent user ID; lengths; missing permission; stability of key and associated secrets |
| F19 | largeBlobs read | Empty array; whole and fragmented reads | Offset and length; past-end read; unknown parameters |
| F20 | largeBlobs write | Single and multiple fragments; replacement | Digest; total length; offset; order; timeout; intervening command; preservation of previous array |
| F21 | authenticatorConfig | Enterprise attestation, alwaysUv, minPINLength, forcePINChange, complexity, other supported options | Missing acfg permission; incorrect MAC; invalid decrease or value; unknown subcommand |
| F22 | selection | Confirm device selection | Cancel, no touch, competing operation |
| F23 | reset | Permitted window and confirmation | Outside window; refusal; timeout; old credential IDs and tokens after reset |
| F24 | Bio enrollment, if supported | Sensor information; begin, capture, enumerate, rename, remove | Invalid sequence; cancel; duplicate or full enrollment set; missing permission |
| F25 | Preview commands | Only where defined by the profile | Never select command meaning from its byte alone |

Expand `rk`, `up`, `uv`, PIN presence, alwaysUv, and credProtect levels into
explicit cases. Distinguish an omitted option, false, true, and an invalid
type. Exercise allowList and excludeList at their list and credential-ID
boundaries, including a matching element at the beginning, middle, and end.

Test each supported algorithm alone, then preference lists with different
orders and an unsupported first element. Current RS-Key includes classic
EC/EdDSA, supported alternative COSE identifiers, and ML-DSA-44/65/87.
Implemented support and getInfo advertisement are separate properties.

Command `0x41` requires particular care: the legacy credential-management
preview and RS-Key's vendor protocol use the same command byte. Select its
meaning from the confirmed profile and capability context.

## 5. FIDO2 extensions and response properties

| ID | Extension or property | Required scenarios |
|---|---|---|
| FE01 | credProtect | Every level; discoverable and allowList; with and without UV; excludeList visibility |
| FE02 | credBlob | Absent, empty, length boundaries; read with and without UV; after user-information update |
| FE03 | hmac-secret | One and two salts; PIN protocols 1 and 2; invalid MAC, point and lengths; repeated calls and different credentials |
| FE04 | hmac-secret-mc | Registration and later evaluation; consistent result; invalid input combinations |
| FE05 | largeBlobKey | Permitted credential types; stability after reboot and update; no unsolicited result |
| FE06 | largeBlob | Where supported: support detection, write, read, boundaries, replacement, credential deletion |
| FE07 | minPinLength and pinComplexityPolicy | Permitted and unrelated RPs; before and after policy changes |
| FE08 | uvm | Actual verification method; presence and absence; consistency with signed data |
| FE09 | thirdPartyPayment | Registration with and without the property; requested result; invalid type |
| FE10 | previewSign and ARKG | Matching build only: creation, signing, verification, malformed parameters |
| FE11 | Unknown extension | Unknown name separately from invalid type of a known extension |
| FE12 | Attestation | Ordinary, requested formats, enterprise types 1 and 2; eligible and unrelated RP; certificate and signature verification |
| FE13 | Counters | Repeat one credential; alternate credentials; reboot; nonresident credentials; failed operations |
| FE14 | Encrypted identifier and credential-store state | Repeated reads; decrypted stability with an available token; create, update, delete, and reset transitions |

Treat `largeBlob` and the `largeBlobKey`/`largeBlobs` design as separate
implementation profiles. Current RS-Key selects between them at build time.
Record requested versus returned extensions, signed versus unsigned outputs,
authenticator-data flags, and the exact bytes covered by every signature.

## 6. U2F

| ID | Operation | Successful cases | Rejections and transitions |
|---|---|---|---|
| U01 | VERSION | Every supported transport | Extra data; APDU encoding variants; U2F disabled |
| U02 | REGISTER | Verify public key, key handle, attestation, and signature | Challenge and application lengths; absent touch; cancel |
| U03 | AUTH check-only | Own handle and application | Other application; foreign or damaged handle; no presence interaction |
| U04 | AUTH enforce-UP | Signature, UP flag, counter | No touch; cancel; invalid handle |
| U05 | AUTH without enforce-UP | Behavior of the selected profile | strict-UP or alwaysUv; unsupported control byte |
| U06 | Lifetime and isolation | Handle after reboot; mixed U2F and FIDO2 operations | Reset or seed replacement; vendor SELECT isolation; transport isolation |

## 7. PIV

Expand slots, algorithms, PIN policies, and touch policies per profile.
The [Yubico PIV command catalog](https://docs.yubico.com/yesdk/users-manual/application-piv/commands.html)
identifies standard operations and supported vendor extensions.

| ID | Operation | Successful cases | Rejections and transitions |
|---|---|---|---|
| P01 | SELECT, version, serial | Full and truncated AID; reselect | Invalid AID; appended suffix; disabled applet; selection changes |
| P02 | GET METADATA | Every key slot, PIN, PUK, management key | Empty or unknown slot; consistency with actual key and origin |
| P03 | VERIFY | Correct PIN; status query; repeat | Wrong PIN; padding and length; block; authorization after failure |
| P04 | CHANGE PIN and PUK | New secret works; stored keys remain usable | Wrong old secret; invalid new secret; counters; preservation of keys |
| P05 | RESET RETRY | Unblock using PUK | Wrong or blocked PUK; invalid replacement PIN |
| P06 | Management authentication | Supported schemes and algorithms | Wrong challenge or response; replay; missing step; intervening command |
| P07 | SET MANAGEMENT KEY | New key works; old key fails | Missing authentication; algorithm and length; touch policy; state after failure |
| P08 | SET RETRIES | Boundary values; read back result | Missing authorization; zero or unsupported values; PIN/PUK values and authorization |
| P09 | GENERATE | Every supported slot, algorithm, PIN policy, touch policy | Missing authentication; unsupported slot or algorithm; replacement of existing key |
| P10 | IMPORT | Valid fixture keys; subsequent sign and ECDH | Missing or inconsistent components; invalid length; protection of F9 |
| P11 | GENERAL AUTH sign | Every algorithm, input length, and policy | Missing or expired authentication; empty slot; wrong algorithm; input encoding |
| P12 | GENERAL AUTH decrypt and ECDH | Independently verified result | Invalid ciphertext or point; infinity or off-curve; length; policy |
| P13 | GET and PUT DATA | Standard and vendor objects; certificates; deletion with empty value | Per-object ACL; read-only object; TLV; object and aggregate capacity |
| P14 | ATTEST | Device-generated key; certificate verification | Imported or empty key; invalid reference; signature and origin |
| P15 | MOVE and DELETE KEY | Supported source and destination combinations | Empty source; occupied destination; protected slot; resulting metadata and certificate |
| P16 | RESET | Required preconditions; resulting factory state | Premature reset; incomplete blocking; old keys and sessions after reset |
| P17 | Cached PIN and touch | Immediate repeat; after expiry; another slot | Failed VERIFY; applet change; reconnect; power cycle |

Measure the single-APDU limit, chained-command limit, object limit, and total
object-storage limit separately. They are different boundaries.

## 8. OpenPGP

Keep PW1.81, PW1.82, PW3, reset code, and lifecycle state separate.
Use [OpenPGP Card 3.4.1](https://www.gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf)
for standard families and the implementation profile for extensions.

| ID | Operation | Successful cases | Rejections and transitions |
|---|---|---|---|
| O01 | SELECT and GET DATA | Complete supported DO catalog; composite and individual DOs | Unknown DOs; nested-only DOs; same and different applet selection |
| O02 | VERIFY, status, logout | Every PW reference and mode | Wrong PW; invalid reference or P1; block; independence of modes 81 and 82 |
| O03 | CHANGE REFERENCE DATA | PW1 and PW3; boundaries; profile-permitted Unicode | Wrong old PW; invalid new PW; existing keys after change |
| O04 | Reset code | Set, replace, clear; unblock PW1 | Unset, incorrect, blocked, invalid length |
| O05 | RESET RETRY COUNTER | PW3 and reset-code paths | Missing authorization; wrong mode; preservation of keys |
| O06 | SET RETRIES | Supported extension; all three counters | Missing PW3; malformed body; PIN and policy persistence after reboot |
| O07 | PUT DATA | Every writable DO: personal data, fingerprints, timestamps, private DOs | Per-DO ACL; length; read-only or unknown tag |
| O08 | Algorithm attributes | SIG, DEC, AUT; supported algorithms; identical rewrite | Invalid OID or size; changing algorithm while a key exists |
| O09 | GENERATE and READ PUBLIC KEY | Every supported slot and algorithm; repeated public read | Missing PW3; empty slot; incorrect CRT or reference; key replacement |
| O10 | IMPORT KEY | Supported formats and algorithms | Incomplete extended header; incompatible attributes; invalid components |
| O11 | PSO SIGN | Supported algorithms; one-shot and reusable PW1; signature verification | Missing PW1.81; wrong input; empty slot; UIF |
| O12 | INTERNAL AUTHENTICATE | AUT key and supported variants | Missing PW1.82; invalid reference or input; UIF |
| O13 | PSO DECIPHER and ECDH | Supported RSA, ECDH, X25519 | Invalid padding, point, marker or length; missing PW1.82 |
| O14 | MSE | Supported key-reference changes | Invalid references; default restoration; PIN and UIF after reassignment |
| O15 | AES PSO | Key installation, encrypt, decrypt, known-answer vectors | Missing authorization or key; length; invalid mode; independence from DEC slot |
| O16 | Certificates | SELECT DATA, GET, PUT, GET NEXT for every occurrence | Invalid occurrence; past-end step; missing anchor; selecting another DO |
| O17 | GET CHALLENGE | Supported Le values; repeated reads | Unsupported length; short and extended encodings |
| O18 | KDF | Read, enable, change parameters; PIN after reboot | Malformed DO; incompatible verifier; continued access to existing keys |
| O19 | UIF | Disabled, enabled, fixed policy; every slot | Missing touch; timeout; attempt to remove a fixed policy |
| O20 | ATTEST | Supported generated keys; certificate and signature | Imported or empty key; missing PW1; UIF; one-shot authorization consumption |
| O21 | TERMINATE and ACTIVATE | Active to terminated to factory state | Invalid preconditions; commands while terminated; repeated ACTIVATE |
| O22 | Signature counter | Successful and failed operations; other operations; reboot | Increment on rejection; reset on key replacement according to profile |

Expand every DO into read ACL, write ACL, lengths, reset value, and power-cycle
persistence cases. One successful GET DATA does not cover the DO catalog.

## 9. OATH

CALCULATE can change persistent state. Follow the
[YKOATH protocol](https://developers.yubico.com/OATH/YKOATH_Protocol.html)
and add extensions only for profiles that define them.

| ID | Operation | Successful cases | Rejections and transitions |
|---|---|---|---|
| A01 | SELECT | Version, identifier, challenge, algorithm | Reselect; different applet; locked and unlocked state |
| A02 | PUT | HOTP and TOTP; hashes; digits; touch and increasing properties | Secret, name, digits, flags; duplicate name; replacement; full storage |
| A03 | LIST | Empty, one, many; types and names | Missing authentication; paging; order; binary and UTF-8 names |
| A04 | CALCULATE | Full and truncated response; known-answer vectors | Unknown name; challenge length; touch; invalid P1 or P2 |
| A05 | HOTP counter | Sequential requests; initial value; reboot | Error, timeout or lost response; replay; overflow where reachable |
| A06 | TOTP and increasing challenge | Repeated challenge; greater challenge | Lower or equal challenge; boundaries; persistence after reboot |
| A07 | CALCULATE ALL | Mixed types and touch policies; full walk | Authentication; invalid challenge; effects on HOTP and increasing state |
| A08 | SEND REMAINING | Complete every page | Nothing pending; past end; intervening command; reselect |
| A09 | DELETE and RENAME | Delete; rename while preserving properties | Unknown name; collision; identical name; length; full storage |
| A10 | SET CODE | Set, change, remove access code | Missing current authentication; wrong HMAC or algorithm; alternate-path bypass |
| A11 | VALIDATE | Mutual challenge-response verification | Wrong response; stale challenge; replay; repeated SELECT |
| A12 | RESET | Required preconditions; resulting empty applet | Incorrect parameters; stale authentication and credentials after reset |
| A13 | VERIFY CODE | Where implemented: valid and invalid OTP | Counter or window, replay, retry consumption |
| A14 | OTP-PIN extensions | SET, VERIFY, CHANGE PIN; blocking; GET CREDENTIAL | Wrong PIN; SET CODE or other-command bypass; read before authentication |
| A15 | Additional records | Password records and metadata where supported | ACL, sizes, enumeration, deletion, complete reset cleanup |

Use fixed TOTP challenges for differential runs. Host wall-clock differences
must not manufacture mismatching OTP results.

## 10. OTP slots and keyboard output

The [Yubico OTP slot catalog](https://docs.yubico.com/yesdk/users-manual/application-otp/slots.html)
includes Yubico OTP, HOTP, static passwords, and challenge-response. Slot count
and transport support belong to the device profile.

| ID | Operation | Successful cases | Rejections and transitions |
|---|---|---|---|
| Y01 | Status, serial, config | Supported reads; program sequence | Empty and occupied slots; OTP disabled; transport consistency |
| Y02 | Configure slot | Every mode, slot, and relevant flag combination | CRC; length; incompatible flags; invalid slot or access code |
| Y03 | Update slot | Permitted changes without key replacement | Forbidden changes; no update permission; counter preservation |
| Y04 | Delete slot | Empty and occupied slot | Wrong access code; rejection without partial change |
| Y05 | Swap | Empty/empty, empty/full, full/full | Different access codes; resulting counters, flags, and secrets |
| Y06 | Access code | Set, replace, remove | Missing, wrong, or invalid-length code; reboot |
| Y07 | HMAC challenge-response | Fixture key; challenge boundaries; touch and no-touch | Wrong mode or slot; length; absent touch; cancel |
| Y08 | Yubico challenge-response | Fixture key; verify response block | Invalid length or mode; device-specific fields |
| Y09 | Yubico OTP typing | Decrypt with fixture key; CRC; counters | Repetition; reboot; interrupted action; gesture boundaries |
| Y10 | HOTP typing | Known answers; digits; counter | Repetition or interruption; counter persistence; slot independence |
| Y11 | Static password typing | Exact HID reports and resulting text | Layout, modifiers, TAB/CR, length, pacing |
| Y12 | Gestures | Short and long press or profile-defined press sequence | Timing boundaries; hold; repeat; busy |
| Y13 | Admin slots | Scan map, legacy config, NDEF config, DeviceInfo where supported | Malformed structure; strict-config; persistence after reboot |
| Y14 | Additional RS-Key slots | Slots 3 and 4; CCID offset; gesture selection | Out-of-range slot; isolation from slots 1 and 2; status consistency |

Keyboard output is an operation that may start with a physical gesture rather
than a host request. Record gesture start only when observed, its observation
source and uncertainty, and first and final HID reports. Do not fabricate a
host request or exact touch timestamp for unsolicited output.

## 11. Management

Check actual enforcement as well as reported configuration.

| ID | Operation | Successful cases | Rejections and transitions |
|---|---|---|---|
| M01 | SELECT and READ CONFIG | Supported pages and TLV; advertised capabilities | Extra body; page numbers; identity consistency |
| M02 | WRITE CONFIG | Each writable tag; partial update; identical repeat | Duplicates; read-only or unknown tags; lengths; unsupported capability bits |
| M03 | Enable and disable applets | Individual bits, combinations, all permitted apps disabled | Every affected command after change; reachable re-enable path |
| M04 | Configuration lock | Set, change, clear with correct code | Missing or wrong code; malformed code; identical write while locked |
| M05 | All config writers | CCID, OTP HID, CTAPHID vendor, FIDO vendor where supported | Lock or confirmation bypass through another interface |
| M06 | Persistence | Immediate effect; replug; each applet reset | Unintended clearing of configuration or lock |
| M07 | Unknown and service INS | Explicitly profiled cases | Acknowledgment without action versus an operation actually performed |

Changing USB interfaces and changing enabled applications are separate cases.
An interface change can remove the transport used to configure the device.

## 12. RS-Key vendor surfaces

Include RS-Key-specific operations even when reference hardware has no
equivalent. Compare them against the RS-Key contract and their other
transport paths; report external comparison as not comparable.

| ID | Surface | Successful cases | Rejections and transitions |
|---|---|---|---|
| V01 | Classical and hybrid MSE | Establish channel; protected operation | Points, lengths, KEM; repeated MSE; other CID; replay; channel consumption on failure |
| V02 | BACKUP STATE and EXPORT | Permitted state; verify decrypted fixture seed | Missing MSE, PIN or touch; sealed window; policy profile |
| V03 | BACKUP LOAD | Install fixture seed; verify resulting properties | Invalid AEAD; soft lock; refused confirmation; old credentials |
| V04 | BACKUP FINALIZE | Close export window; repeated call | Missing authorization; cancel; persistence after reboot |
| V05 | Soft lock and unlock | Enable, locked boot, unlock, disable | Incorrect key; repeat; reboot; command availability in each state |
| V06 | ATT STATE, IMPORT, CLEAR | Fixture key and chain; subsequent attestation | Inconsistent chain; lengths; authorization and MSE; refusal preserves identity |
| V07 | AUDIT CONFIG and READ | Enable, disable, status; empty and full ring; wrap | ACL; invalid operation; policy persistence |
| V08 | AUDIT CHECKPOINT | Verify signature, chain head, nonce | Nonce boundaries; missing permission; replay |
| V09 | CONFIG READ and WRITE | DEV_CONF, PHY, LED; partial update; immediate and reboot effects | Lock; strict-config; malformed record; identical write |
| V10 | CONFIG COMMANDS and vendor config | Supported IDs, soft-lock commands, phy commands | Unknown ID; type and range; permission; advertised-list consistency |
| V11 | Vendor counter | Read, increment, persistence | Missing confirmation; refusal; transport isolation |
| V12 | LED | Every status, effect, color, brightness, speed | Boundaries; normalization; lock; stored versus effective reads |
| V13 | Measurement commands | Measurement build only | Shipping build must not expose them |

For MSE, test a successful protected operation and every defined rejection
path separately. After each outcome, test whether the channel can be reused.

## 13. RS-Key rescue

| ID | Surface | Successful cases | Rejections and transitions |
|---|---|---|---|
| R01 | Identity and status | MCU/SDK, flash usage, secure boot, rollback, storage, migration status | Lengths, selectors, unsupported values |
| R02 | Device key | Public key; signature of fixture digest; fixture certificate installation | Missing confirmation; invalid length; key binding |
| R03 | PHY | Read and update; preserve untouched fields; reboot effect | TLV; lock; range; rejection without partial update |
| R04 | RTC | Civil and Unix forms; reads; date boundaries | Unset clock; invalid date or time; overflow |
| R05 | Reboot | Warm and BOOTSEL; response before disconnect | Refusal; invalid selectors; rediscovery |
| R06 | Recovery mode | Permitted status and setup commands; initialize or import | Active, occupied or incompatible storage; other applets remain unavailable |
| R07 | OTP fuses | Describe preconditions, rejection paths, and expected transitions | Positive fuse writes are excluded from ordinary hardware capture |

Precise write interruption and flash damage can be injected in an emulator.
A physical reference key provides evidence only for an interruption that was
actually performed and observed. Keep emulator fault injection and physical
power-interruption results distinct.

## 14. Additional external-device profiles

These families require a confirmed model and firmware-specific command
catalog before execution. An absent RS-Key equivalent is an applicability
result, not a failed implementation test.

| Profile | Operation matrix |
|---|---|
| CanoKey Admin | Version, serial, configuration, storage; verify and change admin PIN; applet enable/disable; touch and keymap settings; applet resets; attestation provisioning. For each: authorization, lengths, persistence, effects on neighboring applets. [Command catalog](https://docs.canokeys.org/development/protocols/admin/) |
| NDEF exposed over USB | Select application and files; read CC/NDEF; READ/UPDATE BINARY; offset and length; NLEN; interrupted update; read-only state. This does not test an NFC radio. [CanoKey protocol](https://docs.canokeys.org/development/protocols/ndef/) |
| YubiHSM Auth | Version, retries, list; put and delete credentials; calculate; change management key; reset. Check password and touch, labels, capacity, context, and independent calculations with fixture secrets. [Commands](https://developers.yubico.com/yubihsm-shell/Manuals/yubihsm-auth.1.html) |
| OnlyKey | Locked and unlocked states; profiles and slots; configuration; time-dependent OTP; challenge-response; import and delete keys; sign and decrypt through the supported vendor protocol. For WebCrypt: handshake, framing, authentication, interrupted session. [WebCrypt protocol](https://docs.onlykey.io/webcrypt.html) |
| Trezor | Shared FIDO/U2F scenarios; device lock/unlock and screen confirmation; vendor credential list, add, and remove where supported. Check imported credential-ID binding to the active seed and subsequent signatures. [FIDO functionality](https://trezor.io/guides/bonus-tools/using-your-trezor-as-a-security-key-fido-2-and-u2f) |
| Other vendor applets and secure domains | Firmware-specific catalog; version and status, authentication, object management, lifecycle on isolated fixture states |

Trezor wallet operations are a separate scope. This plan covers its
authenticator functions.

## 15. Cross-applet and cross-transport sequences

| ID | Sequence | Required observation |
|---|---|---|
| X01 | Authenticate in A, then command B | Authorization does not transfer without a defined mechanism |
| X02 | SELECT A, then A, B, or an invalid AID, then A | Which authorization, cursors, and challenges survive |
| X03 | Start over HID, continue over CCID | Actual scope of sequence state and tokens |
| X04 | Alternate wrong PIN attempts across transports | Shared attempt budget; no additional budget from another transport |
| X05 | Await touch in A, then request or cancel from B | Presence owner, busy behavior, cancellation isolation |
| X06 | Reset A, then inspect B, C, and management | Exact deletion scope and retained configuration |
| X07 | Fill A, then create an object in B | Shared resource limits, independent quotas, recovery after deletion |
| X08 | Write configuration through A, read and use through B | Shared configuration and actual enforcement |
| X09 | Long RSA or PQC operation, then another interface | Keepalive, busy, responsiveness, correct completion of both requests |
| X10 | Lose a write response, reconnect, read back | Whether it committed and whether a partial result exists |
| X11 | Applet reset, session reset, USB reset, warm reboot, physical power cycle | Different volatile and persistent lifetimes |
| X12 | Reject a request, then valid operation in another applet | No stuck transport or damaged shared session |

A timeout does not establish that a write failed. Do not automatically retry
a mutating operation whose result is unknown. First run its explicit readback
or recovery scenario; retain an unknown result when no decisive observation
is available.

## 16. Trace artifacts and records

Use append-only JSONL for capture and JSON for derived reports. Preserve raw
observations independently of comparison verdicts.

| Artifact | Contents |
|---|---|
| manifest.json | Environment, device bindings, profile and scenario revisions, capture settings |
| events.jsonl | Ordered execution events |
| results.json | Per-case outcomes, assertions, evidence references, derived exchange summaries |
| comparison.json | Selected run comparison and rules applied |
| Optional blob files | Large payloads, referenced by relative path, length, and SHA-256 |

### Manifest and identity

The manifest records:

- Schema version, run ID, UTC start, monotonic clock source and resolution.
- Host OS and architecture, tool and library versions, backend, capture mode.
- Suite revision, scenario revisions, generator seed, input-corpus digest.
- Device profile revision, model, firmware, RS-Key build identity where known,
  and physical or emulator backend identity.
- Transport, interface and endpoint details available to the backend; USB port
  or hub placement where known; reader binding and rebinding evidence.
- Advertised capabilities separately from observed support and uncertainty.
- Execution permissions, fixture references, redaction policy, flush policy,
  and known observation limitations.

AAGUID and VID/PID alone do not distinguish two physical devices of the same
model. Bind each interface to the intended instance, record the evidence, and
make reconnection or rebinding explicit. Abort an ambiguous binding rather
than silently capture a neighboring key.

### Event envelope

Every event has `schema_version`, `record_type`, `run_id`, a unique `event_id`,
a monotonically increasing `sequence`, and a monotonic `time_ns` relative to
the run origin. Scenario events additionally identify the concrete case and
invocation. Operation, exchange, session, and device IDs are included where
applicable. An ID is a reference, not a decoded device-state claim.

| Record type | Required payload |
|---|---|
| run_started | Environment, clock origin, suite revision, seed, manifest reference |
| device_bound | Device/profile IDs; model and firmware; interface or reader binding; identification evidence |
| scenario_started | Family and case IDs, parameters, preconditions, fixtures, effects |
| exchange_started | Operation, exchange and session IDs; phase; request; timeout |
| io_event | TX or RX, observation layer, bytes, timestamp, order; CID and transport sequence where visible |
| interaction | Requested or observed operator action, source, timestamp uncertainty |
| exchange_finished | Response or termination cause; timing; transmission evidence; uncertain side effects |
| observation | Observed state property and evidence step IDs |
| assertion | Expected and actual properties, expectation source, verdict, evidence |
| scenario_finished | Completion, cleanup result, repeatability and comparison eligibility |

Write the exchange-start record before transmission. A missing finish record
means an incomplete exchange. Recover complete JSONL records after a crash;
report a truncated final record without interpreting it as a completed action.
The selected flush policy must state which records can be lost on a crash.

One logical operation can contain management authentication, chained writes,
response continuations, and readback. Each actual exchange has its own ID and
timing; `operation_id` connects them. Retries are separate exchanges with an
explicit cause and reference to the preceding attempt. Do not hide retries
inside a successful summary.

The phase is one of `setup`, `probe`, `verify`, or `cleanup`. Capture and time
every phase. Connection changes, waits, and physical actions are recorded even
when no protocol request is sent.

### Byte and decoded representations

- Store byte strings as lowercase hex with explicit byte lengths.
- Keep raw requests and responses as the primary evidence.
- Keep decoded values separately, with decoder identity and revision.
- Represent CBOR maps without losing key types, order, duplicates, or unknown
  entries. Represent TLV as ordered elements, including unknown and repeated tags.
- Distinguish absent, empty, zero, false, and unknown values.
- Use an explicit exact representation for integers a JSON consumer would round.
  Nanosecond offsets are JSON integers limited to the exact interoperable range
  `0..9007199254740991`; rotate to a new run before exceeding it.
- Keep normalization separate from raw data and identify the normalization rules.
- Bind device-returned values symbolically, such as `credential_1`, `token_2`,
  and `public_key_3`, with references to the producing exchange.
- During replay, obtain fresh IDs, tokens, ephemeral keys, and authenticated
  messages from the current device. Reusing another device's captured bytes is
  a separate deliberate foreign-object test.

### Example exchange summary

This is a derived summary for `results.json`, not an events.jsonl envelope.
All response bytes and timing values below are illustrative, not measurements.

```json
{
  "schema_version": 1,
  "record_type": "exchange",
  "run_id": "example-run",
  "scenario_id": "piv.version.default",
  "operation_id": "op-01",
  "exchange_id": "ex-01",
  "device_id": "reference-01",
  "session_id": "pcsc-01",
  "phase": "probe",
  "observation_layer": "pcsc_apdu",
  "request": {
    "hex": "00fd0000",
    "length": 4
  },
  "response": {
    "hex": "0508009000",
    "length": 5,
    "decoded": {
      "version": [5, 8, 0],
      "sw": "9000"
    }
  },
  "timing": {
    "clock": "host_monotonic",
    "call_start_ns": 1000000,
    "call_end_ns": 1820000,
    "api_duration_ns": 820000,
    "tx_complete_ns": null,
    "first_rx_ns": null,
    "deadline_ns": 1000000000
  },
  "execution_outcome": "completed",
  "protocol_outcome": "success",
  "side_effect_status": "not_assessed"
}
```

Here PC/SC returns a complete response. It does not expose the first incoming
byte or completion of lower-layer transmission. Those timestamps remain null.

## 17. Independent result dimensions

| Dimension | Values |
|---|---|
| Execution | completed, host_rejected, deadline, disconnected, cancelled, runner_error |
| Protocol | success, response_continuation, applet_error, transport_error, malformed_response, no_response |
| Assertion | pass, fail, inconclusive |
| Applicability | applicable, unsupported_confirmed, unknown, blocked_by_precondition, not_run |
| Comparison | equal, allowed_difference, unexpected_difference, not_comparable |
| Side effects | not_assessed, observed_applied, observed_not_applied, observed_partial, unknown |

An expected device rejection can pass its assertion. A local library exception
before transmission cannot prove a device rejection. Missing advertisement
alone is not a measured unsupported response. Use null with an explanation
when a dimension has no result yet; do not manufacture success for skipped work.

Record exact SW, CTAP status, HID error, backend error code, and failure layer
alongside these classifications. Preserve both a cancellation request and the
actual device outcome: a late cancel can race with a successful completion.

## 18. Per-request timing contract

Time every request, including setup, negative cases, continuations,
verification, cleanup, and explicit retries.

| Metric | Definition |
|---|---|
| call_start_ns | Immediately before entering the measured transport API |
| call_end_ns | Immediately after that API returns a response or failure |
| api_duration_ns | call_end_ns minus call_start_ns |
| tx_complete_ns | Completion of submission at the declared observation layer, when visible |
| first_rx_ns | First incoming event, including keepalive |
| first_final_rx_ns | Start of the final response, when visible |
| final_rx_ns | Complete final response received, when visible |
| response_latency_ns | Complete response minus request-submission start at the same declared observation layer |
| keepalive_intervals_ns | All observed intervals and status changes |
| cancel_latency_ns | Cancellation submission to observed termination, with the terminating outcome identified |
| operation_duration_ns | Entire multi-step operation, explicitly stating included waits |
| recovery_duration_ns | Observed disconnect or reset to readiness for a defined control request |

Each duration identifies its start and end events. `deadline_ns` is the
absolute offset of the host deadline from the run origin; also record the
configured timeout duration in the exchange-start record. Do not combine
timestamps from unsynchronized clocks or different observation layers.

Use one monotonic origin per run. UTC identifies the run and is not used to
calculate latency. Encoding, response decoding, JSON serialization, and console
output stay outside the measured API interval. Record capture overhead and
detail mode because per-frame instrumentation can itself change latency.

Host-side latency includes the selected API, scheduling, driver, and transport
path. It does not measure pure cryptographic execution time on a closed device.
Do not subtract a PING baseline and label the remainder device CPU time.

For a timeout, retain the elapsed wait, configured deadline, and absence of a
final response. Treat response latency as right-censored, not a successful
response at exactly the timeout and not a zero-duration sample. A local
pre-transmission failure still has a host API duration but no device-response
latency.

For touch or local PIN entry, retain the full operation duration and available
interaction signals. `UPNEEDED` indicates a presence wait; it does not expose
the exact instant of physical contact. Do not infer pure compute time by
subtracting keepalive intervals. See
[CTAPHID KEEPALIVE](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#usb-hid-keepalive).

Statistics rules:

- Retain every sample, execution order, exclusion, and exclusion reason.
- Separate first call after physical power cycle, first call after opening a
  session, and subsequent calls. A warm reboot is not a physical power cycle.
- Match algorithm, request and response size, occupancy, authorization, and
  touch policy before comparing devices or builds.
- Report sample count, minimum, median, MAD, and quantiles justified by sample
  size. Do not treat p99 from a small sample as a stable tail estimate.
- Analyze successes and each distinct rejection cause separately.
- Define repetitions and warmups per operation. Record warmups and reset their
  effects where comparable initial state requires it.
- Repeated writes, HOTP, counters, and key generation can change subsequent
  conditions. Reestablish the fixture or report the changing state explicitly.
- Keep physical hardware, host emulator, and firmware-image emulator results in
  separate performance populations.
- Compare manual-interaction operations as end-to-end observations unless a
  separate, trustworthy interaction timestamp supports a narrower metric.

## 19. Oracle rules, coverage, and execution boundaries

### Property-level comparison

| Property | Comparison rule |
|---|---|
| Deterministic response | Exact bytes |
| SW or CTAP error | Exact code for matching state and profile |
| Random challenge | Format, length, and observable properties; no claim of proven entropy |
| Signature | Verify with the correct public key over the exact expected data |
| ECDH, HMAC, OTP | Independent calculation using fixture inputs |
| Certificate | Parse, signature, key binding, extensions; CA trust checked separately |
| Credential ID or token | Format, lifecycle, usability in following steps |
| Counter | Update rules, scope, persistence |
| List | Membership, order, duplicates, completeness |
| State | Explicit witness operations and evidence references |
| Time | Distribution under comparable conditions |
| Vendor difference | Narrow, versioned rule with a reason |

YubiKey remains RS-Key's primary compatibility reference. Preserve OnlyKey,
Trezor, CanoKey, and other observations independently. A majority of devices
does not establish the correct behavior. Report specification and reference
disagreements separately; do not silently change expectations to match a run.
Compatibility differences do not authorize data-loss regressions in RS-Key.

Use complete private captures and separately marked publication exports.
Fixture references should identify test secrets. If sensitive raw bytes are
removed, record every redaction and the resulting limits on exact replay.
Do not commit real PINs, private keys, exported device seeds, or unreviewed
device captures as part of implementing this plan.

### Coverage report

For each concrete device profile report:

- Known commands and subcommands, including confirmed unsupported operations.
- Expanded success cases and every planned rejection case.
- Exercised valid and invalid state transitions.
- Length and value boundaries, combined defects, and sequence coverage.
- Generation method, seed, bounds, and corpus revision.
- Every omission and its cause: unknown support, missing preconditions,
  backend limits, pending manual action, or execution permission.
- Requests with raw exchange evidence, timing, and result verification.
- Ambiguous outcomes after timeout or disconnect, with readback results.
- Unexpected differences and their shortest known reproducing sequences.

An unchanged raw capture can be re-decoded or re-compared with a new rule
revision. Preserve the original comparison and identify which scenario or
normalization changes require a fresh device run.

### Requirement audit, 2026-10-18

The bounded implementation requirements for confirmed protocol profiles are
implemented below, with separate scenarios for individual clauses and offline
regressions that deliberately break their witnesses. The former
zero-missing-families result only established catalog membership; it was not
this audit. Hardware execution and reference captures remain unperformed.
These checkboxes refer to the named clauses, never to an entire family.
Any future unchecked clause appears verbatim in `plan` and capture reports.
A family remains `not_certified` until actual applicable device evidence is
reviewed; removing an implementation gap cannot manufacture that evidence.
Section 14's unresolved model/firmware catalogs stay explicitly `unknown`.

- [x] `G02, G14`: `fields.*` varies each parsed outer and nested field's CBOR type across makeCredential, getAssertion, clientPIN subcommands, credential management, largeBlobs, config and RS-Key vendor commands; verify exact type error, unchanged PIN retries and public FIDO state. This does not cover every presence, length or semantic combination.
- [x] `T04, T05, T06, T08`: `transport.assembly.interval-*`, `transport.assembly.foreign-CID-continuation` and `transport.KEEPALIVE.after-completion` cover scheduled completion around the RS-Key assembly deadline, foreign continuation isolation and an explicit idle observation window. Record host write intervals and uncertainty; do not assert exact device arrival at 500 ms.
- [x] `T11, T13, O07, O17`: `transport.APDU.case-*`, `transport.APDU.response-chain.*` and `openpgp.GET-CHALLENGE.*` cover short/extended cases 1-4, Lc/Le boundaries, exact response reconstruction, no-pending/final-repeat continuations and valid/refused/SELECT interruptions. `61xx` has its own continuation outcome and cannot satisfy a refusal assertion.
- [x] `FE02, FE03, FE05, FE11, FE13`: `fido.credBlob.visibility.*`, `fido.hmac-secret.isolation.*`, `fido.hmac-secret.member-*`, `fido.largeBlobKey.*`, `fido.extension-type.*`, `fido.unknown-extension.*` and `fido.counters.*` cover absent and non-UV blob reads, secret isolation, repeated evaluations, independently malformed HMAC fields, user-update stability, unsolicited results, and per-credential counters. Connection cases are conditional on an explicit backend.
- [x] `A05, A06, A07, A08`: `oath.HOTP.initial-*`, `oath.increasing.equal-bulk-reselect.*` and `oath.paging.*` cover 32-bit IMF boundaries, bulk/error counter preservation, equal/decreasing challenge refusal, bulk high-water marks, reselect/power persistence and continuation retirement. Tests do not claim an unreachable 64-bit HOTP wrap.
- [x] `R01, R04, R05, R06`: `rescue.READ.selector-*`, `rescue.refuse.*`, `rescue.RTC.civil.*`, `rescue.RTC.refuse.*` and `rescue.RTC.power-cycle-unsets` cover profiled selectors, civil writes, leap/month/year/epoch limits, normalization, ignored weekday, refusal preservation, and unset RTC after power loss. RS-Key normalizes short-month overflow and leap seconds; it must not be tested against an invented strict-date refusal.
- [x] `P05, P16`: `piv.puk.block-unblock` checks wrong PUK without unblocking the PIN, then correct recovery; `piv.reset.preconditions-and-factory-state` checks that blocking only PIN cannot authorize reset. Recovery uses the known PUK even when an assertion interrupts the fixture flow.

- [x] `F02, F03, F04, F05, G03, G08, G14`: `pin-matrix` and `pin-setup-matrix` use actual ECDH/AES/HMAC for configured/factory-unset PIN paths, ciphertext/padding/MAC/point defects, code-point and UTF-8 byte limits, wrong-old/same-PIN paths, retry accounting, and retained private credentials. `test_oracle_pin_matrix.py` independently decrypts requests and falsifies MAC, character-count, agreement-rotation and retained-key defects.
- [x] `F06, F09, F10`: `token-matrix` exhausts permission bytes plus overflow boundaries, legacy/scoped request fields, RP binding and first-use binding, ordinary/persistent isolation, all legacy/scoped replacement pairs, PIN-change revocation and rejected-change ordering. `reset-tokens` proves each grant live after reboot before resetting it, on both protocols, and checks reprovisioning cannot revive it. `test_oracle_token_matrix.py` and `test_oracle_cross_reset.py` inject scope, replacement and reset-retention defects.
- [x] `F11, F12, F14, F17, F18`: `registration-matrix`, `credential-matrix` and `fido-lists` cover host-PIN/no-local-UV makeCredential option products, owned RP/user replacement identities, reported credential-ID bounds, populated mutation refusals, exact user preservation, repeated deletion, filled metadata and reclamation. Local-UV combinations remain listed separately below.
- [x] `F19, F20`: `blob-matrix` covers read offset/fragment bounds, staging order/timeout/intervening commands, digest and committed-array preservation, total/fragment width boundaries and exact maximum-array reconstruction. `test_oracle_blob_matrix.py` falsifies partial commits, staging retention and completed-write replay.
- [x] `F21, FE07`: `config-matrix` checks missing/wrong protocol and MAC, permission and read-only grant refusals, command/protocol precedence, advertised RP-list capacity and visibility, monotonic complexity/minimum policies, length-valid weak and Unicode PINs, forced same-PIN refusal, unchanged retry budgets and power persistence. A final permitted reset reprovisions the original PIN. `test_oracle_config_matrix.py` falsifies authorization, truncation, complexity and RP-disclosure defects.
- [x] `FE01, FE03, FE04, FE05`: `registration-matrix` covers resident/wrapped credProtect exclude visibility with/without host-PIN UV, hmac-secret-mc opt-in combinations and protocol-specific encrypted outputs, and nonresident largeBlobKey refusal. `test_oracle_registration_matrix.py` uses independently retained signing/HMAC state.
- [x] `T01, T14, T15`: Discovery/selector/open failures are journaled before device sessions exist; PC/SC shared/exclusive/direct competition has owner recovery; `otp-transport` records each raw feature SET/GET and covers CRC, sequence, restart, missing/final/repeated reports and output aborts. `test_oracle_discovery.py`, `test_oracle_pcsc_sessions.py` and `test_oracle_otp_transport.py` use synthetic backends. Busy/presence and lower USB conditions remain below.
- [x] `P03, P04, P05, P09, P10, P11, P12, G14`: `card-pin-matrix` and `piv-matrix` cover PIN/PUK byte boundaries, VERIFY validation/grant ordering, wrong-PIN retry/grant effects, malformed import/generate/private inputs and raw private-operation lengths, with real retained-key controls. Remaining policy/presence and reference cases remain below.
- [x] `P13, T12`: `piv-objects` walks the profile's fixed object namespace and profiled pooled objects under all PIN/management grant states, deletion and connection lifetimes. Chain and object ceilings are distinguished explicitly where their envelopes coincide. `piv-pool-capacity` establishes an empty store through a permitted reset and independently fills/reclaims byte and record quotas. `test_oracle_piv_objects.py` falsifies ACL, persistence and quota defects.
- [x] `P15`: `piv-moves` verifies retained/moved algorithm, origin and PIN/touch metadata, independent private controls on both populated references, and stationary certificate objects with restoration. `test_oracle_piv_moves.py` falsifies certificate movement and destination-policy remapping. `card-keys` now expands the complete slot/algorithm/origin/PIN/touch product.
- [x] `O01, O07`: `openpgp-catalog` checks ordinary writable DO owner combinations, nested/internal/read-only visibility and connection persistence; `openpgp-catalog-reset` checks each populated ordinary DO's factory value. Routed KDF/AES/reference/UIF semantics have their own suites. `test_oracle_openpgp_catalog.py` falsifies foreign-owner overrides and lost persistent records.
- [x] `O08, O09, O10, O18, O21`: `openpgp-matrix` covers malformed CRT/import components, unsupported algorithm attributes and populated-key invalidation, KDF with retained keys across power cycles, and the terminated command catalog. `pgp_keys` drives advertised RSA-1024/2048/3072/4096 over actual APDUs without SDK enum/exponent-width rejection; private EC controls choose a digest P-521 accepts. `test_oracle_pgp_keys.py` and `test_oracle_openpgp_matrix.py` verify independent RSA/EC operations.
- [x] `A02, A04, A05, A07`: `oath-semantics` checks hash/digit/secret/property combinations, exact HMAC answers, mixed touch/HOTP bulk results, and both committed/uncommitted lost-response recovery without retrying the uncertain HOTP request. `test_oracle_oath_semantics.py` falsifies invalid-secret acceptance and bulk counter consumption.
- [x] `A09, A10, A11, A12, A13, A14, A15`: `oath-access` and `oath-gates` check all access-code hashes and key widths, isolated SET CODE/VALIDATE grammar/proof failures and standing grants, access-code versus OTP-PIN authorization in both orders, SELECT's distinct effects on each grant, all additional record types after reset, and rename/replacement/reclamation at full capacity. The existing stale-proof fixture now performs an actual deselection. `test_oracle_oath_access.py` and `test_oracle_oath_gates.py` falsify proof/grant bypasses, leaked reset secrets and capacity-dependent rename.
- [x] `V01, V03, V05, V06`: `vendor-matrix` checks malformed/foreign-CID MSE inputs and one-shot consumption after refused consumers, seed/identity/private-key preservation and malformed wrapped payloads. ATT_CLEAR cleanup establishes its required fresh MSE. Populated identity/chain and sealed/locked-boot cases remain below.
- [x] `X06, X07, M06`: `cross-reset` creates PIV/OpenPGP/FIDO private keys, OATH/OTP secrets and a known management lock before each applet reset; it proves the target's old key unusable and each neighbor's private operation, configuration and lock enforcement preserved. `test_oracle_cross_reset.py` injects neighboring-key deletion, lost shared locks and retained persistent grants.
- [x] `G05, G06`: `cbor-matrix` applies truncation, trailing items, duplicate/order rules, indefinite maps, skipped tags, unknown keys and non-shortest forms to every currently cataloged parsed CTAP subcommand. Vendor's permissive duplicate/order behavior is recorded separately. These are parser-gate controls with crypto placeholders, backed by retained private credentials; semantic field combinations remain below. `test_oracle_cbor_matrix.py` falsifies trailing-data acceptance.

- [x] `G01, G03, G04`: The per-command semantic suites discharge presence, empty values and profile bounds separately from `fields` and `numeric`. `pin-commands` covers ClientPIN dispatch widths/reserved values and ignored optional fields; `pin-matrix` supplies real encrypted PIN fields and every AES-block neighbor. `registration-matrix`, `assertion-matrix`, `fido-lists`, `cm-matrix`, `blob-matrix`, `config-grammar` and `vendor-matrix` cover required/optional nested fields, empty versus absent lists/maps, raw 384-byte subparameter spans, advertised list/store limits and protocol/MAC/reference/user/RP boundaries. PIV/OpenPGP/OATH/OTP/management/rescue/vendor command suites below provide their fixed byte catalogs, field widths and capacity-specific controls. Ignored values retain their actual permissive profile meaning; parser placeholders cannot satisfy semantic success. Independent peers falsify dispatch order, raw limits, character counts, counter changes and state loss.
- [x] `G05, G06, G07, G08`: `cbor-matrix` applies every truncation byte, declared lengths, trailing items, nested duplicates/order, non-shortest encodings and known versus skipped indefinite containers/strings across parsed RS-Key CTAP schemas. CM descriptor transports are read; MC/GA transports and MC RP name are skipped. The command-specific card/PHY/identity suites below cover their TLV/DER/one-byte grammars and actual opaque-versus-UTF8 semantics. `openpgp-objects` adds all byte-boundary/private/personal DOs and all 256 sex bytes; `card-pin-matrix` adds opaque binary/NUL/invalid-UTF8 PW1/PW3, exact verifier use, original private signatures and known-secret restoration. Registration/CM user text checks whole-codepoint truncation, while PIN checks first-NUL prefix/codepoint limits and ignored tails. Directed normalization/filter/length/parser defects reach the intended assertions.
- [x] `G09, G10, G11, G12, G13, G14`: The populated-reference, grant/cursor/channel, reset, cross-surface and unknown-response suites below provide existing/deleted/replaced/foreign reference controls, same/other/invalid SELECT and session/USB/CPU/power lifetimes, named cancellation/timeout/transfer interruptions, and selected parser/authorization/semantic precedence products. Every uncertain mutation is sent once; readback either proves whole old/new state, identifies a partial result or retains `unknown`. A failed private/readback control halts cleanup and later mutations. `oath-sequences` adds seeded valid state histories with exact private HOTP/neighbor witnesses after each step. The offline minimizer reconstructs each trial from its semantic recipe and accepts only the same named assertion, triggering action and protocol evidence, then confirms the shortened recipe twice. It cannot accept an unrelated red run or replay captured raw mutators.
- [x] `T02, T06, T07, T08, F22`: `hid-operations` exercises reserved/unallocated CIDs, INIT during outstanding UP, processing/UP/final-response CANCEL scheduling and retained private controls. Interleaved INIT replies have an explicit report-consumption contract. `selection-matrix` covers confirmation, decline, timeout, cancellation and a competing selection. `test_oracle_hid_operations.py`, `test_oracle_hid_processing.py` and `test_oracle_selection_matrix.py` falsify nonce corruption, lost private keys, late CANCEL replies and changed retries.
- [x] `T16`: `pinpad-matrix`, `pinpad-properties` and `pinpad-headless` check Part 10 structure fields/lengths, PIN/display property consistency, driver-layer idle ABORT, secure-entry success/refusal/timeout with and without a standing grant, and raw CCID Secure refusal on a positively declared headless build. `test_oracle_pinpad_matrix.py` uses a real protected PIV private operation and falsifies false grants, lost standing grants and malformed property replies. This does not claim USB control-transfer ABORT coverage.
- [x] `F01, F03`: `info-matrix` checks discovery types, coherent limits/options/algorithms, ignored getInfo bodies, valid agreement points, cross-protocol stability and INIT/SELECT/connection/power lifetimes with retained private credentials. `test_oracle_info_matrix.py` falsifies invented version strings and agreement rotation at the wrong boundary. Policy/PIN/store changes are checked by their mutation suites.
- [x] `F06, F09, F10, FE08`: `uv-matrix` exhausts local-UV permission bytes and overflow boundaries, verifies signed internal/external passcode provenance, refusal retry/grant effects and local PIN-change revocation of ordinary/persistent grants. Replacement PIN confirmation uses read-only issuance so it cannot invalidate the ordinary grant under test. `test_oracle_uv_matrix.py` and `test_oracle_uv_local_change.py` falsify permission, provenance, retry and revocation defects.
- [x] `F07, F08, F22, F23, F24`: `uv-block` checks shared retry accounting, temporary/permanent local blocks, cold-power persistence and reset recovery. `reset-matrix` checks window expiry, the display exemption, decline/cancel/timeout and preservation of live keys/grants on refusal. `bio-matrix` checks invalid capture sequences, wrong/missing authorization, incomplete-capture cancellation, duplicate-sample feedback, friendly-name byte bounds and full-store reclamation without deleting preexisting templates. Regression peers inject block bypass, replenished retries, revoked grants, retained capture cursors and neighboring-template deletion.
- [x] `F11, F12, FE01, FE03, FE04, FE08`: `uv-matrix` expands local-UV MC/GA option products, allow-list/discovery and credProtect visibility, silent-probe behavior, host-token precedence, signed UVM factors, local hmac-secret-mc output and equality of the retained UV secret across host/local token/local ceremony paths. `test_oracle_uv_ceremonies.py` uses independently signed EC results and encrypted HMAC outputs; it falsifies cleared UV flags, a silent local ceremony and a different local HMAC secret.
- [x] `F13, F15, F16`: `cursor-matrix` creates owned RP/credential/assertion walks, checks declared counts, exact references/users/signatures, expiry, refused-command/getInfo/metadata/update interruptions, restart, wrong-kind continuation and foreign-CID refusal followed by owner completion. `test_oracle_cursor_matrix.py` falsifies cross-CID continuation and missing expiry. Remaining deletion/replacement and connection interactions stay below.
- [x] `P13`: `piv-escrow` checks live-key synthesis only after ADMIN opt-in, PIN versus management ACL, acknowledged-but-unstored host escrow copies, exact discrimination of nested/trailing/ordinary PRINTED data, rotation revocation, and immutable discovery/factory-attestation objects. `test_oracle_piv_escrow.py` falsifies stored host key copies, retained escrow after rotation and management-only disclosure.
- [x] `P03, P11, P12, P17`: `piv-policies` covers every slot/PIN/touch-policy product for signature and ECDH, repeated operations, refused touch/timeout, malformed-input freshness ordering, idle/SELECT/connection actions and retained private controls. Unsupported biometric PIN policies reach raw negative APDUs. `test_oracle_piv_policies.py` independently enforces freshness and presence and injects reusable ALWAYS grants, ignored touch and PIN consumption on refused touch.
- [x] `FE05, FE14`: `store-state` decrypts independently keyed identity/store tags, checks fresh IVs, create/update/delete changes, unchanged tags after refused updates and assertions, deleted-credential blob-key refusal, encrypted-member absence after reset and a fresh identity/store/grant after reprovisioning. `test_oracle_store_state.py` falsifies fixed IVs, missing/spurious store-tag changes and a reset retaining its identifier.
- [x] `T06, T07, T08, T09`: `hid-operations` covers processing/UP/final-response scheduling with real independently verified ML-DSA-44/65/87 regression results, including algorithms the RS-Key profile defines without advertising. Missing stages are reported as unobserved rather than invented. Together with `transport-boundaries`, `hid-sequences` and `cursor-matrix`, it records KEEPALIVE timelines/idle windows, foreign continuation ownership, WINK/LOCK parameter/expiry behavior, broadcast/owner INIT, foreign WINK/release/CANCEL, refresh and explicit owner release. `test_oracle_hid_processing.py` and `test_oracle_hid_operations.py` exercise the actual report assembler.
- [x] `T10, T14`: `usb-ccid` records native bulk packets and actual USB control-transfer ABORT/STALL, matching/foreign slot/sequence cases during time extension, removal during consent, exact rebinding and uncertain-signature recovery without replay. Private signatures and counters detect lost keys and duplicate execution. `pcsc-grants` checks every PIV PIN/management, OpenPGP PW1.81/PW1.82/PW3 and OATH code/PIN grant subset across end-transaction/reconnect and leave/reset/unpower, with retained private keys/fields/HOTP controls. Synthetic native endpoints and reader peers falsify cancellation, grant retention/revocation, key loss and duplicate execution. `ccid-matrix` separately covers whole-message header/body/declared-length/trailing/idle-command faults. These layers are not interchangeable; hardware execution remains pending.
- [x] `T15, Y07`: `otp-transport` covers feature sequencing/CRC/restart/response abort; `otp-waits` observes actual UP-needed, reset/dummy abort, complete command supersession and partial/bad-CRC frames that must preserve the wait. Program sequence, flags, the independent serial and the stored HMAC secret remain witnessed. `test_oracle_otp_waits.py` falsifies stale private output after abort, invalid-frame cancellation and replacement that retains the old wait. Cross-transport presence ownership remains in X05.
- [x] `T11, T12`: `apdu-dispatch` checks every CLA byte on SELECT and a harmless command in all eight RS-Key applets, explicitly observing unserved classes as empty CCID blocks. Per-applet malformed short/extended Lc and unknown INS have distinct reader/parser/class refusals and valid controls. Command chains cover zero/boundary/overflow accumulation, distinct 2048-byte object and 3072-byte chain ceilings, wrong CLA/INS/P1/P2, same/other/refused SELECT, unserved classes, idle persistence and repeated final commands. `piv-objects` and `piv-pool-capacity` separately check object and full-store quotas; store capacity is never inferred from a chain refusal. `test_oracle_apdu_dispatch.py` falsifies fabricated status words, premature abandonment and swapped ceiling errors.
- [x] `F12`: `assertion-matrix` adds mandatory/optional presence, empty/hash/RP byte boundaries, ASCII whitespace versus opaque Unicode/NUL RP strings, option maps, independent protocol/MAC failures and exact per-credential counter changes. Each accepted result is independently signed; refusals retain the key and retry budget. `test_oracle_assertion_matrix.py` falsifies accepted field defects and counter consumption on refusal.
- [x] `F13, F15, F16`: `cursor-matrix` additionally checks owned deletion/replacement/creation, card-command and card-continuation isolation, reconnect/card-reset/USB-rebind/cold-power outcomes and deleted-key refusal. Mutation grants are issued before Begin so issuance cannot mask a mutation's effect. `test_oracle_cursor_matrix.py` uses shared synthetic transports and independently held key/channel/cursor state; exact continuation and expiry checks are described above.
- [x] `F21, G01, G03, G10, G13, G14`: `config-factory` witnesses an unset PIN after a permitted reset, then checks every standard/vendor CONFIG command against absent/unsupported/supported protocols and missing/empty/short/full/long authentication bytes. Unset PIN does not bypass the required configuration grant. Every refusal preserves public policy and an independently retained credential signature; the original supplied PIN is reprovisioned from observed factory state. A peer falsifies the no-PIN authorization bypass.
- [x] `G10, G11`: The shared HID/card attempt guard also accounts for local PIN use by makeCredential/getAssertion, including alwaysUv and unknown policy after reconnect. A supplied host authenticator and parser-invalid UV flag do not spend a local-entry budget. `test_oracle_local_attempt_guard.py` first reproduced unintended second/third transmissions, then proves pre-I/O blocking on both routes and bounded intentional failures. `uv-block` now refreshes policy after power changes and witnesses factory policy before its no-UV deleted-key recovery probe.
- [x] `F21, G01, G03, G04, G05, G06, G08, G10, G13, G14`: `config-grammar` authenticates each original nested CBOR span and checks raw 384-byte bounds, unsigned widths/overflow, strings/UTF-8, absent/empty/type/array/count cases, nested ordering/duplicates, indefinite known containers, skipped values/tags and truncation. Unknown vendor IDs and an invalid monotonic floor keep parser controls from replacing hidden RP authorization lists. The same configuration grant, public policy, retry record and retained private key witness each refusal. `config-vendor` checks the exact complete vendor-ID catalog and each PHY integer ID's omitted/default/full-u64 truncation, replay, bad MAC, shared lock and stored-versus-boot-effective values. Invalid wiring/identity integers are restored before boot. Independent byte-walker and PHY peers falsify canonicalized MACs, overflow/type confusion, incorrect RP filtering, missing IDs, overflow refusal, immediate application and lock bypass.
- [x] `F21, FE12, V06`: The enterprise suite now authenticates positive CONFIG with a real configured host-PIN grant. Its vendor RP-list product covers both protocols, empty/replacement/duplicate lists, count and exact raw-byte boundaries, opaque Unicode/NUL and separately invalid makeCredential RP strings, replay, rejected-MAC preservation, actual type-1 chain/signing eligibility and all connection lifetimes. Unreachable empty/oversized RP hashes are not claimed as directly readable stored bytes. Independent peers falsify ignored count/raw limits, empty-list retention and wrong eligibility/signing. Seed/soft-lock and populated identity-chain state products retain their separate open clause below.
- [x] `FE06, FE07, FE08, FE09, FE10, FE12`: `extension-matrix` checks largeBlob deletion/replacement/connection lifetimes, reused-slot isolation, exact CDDL, storage/integer ceilings and unchanged prior values after refusal; payment opt-in/request/credProtect/host-local-no-UV/UP products and signed UVM provenance; ordinary attestation format/list/type boundaries and certificate signatures. `preview-sign` checks ARKG argument/handle/type/length grammar, omitted/default/reserved flags, algorithm negotiation, UP/UV policies and actual derived signatures. `test_oracle_extension_matrix.py` and `test_oracle_preview_matrix.py` falsify leaked slot blobs, overflow acceptance, ignored format/presence policies, reused arguments and wrong signatures. Policy RP disclosure, local UV, largeBlobKey deletion and encrypted store state have separate witnesses above.
- [x] `U02, U03, U04, U05, U06`: `u2f-semantics` covers fixed REGISTER/body and foreign-handle/control bounds, global counter isolation/persistence, card/HID/vendor-selection and reboot lifetimes, owner/foreign cancellation and withheld presence with retained handles/counters. `test_oracle_u2f_presence.py` runs the actual HID assembler with real attestation/signature results and falsifies foreign cancellation and a refused operation consuming a counter. `test_oracle_u2f_semantics.py` separately falsifies REGISTER refusal and per-handle counter defects. Reset/seed revocation has its own populated-key witnesses.
- [x] `P01, P02, P03, P04, P05, P08`: `piv-references` expands unknown metadata/attestation references, metadata parameters, full/truncated/refused SELECT preservation, binary/NUL/FF-padded PIN/PUK changes, old-secret versus invalid-replacement ordering, malformed/reference/mode cases, both-grant retry-policy authorization, zero/full-byte bounds and cold-power persistence, and blocked-PUK refusal with authenticated recovery. Existing VERIFY/boundary suites retain real private-key controls. `test_oracle_piv_references.py` falsifies revoked grants after refused changes/SELECT and lost keys on policy changes. Same PIV SELECT preserves status; a final wrong comparison answers `6983`, both corrected against current source and regression evidence.
- [x] `P06, P07`: `piv-matrix` exercises single/mutual handshakes under 3DES/AES-128/192/256, old-key rejection, replacement challenges, response widths, scheme/replay/missing-step cases, SELECT/VERSION/metadata/unknown/GA lifetimes and short-host-challenge grant ordering. Every outcome has a protected-operation witness. `piv-references` checks rotation grammar/auth refusal and management-touch confirmation/decline/timeout with restoration. The independent peers perform actual symmetric cryptography and retained-key operations.
- [x] `P09, P10, P11, P12, P14, P15, P16, P17`: `piv-matrix`, `card-keys`, `piv-policies`, `piv-references`, `piv-moves` and `cross-reset` combine malformed populated-key controls, the complete slot/algorithm/origin/PIN/touch product, private-operation widths and freshness ordering, cached-touch refusal after idle and connection transitions, generated/imported/deleted/protected attestation references, stationary certificates and moved policies, and reset revocation with neighboring private-key preservation. An empty private-operation fixture now names a confirmed empty asymmetric slot, rather than a PIN/PUK reference.
- [x] `O01, O07`: `openpgp-kdf`, `openpgp-aes`, `openpgp-certificates`, `openpgp-recovery` and `openpgp-reset-profile` cover routed policy/secret/reference lifetimes, all certificate occurrences, permanent UIF and complete routed reset defaults. Every connection action has persistent-value and private-operation controls; reset additionally checks absent AES, raw factory references, reset-code removal, disabled KDF and each permanent-policy default.
- [x] `O02, O03, O04, O05, O06`: `openpgp-references` covers every reference byte, VERIFY/status/logout/CHANGE modes, old/new-value precedence and independent access latches with a real SIG witness. `openpgp-recovery` covers all three retry policies, zero/full-byte values, malformed/auth failures, reset-code widths/modes, bounded blocking and retained keys after each connection action. `openpgp-reset-profile` adds persistently blocked PW3 and its authorized reset escape. Independent peers falsify shared-counter, lost-key and grant-revocation defects.
- [x] `O14`: `openpgp-mse` uses distinct populated DEC/AUT keys to check both templates and references, P1/P2/reference/tag/length/truncation/tail grammar, MSE versus consumer authorization, independent signatures/ECDH, unaffected opposite mappings and SIG counters, same/refused/different SELECT and all connection lifetimes. The selected key's UIF is independently varied against the other slot for confirmation/decline/timeout. `test_oracle_openpgp_mse.py` falsifies ignored/reset mappings, command-slot UIF and PW3 overriding PW1.82.
- [x] `O11, O12, O13, O19, O20, O22`: `openpgp-operations` checks raw RSA/EC/EdDSA width products and independently verified signatures; `openpgp-decipher` checks RSA padding/integers/indicators, EC TLV/point encodings and X25519 low-order refusal. `openpgp-operation-state` checks empty keys, parameter precedence and counter persistence/SIG-only replacement resets. `openpgp-uif`, `openpgp-uif-fixed` and `openpgp-attestation` cover disabled/enabled/permanent policies, confirmation/decline/timeout, each grant, distinct SIGN/ATTEST one-shot boundaries, generated/imported/empty subjects, issued certificates and retained private keys. Fault peers falsify wrong signatures, padding acceptance, lost grants, counter resets and imported attestation. Release-library vectors independently cross-check the pinned P-521 prehash rule; no debug-only assertion is claimed as firmware behavior.
- [x] `O15, O16, O18, O21`: `openpgp-aes` checks key/block/ACL/UIF grammar, AES known answers and persistence independent of DEC import/replacement/deletion/generation and MSE. `openpgp-certificates` checks every occurrence, exact selector grammar/precedence, refusal-preserved cursor and connection lifetimes. `openpgp-kdf` checks fixed field layouts, opaque host metadata, incompatible old verifiers, reset-code retirement, rejection beside every owner slot and private use after KDF/key installation and reboot. `openpgp-reset-profile` checks missing AES, TERMINATE preconditions, the terminated command catalog, terminated SELECT/reconnect and repeated active ACTIVATE. Source-backed KDF refusal also has an observed existing Rust regression.
- [x] `A01, A02, A03, A04, A13, A14`: `oath-commands` applies CLA/P1/P2/grant products to each known command with otherwise valid fields, exact private-field and HOTP witnesses. `oath-presence` checks CALCULATE/VERIFY CODE confirmation, decline, panel cancel and timeout, HOTP/increasing-state preservation and code-less OTP-PIN consent. `test_oracle_oath_commands.py` falsifies class/parameter/code-gate bypasses; `test_oracle_oath_presence.py` falsifies ignored presence and state changes on refusal. Secret/digit/property products and challenge-width controls have separate suites.
- [x] `A04, G03, G07`: `oath-challenges` checks empty/short/max/overflow challenges under every code/PIN grant state, full/truncated replies, absent/reordered/nested/duplicate/unknown/truncated/long-form TLVs and exact HMAC bytes. Individual CALCULATE rejects extra fields; CALCULATE ALL ignores its trailing bytes. Private-record grants, fields and the neighboring HOTP counter remain witnessed. `test_oracle_oath_challenges.py` falsifies both wrong tail policies and grant revocation.
- [x] `A05, A06, A07, A08`: `oath-pages` checks exact LIST/CALCULATE ALL reconstruction, exhaustion/restart, unauthorized begins, ignored continuation parameters/body, class refusal versus dispatch retirement, record/code/PIN mutations and SELECT interruptions, with independent code/PIN grants, private fields and HOTP controls. `test_oracle_oath_pages.py` falsifies stale pages, premature retirement and cross-grant loss. Committed/uncommitted uncertain HOTP recovery and mixed touch/HOTP bulk output are checked by `oath-semantics` above.
- [x] `A09, A10, A11, A14, A15`: `oath-pin-matrix` checks first-match/missing/nested/truncated/reordered/duplicate/long-form TLVs, opaque/empty/binary PIN bytes, authorization retirement after PIN changes, and private record/code/PIN/HOTP persistence across each connection action. `test_oracle_oath_pin_matrix.py` falsifies PIN truncation, malformed-input grant loss, retained grants after change and lost private fields. Rename grammar is listed separately below.
- [x] `A09, G07, G08, G13`: `oath-rename` checks absent/truncated/nested/reordered/duplicate/unknown/long-form TLVs, compact property handling, byte/UTF-8/binary/NUL name bounds and authorization/grammar/reference precedence. An already-used HOTP record retains its moving factor, secret and every private field. `test_oracle_oath_rename.py` falsifies a reset moving factor and dropped password fields.
- [x] `Y02, Y03, Y04, Y05, Y06, Y07, Y08, Y14`: `otp-commands`, `otp-swap`, `otp-challenges`, `otp-lifetime` and `otp-waits` check all slot/mode/single-flag boundaries, configure/update/delete grammar and authorization order; behavior of occupied and absent slots; all valid swap pairs and code/occupancy combinations; code changes across connection actions; exact HMAC/AES challenge results; padding/length/mode gates and observed wait/cancel/abort behavior. Program sequence, mode flags, retained secrets and cleanup ownership distinguish rejection from a committed write. Native feature-report SWAP is explicitly refused by the current profile's fixed 64-byte framing; CCID uses the supported variable body layouts. Fault peers falsify no-op swaps, wrong slot contents, CRC and cancellation errors.
- [x] `Y01, M03, M05, X08`: `otp-disabled` checks immediate dispatch refusal on an already-selected card applet, every feature function becoming inert, retained serial/extended status/DeviceInfo reads on all writers, reachable re-enable paths and exact keys afterwards. Each slot's disabled gesture is silent and cannot consume its HOTP moving factor. A separate case distinguishes stale unsolicited feature status from refresh after a completed feature command. `test_oracle_otp_disabled.py` falsifies card/feature/keyboard bypass, hidden slot deletion, invented live caches and silent counter consumption.
- [x] `Y09, Y10, Y11, Y14`: `keyboard-matrix` checks every slot's raw static bytes, modifiers, exact US text, length, CR/TAB and stored/inert pacing flags. `keyboard-counters` independently decrypts Yubico OTP/CRC/session/use counters, verifies HOTP digits and programmed counters across updates/reconfiguration/swaps/connections, observes intentional partial host capture without inventing device interruption, and crosses all 257 session positions. Fault peers detect counter replay/reset and RAM state failing to follow a swapped record.
- [x] `Y13, Y14`: `otp-admin-matrix` checks NDEF/legacy-mode/scan-map length and truncation behavior, fixed feature versus variable card payloads, every programmed slot's access-code gate, mixed-code refusal and strict-build no-ops. Scan-map effects are verified through actual decoded HOTP output in every slot after every connection action. NDEF/legacy records are explicitly opaque and inert on this USB-only profile: their acknowledged sequence change is not presented as a readback of stored bytes. The independent peers falsify single-slot authorization of a global map, strict-build writes and lost maps on reconnect.
- [x] `Y12, Y14, X05`: `button-gestures` independently programs four empty static slots and observes full unsolicited keyboard windows for 1-5 and 255/256/257 clicks, long holds, a press held across the prior window, separate repeated gestures, 999/1000/1001-ms sampled boundaries and dispatch-consumed presses. Both a presence press held through completion and a command interrupting an unfinished idle gesture must remain silent; the next independent click must still type. A sensor-backed trusted adapter supplies bounded host-clock edge intervals and, for exact boundaries, actual device-sample times. Actuator ACKs cannot substitute for input evidence; electrical-only boundary captures remain inconclusive. Nine independent sensor/report regressions falsify inclusive deadline comparison, counter wrap, firing while held, leaked consumed presses, permanent suppression and incomplete observation. Nine existing host Rust click tests separately check exact state-machine boundaries. A software-emulator keyboard without a physical button is not presented as a gesture source.
- [x] `M01, M02, M04, M05, M06`: `management-matrix` checks page/body reads, every writable tag's widths/partial/duplicate/unknown/reserved-bit behavior and exact deltas. `management-state` adds every owner/writer lock pair with missing/wrong/empty/short/long/correct code, identical locked writes followed by a real mutation control, confirmation/decline/panel cancel/timeout, and strict-build disabled writers. `cross-reset` proves shared configuration and lock enforcement survive every applet reset; `management-enforcement`/connection cases check the remaining connection actions. Directed peers falsify no-op lock bypass, missing consent and strict-interface bypass.
- [x] `M03, V09, R03, X08, X11`: `usb-identity` expands every byte-valued interface mask through rescue staging/explicit warm boot and native FIDO PHY auto-reboot, while changing VID/PID/product/manufacturer. It verifies stored fields before boot, actual USB classes/order and HID usages after observed disconnect, manageable-mask fallback and the surviving FIDO/CCID restoration route. Initial selectors and all candidate states must resolve uniquely; before any PIN/config write, a freshly challenged signature proves the original UV-optional private credential on the rebound endpoint. Baseline VID/PID/mask overrides are retained only when the protocol cannot delete formerly absent numeric fields. Complete PHY/topology restoration, VID-dependent ATR/OpenPGP manufacturer and stable OpenPGP serial/version are checked. A failed restoration halts following mutations. Native synthetic endpoints falsify ignored masks, lost keys, replayed continuity proofs, stale public identities and corrupted restoration; pure selectors reject neighbors/ambiguity and wallet targets before enumeration. This is an explicit native-only suite with no OTP/keyboard handles; no hardware transition has been run.
- [x] `R03, V09, G01, G03, G04, G05, G07, G08, G13, G14`: `phy-records` walks every defined PHY field's widths/byte bounds, both string fields' byte/UTF-8/NUL limits, duplicate order, unknown/nested fields, incorrect/truncated lengths and BER-versus-PHY length ambiguity. Its independent one-byte overlay expectation accepts the valid prefix before truncation, matching the profile rather than inventing an atomic refusal. Complete stored-field comparisons and a retained secp256k1 device-key signature witness every case. Deliberately invalid wiring/identity values are staged through rescue and restored before any reboot. A previously absent numeric field requires an explicit known boot default; its retained default override is reported because the protocol cannot delete numeric tags. Fault peers falsify first-wins, atomic rejection, UTF-8 filtering, failed string clear and device-key replacement.
- [x] `V01, V02, V03, V05, V06`: `mse-lifetimes` checks every consuming vendor operation plus AUT_ENABLE across owner/foreign CIDs and both FIDO routes. Parser-invalid requests retain the original usable channel; semantic consumer failures spend it. Repeated semantic MSE requests vacate a live channel before coordinate/KEM checks. COSE metadata is explicitly ignored, an empty KEM field selects classical ECDH, fresh handshakes change the ephemeral point, and real AEAD exports bind to the supplied coordinates. Seed/lock/organization state and retained private credentials witness recovery. Independent peers falsify foreign ownership, retained consumers, premature parser consumption and reused ephemeral points.
- [x] `V01, V06, U02, G03, G04, G05, G09, G10, G11, G13, G14`: `identity-chain` tests imports over an actual populated organization identity on both PIN protocols: DER sequence counts/lengths/truncation/tails/non-minimal headers, the exact 2132-byte profile ceiling, authorization and invalid P-256 scalar precedence, and MSE consumption witnessed through UNLOCK rather than an export that could be sealed. Exact packed-chain commitments and real U2F signatures witness the retained/replaced scalar and leaf bytes. Empty/non-X.509 sequences, untrusted/reversed chains and scalar/leaf mismatch are explicitly accepted by this framing-only profile, with failed certificate-key verification recorded for the mismatch. No invented semantic certificate refusal hides that behavior. Independent peers falsify excessive validation, reversed validation order, retained MSE and a refusal deleting the populated identity.
- [x] `V01, V02, V03, V04, V05, V06`: `seed-matrix` checks both PIN protocols, all authorization shapes, real AEAD/scalar/length failures, named confirmation refusals, independent PIN-less LOAD prompts and the import-only FIPS policy with an exact imported-key certificate/signature witness. `seed-lifetimes` checks imported classical/hybrid seeds and original MSE channels over same/other/invalid SELECT, card/session/USB reconnect, observed warm reboot and actual power-cycle boundaries. It distinguishes flash lock from RAM unlock, locked/unlocked command availability, invalid/repeated unlocks, populated AUT_DISABLE authorization, consent, exact cleanup and seal/lock interactions. FINALIZE needs no MSE, does not consume one on refusal, remains sealed across those boundaries, allows LOAD, and reopens only after an observed authenticatorReset. `identity-reset` wraps the actual PIV/OpenPGP/OATH/FIDO reset handlers with an installed organization key, requires a completed reset exchange and proves the same private signing key and packed chain afterward. Directed peers falsify authorization, scalar, old-reference, prompt, RAM, channel, seal, certificate and identity lifetime failures. The existing 106 Rust vendor host tests also passed, including persistent-write restart/cut tests. These are offline implementation checks; no physical lifecycle was executed.
- [x] `V13`: `vendor-measurements` expands shipping and explicitly declared measurement profiles independently for CORE1_STATS, KEYGEN_BENCH, BENCH and STACK_RESIDUE. It checks ignored parameters/body, length-before-selector precedence, candidate/pattern boundaries, exact summaries and sample counts through warmup exhaustion/overflow, OTP batch divisors, scan bounds and no measurement bytes on refusal. Declared sweep-stop cases always request restart during cleanup; acknowledgments are not claimed as a proof of prior pause state. Independent peers falsify shipping exposure, unsigned warmup underflow, wrong divisors and persistent counter mutation.
- [x] `V09, G07, G14`: The existing `vendor` config scenario now distinguishes an incomplete PHY no-op from a short LED refusal, and preserves raw stored bytes in both paths. `test_oracle_vendor_config.py` first reproduced its incorrect blanket-refusal expectation, then falsifies accepted short LED input and lost PHY fields. Unexpected grammar or record changes stop the session before another mutation is attempted.
- [x] `V07, V08, V09, V10, V11, V12`: `audit-access` checks both PIN protocols' authorization failures before touch, PIN-unset consent/refusal, exact journal windows, signed pre-command head/sequence/nonce, nonce-replay refusal, repeated checkpoints and opt-in/history persistence. `vendor-records` distinguishes raw stored LED bytes from complete live normalization, short/trailing bodies, all P2 bytes and optional effect/speed fields, strict/default authorization/consent, selector/length/lock precedence and connection persistence. `vendor-counter` checks shared HID/card state, consent/refusal recovery, ignored parameters/body, unsigned wrap, connection persistence and committed/uncommitted response loss without replay. Directed peers falsify ACL/consent bypass, wrong nonce binding, raw/live confusion, wrong tail policy, lost history/LED/counters, separate counters and duplicate execution. Actual changed PHY identity/interface application retains its separate open clause above.
- [x] `V01, V02, V03, V04, V06, V07, V08, V09, G10, G14`: `vendor-local-pin` checks the separate display PIN without a configured clientPIN on both routes: correct entry, decline, cancel, timeout, one bounded mismatch and correct recovery; a headless build must preserve the gate. Exact public refusal/state/private-key witnesses never present clientPIN retries as the device-PIN retry record. Six existing Rust vendor-pad tests independently check the private record, including exhaustion, non-entry preservation and correct recovery; the existing headless-gate regression also passed. The shared attempt guard conservatively accounts for this potentially hidden PIN until `--device-pin-state unset` is explicitly declared. getInfo's `uv` describes EF_PIN and cannot establish absence of EF_DEVICE_PIN. Directed peers falsify a repeated unplanned transmission, skipped local gate, spent host retries and lost retained keys.
- [x] `R02, R03, R05, R06`: `rescue-presence` checks SIGN/certificate/PHY/BOOTSEL confirmation, decline, panel cancel, timeout and malformed-body-before-consent ordering, plus the shared lock's refusal of identical and changed PHY writes. Each path retains an independently verified device private key and complete staged PHY state. `phy-persistence` checks all fields and the private key after every connection action. `rescue-reboot` observes the complete ACK before an actual native USB disconnect, exact normal-mode rebinding and retained signatures, for both rescue/vendor and warm/BOOTSEL paths. `rescue-recovery` checks the complete recovery whitelist, ordinary AID exclusion, allowed RTC/status reads, selector/magic precedence and consent refusals on explicitly prepared empty/legacy/occupied/incompatible fixtures. The occupied profile has existing authenticated authority; the incompatible profile has an authenticated authority/partition contradiction causing a storage error. Neither profile is inferred from the ready bit. Existing host Rust checks independently prove refusal preserves flash bytes (5 storage API tests) and maps storage errors without rebooting (2 rescue tests). Positive fuse writes remain excluded. Actual USB identity/interface changes retain their separate implementation clause above.
- [x] `X01`: `cross-authorization` checks all 60 foreign authority/target combinations across PIV PIN/management, three OpenPGP references, OATH code/PIN/both, FIDO ACFG/read-only, OTP access code and management lock code. Targets contain actual keys, private fields, records or armed locks, reject foreign authority, and succeed under their own authority. Independent peers falsify grant transfer into PIV/OpenPGP/OATH/FIDO and management. Intra-applet independent grant combinations have their separate reference/PIN suites above.
- [x] `X03, X04`: `cross-walks` covers both route directions, all three populated walks, both protocols and ordinary/read-only tokens. Foreign continuation refusal must preserve the owner's complete signed walk and the device-wide token. MSE has its consuming/parser/owner-route products and original-channel lifetime tests above; counter/config/OTP routes have exact shared-state witnesses. `cross` alternates two actual incorrect FIDO PIN comparisons across HID/CCID, observes the same persistent retry decrements and restores the budget with the known PIN; one transport does not invent an additional budget.
- [x] `X07`: `cross-quota` independently fills OATH records, FIDO residents and PIV pool byte/record quotas, observes each source's actual exhaustion and reclaimed slot, then creates and uses neighboring objects. It fills all four OTP and all three regular OpenPGP key slots with distinct keys and proves private operations plus later object creation while they are occupied. Full source contents, private controls and final owned-object cleanup are checked. Directed peers falsify OATH-full blocking PIV, FIDO-full blocking OATH and PIV-full blocking OpenPGP. The separate attestation identity is not treated as a regular user slot.
- [x] `X09`: existing `cross` schedules HID beside RSA generation and verifies the generated key. `cross-processing` additionally runs all three actual ML-DSA sizes for creation/assertion against each PIV/OpenPGP/OATH public operation, requires observed PROCESSING, verifies exact competing results and original private signatures, and records callback timing limitations. Faults reach wrong-result/signature assertions; a missing processing observation cannot establish overlap.
- [x] `X12`: `cross-rejections` establishes private PIV/OpenPGP/FIDO/OATH/OTP fixtures and an enforcing management lock before unknown-instruction and known-command parser/authorization/semantic refusals in all eight confirmed RS-Key applets. It then verifies all existing private neighbors and the complete shared configuration without recreating their keys. Fault peers delete a neighboring private key or remove the management lock on refusal and fail their subsequent private/lock witnesses. External vendor AIDs are excluded from this confirmed RS-Key command catalog.
- [x] `X02, X03, X11, G09, G10, G11, G14`: `cross-walks` checks 96 route/protocol/token/walk/SELECT combinations with actual populated continuations, foreign-route refusal, complete owner enumeration and retained private credentials. `extended-lifetimes` checks all PIV PIN/management, OpenPGP PW81/PW82/PW83 and OATH code/PIN grant subsets across same/different/invalid SELECT, native USB bus reset and CPU warm boot; FIDO adds ordinary/persistent tokens, encrypted identity/store state and PIN ECDH lifetime. The native path avoids an intervening card SELECT before grant observation and proves the original private credential with a fresh nonce before PIN/config writes. OATH pages additionally retain exact content, grants and moving factors after an invalid AID; separate MSE/certificate suites witness their selected references and challenges.
- [x] `X05, G10, G12, G14`: `cross-presence` covers every supported cross-scope cancellation pair among FIDO, CCID and OTP HID, all four touch-capable CCID applet owners, actual CCID time extensions / FIDO UP-needed / OTP pending reports, foreign request busy/echo behavior, owner-only cancellation and independently confirmed private/counter controls. Unmatched FIDO/OTP serials and absent native scheduling surfaces are excluded before fixture writes. Independent peers falsify each of the six foreign cancel directions; host callbacks are not device presence timestamps.
- [x] `X08, X11, M02, M03, M04, M05, M06, G10, G11, G14`: `config-lifetimes` installs a real disabled-applet mask, flags and known management lock through each enabled writer, then traverses all nine SELECT/session/card/USB/warm/power boundaries. All selected readers must return the entire original changed configuration; actual disabled OATH dispatch, locked real mask changes and an original private FIDO credential witness enforcement before known-code restoration. USB bus reset is a selected-device libusb API, distinct from handle reconnect and physical power loss; reset/reopen includes ICC power-on and does not locate the CPU reset instant.
- [x] `X10, G09, G10, G11, G12, G14`: `unknown-slots`, `unknown-secrets` and `unknown-fido` add OTP create/replace/update/delete/access-code changes in every slot, all six SWAP pairs, whole management field/lock transitions, bounded PIV PIN/PUK/OpenPGP/OATH secret recovery, both FIDO PIN protocols, resident create/replace/update/delete, partial/final large-blob writes and CONFIG policy changes. Each unknown mutation is sent once before explicit old/new readback, private controls and known-state recovery. An unrecognized verifier, partial swap/configuration or corrupt private state halts cleanup and further mutations. PUK has no VERIFY API: its bounded CHANGE-to-original recovery is explicitly recorded and differs from the lost CHANGE-to-new request.
- [x] `X10, R02, R03, R04, Y13, G11, G12, G14`: `unknown-admin` checks whole staged PHY records, bounded running RTC windows and actual keyboard effects of a lost scan-map update. Device certificate, NDEF and legacy-mode records without a decisive export/effect retain an explicit unknown commit/partial outcome after independent private neighbor controls; a SELECT-reset program sequence is never durable commit evidence. Prior write-only custom maps/certificates cannot be restored and the retained known fixture/default is reported.
- [x] `G09, G14, F12, U04`: `foreign-references` consumes bounded, offline signature-checked FIDO2/U2F public proof bundles, requires a different observed target USB serial, distinguishes declared distinct/same/unknown seed relations and verifies the original key for accepted portable references. Unknown serial/seed provenance is not invented; the source device is never opened by this suite. Malformed proofs fail before discovery. Same-device serials are blocked before fixture writes.
- [x] `X10`: `unknown-resets` covers OATH/PIV/FIDO reset and OpenPGP TERMINATE/ACTIVATE with complete old/new reset tuples, old-key/grant revocation, factory private controls and original private neighbors/shared locks. A blocked old PIV key is explicitly unobservable until a decisively uncommitted reset is recovered. `unknown-boot` covers prepared empty/legacy storage setup and rescue/vendor warm/BOOTSEL reboot. Setup reads readiness and available private state but cannot certify whole-media migration; reboot rebinds the exact key and proves the original FIDO private credential before PIN/config use but cannot infer a CPU/BOOTSEL event from a lost ACK. These outcomes retain `unknown`, with no unknown setup/reboot retry. Committed/uncommitted, partial reset, lost neighbor and retained-grant peers falsify the recovery controls.

The timing and artifact clauses use the same normal recorder entry points.
`--warmups` retains complete fixture cycles separately from measured samples;
session-open/reconnect/card-reset and reported/emulated power boundaries have
separate populations. Operator reports never establish physical cold-boot
timestamps. Comparisons suppress latency ratios for unmatched fixtures,
warmups, host/backend contexts, scenario contracts and failed/different results.
Quantile/MAD, censored waits, dropped events, incompatible contracts and raw
capture preservation have offline regressions. Repeated persistent counters
and irreversible policies remain explicitly changing state, not fabricated
fresh fixtures. Unknown external catalogs and unrun physical checks remain
visible independently of this implementation audit.

### Execution permissions

Listing a destructive scenario does not authorize its execution. Permissions
are explicit per device: test-data writes, PIN-attempt consumption and blocking,
applet reset, factory identity replacement, power interruption, and irreversible
provisioning are separate permissions. A broad suite selection must not imply
all of them. Ordinary hardware runs exclude positive OTP fuse operations.

The model and firmware inventory, permitted effects, host platforms, and
available observation layers must be fixed before hardware execution. This
design adds no implementation, dependencies, CI gates, registries, or device
operations.
