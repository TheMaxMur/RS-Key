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

The implementation is **incomplete**. The former zero-missing-families result
only established catalog membership. These checkboxes refer to the named
clauses, never to an entire family. Checked clauses have executable scenarios
and offline regression evidence; hardware execution remains pending. Unchecked
clauses are implementation work, not capability exclusions or permission skips.
The `plan` and capture coverage reports include the unchecked clauses verbatim.
A family without an unchecked clause is still `not_certified`, since absence
from this list does not establish a clause-by-clause completeness proof.

- [x] `G02, G14`: `fields.*` varies each parsed outer and nested field's CBOR type across makeCredential, getAssertion, clientPIN subcommands, credential management, largeBlobs, config and RS-Key vendor commands; verify exact type error, unchanged PIN retries and public FIDO state. This does not cover every presence, length or semantic combination.
- [x] `T04, T05, T06, T08`: `transport.assembly.interval-*`, `transport.assembly.foreign-CID-continuation` and `transport.KEEPALIVE.after-completion` cover scheduled completion around the RS-Key assembly deadline, foreign continuation isolation and an explicit idle observation window. Record host write intervals and uncertainty; do not assert exact device arrival at 500 ms.
- [x] `T11, T13, O07, O17`: `transport.APDU.case-*`, `transport.APDU.response-chain.*` and `openpgp.GET-CHALLENGE.*` cover short/extended cases 1-4, Lc/Le boundaries, exact response reconstruction, no-pending/final-repeat continuations and valid/refused/SELECT interruptions. `61xx` has its own continuation outcome and cannot satisfy a refusal assertion.
- [x] `FE02, FE03, FE05, FE11, FE13`: `fido.credBlob.visibility.*`, `fido.hmac-secret.isolation.*`, `fido.hmac-secret.member-*`, `fido.largeBlobKey.*`, `fido.extension-type.*`, `fido.unknown-extension.*` and `fido.counters.*` cover absent and non-UV blob reads, secret isolation, repeated evaluations, independently malformed HMAC fields, user-update stability, unsolicited results, and per-credential counters. Connection cases are conditional on an explicit backend.
- [x] `A05, A06, A07, A08`: `oath.HOTP.initial-*`, `oath.increasing.equal-bulk-reselect.*` and `oath.paging.*` cover 32-bit IMF boundaries, bulk/error counter preservation, equal/decreasing challenge refusal, bulk high-water marks, reselect/power persistence and continuation retirement. Tests do not claim an unreachable 64-bit HOTP wrap.
- [x] `R01, R04, R05, R06`: `rescue.READ.selector-*`, `rescue.refuse.*`, `rescue.RTC.civil.*`, `rescue.RTC.refuse.*` and `rescue.RTC.power-cycle-unsets` cover profiled selectors, civil writes, leap/month/year/epoch limits, normalization, ignored weekday, refusal preservation, and unset RTC after power loss. RS-Key normalizes short-month overflow and leap seconds; it must not be tested against an invented strict-date refusal.
- [x] `P05, P16`: `piv.puk.block-unblock` checks wrong PUK without unblocking the PIN, then correct recovery; `piv.reset.preconditions-and-factory-state` checks that blocking only PIN cannot authorize reset. Recovery uses the known PUK even when an assertion interrupts the fixture flow.

- [ ] `G01, G03, G04`: Expand presence, empty values, all profile-derived bounds and reserved/overflow values for every parsed command and subcommand, beyond the existing targeted vectors. Typed-field expansion does not discharge these dimensions.
- [ ] `G05, G06, G07, G08`: Apply truncation/trailing data, CBOR ordering/duplicates/indefinite encodings, TLV grammar and UTF-8/code-point boundaries to the remaining command schemas with correct single-defect controls.
- [ ] `G09, G10, G11, G12, G13, G14`: Complete deleted/replaced/foreign-reference, authorization-lifetime, lost-response, interruption and selected validation-precedence cases with populated-object and state/counter/cursor witnesses for each applicable command.
- [ ] `T01, T02`: Record discovery/open failures as cases and cover INIT during an outstanding operation and reserved/unallocated CID behavior, with subsequent owner-channel recovery.
- [ ] `T06, T07, T08, T09`: Complete processing-stage cancellation and completion races, all applicable KEEPALIVE transitions, concurrent continuation ownership, and WINK/LOCK parameter/expiry interactions. The new idle window only covers post-completion reports.
- [ ] `T10, T14, T15, T16`: Implement raw CCID malformed-length/abort/removal injection where the backend permits it; complete PC/SC sharing/disposition cases, OTP feature-report sequence/busy/cancel faults and Part 10 structure/display/grant postconditions. A PC/SC APDU cannot substitute for raw USB evidence.
- [ ] `T11, T12`: Finish unsupported CLA/INS and malformed APDU encoding combinations per applet; distinguish chain-buffer overflow, object-size refusal and total-store capacity, including abandonment controls.
- [ ] `F01, F02, F03, F04, F05`: Complete getInfo change/consistency witnesses, key-agreement lifetimes, set/change PIN encrypted padding/MAC/point failures, minimum/maximum Unicode PINs, wrong-old/same-PIN paths and preserved credentials. Structural type rejection alone cannot establish these paths.
- [ ] `F06, F09, F10`: Complete legacy/scoped token permission and RP-binding cases and each PIN-change/reset/replacement invalidation, including ordinary versus persistent read-only grants.
- [ ] `F07, F08, F22, F23, F24`: Complete local UV error/block/cancel/timeout paths, selection competition, reset outside its window and refusal/timeout, and biometric invalid-sequence/cancel/full/authorization cases on profiles that implement them.
- [ ] `F11, F12`: Expand makeCredential option axes and same/different RP/user replacement cases, dynamic credential-ID bounds and capacity recovery with owned credential controls.
- [ ] `F13, F14, F15, F16, F17, F18`: Complete empty/partial/full metadata and owned RP/credential enumeration fixtures, mutation during walks, foreign-CID continuation, unknown/repeated deletion, invalid user updates and capacity reclamation.
- [ ] `F19, F20, F21`: Complete read fragmentation/offset boundaries, partial-write timeout/intervening command/order/length combinations, and configuration permission/MAC/subcommand/value failures with persistent-state controls.
- [ ] `FE01, FE03, FE04`: Add credProtect excludeList visibility and remaining HMAC registration input combinations, including hmac-secret-mc without the required registration opt-in and UV-specific outputs.
- [ ] `FE05, FE06, FE07, FE08, FE09, FE10, FE12, FE14`: Complete nonresident largeBlobKey refusal, blob deletion lifecycle, policy/verification-output combinations, remaining preview/ARKG malformed parameters, attestation format/list boundaries, and store-state update/reset witnesses.
- [ ] `U02, U03, U04, U05, U06`: Complete REGISTER/AUTH length and presence/cancel cases, counters and handle survival across reboot, vendor selection and transport isolation. Reset/seed invalidation already has separate witnesses.
- [ ] `P01, P02, P03, P04, P05, P08`: Complete selection/authentication-state preservation, unknown metadata references, VERIFY padding/length/failure grants, PIN/PUK boundary changes, blocked PUK/invalid replacement and retry-policy rejection/persistence cases.
- [ ] `P06, P07`: Complete single/mutual management-auth challenge ordering, replay/intervening-command failures and key-rotation refusal state. Validate authentication using a protected operation after each outcome.
- [ ] `P09, P10, P11, P12, P14, P15, P16, P17`: Complete malformed key generation/import/private operations, policy/touch-cache expiration and selection/reconnect effects, attestation empty/protected references, MOVE certificate/policy semantics and reset revocation of populated private keys.
- [ ] `P13`: Cover each profile-defined object's ACL, deletion and persistence; measure APDU, chain, individual-object and aggregate-store limits independently.
- [ ] `O01, O07`: Finish each supported DO's read/write ACL, reset value and power-cycle persistence, including read-only/unknown and nested-only forms. Successful GET or a single writable-DO loop is insufficient.
- [ ] `O02, O03, O04, O05, O06`: Complete reference/P1/mode failures, PIN/reset-code boundaries and blocking, retry-policy body/auth failures and reboot persistence with retained private keys.
- [ ] `O08, O09, O10, O14`: Complete invalid algorithm OIDs/sizes, attribute changes with populated keys, malformed CRT/import components, replacement and MSE reassignment policy/authorization effects.
- [ ] `O11, O12, O13, O19, O20, O22`: Complete malformed private-operation inputs, UIF refusal/timeout and one-shot consumption, empty/imported attestation references, and counter behavior after failure/reboot/key replacement.
- [ ] `O15, O16, O18, O21`: Complete AES missing-key/mode/DEC independence, remaining certificate selector failures, KDF with existing keys and reboot/incompatible verifier, and all relevant terminated-state command/precondition cases.
- [ ] `A01, A02, A03, A04`: Complete authentication/selection interactions, PUT secret/digits/flag combinations and challenge/P1/P2/touch boundaries with exact record preservation and known answers.
- [ ] `A05, A06, A07, A08`: Add uncertain/lost HOTP response recovery, touch-policy mixed bulk output and remaining challenge/authorization/page-invalidation combinations. The new counter and page suites cover only their stated clauses.
- [ ] `A09, A10, A11, A12, A13, A14, A15`: Complete rename/identical/full-store cases, access-code algorithm/proof and alternate-path bypasses, OTP-PIN cross-command gates and complete reset cleanup of additional record types.
- [ ] `Y01, Y02, Y03, Y04, Y05, Y06, Y07, Y08`: Complete status/disabled/transport consistency, slot/mode/flag grammar, update/delete/swap/access-code error states and reboot persistence, challenge-response length/mode/presence/cancel cases.
- [ ] `Y09, Y10, Y11, Y12, Y13, Y14`: Complete keyboard layout/modifier/TAB/length, interrupted output and counter persistence, gesture timing/hold/busy/slot selection, admin-record strict-config/reboot behavior and extra-slot gesture/status consistency.
- [ ] `M01, M02, M03, M04, M05, M06`: Complete page/body reads, each writable tag's partial/duplicate/unknown/reserved-bit cases, USB-interface changes, identical locked writes, confirmation bypass and configuration/lock survival across each applet reset.
- [ ] `V01, V02, V03, V04, V05, V06`: Complete every defined MSE failure/reuse and CID case, seed export/load/finalize authorization/refusal/reboot states, locked-boot availability and malformed identity-chain/MSE/permission combinations with preserved identity controls.
- [ ] `V07, V08, V09, V10, V11, V12, V13`: Complete audit ACL/config persistence/replay, every configuration command/record and advertised-list consistency, lock/strict-config/immediate/reboot behavior, vendor-counter refusal/lifetimes and measurement-build selectors.
- [ ] `R02, R03, R05, R06`: Complete device-key confirmation refusal, all PHY tags/lock/range/persistence, reboot refusal/response-before-disconnect and occupied/incompatible recovery fixtures with the full recovery command whitelist. Positive fuse writes remain deliberately excluded by R07.
- [ ] `X01, X02, X03, X04, X05, X06, X07, X08, X09, X10, X11, X12`: Complete populated cross-applet authorization/cursor/challenge and private-key reset witnesses, presence ownership, each quota's reclamation, long PQC overlap, uncertain writes and the full volatile/persistent lifetime table. Existing representative sequences cannot certify every cross-applet clause.

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
