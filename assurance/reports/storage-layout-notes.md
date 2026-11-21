<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Storage layout and implementation notes

## Capacity — why the flash is mostly empty

Storage v2 keeps the partition offsets and the 4078-byte value ceiling. KVMAIN
still carries the existing payload map. The 128 KiB KVCNT window now contains
two 44 KiB main-directory journals and two 20 KiB counter banks. The directory
signs the complete live FID set; each entry authenticates its partition, epoch,
generation, length and full payload. CRC-discarded expected values and damaged
bytes resembling legacy layouts fail as storage errors. Counter traffic leaves
KVMAIN and the main-directory journals unchanged.

Main writes reserve a candidate before publishing an authenticated intent,
verify that exact candidate, and then publish to both journals. Recovery
finishes a complete candidate or cancels its reserved span before allowing GC.
Counter values and their authority are committed together and mirrored before
success. From `0x0B66`, counter reads and write admission reuse authenticated
locations only after freshly checking both complete physical banks. The used
prefix is hashed and every byte of the erased tail is checked; changed bytes
trigger full replay and recovery. Fingerprints are bound to the current root
key, epoch and root arm, and requested values retain their full MAC check.
Fingerprints are formed from the same bytes as the authenticating scan, not a
second read of potentially changed data. Mutation discards the mount before
programming; verified closure seeds the next mount. Invalid occupied suffixes
retain authenticated progress as a minimum generation; an older replica cannot silently replace that progress.

From `0x0B83`, each directory digest prepares one local HMAC template for its
fixed root key. Every original frame is still authenticated. Payload reads,
root observations, rollback floors and publication order are unchanged.
The template lives only in returned frames covered by the Secure stack sweep;
it never enters the mounted store. Persistent bytes are unchanged. The digest
loop stays out of line so the template does not enlarge its callers' frames.
The P-256 ECDH multiplication also executes from existing Secure RX SRAM;
from `0x0BA8`, its complete point addition and field inversion do too.
The addition's upstream monomorph has a linker size assertion: a dependency
or code-generation change requires reviewing the relocation again.
Its scalar arithmetic and point validation are unchanged. P-256 and P-384
peer decoding use separate frames to keep their workspaces out of other curves.
P-384 addition, subtraction and doubling stay out of line on 32-bit targets;
these are the existing constant-time field operations, with no change to point
validation or scalar handling. The Fiat and 64-bit backends keep their inlining.

From `0x0BA8`, PIN retry bytes and AES-GCM-sealed HOTP moving factors use private
counter-journal buckets. The complete public PIV/OpenPGP retry records live in
separate private counter entries; a durable tombstone prevents legacy fallback
after deletion. Verifier-bearing PIN presence probes authenticate their main-file owner
without fetching retry bytes. Each slot names the main record's publication
generation; changing or deleting that record invalidates the old slot. Root
re-keying preserves publication generations. PIN verifiers and OATH secrets
remain in the main payload map; the buckets contain neither. A retry update
keeps all other bytes of the PIN record intact. HOTP reads combine its sealed
credential with its separately sealed moving factor, and rename materializes
that effective value before replacing the credential.

Legacy records remain authoritative until a matching bound slot is published.
Both counter banks must acknowledge an update before comparison or a code can
escape. A malformed, unreadable or unauthenticated bucket is an error, never
permission to use the legacy value. Counter authority retains its authenticated
live state across read failures and admits only its staged writes. Mounted
PIN/HOTP reads fetch the requested entry and payload in both banks, require
byte-identical copies and authenticate the value against that live authority. As with
the main payload map, unrelated historical records are checked at mutation and
recovery boundaries, rather than on each addressed read. Every update still
checks both complete banks before and after publication; the original four
counter APIs retain their complete-bank reads.

Mounted reads retain only nonsecret authentication tags. Each read fetches the
root again, authenticates the current authority and reads the physical payload.
An unchanged entry may reuse its payload tag across unrelated publications,
but only while it exactly matches the current authenticated directory entry;
the fresh mount proof binds it to the current authority. A payload tag already
bound to the current authority authenticates both together. After a successful
read across an unrelated publication, the payload tag is refreshed to that bound.
The counter authority MAC covers a SHA-256 digest of the entire canonical
directory, plus its epoch, root arm and sequence. Persistent directory MACs and
checkpoint encodings are unchanged.
Warm mutations compare fresh complete-bank SHA-256 digests with the verified
mount and check its authority MAC with the current key. Append confirmation
verifies the saved prefix MAC before comparing the intended and physical digests.
No root, derived key or keyed hash state survives the call. Private reads do
not reread unrelated journal bytes; writes and recovery authenticate both full
banks, including their erased suffixes. A changed private value is refused on
read even when both banks are replayed, and reading an unchanged value cannot
lower another counter's retained floor. A complete flash replay across cold
boot retains the limitation described in the threat model. Earlier v2 builds reject the new private
FIDs during mount, so downgrade cannot expose the old embedded counts.

The bucket layout keeps all 255 OATH slots and all 256 FIDO counters. Directory
entries use an unaligned byte representation for their generation in RAM to
make room for the larger counter index; the 32-byte on-flash entry is unchanged.
The original four-counter legacy import manifest also remains unchanged.

From `0x0BB0`, raw-bank writes end each chunk at a 256-byte page boundary,
avoiding overlapping physical page programs on byte-writable flash drivers.
Counter appends gather the header, value and erased padding directly into
the raw bank's page buffer, without a full-record staging buffer. Their on-flash
bytes are unchanged, so `0x0BA8` can still reopen the store. The scanner advances
its authenticated sequence only after verifying
the complete value MAC; a complete header over a torn value stays dirty and
retains the previous authenticated floor. Both banks are still published and
checked before success. Checkpoint construction keeps its existing ordering.

From `0x0BD6`, counter snapshots pack consecutive entries and padded values into
256-byte body pages. Each value is authenticated before copying, and each page
is read back before the checkpoint header and its final MAC are programmed.
This reduces repeated programs during rotation without changing stored bytes,
capacity, full-bank erasure or either replica's publication checks. Existing
`0x0BA8` and `0x0BB0` stores remain readable in both directions.

The private on-flash FIDs and value layouts are fixed:

| FID | Value |
|---|---|
| `CD00` | Five 16-byte slots: legacy PIV, legacy OpenPGP, FIDO, device and OATH PIN retries |
| `CD01`–`CD20` | Eight 48-byte HOTP slots per bucket, in credential-FID order from `BA00` |
| `CD21`, `CD22` | PIV and OpenPGP retry records: `01` followed by the complete record, or the one-byte tombstone `00` |

A bound slot starts with the owner's 8-byte little-endian publication generation,
then a one-byte value length and that many value bytes; unused bytes are zero.
An unused slot is entirely zero. PIN slots hold up to three retry bytes; HOTP
slots hold the 36-byte nonce, ciphertext and GCM tag. The last HOTP bucket's
eighth slot is unused because `BAFF` belongs to the OATH access code.

From `0x0B70`, main and counter journals retain the SHA state of complete public
metadata blocks from the authenticating scan. Before extending that state, the
partial block is reread and checked against the root-bound prefix fingerprint.
The exact intended append extends this state in RAM. After both publications,
each complete physical bank is read afresh: its occupied prefix must match the
expected fingerprint and every tail byte must remain erased. Only then can the
new append position be reused. This replaces per-record closing replay without
accepting a changed historical prefix, a different append or a hidden suffix.
No root key or payload plaintext is retained. Cold mounts, recovery and
compaction keep the full replay path; missing proof state uses that path too.
A GET RESPONSE that only drains a prepared answer leaves the public OTP HID
status mirror alone. Every new APDU and OTP operation still refreshes it; the
mirror is not used to authorize operations or validate stored values.

From `0x0B05`, TrustZone places shared memory-copy and clearing helpers beside
the verifier in read-only Secure SRAM. Their instruction bodies are unchanged;
startup copies them before use under the existing executable-memory policy.
Build `0x0B66` groups the X25519 ladder, field multiplication, subtraction and
squaring into one aligned 8 KiB XIP cache way. The arithmetic stays unchanged;
neither SRAM nor cache-control permissions change. Ed25519 uses dalek's existing
constant-time base-point tables, with `zeroize` retained and no heap required.
The tables occupy 30 KiB of flash. The store crate uses speed optimization,
as the shared SHA-256 core already does.
From `0x0BD6`, the Ed25519 selection and addition loop uses cache indices after
the shared field core, leaving the other way for its public table. Linker
assertions keep both instruction spans disjoint. X25519's group includes its
constant-time barrier and public ladder multiplier; secp256k1's hot callees
occupy their own aligned cache way.
The checked shared flash reader executes from the existing Secure RX SRAM
region; startup copies it with the other RAM routines before enabling that
mapping. Its reads, bounds and verification remain unchanged. P-521 ECDH uses
131 fixed radix-16 rounds: the top digit including its carry is at most two,
so the encoding's two leading zero digits need no rounds.
P-384 groups its comb and hot field callees within one XIP
cache way; the decoded public tables remain on the stack.

Pre-OTP read proofs use precomputed SHA-256 states for the public `NO-OTP`
key pads. Every backend operation still reads and classifies the OTP root
afresh. Fused-root HMAC, record MACs, bank authentication and rollback checks
are unchanged; no secret-derived state survives between operations.

From build `0x0ACF`, Main keeps its complete authenticated version directory
in protected RAM. A warm read freshly checks the root, verifies its binding to
the mounted directory, and authenticates the complete requested payload against
its expected entry. The complete directory also authorizes absence. Neither root
keys nor payload plaintext are cached. Before reusing a mounted directory for
mutation, full physical-journal fingerprints are checked. Otherwise authenticated
journal resolution and recovery precede mutation.
From `0x0B55`, a verified mount also retains the append offsets and chain heads.
After the physical-journal check, a healthy payload map can reuse this position
without replaying the journal again. The completed write's authenticated
closure seeds the next read mount; errors clear these hints. Payload repair
still takes the original resolution path, and no root key or payload is retained.
From `0x0B66`, unpublished-value retirement first performs an unrepaired,
read-only walk. Known FIDs exclude historical bodies from this walk without
warming their key pointers; included candidates still pass the full CRC.
All published values are authenticated before any deletion or subsequent GC.
Deletion retains the post-cleanup validation; a walk that changed nothing needs
only the pre-mutation validation. The ordinary item iterator stays separate
so the filtered walk does not enlarge lookup futures. Payload seals and
persistent formats are unchanged.
A separate mounted authority tracks the exact epoch, root arm, sequence and
directory digest through Prepare, Commit, Abort and rekey. Errors and remounts
clear acceleration hints but retain this floor; the first verified publication
closes its predecessor before a later replica write can fail. Ready is cleared
before any directory change. Unrelated journal or payload-map damage need not
interrupt a warm read of known correct data; recovery and mutations check that
media before consuming it. The cold-start rollback limitation still applies.

From `0x0AD0`, a ready read lends the map only the requested record's aligned
scratch span, under a wipe guard. Cold reads and mutation paths clear the whole
scratch before reusing a mount; warm reads wipe everything the map could have
filled, including padding and partially completed failing reads. A fallback drops
the bounded guard before full-buffer lookup and cleanup. Absence borrows no
scratch. Fresh root checks and complete value authentication remain required.

From `0x0AD6`, a read-tag miss validates the same checked record geometry, then
borrows the full scratch under its wipe guard. An uncached map lookup can read
larger unrelated values before finding the requested FID. This avoids a small
buffer failure, repeated binding proof and full-buffer retry, and lets the first
verified value seed its read tag. Tag hits retain the bounded span and the
existing recovery checks.

TrustZone build `0x0BE0` gives counter resolution and scanning caller-owned
results, avoiding repeated large return-value copies in unoptimized builds.
Software SHA-256 groups its literal-index schedule and register rotation in
eight-word helpers that can inline in optimized builds. This bounds unoptimized
core1 frames; chaining state, schedule and working state retain `Secret` owners.
Persistent encodings are unchanged.
ML-DSA zero vectors use constant elements. Key expansion fills its final fields
before converting them to the NTT/Montgomery domain; signing fills vectors
without array-constructor copies and reuses the product and LowBits buffers
for the response and hints. Polynomial owners still wipe on every exit.

TrustZone build `0x0ADC` also unrolls SHA-256 schedule expansion. A placement
hint avoids rebuilding the expanded schedule solely for its final wipe. The hint
has no security role: the complete 64-word schedule and chaining state remain
in `Secret`, and cleanup does not depend on optimization. Full MAC frames, fresh
Root reads, rollback floors and persistent record formats are unchanged.

TrustZone build `0x0ADB` fully unrolls the software SHA-256 rounds and places
the unchanged HKDF-SHA256 and HMAC-DRBG helpers in Secure RX SRAM as well.
The full 64-word schedule and chaining state remain in `Secret`. The complete
Secure dead-stack sweep uses 32 stores per pass with the same bounds and tail.
Additional RX code reduces the core0 stack span; data and Non-secure RAM do not
grow. Full record verification, fresh Root observations, rollback floors,
DRBG Generate/reseed boundaries and cleanup before publication are unchanged.

TrustZone build `0x0ADA` executes the unchanged SHA-256 compression/finalization and HMAC template functions
from the existing Secure RX SRAM region. Trusted Reset copies this code together
with the existing RAM routines before enabling the read-only executable mapping.
The region grows by 1824 bytes on the Waveshare 4M test image, reducing the
core0 stack span by the same amount; data, BSS and Non-secure RAM are unchanged.
Full SHA-256 input hashing, MAC frames, fresh Root reads and both Secure stack
sweeps retain their existing contracts. No keyed context or plaintext is cached.

Build `0x0AD3` prepares one operation-local HMAC context for the
full mounted binding and complete payload checks, using the prefix reuse from
[RFC 2104 section 4](https://www.rfc-editor.org/rfc/rfc2104.html#section-4). The context stays in returned
stack frames covered by the Secure sweep; no keyed state is retained for a
later backend read, which derives its root afresh. Authentication frames and
persistent records are unchanged.

From `0x0AD5`, Main can retain 32 read tags and one mounted-binding tag, with
their exact public metadata, in protected RAM. Every admitted backend read still
reads OTP and applies the original arm and latch rules. A miss derives the persisted
key and verifies the full binding and record MACs before seeding a tag from that
same OTP observation. A hit instead verifies a full 32-byte root-key HMAC:
`RSKV2RM1 || serial_hash || bound[100]` for absence, or
`RSKV2RD1 || serial_hash || bound[100] || entry[32] || SHA256(value)` for a value.
The bound contains the canonical snapshot and its full mounted-binding tag.
Every payload byte is hashed before any requested prefix is returned; a miss
reuses the digest already verified by the record MAC. Root bytes are wiped
before map I/O. No root, derived key, plaintext or keyed state survives a read
in Main or KeySource; returned crypto frames remain covered by the Secure sweep.

CRC or missing-map recovery first verifies the original observation's mounted
tag, then freshly reads and derives the root again. The existing full binding
proof checks this second observation before recovery reads payloads. A cached
payload-tag mismatch refuses immediately. Main clears the read tags with its
other hints before mutation and on read errors, retaining the authority floor.
These tags have no persistent representation and do not change journal or record formats.

Boot mounts authority before scanning or provisioning applets. Wholly blank
media and readable legacy stores are initialized or imported automatically.
Read faults, damaged v2 authority and malformed legacy page layouts enter CCID
rescue mode; [attended commands](../../docs/guides/cli.md#storage-initialization-and-upgrades)
remain available for recovery.
Import freezes the main set and four routed counter values in a signed manifest,
verifies backups in KVMAIN before counter erasure, and resumes after interruption.
The legacy counter reader treats the exact SDK E10 256-byte `0xEF` suffix as
erased only when the remainder of that final sector is unused. Its view cannot
write or erase; authenticated banks read the actual flash bytes.
Backend-owned FIDs `CEF8..CEFD` stay outside the public map and dynamic-file
budget. The activation witness survives applet resets. Pre-OTP authority is
re-keyed before the page-58 latch can report migration complete.

The KV store is 1.5 MB by default whatever the `FLASH_SIZE`, so a larger flash only
grows the code region, most of which no firmware writes ([build.md](../../docs/build.md)). That
is deliberate. (A 2 MB board is the one exception: it shrinks the main partition via
`KVMAIN` to leave room for code — still far more than a key ever fills.) A security key's maximum *logical* state is small and hard-capped:
`MAX_RESIDENT_CREDENTIALS` (256 passkeys), `MAX_DYNAMIC_FILES` (1280 files, one
budget shared by every applet), `MAX_OATH_CRED` (255), plus a handful of
OpenPGP/PIV slots. The passkeys dominate the bytes — a file-count ceiling is not
a size ceiling — so a fully provisioned device fills only a few hundred KB, well
under the 1408 KB main partition. Growing the store to "fill" a 16 MB board would buy nothing usable: it
lengthens the `sequential-storage` scan behind every cold boot and absent-key
probe (the present cache exists to dodge exactly that full-partition ~0.2 s cost),
and forces the logical caps (and the RAM/stack buffers sized to them) up for
capacity no one reaches. Empty flash here is headroom, not waste.
