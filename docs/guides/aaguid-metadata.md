<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# AAGUID & metadata

Every FIDO2 authenticator model carries an **AAGUID**, a 128-bit identifier
that says "this is a *Model X* authenticator." It rides inside the attested
credential data of every `makeCredential`. A relying party (RP) uses it to
look up the model's **Metadata Statement**: a machine-readable description of
what the model can do and how it attests.

This page explains RS-Key's AAGUID, the self-published Metadata Statement that
ships in the repo, and (importantly) the line between what that buys you for
free and what is gated behind FIDO certification.

## RS-Key's AAGUID

```
2479c7bf-6b30-5683-9ec8-0e8171a918b7
```

It is a **UUIDv5**, derived reproducibly so its provenance is self-evident:

```sh
python -c 'import uuid; print(uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/TheMaxMur/RS-Key"))'
# -> 2479c7bf-6b30-5683-9ec8-0e8171a918b7
```

An AAGUID is **self-assigned**. No central registration is required to pick
one. Earlier RS-Key builds inherited an upstream AAGUID (the bytes of
`SHA-256("Pico FIDO2")`), which meant the device claimed another project's model
identity. As of firmware `bcdDevice 0x075F` it carries its own.

A few consequences worth knowing:

- **One AAGUID for every flavor.** It identifies the firmware *model*, not the
  USB branding, so the default pid.codes identity and the opt-in YubiKey-identity
  interop build report the same AAGUID. The YubiKey-identity build deliberately
  does **not** claim a real YubiKey AAGUID. That would be a forgery and would
  fail attestation anyway (it cannot chain to Yubico's roots).
- **Existing credentials keep working.** The AAGUID only appears in attestation
  at registration time. Resident keys made on an older build still assert
  fine. Only *new* registrations report the new AAGUID. An RP that pinned the
  old AAGUID for attestation matching would need a re-enroll.
- **Build-time override.** `AAGUID=<uuid-or-32-hex> cargo build` bakes a custom
  AAGUID (`build.rs` validates it, `consts.rs` const-parses it); omit the flag to
  keep the default above. A non-default build makes the checked-in Metadata
  Statement (and the drift guard below) no longer match — reserve it for a fork
  that ships its own metadata, not a cosmetic tweak.

## The Metadata Statement

[`metadata/rs-key.metadata.json`](https://github.com/TheMaxMur/RS-Key/blob/main/metadata/rs-key.metadata.json)
is a [FIDO Metadata Statement v3.1.1](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.1.1-rd-20251016.html)
describing the **default build profile**. It declares the AAGUID, the supported
authentication algorithms, the attestation type, key/matcher protection, and an
embedded `authenticatorGetInfo` that mirrors exactly what the device returns to
`authenticatorGetInfo` (CTAP `0x04`).

| Field | RS-Key value |
|---|---|
| `attestationTypes` | `["basic_surrogate"]`: packed self-attestation, no cert chain |
| `attestationRootCertificates` | `[]`: none, by definition of surrogate |
| `authenticationAlgorithms` | secp256r1 / ed25519 / secp384r1 / secp521r1 / secp256k1 (ECDSA + EdDSA) |
| `keyProtection` | `["hardware"]`: RP2350 flash/OTP, not a separate certified secure element |
| `matcherProtection` | `["on_chip"]`: the PIN is verified on the device |
| `attachmentHint` | `["external", "wired"]`: a USB roaming token |
| `upv` | `1.0`: matches the `FIDO_2_0` entry the device advertises in `versions` |

A drift guard, [`tests/62_metadata_statement.py`](https://github.com/TheMaxMur/RS-Key/blob/main/tests/62_metadata_statement.py),
checks the statement against both the firmware source (the default AAGUID in
`build.rs`) and a live device (the embedded `authenticatorGetInfo` vs the real
one). Run it by hand. It is not in the hardware gate.

### Two caveats baked into the statement

- **ML-DSA is not expressible.** RS-Key implements post-quantum credential types
  (COSE `-48` / `-49`, ML-DSA-44 / ML-DSA-65), but the FIDO Metadata Statement
  registry has **no enum value** for ML-DSA/Dilithium, so they cannot appear in
  `authenticationAlgorithms`. They are visible only inside the embedded
  `authenticatorGetInfo` (and only on the `advertise-pqc` build). A strict MDS
  consumer will not see the PQC capability.
- **One profile per statement.** The build features `advertise-pqc` (adds COSE
  `-48` to the algorithm list) and `fips-profile` (drops secp256k1, raises the
  PIN floor to 6) change `getInfo`. The shipped statement describes the
  **default** build. A different profile needs its own statement.

## What this does — and does not — get you

RS-Key works as a passkey/security key with the overwhelming majority of relying
parties **without any of this**. Self-attestation is accepted by GitHub,
Google, Microsoft consumer accounts, browsers, `ssh`, and any RP that does not
*enforce* attestation. The AAGUID and statement add a stable, honest identity
and a machine-readable capability description for tooling that wants one.

The hard boundary is **attestation enforcement**. Taking
[Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-fido2-hardware-vendor)
as the strict reference:

| Entra policy | What RS-Key needs |
|---|---|
| Attestation **not** enforced (the common case) | Nothing extra: `none` / packed-surrogate / a custom format ≤ 32 chars is accepted. RS-Key works today. |
| Attestation **enforced** | A packed attestation chaining to a root **extracted from the FIDO MDS**, the model's metadata **uploaded to the FIDO MDS**, and a **FIDO2 certification** (any level). |

That second row is a deliberate **non-goal** here: official MDS listing and FIDO
certification require FIDO Alliance membership, a certification lab, and money,
none of which is a code change. The self-published statement is the part that
*is* actionable: an RP or library that can import a local metadata file (rather
than only trusting the MDS BLOB) can consume it directly. If RS-Key is ever
certified, the statement is already authored and ready to submit.

See also: [Enterprise attestation](attestation.md) for the org-provisioned
cert-chain path, and the [interop matrix](../interop.md) for what has actually
been observed working on hardware.
