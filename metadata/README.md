<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# metadata — self-published FIDO Metadata Statement

`rs-key.metadata.json` is a [FIDO Metadata Statement v3.1.1](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.1.1-rd-20251016.html)
for the RS-Key FIDO2 authenticator, describing the **default build profile**.

It is **self-published**, not a FIDO Alliance MDS listing — getting into the MDS
BLOB requires FIDO2 certification and membership, which is out of scope. A
relying party or library that can import a local metadata file can consume this
directly; see [docs/guides/aaguid-metadata.md](../docs/guides/aaguid-metadata.md)
for the full rationale and the certification boundary.

- **AAGUID:** `2479c7bf-6b30-5683-9ec8-0e8171a918b7`
  (`uuid5(NAMESPACE_URL, "https://github.com/TheMaxMur/RS-Key")`).
- **Attestation:** `basic_full` — packed with an `x5c` leaf, signed by the
  device key rather than the credential key (so not `basic_surrogate`, which is
  self-attestation and carries no `x5c` at all). That leaf is self-signed and
  unique per device, so there is no shareable root and
  `attestationRootCertificates` is empty: a relying party can check the leaf
  against the AAGUID and the §8.2.1 subject rules, but cannot chain it to
  anything. See [docs/guides/attestation.md](../docs/guides/attestation.md).
- **Drift guard:** `python tests/62_metadata_statement.py` checks this file
  against the firmware source and a live device.

> Caveat: ML-DSA-44 (COSE `-48`) has no FIDO Metadata enum, so the PQC
> capability is not listed in `authenticationAlgorithms` — only inside the
> embedded `authenticatorGetInfo` on the `advertise-pqc` build.
