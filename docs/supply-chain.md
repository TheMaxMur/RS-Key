<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Supply chain

How a downloaded RS-Key release proves it came from this source tree, was built
by this project's CI, and pulls in only reviewed dependencies. And how you
verify each claim yourself.

**No private keys are involved here.** The build provenance is keyless
(sigstore/Fulcio, signed against this workflow's GitHub OIDC identity, recorded
in the public Rekor transparency log). The only signing key in the project is
the *secure-boot* key. That is a different thing entirely. It seals an image
so the RP2350 bootrom will run it. It has nothing to do with the supply chain.
See [production.md](production.md) for that.

## What every release carries

| Layer | Artifact | What it proves |
|---|---|---|
| Reproducible build | the 11 `.uf2` flavors | the binary is a pure function of the source at the tag. Anyone can rebuild it |
| Repro **gate** | (CI, blocking) | the release job *fails* if any flavor doesn't rebuild bit-identical, so a non-reproducible image is never published |
| Checksums + signature | `SHA256SUMS` + `SHA256SUMS.sigstore.json` | the hashes were signed by this repo's release workflow (keyless cosign). Up to v0.4.10 the same file is named `SHA256SUMS.cosign.bundle` |
| Build provenance | a GitHub **attestation**, plus `rs-key-<tag>.intoto.jsonl` on the release | which reusable workflow, at which commit, on which runner built each `.uf2`. **SLSA v1 Build L3**, keyless via `attest-build-provenance`. The API copy is authoritative; the file is for offline checking |
| SBOM | `rs-key-<tag>-sbom.cdx.json` | the CycloneDX bill of materials for the firmware crate |
| Dependency audit | `supply-chain/` (in-repo) | every dependency is covered by an imported audit or a recorded exemption (cargo-vet) |

## Verifying a download

### 1. Reproducible build

Rebuild from the tagged source and compare. This is the strongest check, because
it needs no trust in the publisher at all:

```sh
git checkout <tag>
nix build .#firmware            # or .#firmware-pqc, .#firmware-fips, …
sha256sum result/firmware.uf2   # compare against SHA256SUMS
```

CI already enforces this: the release job rebuilds all eleven flavors with
`nix build --rebuild` and fails on any bit-level difference before publishing.

### 2. Checksum signature (keyless cosign)

```sh
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/TheMaxMur/RS-Key/\.github/workflows/release-build\.yml@.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
sha256sum -c SHA256SUMS          # then check the artifacts against it
```

The certificate identity is **`release-build.yml`**, not `release.yml`: cosign
runs inside the reusable builder. Sigstore stamps the cert with the reusable
workflow's identity (`job_workflow_ref`).

### 3. Build provenance (GitHub attestation)

```sh
gh attestation verify rs-key-<tag>-default.uf2 \
  --repo TheMaxMur/RS-Key \
  --signer-workflow TheMaxMur/RS-Key/.github/workflows/release-build.yml
```

This confirms the `.uf2` was built by the **`release-build.yml` reusable
workflow** in this repo. The attestation records the workflow, commit and
runner, so a hand-built upload won't verify. Pinning `--signer-workflow` to the
reusable builder is the **SLSA Build L3** check: it proves a *specific, trusted*
workflow produced the artifact, not merely that something in the repo did.
(Dropping `--signer-workflow` still verifies an attestation exists for this repo,
a weaker Build-L2-style check.) The provenance is a GitHub attestation
(Sigstore-signed, logged in Rekor) kept in the attestation API rather than as a
release asset, so it stays available even though the published release is
immutable.

## Dependency review — cargo-vet

`cargo-deny` already blocks bad licenses and known advisories. `cargo-vet`
answers a different question (*has anyone actually reviewed this crate's code?*)
by requiring every dependency to be covered by a recorded audit.

The audit set lives in [`supply-chain/`](https://github.com/TheMaxMur/RS-Key/tree/main/supply-chain):
imported audits from Mozilla, Google, ISRG and Zcash, plus our own
`exemptions` for everything they don't cover. The gate runs in `check.sh`:

```sh
nix develop -c cargo vet --locked
```

**Honest scope.** RS-Key is an embedded tree: embassy, the RP2350 HAL, `defmt`
and many RustCrypto crates are not in the big organizations' audit sets, so they
are recorded as **exemptions** (grandfathered in, not yet line-reviewed). The
point isn't that every line is audited. It's that a **new, unreviewed crate
cannot enter the tree silently**. It fails `cargo vet` until it's audited,
imported, or explicitly exempted. To see the current state and shrink the
exemption list:

```sh
nix develop -c cargo vet              # what's audited vs exempted
nix develop -c cargo vet suggest      # diffs to review next
```

The host `tools/tui` workspace is separate and not yet under cargo-vet. It is
covered by Dependabot and `cargo-deny`.

## Transparency-log monitoring

The Rekor log that backs every signature above is tamper-*evident*, not
tamper-*proof*: it records misuse, but only if someone looks. A scheduled
workflow,
[`rekor-monitor.yml`](https://github.com/TheMaxMur/RS-Key/blob/main/.github/workflows/rekor-monitor.yml),
does the looking. Every hour it runs
[`sigstore/rekor-monitor`](https://github.com/sigstore/rekor-monitor) and files
a GitHub issue listing any Rekor entry signed as an RS-Key GitHub-Actions
identity (any `…/RS-Key/.github/workflows/*` subject under the GitHub OIDC
issuer).

This is the **detection** half that complements the **verification** above: the
attestations prove a *legitimate* release is genuine, while the monitor surfaces
an *illegitimate* signature, one made with our identity by something we didn't
run (a compromised OIDC token, repo, or runner). Each real release adds a couple
of expected entries from `release-build.yml`, so a known issue or two per release
is normal. The alarm is an entry you don't recognise.

## What's deliberately *not* here

- **No `cargo-vet` of a fully line-reviewed tree.** See the honest scope above.
- **No image encryption / signed-for-boot release artifacts.** The published
  `.uf2`s are unsigned for secure boot by design. You seal them with your own
  key ([production.md](production.md)). The signatures on this page attest the
  build, not the boot.

See also: [releases.md](releases.md) for the release index, and
[COMPLIANCE.md](https://github.com/TheMaxMur/RS-Key/blob/main/COMPLIANCE.md) for
the licensing posture.
