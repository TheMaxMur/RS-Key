# Releases & verification

Releases live on the [GitHub Releases](https://github.com/TheMaxMur/RS-Key/releases)
page. Each is cut from a `v*` git tag by the
[release workflow](https://github.com/TheMaxMur/RS-Key/blob/main/.github/workflows/release.yml).
It builds every artifact reproducibly, hashes it, and signs the manifest.

## What a release contains

- **Fourteen firmware images**: `rs-key-<tag>-<flavor>.uf2`. Every published image
  requires a physical touch; the `no-touch` test builds are never released (a
  signed presence-bypass asset would remove the consent gate):

  | flavor | flags | use |
  |---|---|---|
  | `default` | touch | the normal build; start here |
  | `pqc` | + advertise-pqc | advertises ML-DSA-65 and ML-DSA-44 in getInfo (breaks old Firefox) |
  | `fips` | + fips-profile | the locked FIPS-style policy ([guides/fips.md](guides/fips.md)) |
  | `fips-pqc` | + both | |
  | `strong-pin` | + strong-pin | 6-code-point PIN floor + trivial-PIN block ([build.md](build.md), [threat-model.md](threat-model.md)) |
  | `strong-pin-pqc` | + both | |
  | `always-uv` | + always-uv | bakes CTAP 2.1 `alwaysUv` on: user verification (a PIN) for every operation, U2F disabled. Set a PIN after flashing ([build.md](build.md)) |
  | `always-uv-pqc` | + both | |
  | `strict-up` | + strict-up | **not spec-conformant:** a touch on *every* assertion, so a WebAuthn `allowCredentials` login asks for two touches ([build.md](build.md)). Pick it only if you want that stricter stance |
  | `strict-up-pqc` | + both | |
  | `display` | + display | experimental trusted-display build (Waveshare RP2350-Touch-LCD-2.8, [guides/display.md](guides/display.md)) |
  | `2mb` | `FLASH_SIZE=2M KVMAIN=896K` | 2 MB boards (Seeed XIAO RP2350, Waveshare RP2350-Zero-CM) |
  | `16mb` | `FLASH_SIZE=16M` | 16 MB boards (e.g. TenStar RP2350-USB) |
  | `strict-config` | + strict-config | the historical strict admin-write posture: config writes stay presence/PIN-gated and the ungated transport writes are refused ([build.md](build.md), [threat-model.md](threat-model.md)). The `default` build is now the permissive full-ykman admin surface |

  All fourteen present the default **RS-Key** USB identity (`0x1209:0x0001`). For the
  YubiKey-interop identity, build `VIDPID=Yubikey5` yourself ([build.md](build.md)).
- **`SHA256SUMS`**: a checksum for every image and the SBOM.
- **`SHA256SUMS.cosign.bundle`**: a keyless [cosign](https://docs.sigstore.dev/)
  signature of `SHA256SUMS` (sigstore/Fulcio; the signer is the reusable build
  workflow's GitHub OIDC identity, `release-build.yml`, see the verify step
  below; logged in Rekor).
- **`rs-key-<tag>-sbom.cdx.json`**: a CycloneDX software bill of materials for the
  firmware's dependency tree.

> **The images are UNSIGNED for secure boot.** The cosign signature attests *who
> built them*, not the boot seal. On a secure-boot device you seal an image with
> your own key before flashing. `nix run .#flash` does it, or see
> [production.md](production.md). The reproducibility claim is about the unsigned
> payload (a seal is signer-specific and not reproducible by a third party).

## Verify a download

Grab the images you want plus `SHA256SUMS` and `SHA256SUMS.cosign.bundle`.

```sh
# 1. the checksums file is authentic (keyless cosign — needs cosign >= 2.0)
#    The signer is the *reusable* build workflow (release-build.yml), not the
#    thin release.yml caller: a workflow_call job's OIDC identity is its own
#    job_workflow_ref, so that is what the Fulcio cert's SAN carries.
cosign verify-blob \
  --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity-regexp '^https://github\.com/TheMaxMur/RS-Key/\.github/workflows/release-build\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  SHA256SUMS

# 2. the images match the (now-trusted) checksums
sha256sum -c SHA256SUMS
```

Both must pass. Step 1 proves `SHA256SUMS` was produced by this repo's release
workflow; step 2 ties each `.uf2` (and the SBOM) to it.

## Verify the build is reproducible

The images are bit-for-bit reproducible per platform, per `flake.lock`, so you can
rebuild them yourself and compare (no need to trust the published binary):

```sh
git checkout <tag>
nix build .#firmware              # the default flavor (others: .#firmware-fips, …)
sha256sum result/firmware.uf2     # compare against SHA256SUMS for rs-key-<tag>-default.uf2
```

A match on Linux reproduces the CI-built artifact exactly. (Cross-platform
identity, macOS vs Linux, is not guaranteed; the canonical bytes are the
Linux ones the workflow publishes.)
