# Enterprise attestation (org provisioning)

Out of the box, ordinary `makeCredential` returns packed **basic** attestation:
an ES256 signature by the device key over `authData ‖ clientDataHash`, with the
device's own certificate as the `x5c` leaf. That certificate is a per-device
P-256 X.509 leaf (subject `C=XX, O=RS-Key, OU=Authenticator Attestation,
CN=RS-Key FIDO2`) built over the seed at first boot, and U2F registration
presents the same one.

The two alternatives were both tried and both break clients. `fmt:"none"` with
an empty statement is rejected by OpenSSH below 10.0, which hands every
credential without a certificate to libfido2's `fido_cred_verify_self()`
regardless of format. Packed **self**-attestation signs with the credential key
and so inherits its algorithm, and an Ed25519 statement fails on Windows
WinHello, which broke `ed25519-sk` enrollment (issue #26). Basic attestation
signs with ES256 whatever the credential algorithm is, so neither path is
reached.

Because the leaf is per-device it is a stable identifier: every relying party
that asks for attestation sees the same certificate, and two of them can tell
they met the same key. Browsers strip it unless the site explicitly requests
`attestation: "direct"` (WebAuthn §5.1.3 replaces the statement otherwise), but
native CTAP clients do not. There is also no root to publish — a per-device
self-signed leaf chains to nothing, so `attestationRootCertificates` in the
metadata statement stays empty and a relying party that requires a trusted
anchor will treat the attestation as untrusted.

An organization can replace that device cert with its
**own attestation key and certificate chain**, so its relying parties can
verify "this credential was created on one of *our* keys". This is the CTAP 2.1
enterprise-attestation (EA) feature.

This page is for the team that provisions fleet keys. If you do not work for an
org that has provisioned yours, it is a no-op: nothing here changes how an
unprovisioned key behaves, and EA is never served unless a managed platform
explicitly asks for it.

## The key + chain model

Two pieces of state make up an org attestation, stored separately on the device:

| Stored as | Holds | Sealing |
|---|---|---|
| `EF_ATT_KEY` (`0xCE10`) | the org attestation **P-256 private scalar** | kbase-sealed, exactly like the master seed |
| `EF_ATT_CHAIN` (`0xCE11`) | the **DER certificate chain**, leaf first (`count ‖ (len ‖ der)*`) | public material, stored plain |

The key signs each attestation; the chain is what relying parties walk back to
your CA. The leaf's public key must match the imported scalar. The device does
not check this (framing only), so a key/chain mismatch surfaces as your own
relying party's first signature-verification failure, not an import error.

## Provisioning

Generate an attestation CA and a leaf however your PKI does it. The leaf's
subject public key must be the P-256 point of the private key you import; only
**P-256 (secp256r1)** keys are accepted. `rsk` rejects any other curve before
it touches the device.

```sh
# host-side, with your PKI:
#   org-att.pem    P-256 private key (PEM)
#   org-chain.pem  leaf cert first, then intermediates, then (optionally) the CA
rsk fido attestation import --key org-att.pem --chain org-chain.pem [--pin …]
rsk fido attestation status
```

`--chain` takes a PEM bundle (concatenated `-----BEGIN CERTIFICATE-----`
blocks) or already-concatenated DER. Limits, enforced host-side and again in
firmware:

| Limit | Value |
|---|---|
| Curve | P-256 only |
| Chain size | ≤ 2048 bytes total |
| Certs in chain | ≤ 4 |

`status` is ungated and prints whether a chain is installed plus the
SHA-256 of the packed chain (so you can confirm a fleet is on the right CA
without moving any secret):

```sh
$ rsk fido attestation status
org attestation : installed
chain hash      : 9f2c…
```

To roll back to the factory self-signed cert:

```sh
rsk fido attestation clear [--pin …]
```

## What changes once a chain is installed

- **makeCredential with `enterpriseAttestation` 1 or 2** (sent by managed
  platforms) returns a full attestation: signature by the org key, `x5c` = your
  chain (leaf first), and the `ep` response flag (`true`). With an org key
  installed, **both** EA levels emit the org attestation.
- **U2F / CTAP1 registration** attests with the chain's **leaf** instead of the
  self-signed device cert (classic batch attestation: a U2F response carries
  exactly one certificate, so only the leaf travels).
- **Ordinary makeCredential is untouched**: packed basic attestation under the
  device's own certificate, no org chain. EA fires only when the platform sets
  the `enterpriseAttestation` request field *and* `enableEnterpriseAttestation`
  is on (below).

### Without an org chain (the default)

If no org key is provisioned, the request field still has an effect, per the
spec:

| EA level | Without org key | With org key |
|---|---|---|
| (absent / 0) | basic, device cert | basic, device cert |
| 1 — vendor-facilitated | basic, device cert | full org attestation |
| 2 — platform-managed | basic, device cert, no `ep` flag | full org attestation |

Without an org key every level answers with the same per-device basic
attestation; what an EA request adds is the org chain and the `ep` response
flag. The device key and that self-signed cert are the same pair U2F register
uses.

## Enabling EA on the device (`enableEnterpriseAttestation`)

Importing the key is **not** enough. A `makeCredential` with the EA field is
honored only after `enableEnterpriseAttestation` (CTAP 2.1
`authenticatorConfig`, subcommand `0x01`) has been issued. RS-Key has no `rsk`
command for this. It is the **managed platform's** job (the OS/MDM/browser
stack that drives EA), and it requires an `acfg` pinUvAuthToken, i.e. a FIDO PIN
must be set. `getInfo` reports the current state in the `ep` option, which the
firmware mirrors straight from `EF_EA_ENABLED`:

```sh
# python-fido2, the same library `rsk` uses:
python3 - <<'PY'
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2
info = Ctap2(next(CtapHidDevice.list_devices())).info
print("ep =", info.options.get("ep"))   # True once enableEnterpriseAttestation ran
PY
```

`enableEnterpriseAttestation` **persists across power cycles**. It is
written to flash (`EF_EA_ENABLED`), as CTAP 2.1 specifies. It is cleared only by
`authenticatorReset` (see below).

## Transport and gating

The P-256 private scalar crosses USB ChaCha20-Poly1305-wrapped on the same
ephemeral-ECDH channel ([MSE handshake](seed-backup.md#mechanics-for-the-curious):
P-256 ECDH → HKDF-SHA256 → ChaCha20-Poly1305) the seed backup uses. The chain
is public certificate material and travels in the clear, MAC-covered by the PIN
token like every subcommand parameter.

Import (`0x09`) and clear (`0x0A`) are gated exactly like a seed move:
**channel + PIN (when one is set) + physical touch**. On this board the touch
is the BOOTSEL button ([build.md](../build.md)). On a device with **no** PIN the
import asks for a second, named confirmation first ("Replace attestation
identity?"): the PIN half of the gate is waived in that state, and one generic
touch should not hand over the identity every later U2F registration signs with.
`status` (`0x0B`) is ungated;
the chain it returns is public. Both mutations land in the
[audit journal](audit.md) (`ATT_IMPORT` / `ATT_CLEAR`), and so does an
`enableEnterpriseAttestation` (`CFG_EA`).

```sh
rsk fido attestation import …    # → "touch the device (BOOTSEL) to authorise…"
rsk fido attestation clear …     # → "touch the device (BOOTSEL) to remove…"
```

On the device the key is sealed under the same kbase arms as the master seed.
The seal tag records which arm wrapped it, so importing **before or
after** the OTP burn both stay loadable. Burn the
[OTP master key](../production.md) *before* importing and the sealed attestation
key is rooted in fuses, not just flash ([otp-fuses.md](../otp-fuses.md)).

## Reset semantics

`authenticatorReset` wipes FIDO user state, but the org provisioning splits
across that line:

| State | Survives `authenticatorReset`? |
|---|---|
| `EF_ATT_KEY` (org key) | **yes**: org-provisioned device identity, not user data |
| `EF_ATT_CHAIN` (chain) | **yes** |
| `EF_EA_ENABLED` (the enable flag) | **no**: wiped with PIN, credentials, counter |

So a factory reset leaves the org attestation installed but **switches EA off**:
the managed platform must re-issue `enableEnterpriseAttestation` before EA
fires again. The reset itself is recorded in the audit journal. Removing the key
and chain is the explicit, gated `attestation clear`. Nothing else clears them.

## Privacy note

A shared org chain makes credentials linkable *to the organization* across its
relying parties. That is the entire point of EA, and why the spec gates it
behind both an explicit per-request field and a device-wide enable. Ordinary
(non-EA) makeCredential still carries the per-device certificate, which is
linkable to the device but not to the organization; the org chain is served only
on explicit EA requests.

## Troubleshooting

- `attestation key must be P-256 (got …)`: the `--key` PEM is the wrong curve.
  RS-Key attests with ECDSA P-256 only. Re-issue the org key on secp256r1.
- `chain too large (… B, max 2048)`: trim the bundle. You rarely need the root
  CA in `x5c`; leaf + one intermediate is usually enough, and the leaf alone is
  all U2F can carry.
- `device requires a PIN — pass --pin` (status `0x36`): import/clear are gated;
  set a FIDO PIN first (`rsk fido set-pin`) and pass it.
- An EA `makeCredential` comes back self-attested (no `x5c`, no `ep`). Either
  `enableEnterpriseAttestation` was never issued (check `options.ep`), or it was
  cleared by a factory reset. Have the managed platform re-enable it.
- `import failed: 0x33` (`PIN_AUTH_INVALID`): the PIN was wrong, or its token
  lacked the `acfg` permission. Re-run with the correct `--pin` (do not guess,
  wrong attempts burn PIN retries).
- The import hangs at "touch the device...": the physical touch never arrived.
  Press the BOOTSEL button while the prompt is up, then it completes.
