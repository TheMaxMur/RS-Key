<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Constant-time audit findings

## Findings (fixed)

| Severity | Location | Issue | Fix |
|---|---|---|---|
| Medium | `crates/rsk-rsa/src/pkcs1v15.rs` (`rsa_raw`; was `rsk-openpgp/src/keys.rs`) | **Unblinded RSA private-exponent modexp.** `rsa_sign` fell through to a raw `m^d mod n` for any input that is not a recognized DigestInfo or standard-length hash (reachable via PSO:CDS and INTERNAL AUTHENTICATE). Unlike the mainline sign/decipher paths, this fallback applied no blinding. A Marvin-class private-key timing path the documented residual did not cover. | The raw operation is now **base-blinded** `(m·rᵉ)ᵈ·r⁻¹ mod n` with a fresh random `r`, so the variable-time exponentiation runs on a base unrelated to caller input. A unit test pins `rsa_raw == m^d mod n` and proves the result is independent of the blinding factor. Since 0x0A4F neither exists: `rsa_raw` went with the full-key `rsa_sign` that fell back to it, once PIV stopped writing certificates. The raw private operation left, PIV GENERAL AUTHENTICATE's over a host-padded block, runs on the blinded asm CRT core. |
| Medium | `crates/rsk-otp/src/lib.rs` (`cmd_configure`) | **Non-constant-time compare of the 6-byte OTP slot access code** via slice `!=`, a position-of-first-mismatch leak. Reachable over CCID and HID with no PIN gate and **no retry counter**, so the leak collapses brute force from ~2⁴⁸ to ~6·256 probes. The access code authorizes overwriting a slot's key material. | Replaced with the constant-time `rsk_crypto::ct_eq`. |
| Medium | `crates/rsk-otp/src/lib.rs` (`cmd_update`) | Second, byte-identical instance of the same non-CT access-code compare on the slot-update path. | Same fix. |
