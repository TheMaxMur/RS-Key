#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Third-party-stack check: ML-DSA-44 via Yubico's python-fido2 client + OpenSSL.

Unlike tests/60_pqc_mldsa.py (raw CTAPHID + our own CBOR), everything protocol
here is Yubico's python-fido2 (>= 2.2): their HID transport, CTAP2 CBOR, full
WebAuthn client (real clientDataJSON / origin / rpId handling) and attestation
parsing. Signature verification is OpenSSL's ML-DSA via pyca/cryptography
(>= 48, bundling OpenSSL 3.5+). Only this glue file is ours.

python-fido2 2.2 has no ML-DSA CoseKey yet — the credential public key parses
as `UnsupportedKey` (raw COSE map), so the AKP `pub` (-1) bytes are handed to
OpenSSL directly.

Shipping firmware returns fmt="none" with an empty attStmt, so the packed
self-attestation verify only runs on a `--features fido-conformance` build; on a
default board it is skipped and the getAssertion signature carries the check.

    python3 -m venv /tmp/fido2-latest
    /tmp/fido2-latest/bin/pip install fido2 cryptography
    /tmp/fido2-latest/bin/python tests/61_pqc_thirdparty_client.py

Flash the no-touch build (firmware-test.uf2) first. Asks for a replug before its
reset — CTAP 2.1 §6.6 accepts one only just after power-up (see replug.py).
"""
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import replug  # noqa: E402

from cryptography.hazmat.primitives.asymmetric import mldsa
from fido2.client import DefaultClientDataCollector, Fido2Client
from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice
from fido2.webauthn import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
    UserVerificationRequirement,
)

RP_ID = "example.com"
ORIGIN = "https://example.com"
PK = PublicKeyCredentialType.PUBLIC_KEY


def main():
    dev = next(CtapHidDevice.list_devices(), None)
    if dev is None:
        sys.exit("No FIDO HID device found — is the board plugged in?")

    info = Ctap2(dev).get_info()
    # Default builds keep -48 out of getInfo (shipped Firefox authenticator-rs
    # hard-fails on unknown COSE ids); the advertise-pqc build prepends it. The
    # capability is proven either way by the -48 pick below.
    algs = [a["alg"] for a in info.algorithms]
    assert algs in ([-7, -35, -36, -8], [-49, -48, -7, -35, -36, -8]), f"unexpected algorithms: {algs}"
    print(f"getInfo algorithms: {algs}")
    dev = replug.reset_fido2(dev, "the clean-slate reset")  # idempotent

    client = Fido2Client(dev, client_data_collector=DefaultClientDataCollector(ORIGIN))

    # Register with -48 first: CTAP 2.1 §6.1.2 step 4 selects the FIRST supported
    # entry of pubKeyCredParams, so the RP's order is what picks ML-DSA-44.
    reg = client.make_credential(
        PublicKeyCredentialCreationOptions(
            rp=PublicKeyCredentialRpEntity(id=RP_ID, name="Example"),
            user=PublicKeyCredentialUserEntity(id=b"\x01\x02\x03\x04", name="pqc"),
            challenge=secrets.token_bytes(32),
            pub_key_cred_params=[
                PublicKeyCredentialParameters(type=PK, alg=-48),
                PublicKeyCredentialParameters(type=PK, alg=-7),
            ],
            # No PIN is set after the reset; the 2.2 client refuses the default
            # "preferred" UV when nothing can satisfy it (browsers just skip).
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.DISCOURAGED
            ),
        )
    )
    att = reg.response.attestation_object
    cred_data = att.auth_data.credential_data
    cose = dict(cred_data.public_key)
    assert cose[1] == 7 and cose[3] == -48, f"COSE key not AKP/ML-DSA-44: {cose.keys()}"
    pub = mldsa.MLDSA44PublicKey.from_public_bytes(bytes(cose[-1]))

    if att.fmt == "none" or not att.att_stmt:
        print("SKIP: self-attestation verify needs a --features fido-conformance "
              "firmware (shipping firmware sends fmt=none)")
        print(f"registration: AKP key parsed by python-fido2 "
              f"(credId {len(cred_data.credential_id)}B, fmt=none)")
    else:
        assert att.att_stmt["alg"] == -48, f"attStmt alg {att.att_stmt['alg']}"
        pub.verify(att.att_stmt["sig"], bytes(att.auth_data) + reg.response.client_data.hash)
        print(f"registration: AKP key parsed by python-fido2, attestation verified by OpenSSL "
              f"(credId {len(cred_data.credential_id)}B, sig {len(att.att_stmt['sig'])}B)")

    # Authenticate with the returned credential; verify under the same key.
    sel = client.get_assertion(
        PublicKeyCredentialRequestOptions(
            challenge=secrets.token_bytes(32),
            rp_id=RP_ID,
            allow_credentials=[
                PublicKeyCredentialDescriptor(type=PK, id=cred_data.credential_id)
            ],
            user_verification=UserVerificationRequirement.DISCOURAGED,
        )
    )
    auth = sel.get_response(0)
    pub.verify(
        auth.response.signature,
        bytes(auth.response.authenticator_data) + auth.response.client_data.hash,
    )
    print(f"assertion: verified by OpenSSL (sig {len(auth.response.signature)}B)")
    print("PQC THIRD-PARTY PASS (python-fido2 client + OpenSSL ML-DSA verify)")


if __name__ == "__main__":
    main()
