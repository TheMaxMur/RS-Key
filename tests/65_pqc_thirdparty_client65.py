#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Third-party-stack check: ML-DSA-65 via Yubico's python-fido2 client + OpenSSL.
The -65 twin of tests/61 — everything protocol is Yubico's python-fido2 (>= 2.2):
their HID transport, CTAP2 CBOR, full WebAuthn client (real clientDataJSON /
origin / rpId) and attestation parsing; signature verification is OpenSSL's
ML-DSA via pyca/cryptography (>= 48). Only this glue file is ours.

python-fido2 2.2 has no ML-DSA CoseKey yet — the credential public key parses as
a raw COSE map, so the AKP `pub` (-1) bytes are handed to OpenSSL directly.

Shipping firmware returns fmt="none" with an empty attStmt, so the packed
self-attestation verify only runs on a `--features fido-conformance` build; on a
default board it is skipped and the getAssertion signature carries the check.

    python3 -m venv /tmp/fido2v
    /tmp/fido2v/bin/pip install fido2 cryptography
    /tmp/fido2v/bin/python tests/65_pqc_thirdparty_client65.py

Flash the no-touch build built `--features advertise-pqc` first.
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
    algs = [a["alg"] for a in info.algorithms]
    # Default build advertises neither PQC set; advertise-pqc leads with -49, -48.
    assert algs in ([-7, -35, -36, -8], [-49, -48, -7, -35, -36, -8]), f"algorithms: {algs}"
    print(f"getInfo algorithms: {algs}")
    dev = replug.reset_fido2(dev, "the clean-slate reset")  # idempotent

    client = Fido2Client(dev, client_data_collector=DefaultClientDataCollector(ORIGIN))

    # Register, offering ES256 first — the PQC-priority policy must pick -49.
    reg = client.make_credential(
        PublicKeyCredentialCreationOptions(
            rp=PublicKeyCredentialRpEntity(id=RP_ID, name="Example"),
            user=PublicKeyCredentialUserEntity(id=b"\x01\x02\x03\x04", name="pqc65"),
            challenge=secrets.token_bytes(32),
            pub_key_cred_params=[
                PublicKeyCredentialParameters(type=PK, alg=-7),
                PublicKeyCredentialParameters(type=PK, alg=-49),
            ],
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.DISCOURAGED
            ),
        )
    )
    att = reg.response.attestation_object
    cred_data = att.auth_data.credential_data
    cose = dict(cred_data.public_key)
    assert cose[1] == 7 and cose[3] == -49, f"COSE key not AKP/ML-DSA-65: {cose.keys()}"
    pub = mldsa.MLDSA65PublicKey.from_public_bytes(bytes(cose[-1]))
    assert len(bytes(cose[-1])) == 1952, "ML-DSA-65 pk length"

    if att.fmt == "none" or not att.att_stmt:
        print("SKIP: self-attestation verify needs a --features fido-conformance "
              "firmware (shipping firmware sends fmt=none)")
        print(f"registration: AKP key parsed by python-fido2 "
              f"(credId {len(cred_data.credential_id)}B, fmt=none)")
    else:
        assert att.att_stmt["alg"] == -49, f"attStmt alg {att.att_stmt['alg']}"
        assert len(att.att_stmt["sig"]) == 3309, "ML-DSA-65 sig length"
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
    print("PQC-65 THIRD-PARTY PASS (python-fido2 client + OpenSSL ML-DSA-65 verify)")


if __name__ == "__main__":
    main()
