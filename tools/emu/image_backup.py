# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Seed replacement, certificate binding and temporary secrets in the image."""

import hashlib
from pathlib import Path
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rsk import backup  # noqa: E402
from image_operations import CDH, RP, verify_fido  # noqa: E402
from ctaphid import decode  # noqa: E402

REPLACEMENT = hashlib.sha256(b"image backup replacement seed").digest()
NONCE = hashlib.sha256(b"image backup load nonce").digest()[:12]
INTEGRITY_FAILURE = 0x3D


def run(ops):
    dev = ops.dev

    def export(label, expected=None):
        secrets = {}

        def command():
            key, aad = backup.mse_handshake(dev.hid, dev.cid)
            secrets["backup_mse"] = key
            response = dev.ctap(backup.CTAP_VENDOR, {1: backup.EXPORT})
            seed = ChaCha20Poly1305(key).decrypt(response[1][:12], response[1][12:], aad)
            assert len(seed) == 32
            if expected is not None:
                assert seed == expected, "backup restored a different seed"
            secrets["backup_seed"] = seed
            return seed

        return ops.run(label, command, secrets)

    original = export("backup_export")

    def load(label, seed, corrupt=False):
        secrets = {"backup_original": original, "backup_replacement": seed}

        def command():
            key, aad = backup.mse_handshake(dev.hid, dev.cid)
            secrets["backup_mse"] = key
            blob = NONCE + ChaCha20Poly1305(key).encrypt(NONCE, seed, aad)
            if corrupt:
                blob = blob[:-1] + bytes([blob[-1] ^ 1])
            dev.ctap(backup.CTAP_VENDOR, {1: backup.LOAD, 2: {1: blob}},
                     INTEGRITY_FAILURE if corrupt else 0)

        ops.run(label, command, secrets)

    def create(seed):
        response = dev.ctap(1, {1: CDH, 2: {"id": RP}, 3: {"id": b"backup"},
                               4: [{"alg": -7, "type": "public-key"}], 7: {"rk": True}})
        auth, attestation = response[2], response[3]
        cert = x509.load_der_x509_certificate(attestation["x5c"][0])
        key = cert.public_key()
        expected = ec.derive_private_key(int.from_bytes(seed, "big"), ec.SECP256R1()).public_key()
        assert key.public_numbers() == expected.public_numbers(), "certificate retained the old seed"
        key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
        key.verify(attestation["sig"], auth + CDH, ec.ECDSA(hashes.SHA256()))
        size = int.from_bytes(auth[53:55], "big")
        return auth[55:55 + size], decode(auth[55 + size:])

    load("backup_load", REPLACEMENT)
    export("backup_replacement_export", REPLACEMENT)
    credential, public = ops.run("backup_replacement_certificate", lambda: create(REPLACEMENT),
                                 {"backup_seed": REPLACEMENT})

    def sign():
        response = dev.ctap(2, {1: RP, 2: CDH, 3: [{"id": credential, "type": "public-key"}]})
        verify_fido(public, response[2] + CDH, response[3])

    ops.run("backup_replacement_assertion", sign, {"backup_seed": REPLACEMENT})
    load("backup_restore_original", original)
    ops.run("backup_old_credential_refused", lambda: dev.ctap(2, {
        1: RP, 2: CDH, 3: [{"id": credential, "type": "public-key"}]}, 0x2E))
    export("backup_original_export", original)
    dev.power_cycle()
    credential, public = ops.run("backup_certificate_after_reboot", lambda: create(original),
                                 {"backup_seed": original})
    ops.run("backup_finalize", lambda: dev.ctap(backup.CTAP_VENDOR, {1: backup.FINALIZE}))
    load("backup_invalid_tag_refused", REPLACEMENT, corrupt=True)
    ops.run("backup_credential_after_refusal", sign, {"backup_seed": original})
    ops.run("backup_certificate_after_refusal", lambda: create(original), {"backup_seed": original})
    state = ops.run("backup_sealed_state", lambda: dev.ctap(backup.CTAP_VENDOR, {1: backup.STATE}))
    assert state[1] is True and state[2] is True and state[3] is False
    key, _ = backup.mse_handshake(dev.hid, dev.cid)
    ops.run("backup_sealed_export_refused", lambda: dev.ctap(backup.CTAP_VENDOR,
            {1: backup.EXPORT}, backup.ERR_NOT_ALLOWED),
            {"backup_seed": original, "backup_mse": key})
    dev.power_cycle()
    state = ops.run("backup_sealed_state_after_reboot", lambda: dev.ctap(
        backup.CTAP_VENDOR, {1: backup.STATE}), {"backup_seed": original, "backup_mse": key})
    assert state[1] is True and state[2] is True and state[3] is False
    ops.control("backup_seed", original)
