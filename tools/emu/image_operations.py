# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Command stacks and known-secret lifetimes in the running firmware image."""

import hashlib
import hmac
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87

from ctaphid import Protocol2, decode

PIV = bytes.fromhex("a000000308000010000100")
OPENPGP = bytes.fromhex("d27600012401")
OTP = bytes.fromhex("a0000005272001")
RP = "image-operations.invalid"
MESSAGE = b"image operation oracle"
CDH = hashlib.sha256(MESSAGE).digest()
PIN = b"1234"
NEW_PIN = b"5678"
SCALAR = hashlib.sha256(b"image imported P-256 scalar").digest()
ED_SEED = hashlib.sha256(b"image imported Ed25519 seed").digest()
OTP_KEY = hashlib.sha256(b"image OTP HMAC key").digest()[:20]
AES_KEY = hashlib.sha256(b"image OTP AES key").digest()[:16]
MGM_KEY = bytes(range(1, 9)) * 3
P256_OID = bytes.fromhex("2a8648ce3d030107")
ED25519_OID = bytes.fromhex("2b06010401da470f01")
DI_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")
CONTROL_ADDRESS = "20081000"
SERIAL = b"RSKEMU\x00\x01"
EC_ALGORITHMS = {-7: (ec.SECP256R1(), hashes.SHA256()),
                 -35: (ec.SECP384R1(), hashes.SHA384()),
                 -36: (ec.SECP521R1(), hashes.SHA512()),
                 -47: (ec.SECP256K1(), hashes.SHA256())}
ML_DSA_ALGORITHMS = {-48: ML_DSA_44, -49: ML_DSA_65, -50: ML_DSA_87}


def ber_len(size):
    if size < 128:
        return bytes([size])
    if size < 256:
        return bytes([0x81, size])
    return b"\x82" + size.to_bytes(2, "big")


def tlv(tag, value):
    return tag.to_bytes((tag.bit_length() + 7) // 8, "big") + ber_len(len(value)) + value


def apdu(ins, p1=0, p2=0, data=b""):
    header = bytes([0, ins, p1, p2])
    if not data:
        return header + b"\x00"
    length = bytes([len(data)]) if len(data) < 256 else b"\x00" + len(data).to_bytes(2, "big")
    return header + length + data


def value(data, tag):
    prefix = tag.to_bytes((tag.bit_length() + 7) // 8, "big")
    assert data.startswith(prefix), f"expected TLV {tag:x}"
    at = len(prefix)
    size = data[at]
    at += 1
    if size & 128:
        count = size & 127
        size = int.from_bytes(data[at:at + count], "big")
        at += count
    assert len(data) == at + size, f"truncated/trailing TLV {tag:x}"
    return data[at:]


def patterns(secret):
    # Scalars also occur as little-endian limbs; scan both ends in both orders.
    return tuple(dict.fromkeys((secret[:16], secret[-16:], secret[::-1][:16], secret[::-1][-16:])))


def verify_fido(cose, signed, signature):
    alg = cose[3]
    if alg in EC_ALGORITHMS:
        curve, digest = EC_ALGORITHMS[alg]
        key = ec.EllipticCurvePublicNumbers(int.from_bytes(cose[-2], "big"),
                int.from_bytes(cose[-3], "big"), curve).public_key()
        key.verify(signature, signed, ec.ECDSA(digest))
    elif alg == -8:
        ed25519.Ed25519PublicKey.from_public_bytes(cose[-2]).verify(signature, signed)
    else:
        assert ML_DSA_ALGORITHMS[alg].verify(cose[-1], signed, signature), "ML-DSA signature invalid"


def scan(dev, pattern):
    return dict(item.split("=", 1) for item in dev.inspect(f"scan {pattern.hex()}").split())


def clean(dev, secrets):
    time.sleep(0.05)  # The worker sweeps after sending the response.
    results = {}
    for name, secret in secrets.items():
        counts = []
        for pattern in patterns(secret):
            found = scan(dev, pattern)
            count = int(found["count"])
            assert count == 0, f"{name}: secret residue remains at {found['addresses']}"
            counts.append(count)
        results[name] = counts
    return results


class Operations:
    def __init__(self, dev, report):
        self.dev, self.report = dev, report

    def run(self, label, operation, secrets=None):
        print(f"image operations: {label}", flush=True)
        row = self.report.setdefault(label, {})
        if self.dev.image:
            result = self.dev.measured("stack", operation, row)
            if secrets:
                row["residue"] = clean(self.dev, secrets)
        else:
            result = operation()
        row["oracle"] = "passed"
        return result

    def control(self, label, secret):
        if not self.dev.image:
            return
        self.dev.inspect(f"plant {CONTROL_ADDRESS} {secret[:16].hex()}")
        try:
            try:
                clean(self.dev, {label: secret})
            except AssertionError as error:
                assert str(error) == f"{label}: secret residue remains at {CONTROL_ADDRESS}", error
            else:
                raise AssertionError(f"{label}: planted leak escaped the command residue assertion")
        finally:
            self.dev.inspect(f"plant {CONTROL_ADDRESS} {'00' * 16}")
        clean(self.dev, {label: secret})
        self.report[f"{label}_control"] = "planted leak refused and cleared"


def fido(ops):
    dev = ops.dev
    pub = ops.run("fido_key_agreement", lambda: dev.ctap(6, {1: 2, 2: 2}))[1]
    proto = Protocol2(pub[-2], pub[-3])
    shared = {"pin_hmac": proto.hmac_key, "pin_aes": proto.aes_key}
    encrypted = proto.encrypt(PIN.ljust(64, b"\x00"))
    ops.run("fido_set_pin", lambda: dev.ctap(6, {1: 2, 2: 3, 3: proto.cose(),
            4: proto.authenticate(encrypted), 5: encrypted}), shared)

    def token():
        answer = dev.ctap(6, {1: 2, 2: 5, 3: proto.cose(),
                              6: proto.encrypt(hashlib.sha256(PIN).digest()[:16])})
        return proto.decrypt(answer[2])

    for alg in (*EC_ALGORITHMS, -8, *ML_DSA_ALGORITHMS):
        current = ops.run(f"fido_token_{alg}", token, shared)
        if dev.image:
            found = scan(dev, current)
            assert int(found["count"]) > 0, "live FIDO token was not found in SRAM"
            ops.report[f"fido_token_{alg}"]["live_token_matches"] = int(found["count"])
        def create():
            answer = dev.ctap(1, {
                1: CDH, 2: {"id": RP}, 3: {"id": bytes([abs(alg)]), "name": "image"},
                4: [{"alg": alg, "type": "public-key"}], 7: {"rk": True},
                8: hmac.digest(current, CDH, "sha256"), 9: 2})
            auth = answer[2]
            assert auth[:32] == hashlib.sha256(RP.encode()).digest() and auth[32] & 0x45 == 0x45
            attestation = answer[3]
            att_key = x509.load_der_x509_certificate(attestation["x5c"][0]).public_key()
            att_key.verify(attestation["sig"], auth + CDH, ec.ECDSA(hashes.SHA256()))
            size = int.from_bytes(auth[53:55], "big")
            cose = decode(auth[55 + size:])
            assert cose[3] == alg
            return auth[55:55 + size], cose

        cred, cose = ops.run(f"fido_create_{alg}", create, shared)
        current = ops.run(f"fido_assertion_token_{alg}", token, shared)

        def sign():
            answer = dev.ctap(2, {1: RP, 2: CDH, 3: [{"id": cred, "type": "public-key"}],
                                  6: hmac.digest(current, CDH, "sha256"), 7: 2})
            assert answer[2][32] & 4, "getAssertion missing UV"
            verify_fido(cose, answer[2] + CDH, answer[3])

        ops.run(f"fido_sign_{alg}", sign, shared)
    old_hash = proto.encrypt(hashlib.sha256(PIN).digest()[:16])
    encrypted = proto.encrypt(NEW_PIN.ljust(64, b"\x00"))
    ops.run("fido_change_pin", lambda: dev.ctap(6, {1: 2, 2: 4, 3: proto.cose(),
            4: proto.authenticate(encrypted + old_hash), 5: encrypted, 6: old_hash}),
            {**shared, "old_pin_token": current})
    ops.run("fido_old_token_refused", lambda: dev.ctap(2, {1: RP, 2: CDH,
            3: [{"id": cred, "type": "public-key"}], 6: hmac.digest(current, CDH, "sha256"), 7: 2}, 0x33), shared)
    ops.control("fido_shared_key", proto.hmac_key)
    # A cold cycle reopens the CTAP reset window; the socket acknowledges readiness.
    dev.power_cycle()
    ops.run("fido_reset", lambda: dev.ctap(7))
    assert dev.ctap(4)[4]["clientPin"] is False, "reset retained the PIN"
    ops.run("fido_deleted_credential", lambda: dev.ctap(2, {1: RP, 2: CDH,
            3: [{"id": cred, "type": "public-key"}]}, 0x2E))


def piv(ops, rsa_key):
    dev = ops.dev
    dev.select(PIV)
    ec_key = ec.derive_private_key(int.from_bytes(SCALAR, "big"), ec.SECP256R1())
    secret = {"piv_scalar": SCALAR}

    def authenticate():
        wit = value(value(dev.apdu(apdu(0x87, 0x0A, 0x9B, tlv(0x7C, tlv(0x80, b"")))), 0x7C), 0x80)
        decrypt = Cipher(algorithms.AES(MGM_KEY), modes.ECB()).decryptor()
        witness = decrypt.update(wit) + decrypt.finalize()
        challenge = CDH[:16]
        answer = dev.apdu(apdu(0x87, 0x0A, 0x9B, tlv(0x7C, tlv(0x80, witness) + tlv(0x81, challenge))))
        encrypt = Cipher(algorithms.AES(MGM_KEY), modes.ECB()).encryptor()
        assert value(value(answer, 0x7C), 0x82) == encrypt.update(challenge) + encrypt.finalize()

    ops.run("piv_management_auth", authenticate)
    ops.run("piv_import_ec", lambda: dev.apdu(apdu(0xFE, 0x11, 0x9D, tlv(6, SCALAR))), secret)
    ops.run("piv_verify", lambda: dev.apdu(apdu(0x20, 0, 0x80, b"123456\xff\xff")))

    def sign():
        answer = dev.apdu(apdu(0x87, 0x11, 0x9D, tlv(0x7C, tlv(0x82, b"") + tlv(0x81, CDH))))
        ec_key.public_key().verify(value(value(answer, 0x7C), 0x82), CDH,
                                   ec.ECDSA(utils.Prehashed(hashes.SHA256())))

    ops.run("piv_sign_ec", sign, secret)
    peer = ec.derive_private_key(17, ec.SECP256R1())
    point = peer.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

    def exchange():
        answer = dev.apdu(apdu(0x87, 0x11, 0x9D, tlv(0x7C, tlv(0x82, b"") + tlv(0x85, point))))
        assert value(value(answer, 0x7C), 0x82) == peer.exchange(ec.ECDH(), ec_key.public_key())

    ops.run("piv_ecdh", exchange, secret)
    parts = rsa_key.private_numbers()
    p, q = parts.p.to_bytes(128, "big"), parts.q.to_bytes(128, "big")
    rsa_secrets = {"piv_rsa_p": p, "piv_rsa_q": q}
    ops.run("piv_import_rsa", lambda: dev.apdu(apdu(0xFE, 7, 0x9E, tlv(1, p) + tlv(2, q))), rsa_secrets)

    def sign_rsa():
        di = DI_SHA256 + CDH
        block = b"\x00\x01" + b"\xff" * (256 - 3 - len(di)) + b"\x00" + di
        answer = dev.apdu(apdu(0x87, 7, 0x9E, tlv(0x7C, tlv(0x82, b"") + tlv(0x81, block))))
        rsa_key.public_key().verify(value(value(answer, 0x7C), 0x82), MESSAGE, padding.PKCS1v15(), hashes.SHA256())

    ops.run("piv_sign_rsa", sign_rsa, rsa_secrets)
    ops.run("piv_deauthenticate", lambda: dev.apdu(apdu(0x20, 0xFF, 0x80)), secret)
    ops.run("piv_sign_refused", lambda: dev.apdu(apdu(0x87, 0x11, 0x9D,
            tlv(0x7C, tlv(0x82, b"") + tlv(0x81, CDH))), 0x6982), secret)
    ops.control("piv_scalar", SCALAR)


def openpgp(ops, rsa_key):
    dev = ops.dev
    dev.select(OPENPGP)
    ops.run("openpgp_verify_admin", lambda: dev.apdu(apdu(0x20, 0, 0x83, b"12345678")))
    ec_key = ec.derive_private_key(int.from_bytes(SCALAR, "big"), ec.SECP256R1())
    secrets = {"openpgp_scalar": SCALAR, "openpgp_ed_seed": ED_SEED}

    def install(slot, crt, attributes, secret):
        dev.apdu(apdu(0xDA, 0, slot, attributes))
        header = tlv(0x4D, bytes([crt, 0]) + tlv(0x7F48, b"\x92" + ber_len(len(secret))) + tlv(0x5F48, secret))
        dev.apdu(apdu(0xDB, 0x3F, 0xFF, header))

    for slot, crt, attributes, key in ((0xC1, 0xB6, b"\x13" + P256_OID, SCALAR),
                                     (0xC2, 0xB8, b"\x12" + P256_OID, SCALAR),
                                     (0xC3, 0xA4, b"\x16" + ED25519_OID, ED_SEED)):
        ops.run(f"openpgp_import_{slot:x}", lambda: install(slot, crt, attributes, key), secrets)
    for mode in (0x81, 0x82):
        ops.run(f"openpgp_verify_{mode:x}", lambda: dev.apdu(apdu(0x20, 0, mode, b"123456")))

    def sign():
        signature = dev.apdu(apdu(0x2A, 0x9E, 0x9A, CDH))
        assert len(signature) == 64
        der = utils.encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
        ec_key.public_key().verify(der, MESSAGE, ec.ECDSA(hashes.SHA256()))

    ops.run("openpgp_sign_ec", sign, secrets)

    def authenticate():
        signature = dev.apdu(apdu(0x88, 0, 0, MESSAGE))
        ed25519.Ed25519PrivateKey.from_private_bytes(ED_SEED).public_key().verify(signature, MESSAGE)

    ops.run("openpgp_auth_ed25519", authenticate, secrets)
    peer = ec.derive_private_key(23, ec.SECP256R1())
    point = peer.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

    def decipher():
        answer = dev.apdu(apdu(0x2A, 0x80, 0x86, tlv(0xA6, tlv(0x7F49, tlv(0x86, point)))))
        assert answer == peer.exchange(ec.ECDH(), ec_key.public_key())

    ops.run("openpgp_ecdh", decipher, secrets)
    dev.select(PIV)
    dev.select(OPENPGP)
    ops.run("openpgp_auth_refused", lambda: dev.apdu(apdu(0x88, 0, 0, MESSAGE), 0x6982), secrets)
    ops.control("openpgp_seed", ED_SEED)
    dev.apdu(apdu(0x20, 0, 0x83, b"12345678"))
    parts = rsa_key.private_numbers()
    p, q = parts.p.to_bytes(128, "big"), parts.q.to_bytes(128, "big")
    rsa_secrets = {"openpgp_rsa_p": p, "openpgp_rsa_q": q}

    def install_rsa(slot, crt):
        dev.apdu(apdu(0xDA, 0, slot, bytes.fromhex("010800002000")))
        e = b"\x01\x00\x01"
        template = b"\x91" + ber_len(len(e)) + b"\x92" + ber_len(len(p)) + b"\x93" + ber_len(len(q))
        header = tlv(0x4D, bytes([crt, 0]) + tlv(0x7F48, template) + tlv(0x5F48, e + p + q))
        dev.apdu(apdu(0xDB, 0x3F, 0xFF, header))

    for slot, crt in ((0xC1, 0xB6), (0xC2, 0xB8), (0xC3, 0xA4)):
        ops.run(f"openpgp_import_rsa_{slot:x}", lambda: install_rsa(slot, crt), rsa_secrets)
    for mode in (0x81, 0x82):
        dev.apdu(apdu(0x20, 0, mode, b"123456"))

    def sign_rsa(ins, p1, p2):
        signature = dev.apdu(apdu(ins, p1, p2, DI_SHA256 + CDH))
        rsa_key.public_key().verify(signature, MESSAGE, padding.PKCS1v15(), hashes.SHA256())

    ops.run("openpgp_sign_rsa", lambda: sign_rsa(0x2A, 0x9E, 0x9A), rsa_secrets)
    ops.run("openpgp_auth_rsa", lambda: sign_rsa(0x88, 0, 0), rsa_secrets)
    ciphertext = rsa_key.public_key().encrypt(MESSAGE, padding.PKCS1v15())

    def decipher_rsa():
        assert dev.apdu(apdu(0x2A, 0x80, 0x86, b"\x00" + ciphertext)) == MESSAGE, "RSA decipher mismatch"

    ops.run("openpgp_decipher_rsa", decipher_rsa, rsa_secrets)
    ops.control("openpgp_rsa_factor", p)


def crc16(data):
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x8408 if crc & 1 else 0)
    return crc


def otp(ops):
    dev = ops.dev
    dev.select(OTP)
    secrets = {"otp_hmac": OTP_KEY, "otp_ipad": bytes(b ^ 0x36 for b in OTP_KEY[:16]),
               "otp_opad": bytes(b ^ 0x5C for b in OTP_KEY[:16]), "otp_aes": AES_KEY}

    def configure(slot, key, flags):
        config = bytearray(52)
        config[22:38] = key[:16]
        if len(key) == 20:
            config[16:20] = key[16:]
        config[46], config[47] = 0x40, flags
        config[50:52] = (~crc16(config[:50]) & 0xFFFF).to_bytes(2, "little")
        dev.apdu(apdu(1, slot, 0, bytes(config) + bytes(6)))

    ops.run("otp_program_hmac", lambda: configure(1, OTP_KEY, 0x26), secrets)
    ops.run("otp_program_aes", lambda: configure(3, AES_KEY, 0x20), secrets)

    def challenge_hmac():
        answer = dev.apdu(apdu(1, 0x30, 0, MESSAGE + b"\x7f" * (64 - len(MESSAGE))))
        assert answer == hmac.digest(OTP_KEY, MESSAGE, "sha1")

    ops.run("otp_hmac", challenge_hmac, secrets)

    def challenge_aes():
        answer = dev.apdu(apdu(1, 0x28, 0, MESSAGE[:6]))
        decrypt = Cipher(algorithms.AES(AES_KEY), modes.ECB()).decryptor()
        block = decrypt.update(answer) + decrypt.finalize()
        assert len(block) == 16 and block[:6] == MESSAGE[:6]
        assert block[6:] == SERIAL.hex().upper().encode()[:10], "OTP serial mismatch"

    ops.run("otp_aes", challenge_aes, secrets)
    ops.run("otp_delete", lambda: dev.apdu(apdu(1, 1, 0, bytes(58))), secrets)
    def deleted():
        assert dev.apdu(apdu(1, 0x30, 0, bytes(64))) == b"", "deleted OTP slot still answered"

    ops.run("otp_deleted_slot", deleted, secrets)
    ops.control("otp_key", OTP_KEY)


def run(dev, report):
    import image_rsa

    ops = Operations(dev, report)
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    fido(ops)
    piv(ops, rsa_key)
    image_rsa.piv(ops)
    openpgp(ops, rsa_key)
    image_rsa.openpgp(ops, rsa_key)
    otp(ops)
