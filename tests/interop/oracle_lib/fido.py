# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Raw CTAP fixtures with independent signature and PIN protocol checks."""
import hashlib
import hmac
import os

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import codec
from .transport import HID_MSG

HASH_ALGORITHMS = {-7: hashes.SHA256, -35: hashes.SHA384, -36: hashes.SHA512,
                   -47: hashes.SHA256, -9: hashes.SHA256, -51: hashes.SHA384, -52: hashes.SHA512,
                   -257: hashes.SHA256, -258: hashes.SHA384, -259: hashes.SHA512,
                   -37: hashes.SHA256, -38: hashes.SHA384, -39: hashes.SHA512}
SUPPORTED_ALGORITHMS = (*HASH_ALGORITHMS, -8, -19, -48, -49, -50)
RSK_ALGORITHMS = (-7, -35, -36, -47, -8, -9, -19, -51, -52, -48, -49, -50)


def public_key(cose):
    if cose[1] == 2:
        curve = {1: ec.SECP256R1, 2: ec.SECP384R1, 3: ec.SECP521R1, 8: ec.SECP256K1}[cose[-1]]()
        return ec.EllipticCurvePublicNumbers(int.from_bytes(cose[-2], "big"), int.from_bytes(cose[-3], "big"), curve).public_key()
    if cose[1] == 3:
        return rsa.RSAPublicNumbers(int.from_bytes(cose[-2], "big"), int.from_bytes(cose[-1], "big")).public_key()
    if cose[3] in (-8, -19):
        return ed25519.Ed25519PublicKey.from_public_bytes(cose[-2])
    if cose[3] in (-48, -49, -50):
        from cryptography.hazmat.primitives.asymmetric import mldsa
        return {-48: mldsa.MLDSA44PublicKey, -49: mldsa.MLDSA65PublicKey, -50: mldsa.MLDSA87PublicKey}[cose[3]].from_public_bytes(cose[-1])
    raise ValueError("unsupported COSE public key")


def verify(key, algorithm, signature, message):
    if algorithm in (-8, -19, -48, -49, -50):
        key.verify(signature, message)
    elif algorithm in (-7, -35, -36, -47, -9, -51, -52):
        key.verify(signature, message, ec.ECDSA(HASH_ALGORITHMS[algorithm]()))
    else:
        digest = HASH_ALGORITHMS[algorithm]()
        scheme = padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size) if algorithm in (-37, -38, -39) else padding.PKCS1v15()
        key.verify(signature, message, scheme, digest)


def verified(session, label, key, algorithm, signature, message):
    verify(key, algorithm, signature, message)
    session.check(label, True)
    changed = bytes([signature[0] ^ 1]) + signature[1:]
    try:
        verify(key, algorithm, changed, message)
    except InvalidSignature:
        session.check(label + " tamper control", True)
    else:
        session.check(label + " tamper control", False)


def auth_data(data):
    if len(data) < 37:
        raise ValueError("truncated authenticator data")
    result = {"rp_hash": data[:32], "flags": data[32], "counter": int.from_bytes(data[33:37], "big")}
    offset = 37
    if data[32] & 0x40:
        if len(data) < 55:
            raise ValueError("truncated attested credential data")
        length = int.from_bytes(data[53:55], "big")
        offset = 55 + length
        if offset >= len(data):
            raise ValueError("truncated credential ID or public key")
        result.update(aaguid=data[37:53], credential_id=data[55:offset])
        result["cose"], consumed = codec.decode(data[offset:], prefix=True)
        offset += consumed
    if data[32] & 0x80:
        result["extensions"], consumed = codec.decode(data[offset:], prefix=True)
        offset += consumed
    if offset != len(data):
        raise ValueError("unexpected trailing authenticator data")
    return result


class PinProtocol:
    def __init__(self, version, peer):
        if version not in (1, 2):
            raise ValueError("unknown PIN/UV protocol")
        self.version = version
        secret = ec.generate_private_key(ec.SECP256R1())
        point = secret.public_key().public_numbers()
        self.cose = {1: 2, 3: -25, -1: 1, -2: point.x.to_bytes(32, "big"), -3: point.y.to_bytes(32, "big")}
        remote = ec.EllipticCurvePublicNumbers(int.from_bytes(peer[-2], "big"), int.from_bytes(peer[-3], "big"), ec.SECP256R1()).public_key()
        shared = secret.exchange(ec.ECDH(), remote)
        if version == 1:
            self.mac_key = self.aes_key = hashlib.sha256(shared).digest()
        else:
            self.mac_key, self.aes_key = [HKDF(hashes.SHA256(), 32, bytes(32), label).derive(shared) for label in (b"CTAP2 HMAC key", b"CTAP2 AES key")]

    def encrypt(self, value):
        iv = os.urandom(16) if self.version == 2 else bytes(16)
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv)).encryptor()
        return (iv if self.version == 2 else b"") + cipher.update(value) + cipher.finalize()

    def decrypt(self, value):
        iv, body = (value[:16], value[16:]) if self.version == 2 else (bytes(16), value)
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv)).decryptor()
        return cipher.update(body) + cipher.finalize()

    def authenticate(self, value):
        return token_mac(self.version, self.mac_key, value)


def token_mac(version, token, value):
    return hmac.digest(token, value, "sha256")[:16 if version == 1 else 32]


def info(session):
    if "fido.info" not in session.values:
        session.bind("fido.info", session.ctap_value(session.ctap(4)))
    return session.values["fido.info"]


def pin_protocol(session, version=None):
    versions = info(session).get(6, [1])
    version = version or (2 if 2 in versions else 1)
    session.require(version in versions, "PIN protocol is not advertised; command support is unmeasured", "unknown")
    peer = session.ctap_value(session.ctap(6, {1: version, 2: 2}))[1]
    return PinProtocol(version, peer)


def pin_token(session, permissions, rp=None, version=None):
    session.require(session.options.pin is not None, "authenticated scenario requires --pin-env")
    protocol = pin_protocol(session, version)
    modern = info(session).get(4, {}).get("pinUvAuthToken", False)
    request = {1: protocol.version, 2: 9 if modern else 5, 3: protocol.cose,
               6: protocol.encrypt(hashlib.sha256(session.options.pin.encode()).digest()[:16])}
    if modern:
        request[9] = permissions
        if rp is not None:
            request[10] = rp
    response = session.ctap_value(session.ctap(6, request))
    token = protocol.decrypt(response[2])
    session.check("token length", len(token) in ((32,) if protocol.version == 2 else (16, 32)))
    return protocol.version, token


def authorize(session, request, permission, rp, challenge, auth_key, protocol_key):
    options = info(session).get(4, {})
    if session.options.pin and options.get("clientPin"):
        version, token = pin_token(session, permission, rp)
        request[auth_key], request[protocol_key] = token_mac(version, token, challenge), version
    elif options.get("alwaysUv") or session.profile == "trezor" and options.get("uv"):
        request.setdefault(7 if permission == 1 else 5, {})["uv"] = True
    elif permission == 1 and options.get("clientPin") and not options.get("makeCredUvNotRqd"):
        session.require(False, "device has a PIN; supply --pin-env")
    return request


def cm(session, version, token, subcommand, parameters=None):
    request = {1: subcommand}
    if parameters is not None:
        request[2] = parameters
    if subcommand not in (3, 5):
        request.update({3: version, 4: token_mac(version, token, bytes([subcommand]) + (codec.encode(parameters) if parameters is not None else b""))})
    return session.ctap(10, request)


def pin_setup(session):
    with session.case("fido.pin.set-if-unset", ("F03", "F04"), effects=("set_fido_pin_if_unset",)):
        session.require(session.profile != "trezor", "wallet profile excludes host PIN changes", "excluded_by_profile")
        session.require(session.options.pin is not None, "PIN setup requires --pin-env")
        if info(session).get(4, {}).get("clientPin") is True:
            session.observe("PIN setup", "existing PIN retained")
            return
        session.require(info(session).get(4, {}).get("clientPin") is False, "clientPIN is not advertised; command support is unmeasured", "unknown")
        raw = session.options.pin.encode()
        session.require(4 <= len(session.options.pin) and len(raw) <= 63, "fixture PIN must have at least four characters and at most 63 UTF-8 bytes")
        protocol = pin_protocol(session)
        encrypted = protocol.encrypt(raw.ljust(64, b"\x00"))
        session.ctap_value(session.ctap(6, {1: protocol.version, 2: 3, 3: protocol.cose, 4: protocol.authenticate(encrypted), 5: encrypted}))
        session.state("fido.pin", "set")
        session.bind("fido.info", session.ctap_value(session.ctap(4)))


def credential(session, algorithm, resident):
    label = f"fido.fixture.{algorithm}.{'resident' if resident else 'wrapped'}"
    with session.case(label, ("F11", "F12", "F13", "F17", "FE01", "FE02", "FE03", "FE05", "FE11", "FE12", "FE13"), effects=("create_fido_credential",), touch=True):
        capabilities = info(session)
        advertised = [item["alg"] for item in capabilities.get(10, [{"alg": -7}])]
        session.require(algorithm in advertised or session.profile == "rsk" and algorithm in RSK_ALGORITHMS,
                        "algorithm is not in the advertised or confirmed profile catalog", "unknown")
        session.observe("advertised_algorithm", algorithm in advertised)
        session.require(algorithm in SUPPORTED_ALGORITHMS, "no independent verifier for this algorithm")
        if resident:
            session.require(capabilities.get(4, {}).get("rk") and capabilities.get(4, {}).get("credMgmt") and session.options.pin,
                            "resident fixtures require rk, credMgmt, and --pin-env for deletion")
        rp = session.fixture(label + ".rp", 8).hex() + ".oracle.invalid"
        user = session.fixture(label + ".user", 16)
        challenge = session.fixture(label + ".client-hash")
        extensions = {"oracle.unknown": True}
        if "credBlob" in capabilities.get(2, []):
            extensions["credBlob"] = session.fixture(label + ".blob", 16)
        if "credProtect" in capabilities.get(2, []):
            extensions["credProtect"] = 1
        if "hmac-secret" in capabilities.get(2, []):
            extensions["hmac-secret"] = True
        if resident and "largeBlobKey" in capabilities.get(2, []):
            extensions["largeBlobKey"] = True
        request = {1: challenge, 2: {"id": rp, "name": "Oracle fixture"},
                   3: {"id": user, "name": "oracle", "displayName": "Oracle fixture"},
                   4: [{"alg": algorithm, "type": "public-key"}], 6: extensions, 7: {"rk": resident}}
        authorize(session, request, 1, rp, challenge, 8, 9)
        descriptor = None
        try:
            registration = session.ctap_value(session.ctap(1, request))
            parsed = auth_data(registration[2])
            descriptor = {"type": "public-key", "id": parsed["credential_id"]}
            session.bind(label + ".descriptor", descriptor)
            session.state(label, "created")
            session.check("registration RP binding", parsed["rp_hash"], hashlib.sha256(rp.encode()).digest())
            session.check("registration user presence", bool(parsed["flags"] & 1))
            session.check("credential algorithm", parsed["cose"][3], algorithm)
            session.observe("algorithm", algorithm)
            session.observe("attestation_format", registration[1])
            session.observe("registration_flags", parsed["flags"])
            session.observe("registration_extensions", parsed.get("extensions", {}))
            key = public_key(parsed["cose"])
            statement = registration[3]
            if registration[1] == "packed":
                att_key = x509.load_der_x509_certificate(statement["x5c"][0]).public_key() if statement.get("x5c") else key
                verified(session, "packed attestation signature", att_key, statement["alg"], statement["sig"], registration[2] + challenge)
                session.observe("attestation_chain_count", len(statement.get("x5c", [])))
            elif registration[1] == "none":
                session.check("empty none attestation statement", statement, {})
            else:
                session.observe("attestation_verification", "format not verified")
            previous = parsed["counter"]
            blob_key = registration.get(5)
            hmac_previous = None
            repeats = 4 if extensions.get("hmac-secret") else 2
            for repeat in range(repeats):
                assertion_challenge = session.fixture(label + f".assertion.{repeat}")
                query = {1: rp, 2: assertion_challenge, 3: [descriptor], 5: {"up": True}}
                if "credBlob" in extensions:
                    query[4] = {"credBlob": True}
                if blob_key is not None:
                    query.setdefault(4, {})["largeBlobKey"] = True
                authorize(session, query, 2, rp, assertion_challenge, 6, 7)
                hmac_protocol = None
                if extensions.get("hmac-secret"):
                    versions = capabilities.get(6, [1])
                    hmac_protocol = pin_protocol(session, versions[(repeat // 2) % len(versions)])
                    salts = session.fixture(label + ".salt1") + (session.fixture(label + ".salt2") if repeat & 1 else b"")
                    encrypted = hmac_protocol.encrypt(salts)
                    query.setdefault(4, {})["hmac-secret"] = {1: hmac_protocol.cose, 2: encrypted, 3: hmac_protocol.authenticate(encrypted), 4: hmac_protocol.version}
                assertion = session.ctap_value(session.ctap(2, query))
                signed = auth_data(assertion[2])
                session.check("assertion credential ID", assertion.get(1, descriptor)["id"], descriptor["id"])
                session.check("assertion RP binding", signed["rp_hash"], hashlib.sha256(rp.encode()).digest())
                session.check("assertion user presence", bool(signed["flags"] & 1))
                session.check("counter monotonic or unsupported", signed["counter"] > previous or signed["counter"] == previous == 0)
                previous = signed["counter"]
                verified(session, "assertion signature", key, algorithm, assertion[3], assertion[2] + assertion_challenge)
                if "credBlob" in extensions and parsed.get("extensions", {}).get("credBlob") is True:
                    session.check("credBlob readback", signed.get("extensions", {}).get("credBlob"), extensions["credBlob"])
                if blob_key is not None:
                    session.check("largeBlobKey stable", assertion.get(7), blob_key)
                if hmac_protocol:
                    decrypted = hmac_protocol.decrypt(signed.get("extensions", {})["hmac-secret"])
                    session.check("hmac-secret output length", len(decrypted), len(salts))
                    if hmac_previous is not None:
                        session.check("hmac-secret deterministic across salts and protocols", decrypted[:32], hmac_previous)
                    hmac_previous = decrypted[:32]
                    session.observe(f"assertion.{repeat}.hmac_secret", decrypted, "presence")
                session.observe(f"assertion.{repeat}.flags", signed["flags"])
            for defect in ("wrong-rp", "damaged-handle"):
                damaged = dict(descriptor)
                if defect == "damaged-handle":
                    damaged["id"] = bytes([descriptor["id"][0] ^ 1]) + descriptor["id"][1:]
                requested_rp = "foreign.oracle.invalid" if defect == "wrong-rp" else rp
                query = {1: requested_rp, 2: challenge, 3: [damaged], 5: {"up": False}}
                authorize(session, query, 2, requested_rp, challenge, 6, 7)
                refused = session.ctap(2, query)
                session.observe(defect + ".status", refused.status)
                session.check(defect + " finds no credential", (refused.protocol, refused.status), ("applet_error", 0x2E))
                control = {1: rp, 2: challenge, 3: [descriptor], 5: {"up": True}}
                authorize(session, control, 2, rp, challenge, 6, 7)
                assertion = session.ctap_value(session.ctap(2, control))
                session.check("control RP after " + defect, auth_data(assertion[2])["rp_hash"], hashlib.sha256(rp.encode()).digest())
                verified(session, "valid key after " + defect, key, algorithm, assertion[3], assertion[2] + challenge)
        finally:
            if resident and descriptor is not None and not session.broken:
                session.trace.phase = "cleanup"
                version, token = pin_token(session, 4)
                session.ctap_value(cm(session, version, token, 6, {2: descriptor}))
                session.state(label, "deleted")
                query = {1: rp, 2: challenge, 3: [descriptor], 5: {"up": False}}
                authorize(session, query, 2, rp, challenge, 6, 7)
                refused = session.ctap(2, query)
                session.check("deleted credential finds no match", (refused.protocol, refused.status), ("applet_error", 0x2E))


def fido(session):
    pin_setup(session)
    algorithms = [entry["alg"] for entry in session.values.get("fido.info", {}).get(10, [{"alg": -7}])]
    if session.profile == "rsk":
        algorithms += list(RSK_ALGORITHMS)
    for algorithm in dict.fromkeys(algorithms):
        for resident in (False, True):
            credential(session, algorithm, resident)
    with session.case("fido.selection", ("F22",), touch=True):
        session.ctap_value(session.ctap(11))


def u2f(session):
    with session.case("u2f.version", ("U01",)):
        reply = session.hid_call(HID_MSG, u2f_apdu(3), "u2f.version")
        session.observe("status", reply.status)
        session.observe("version", reply.data[:-2])
    with session.case("u2f.fixture.lifecycle", ("U02", "U03", "U04", "U05", "U06"), effects=("create_u2f_credential",), touch=True):
        fixture = u2f_registration(session)
        challenge, application, point, handle = [fixture[field] for field in ("challenge", "application", "public_key", "handle")]
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
        payload = challenge + application + bytes([len(handle)]) + handle
        check = session.hid_call(HID_MSG, u2f_apdu(2, 7, payload), "u2f.check-only")
        session.check("check-only recognizes handle", check.status, 0x6985)
        for mode in (3, 8):
            result = session.hid_call(HID_MSG, u2f_apdu(2, mode, payload), f"u2f.authenticate.{mode}")
            session.observe(f"mode.{mode}.status", result.status)
            if result.status == 0x9000:
                signed = session.card_value(result)
                verified(session, "U2F assertion signature", key, -7, signed[5:], application + signed[:5] + challenge)
                session.check("U2F presence flag matches control mode", bool(signed[0] & 1), mode == 3)
                session.observe(f"mode.{mode}.flags", signed[0])
                session.observe(f"mode.{mode}.counter", int.from_bytes(signed[1:5], "big"), "presence")


def u2f_registration(session, label="u2f"):
    challenge, application = session.fixture(label + ".challenge"), session.fixture(label + ".application")
    body = session.card_value(session.hid_call(HID_MSG, u2f_apdu(1, data=challenge + application), "u2f.register"))
    session.check("registration marker", body[:1], b"\x05")
    session.check("U2F registration public key and handle header present", len(body) >= 67)
    length = body[66]
    point, handle, rest = body[1:66], body[67:67 + length], body[67 + length:]
    session.check("U2F key handle present", len(handle) == length and length > 0)
    session.check("U2F certificate header present", len(rest) >= 2 and rest[0] == 0x30)
    width = rest[1] & 0x7F if rest[1] & 0x80 else 0
    session.check("bounded DER certificate length header", width <= 4 and len(rest) >= 2 + width)
    size = 2 + width + int.from_bytes(rest[2:2 + width], "big") if width else 2 + rest[1]
    certificate = x509.load_der_x509_certificate(rest[:size])
    verified(session, "U2F attestation signature", certificate.public_key(), -7, rest[size:], b"\x00" + application + challenge + handle + point)
    return session.bind("u2f.fixture", {"handle": handle, "application": application, "challenge": challenge, "public_key": point})


def u2f_apdu(ins, p1=0, data=b""):
    return bytes([0, ins, p1, 0, 0]) + len(data).to_bytes(2, "big") + data + b"\x00\x00"
