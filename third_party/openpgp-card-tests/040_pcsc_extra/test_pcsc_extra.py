import hashlib
import os

import pytest
from card_const import FACTORY_PASSPHRASE_PW1, FACTORY_PASSPHRASE_PW3
from constants_for_test import PW1_TEST4, PW3_TEST0

OPENPGP_AID = b"\xD2\x76\x00\x01\x24\x01"
PIV_AID = bytes.fromhex("A000000308")
PW1_DEFAULT = b"123456"
PW3_DEFAULT = b"12345678"
PIV_MGM_KEY = bytes.fromhex("0102030405060708" * 3)

MODE_PW1 = 0x81
MODE_PW2 = 0x82
MODE_PW3 = 0x83

INS_VERIFY = 0x20
INS_CHANGE_PIN = 0x24
INS_RESET_RETRY = 0x2C
INS_PSO = 0x2A
INS_INTERNAL_AUT = 0x88
INS_PUT_DATA = 0xDA
INS_IMPORT = 0xDB
INS_GET_DATA = 0xCA
INS_KEYPAIR_GEN = 0x47
INS_MSE = 0x22
INS_CHALLENGE = 0x84
INS_ACTIVATE = 0x44
INS_TERMINATE = 0xE6
INS_SELECT_DATA = 0xA5

OID_P256 = bytes.fromhex("2A8648CE3D030107")
OID_ED25519 = bytes.fromhex("2B06010401DA470F01")
OID_CV25519 = bytes.fromhex("2B060104019755010501")
ATTR_P256_ECDSA = bytes([0x13]) + OID_P256
ATTR_P256_ECDH = bytes([0x12]) + OID_P256
ATTR_ED25519 = bytes([0x16]) + OID_ED25519
ATTR_CV25519 = bytes([0x12]) + OID_CV25519
ATTR_RSA2K = bytes([0x01, 0x08, 0x00, 0x00, 0x20, 0x00])

CRT_SIG, CRT_DEC, CRT_AUT = 0xB6, 0xB8, 0xA4

DI_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")


def reader(card):
    return card._OpenPGP_Card__reader


def compose_apdu(ins, p1, p2, data=b"", le=None, cls=0x00):
    data = bytes(data)
    apdu = bytearray([cls, ins, p1, p2])
    if data:
        if len(data) < 256:
            apdu.append(len(data))
        else:
            apdu += bytes([0x00, len(data) >> 8, len(data) & 0xFF])
        apdu += data
    if le is not None:
        if le < 256:
            apdu.append(le)
        else:
            apdu += bytes([le >> 8, le & 0xFF])
    return bytes(apdu)


def raw(card, ins, p1, p2, data=b"", le=None, cls=0x00):
    cmd = compose_apdu(ins, p1, p2, data, cls=cls, le=le)
    resp = reader(card).send_cmd(cmd)
    body, sw = resp[:-2], resp[-2:]
    while sw[0] == 0x61:
        more = reader(card).send_cmd(compose_apdu(0xC0, 0x00, 0x00, le=sw[1]))
        body += more[:-2]
        sw = more[-2:]
    return body, sw


def expect(card, ins, p1, p2, data=b"", le=None, sw=b"\x90\x00", cls=0x00):
    body, got = raw(card, ins, p1, p2, data, le=le, cls=cls)
    assert got == sw
    return body


def select_openpgp(card):
    return expect(card, 0xA4, 0x04, 0x00, OPENPGP_AID, le=0)


def select_piv(card):
    return expect(card, 0xA4, 0x04, 0x00, PIV_AID, le=0)


def is_retry_error(exc):
    return exc.args and isinstance(exc.args[0], str) and exc.args[0].startswith("63c")


def verify_pw3(card):
    last_error = None
    for passwd in (FACTORY_PASSPHRASE_PW3, PW3_TEST0):
        try:
            assert card.verify(3, passwd)
            return passwd
        except ValueError as exc:
            if not is_retry_error(exc):
                raise
            last_error = exc
    raise last_error


def verify_pw1(card):
    try:
        assert card.verify(1, PW1_TEST4)
        return PW1_TEST4
    except ValueError as exc:
        if not is_retry_error(exc):
            raise

    assert card.verify(1, FACTORY_PASSPHRASE_PW1)
    assert card.change_passwd(1, FACTORY_PASSPHRASE_PW1, PW1_TEST4)
    assert card.verify(1, PW1_TEST4)
    return PW1_TEST4


def ber_len(n):
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82, n >> 8, n & 0xFF])


def import_ec_apdu(crt, scalar):
    tmpl = bytes([0x92, len(scalar)])
    f7f48 = bytes([0x7F, 0x48, len(tmpl)]) + tmpl
    f5f48 = bytes([0x5F, 0x48, len(scalar)]) + scalar
    body = bytes([crt, 0x00]) + f7f48 + f5f48
    return bytes([0x4D, len(body)]) + body


def rsa_import_header(crt, e, p, q):
    tmpl = b"".join(bytes([tag]) + ber_len(len(v)) for tag, v in ((0x91, e), (0x92, p), (0x93, q)))
    f7f48 = bytes([0x7F, 0x48]) + ber_len(len(tmpl)) + tmpl
    kd = e + p + q
    f5f48 = bytes([0x5F, 0x48]) + ber_len(len(kd)) + kd
    body = bytes([crt, 0x00]) + f7f48 + f5f48
    return bytes([0x4D]) + ber_len(len(body)) + body


def rsa_key_parts(priv):
    nums = priv.private_numbers()
    e = priv.public_key().public_numbers().e.to_bytes(3, "big")
    p = nums.p.to_bytes(128, "big")
    q = nums.q.to_bytes(128, "big")
    return e, p, q


def gen_apdu_data(crt):
    return bytes([crt, 0x00])


def parse_tlv(data):
    out, i = {}, 0
    data = bytes(data)
    while i < len(data):
        tag = data[i]
        i += 1
        ln = data[i]
        i += 1
        if ln == 0x81:
            ln = data[i]
            i += 1
        elif ln == 0x82:
            ln = (data[i] << 8) | data[i + 1]
            i += 2
        out[tag] = data[i:i + ln]
        i += ln
    return out


def tlv(tag, value):
    value = bytes(value)
    return bytes([tag]) + ber_len(len(value)) + value


def authenticate_piv_management(card):
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    response = expect(card, 0x87, 0x0A, 0x9B, tlv(0x7C, tlv(0x80, b"")))
    encrypted_witness = parse_tlv(parse_tlv(response)[0x7C])[0x80]
    decryptor = Cipher(algorithms.AES(PIV_MGM_KEY), modes.ECB()).decryptor()
    witness = decryptor.update(encrypted_witness) + decryptor.finalize()

    challenge = os.urandom(16)
    request = tlv(0x7C, tlv(0x80, witness) + tlv(0x81, challenge))
    response = expect(card, 0x87, 0x0A, 0x9B, request)
    encrypted_challenge = parse_tlv(parse_tlv(response)[0x7C])[0x82]
    encryptor = Cipher(algorithms.AES(PIV_MGM_KEY), modes.ECB()).encryptor()
    assert encrypted_challenge == encryptor.update(challenge) + encryptor.finalize()


def parse_ec_point(do):
    do = bytes(do)
    assert do[:2] == b"\x7f\x49"
    i = 2
    i += 1 + (do[i] & 0x7F) if do[i] & 0x80 else 1
    assert do[i] == 0x86
    i += 1
    if do[i] & 0x80:
        nl = do[i] & 0x7F
        plen = int.from_bytes(do[i + 1:i + 1 + nl], "big")
        i += 1 + nl
    else:
        plen = do[i]
        i += 1
    return do[i:i + plen]


def parse_rsa_pub(do):
    do = bytes(do)
    assert do[:3] == b"\x7f\x49\x82"
    i = 5
    assert do[i:i + 2] == b"\x81\x82"
    i += 2
    nlen = int.from_bytes(do[i:i + 2], "big")
    i += 2
    n = int.from_bytes(do[i:i + nlen], "big")
    i += nlen
    assert do[i] == 0x82
    elen = do[i + 1]
    e = int.from_bytes(do[i + 2:i + 2 + elen], "big")
    return n, e


def decipher_apdu_data(peer_point):
    f86 = bytes([0x86, len(peer_point)]) + peer_point
    f7f49 = bytes([0x7F, 0x49, len(f86)]) + f86
    return bytes([0xA6, len(f7f49)]) + f7f49


def test_openpgp_status_objects(card):
    select_openpgp(card)
    assert expect(card, INS_GET_DATA, 0x00, 0x4F, le=0).startswith(OPENPGP_AID)
    assert expect(card, INS_GET_DATA, 0x5F, 0x52, le=0) == b"\x00\x31\x84\x73\x80\x01\xc0\x05\x90\x00"
    pw = expect(card, INS_GET_DATA, 0x00, 0xC4, le=0)
    assert len(pw) == 7
    assert pw[0] in (0x00, 0x01)
    assert pw[1:5] == bytes([127, 127, 127, 3])
    assert pw[5] in (0, 3)
    assert pw[6] == 3
    app = expect(card, INS_GET_DATA, 0x00, 0x6E, le=0)
    assert app and app[0] == 0x4F
    assert OPENPGP_AID in app
    assert expect(card, 0xF1, 0x00, 0x00, le=0) == b"\x04\x06\x00"


def test_openpgp_fixed_width_status_dos_are_zero_padded(card):
    verify_pw3(card)
    card.cmd_put_data(0x00, 0xC7, b"\xAA")
    card.cmd_put_data(0x00, 0xC8, b"\xBB\xCC")
    card.cmd_put_data(0x00, 0xC9, b"")
    fp = card.cmd_get_data(0x00, 0xC5)
    assert len(fp) == 60
    assert fp[:20] == b"\xAA" + bytes(19)
    assert fp[20:40] == b"\xBB\xCC" + bytes(18)
    assert fp[40:] == bytes(20)

    card.cmd_put_data(0x00, 0xCA, b"\x11")
    card.cmd_put_data(0x00, 0xCB, b"")
    card.cmd_put_data(0x00, 0xCC, b"\x22\x33")
    cafp = card.cmd_get_data(0x00, 0xC6)
    assert len(cafp) == 60
    assert cafp[:20] == b"\x11" + bytes(19)
    assert cafp[20:40] == bytes(20)
    assert cafp[40:] == b"\x22\x33" + bytes(18)

    card.cmd_put_data(0x00, 0xCE, b"\x01")
    card.cmd_put_data(0x00, 0xCF, b"")
    card.cmd_put_data(0x00, 0xD0, b"\x02\x03")
    ts = card.cmd_get_data(0x00, 0xCD)
    assert len(ts) == 12
    assert ts[:4] == b"\x01" + bytes(3)
    assert ts[4:8] == bytes(4)
    assert ts[8:] == b"\x02\x03" + bytes(2)


def test_openpgp_rejects_invalid_algorithm_attributes(card):
    verify_pw3(card)
    for tag in (0xC1, 0xC2, 0xC3):
        _, sw = raw(card, INS_PUT_DATA, 0x00, tag, bytes([0x13]) + bytes(16))
        assert sw == b"\x67\x00"
        _, sw = raw(card, INS_PUT_DATA, 0x00, tag, b"\x01\x08")
        assert sw == b"\x67\x00"


def test_openpgp_pin_put_data_and_change(card):
    verify_pw3(card)
    assert card.cmd_put_data(0x00, 0x5E, b"alice@example")
    assert card.cmd_put_data(0x00, 0x5B, b"Doe<<John")
    assert card.cmd_put_data(0x5F, 0x50, b"https://example/key.asc")
    assert card.cmd_get_data(0x00, 0x5E) == b"alice@example"

    expect(card, INS_VERIFY, 0xFF, MODE_PW3)
    _, sw = raw(card, INS_PUT_DATA, 0x00, 0x5E, b"nope")
    assert sw == b"\x69\x82"

    verify_pw1(card)
    with pytest.raises(ValueError, match=r"^63c[0-9a-f]$"):
        card.verify(1, b"000000")
    verify_pw1(card)

    assert card.change_passwd(1, PW1_TEST4, b"654321")
    assert card.verify(1, b"654321")
    with pytest.raises(ValueError, match=r"^63c[0-9a-f]$"):
        card.verify(1, PW1_TEST4)
    assert card.change_passwd(1, b"654321", PW1_TEST4)
    verify_pw1(card)


def test_openpgp_imported_ec_crypto(card):
    crypto = pytest.importorskip("cryptography")
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    verify_pw3(card)

    sig_priv = ec.generate_private_key(ec.SECP256R1())
    sig_scalar = sig_priv.private_numbers().private_value.to_bytes(32, "big")
    card.cmd_put_data(0x00, 0xC1, ATTR_P256_ECDSA)
    card.cmd_put_data_odd(0x3F, 0xFF, import_ec_apdu(CRT_SIG, sig_scalar))
    msg = b"sign with the imported P-256 key"
    sig = card.cmd_pso(0x9E, 0x9A, hashlib.sha256(msg).digest())
    assert len(sig) == 64
    sig_priv.public_key().verify(
        encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")),
        msg,
        ec.ECDSA(hashes.SHA256()),
    )

    aut_priv = ed25519.Ed25519PrivateKey.generate()
    aut_seed = aut_priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    card.cmd_put_data(0x00, 0xC3, ATTR_ED25519)
    card.cmd_put_data_odd(0x3F, 0xFF, import_ec_apdu(CRT_AUT, aut_seed))
    chal = b"internal-authenticate challenge"
    asig = card.cmd_internal_authenticate(chal)
    assert len(asig) == 64
    aut_priv.public_key().verify(asig, chal)

    dec_priv = ec.generate_private_key(ec.SECP256R1())
    dec_scalar = dec_priv.private_numbers().private_value.to_bytes(32, "big")
    card.cmd_put_data(0x00, 0xC2, ATTR_P256_ECDH)
    card.cmd_put_data_odd(0x3F, 0xFF, import_ec_apdu(CRT_DEC, dec_scalar))
    eph_priv = ec.generate_private_key(ec.SECP256R1())
    eph_pub = eph_priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    z = card.cmd_pso(0x80, 0x86, decipher_apdu_data(eph_pub))
    assert z == dec_priv.exchange(ec.ECDH(), eph_priv.public_key())


def test_openpgp_imported_rsa_crypto(card):
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    verify_pw3(card)

    sig_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    card.cmd_put_data(0x00, 0xC1, ATTR_RSA2K)
    card.cmd_put_data_odd(0x3F, 0xFF, rsa_import_header(CRT_SIG, *rsa_key_parts(sig_priv)))
    msg = b"sign with the imported RSA-2048 key"
    sig = card.cmd_pso(0x9E, 0x9A, DI_SHA256 + hashlib.sha256(msg).digest())
    assert len(sig) == 256
    sig_priv.public_key().verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())

    dec_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    card.cmd_put_data(0x00, 0xC2, ATTR_RSA2K)
    card.cmd_put_data_odd(0x3F, 0xFF, rsa_import_header(CRT_DEC, *rsa_key_parts(dec_priv)))
    session = os.urandom(24)
    ct = dec_priv.public_key().encrypt(session, padding.PKCS1v15())
    assert card.cmd_pso(0x80, 0x86, b"\x00" + ct) == session

    aut_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    card.cmd_put_data(0x00, 0xC3, ATTR_RSA2K)
    card.cmd_put_data_odd(0x3F, 0xFF, rsa_import_header(CRT_AUT, *rsa_key_parts(aut_priv)))
    chal = b"internal-authenticate challenge"
    asig = card.cmd_internal_authenticate(DI_SHA256 + hashlib.sha256(chal).digest())
    aut_priv.public_key().verify(asig, chal, padding.PKCS1v15(), hashes.SHA256())


def test_openpgp_x25519_decipher(card):
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    verify_pw3(card)
    dec = X25519PrivateKey.generate()
    scalar_be = dec.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )[::-1]
    card.cmd_put_data(0x00, 0xC2, ATTR_CV25519)
    card.cmd_put_data_odd(0x3F, 0xFF, import_ec_apdu(CRT_DEC, scalar_be))
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert card.cmd_pso(0x80, 0x86, decipher_apdu_data(b"\x40" + eph_pub)) == dec.exchange(eph.public_key())


def test_openpgp_keygen_public_key_round_trip(card):
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    verify_pw3(card)
    card.cmd_put_data(0x00, 0xC1, ATTR_P256_ECDSA)
    sig_do = card.cmd_genkey(1)
    assert card.cmd_get_public_key(1) == sig_do
    sig_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), parse_ec_point(sig_do))
    msg = b"sign with generated P-256 key"
    sig = card.cmd_pso(0x9E, 0x9A, hashlib.sha256(msg).digest())
    sig_pub.verify(
        encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")),
        msg,
        ec.ECDSA(hashes.SHA256()),
    )

    card.cmd_put_data(0x00, 0xC3, ATTR_ED25519)
    aut_do = card.cmd_genkey(3)
    aut_pub = ed25519.Ed25519PublicKey.from_public_bytes(parse_ec_point(aut_do))
    chal = b"generated internal-authenticate challenge"
    aut_pub.verify(card.cmd_internal_authenticate(chal), chal)

    card.cmd_put_data(0x00, 0xC2, ATTR_P256_ECDH)
    dec_do = card.cmd_genkey(2)
    dec_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), parse_ec_point(dec_do))
    eph = ec.generate_private_key(ec.SECP256R1())
    eph_pub = eph.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    assert card.cmd_pso(0x80, 0x86, decipher_apdu_data(eph_pub)) == eph.exchange(ec.ECDH(), dec_pub)


def test_openpgp_mse_decipher_slot_swap(card):
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    verify_pw3(card)
    dec_priv = ec.generate_private_key(ec.SECP256R1())
    aut_priv = ec.generate_private_key(ec.SECP256R1())
    card.cmd_put_data(0x00, 0xC2, ATTR_P256_ECDH)
    card.cmd_put_data_odd(0x3F, 0xFF, import_ec_apdu(CRT_DEC, dec_priv.private_numbers().private_value.to_bytes(32, "big")))
    card.cmd_put_data(0x00, 0xC3, ATTR_P256_ECDH)
    card.cmd_put_data_odd(0x3F, 0xFF, import_ec_apdu(CRT_AUT, aut_priv.private_numbers().private_value.to_bytes(32, "big")))
    eph = ec.generate_private_key(ec.SECP256R1())
    peer = eph.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    z_dec = card.cmd_pso(0x80, 0x86, decipher_apdu_data(peer))
    expect(card, INS_MSE, 0x41, 0xA4, b"\x83\x01\x03")
    z_aut = card.cmd_pso(0x80, 0x86, decipher_apdu_data(peer))
    assert z_dec == dec_priv.exchange(ec.ECDH(), eph.public_key())
    assert z_aut == aut_priv.exchange(ec.ECDH(), eph.public_key())
    assert z_dec != z_aut


def test_openpgp_reset_code_and_pw_status(card):
    verify_pw3(card)
    before = card.cmd_get_data(0x00, 0xC4)
    new_flag = 0x00 if before[0] else 0x01
    card.cmd_put_data(0x00, 0xC4, bytes([new_flag]))
    after = card.cmd_get_data(0x00, 0xC4)
    assert after[0] == new_flag
    assert after[4:7] == before[4:7]
    card.cmd_put_data(0x00, 0xC4, bytes([before[0]]))

    card.cmd_put_data_remove(0x00, 0xD3)
    pw = card.cmd_get_data(0x00, 0xC4)
    assert pw[5] == 0
    _, sw = raw(card, INS_RESET_RETRY, 0x00, MODE_PW1, b"12345678" + b"222222")
    assert sw == b"\x6A\x88"
    verify_pw1(card)

    assert card.setup_reset_code(b"reset123")
    select_openpgp(card)
    pw = card.cmd_get_data(0x00, 0xC4)
    assert pw[5] == 3
    _, sw = raw(card, INS_CHANGE_PIN, 0x00, 0x82, b"reset123" + b"changed1")
    assert sw == b"\x6A\x88"
    assert card.reset_passwd_by_resetcode(b"reset123", b"111111")
    select_openpgp(card)
    assert card.verify(1, b"111111")
    select_openpgp(card)
    with pytest.raises(ValueError, match=r"^63c[0-9a-f]$"):
        card.verify(1, PW1_TEST4)
    select_openpgp(card)
    assert card.change_passwd(1, b"111111", PW1_TEST4)
    select_openpgp(card)
    verify_pw1(card)
    assert card.change_passwd(1, PW1_TEST4, FACTORY_PASSPHRASE_PW1)
    select_openpgp(card)
    assert card.verify(1, FACTORY_PASSPHRASE_PW1)


def test_openpgp_aes_pso_round_trip(card):
    verify_pw3(card)
    card.cmd_put_data(0x00, 0xC2, ATTR_P256_ECDH)
    card.cmd_genkey(2)
    pt = bytes(range(32))
    enc = card.cmd_pso(0x86, 0x80, pt)
    assert enc[:1] == b"\x02"
    assert enc[1:] != pt
    assert card.cmd_pso(0x80, 0x86, enc) == pt
    _, sw = raw(card, INS_PSO, 0x86, 0x80, bytes(15), le=0)
    assert sw == b"\x67\x00"


def test_openpgp_cardholder_certificate_occurrences(card):
    verify_pw3(card)
    certs = [bytes([0x30, 0x06, 0xC0 + i] + [i] * 5) for i in range(3)]
    for occ, cert in enumerate(certs):
        expect(card, INS_SELECT_DATA, occ, 0x04, b"\x60\x04\x5C\x02\x7F\x21")
        expect(card, INS_PUT_DATA, 0x7F, 0x21, cert)
    for occ, cert in enumerate(certs):
        expect(card, INS_SELECT_DATA, occ, 0x04, b"\x60\x04\x5C\x02\x7F\x21")
        assert card.cmd_get_data(0x7F, 0x21) == cert
    _, sw = raw(card, INS_SELECT_DATA, 0, 0x04, b"\x60\x04\x5C\x02\x00\x65")
    assert sw == b"\x6A\x88"
    _, sw = raw(card, INS_SELECT_DATA, 3, 0x04, b"\x60\x04\x5C\x02\x7F\x21")
    assert sw == b"\x6A\x88"
    for occ in range(3):
        expect(card, INS_SELECT_DATA, occ, 0x04, b"\x60\x04\x5C\x02\x7F\x21")
        expect(card, INS_PUT_DATA, 0x7F, 0x21)
        assert card.cmd_get_data(0x7F, 0x21) in (b"", None)


def test_openpgp_get_challenge_activate_and_terminate(card):
    c1 = expect(card, INS_CHALLENGE, 0x00, 0x00, le=8)
    c2 = expect(card, INS_CHALLENGE, 0x00, 0x00, le=8)
    assert len(c1) == len(c2) == 8
    assert c1 != c2
    assert len(expect(card, INS_CHALLENGE, 0x00, 0x00, le=32)) == 32
    expect(card, INS_ACTIVATE, 0x00, 0x00)
    expect(card, INS_VERIFY, 0xFF, MODE_PW3)
    select_openpgp(card)
    _, sw = raw(card, INS_TERMINATE, 0x00, 0x00)
    assert sw == b"\x69\x82"


def test_management_applet_config(card):
    mgmt_aid = bytes.fromhex("A000000527471117")
    expect(card, 0xA4, 0x04, 0x00, mgmt_aid)
    data = expect(card, 0x1D, 0x00, 0x00, le=0)
    assert data and data[0] == len(data) - 1
    fields = parse_tlv(data[1:])
    assert fields[0x05] == b"\x05\x07\x00"
    assert fields[0x01] in (b"\x18", b"\x00\x18")
    assert len(fields[0x02]) == 4
    assert fields[0x04] == b"\x01"
    select_openpgp(card)


def test_piv_management_auth_flow_binding(card):
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    # A single-auth challenge cannot be replayed as a mutual-auth witness.
    select_piv(card)
    response = expect(card, 0x87, 0x0A, 0x9B, tlv(0x7C, tlv(0x81, b"")))
    challenge = parse_tlv(parse_tlv(response)[0x7C])[0x81]
    request = tlv(0x7C, tlv(0x80, challenge) + tlv(0x81, os.urandom(16)))
    _, sw = raw(card, 0x87, 0x0A, 0x9B, request)
    assert sw == b"\x69\x84"
    _, sw = raw(card, 0xDB, 0x3F, 0xFF,
                tlv(0x5C, bytes.fromhex("5FC102")) + tlv(0x53, b"blocked"))
    assert sw == b"\x69\x82"

    # A caller-supplied tag 0x81 is not a management-key encryption oracle.
    select_piv(card)
    response = expect(card, 0x87, 0x0A, 0x9B, tlv(0x7C, tlv(0x81, b"")))
    challenge = parse_tlv(parse_tlv(response)[0x7C])[0x81]
    _, sw = raw(card, 0x87, 0x0A, 0x9B, tlv(0x7C, tlv(0x81, challenge)))
    assert sw == b"\x6A\x80"

    # A mutual-auth witness is bound to the algorithm that issued it.
    select_piv(card)
    response = expect(card, 0x87, 0x0A, 0x9B, tlv(0x7C, tlv(0x80, b"")))
    encrypted_witness = parse_tlv(parse_tlv(response)[0x7C])[0x80]
    decryptor = Cipher(algorithms.AES(PIV_MGM_KEY), modes.ECB()).decryptor()
    witness = decryptor.update(encrypted_witness) + decryptor.finalize()
    request = tlv(0x7C, tlv(0x80, witness[:8]) + tlv(0x81, os.urandom(8)))
    _, sw = raw(card, 0x87, 0x03, 0x9B, request)
    assert sw == b"\x69\x84"

    # Both sanctioned management authentication flows still work.
    select_piv(card)
    response = expect(card, 0x87, 0x0A, 0x9B, tlv(0x7C, tlv(0x81, b"")))
    challenge = parse_tlv(parse_tlv(response)[0x7C])[0x81]
    encryptor = Cipher(algorithms.AES(PIV_MGM_KEY), modes.ECB()).encryptor()
    encrypted_challenge = encryptor.update(challenge) + encryptor.finalize()
    expect(card, 0x87, 0x0A, 0x9B, tlv(0x7C, tlv(0x82, encrypted_challenge)))

    select_piv(card)
    authenticate_piv_management(card)
    select_openpgp(card)


def test_piv_basic_version_serial_and_object_round_trip(card):
    select_piv(card)
    assert expect(card, 0xFD, 0x00, 0x00, le=0) == b"\x05\x07\x00"
    assert len(expect(card, 0xF8, 0x00, 0x00, le=0)) == 4

    authenticate_piv_management(card)
    expect(card, 0x20, 0x00, 0x80, b"123456\xff\xff")
    chuid = bytes([0x30, 0x19, 0xD4, 0xE7, 0x39, 0xDA, 0x73, 0x9C, 0xED])
    expect(card, 0xDB, 0x3F, 0xFF, tlv(0x5C, bytes.fromhex("5FC102")) + tlv(0x53, chuid))
    got = expect(card, 0xCB, 0x3F, 0xFF, tlv(0x5C, bytes.fromhex("5FC102")), le=0)
    assert parse_tlv(got)[0x53] == chuid
    select_openpgp(card)
