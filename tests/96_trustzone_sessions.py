#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Exercise crypto cancellation and USB session boundaries on a TrustZone ELF."""

import argparse
import hmac
import importlib.util
import json
import socket
import time
from ctaphid import Protocol2
from pathlib import Path

spec = importlib.util.spec_from_file_location("crypto", Path(__file__).with_name("95_trustzone_crypto_keepalive.py"))
crypto = importlib.util.module_from_spec(spec)
spec.loader.exec_module(crypto)

KEEPALIVE_CANCEL = 0x2D
CTAPHID_CANCEL = 0x91
CCID_ABORT = 0x72
CMD_ABORTED = 0xFF
PIV_AID = bytes.fromhex("a000000308000010000100")
SETS = dict(zip((44, 65, 87), crypto.MLDSA_SETS))
RECOVERY_TIMEOUT_S = 180


class Ccid(crypto.Ccid):
    def __init__(self, port, inspect_port, activate=True):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=RECOVERY_TIMEOUT_S)
        self.inspect_port = inspect_port
        self.seq = 0
        if activate:
            atr, _ = self.call(0x62, b"")
            assert atr.startswith(b"\x3b")

    def begin(self, command, body, sequence=None):
        self.deadline = time.monotonic() + RECOVERY_TIMEOUT_S
        sequence = self.seq if sequence is None else sequence
        self.seq = (sequence + 1) % 256
        self.active = sequence
        message = bytes([command]) + len(body).to_bytes(4, "little") + bytes([0, sequence, 0, 0, 0]) + body
        crypto.inspect(self.inspect_port, "transport-begin")
        self.sock.sendall(b"\0" + len(message).to_bytes(4, "big") + message)

    def message(self):
        assert time.monotonic() < self.deadline, "CCID kept sending WTX without worker progress"
        size = int.from_bytes(crypto.receive(self.sock, 4), "big")
        assert 10 <= size <= 3072
        return crypto.receive(self.sock, size)

    def processing(self):
        message = self.message()
        assert message[6] == self.active and message[7] == 0x80, "RSA completed before the event barrier"

    def response(self):
        while True:
            message = self.message()
            assert message[6] == self.active, f"late CCID sequence {message[6]} replaced {self.active}"
            if message[7] != 0x80:
                return message

    def call(self, command, body):
        self.begin(command, body)
        message = self.response()
        assert message[7] & 0xC0 == 0, f"CCID failure: {message[7:10].hex()}"
        return message[10:], {}

    def raw_apdu(self, ins, p1, p2, body=b""):
        header = bytes([0, ins, p1, p2])
        length = bytes([len(body)]) if len(body) < 256 else b"\0" + len(body).to_bytes(2, "big")
        response, _ = self.call(0x6F, header + (length + body if body else b""))
        return response[:-2], int.from_bytes(response[-2:], "big")

    def authorize(self):
        self.apdu(0xA4, 4, 0, PIV_AID)
        key = bytes(range(1, 9)) * 3
        body, _ = self.apdu(0x87, 0x0A, 0x9B, crypto.tlv(0x7C, crypto.tlv(0x80, b"")))
        dec = crypto.Cipher(crypto.algorithms.AES(key), crypto.modes.ECB()).decryptor()
        witness = dec.update(crypto.parse_tlv(crypto.parse_tlv(body)[0x7C])[0x80]) + dec.finalize()
        challenge = bytes(range(16))
        body, _ = self.apdu(0x87, 0x0A, 0x9B, crypto.tlv(0x7C, crypto.tlv(0x80, witness) + crypto.tlv(0x81, challenge)))
        encrypt = crypto.Cipher(crypto.algorithms.AES(key), crypto.modes.ECB()).encryptor()
        assert crypto.parse_tlv(crypto.parse_tlv(body)[0x7C])[0x82] == encrypt.update(challenge) + encrypt.finalize()
        self.apdu(0x20, 0, 0x80, b"123456\xff\xff")
        assert self.raw_apdu(0x20, 0, 0x80)[1] == 0x9000

    def public(self):
        body, _ = self.apdu(0xF7, 0, 0x9C)
        fields = crypto.parse_tlv(crypto.parse_tlv(body)[4])
        return crypto.rsa.RSAPublicNumbers(int.from_bytes(fields[0x82], "big"), int.from_bytes(fields[0x81], "big")).public_key()

    def sign_body(self, message):
        digest = bytes.fromhex("3031300d060960864801650304020105000420") + crypto.hashlib.sha256(message).digest()
        encoded = b"\0\x01" + b"\xff" * (256 - 3 - len(digest)) + b"\0" + digest
        return crypto.tlv(0x7C, crypto.tlv(0x82, b"") + crypto.tlv(0x81, encoded))

    def assert_auth_cleared(self):
        assert self.raw_apdu(0x20, 0, 0x80)[1] != 0x9000, "PIN authorization survived USB reset before SELECT"
        self.apdu(0xA4, 4, 0, PIV_AID)
        status = self.raw_apdu(0x20, 0, 0x80)[1]
        assert status & 0xFFF0 == 0x63C0 and status & 0xF, f"PIN remains authorized after reset: {status:#x}"
        generation = crypto.tlv(0xAC, crypto.tlv(0x80, b"\x07"))
        assert self.raw_apdu(0x47, 0, 0x9C, generation)[1] == 0x6982, "management authorization survived reset"


def rsa_event(args, event, operation="generate"):
    piv = Ccid(args.ccid_port, args.inspect_port)
    fresh = None
    try:
        piv.authorize()
        generation = crypto.tlv(0xAC, crypto.tlv(0x80, b"\x07"))
        message = b"TrustZone session RSA " + event.encode()
        if operation == "sign":
            # Set up the signing key on the host so prime search cannot time out
            # before the session event reaches the private-operation barrier.
            key = crypto.rsa.generate_private_key(public_exponent=65537, key_size=2048)
            numbers = key.private_numbers()
            size = key.key_size // 16
            parts = crypto.tlv(1, numbers.p.to_bytes(size, "big"))
            parts += crypto.tlv(2, numbers.q.to_bytes(size, "big"))
            piv.apdu(0xFE, 7, 0x9C, parts)
            assert piv.public().public_numbers() == numbers.public_numbers
            body = piv.sign_body(message)
            apdu = bytes([0, 0x87, 7, 0x9C, 0]) + len(body).to_bytes(2, "big") + body
        else:
            apdu = bytes([0, 0x47, 0, 0x9C, len(generation)]) + generation
        before = crypto.inspect(args.inspect_port, "status")
        barrier = getattr(args, "rsa_barrier", None)
        if barrier is not None:
            rsa_pause(args, 1)
        piv.begin(0x6F, apdu)
        if barrier is None:
            piv.processing()
        else:
            deadline = time.monotonic() + RECOVERY_TIMEOUT_S
            while rsa_pause(args) != "ok 02000000":
                assert time.monotonic() < deadline, "RSA did not reach the private-operation barrier"
                time.sleep(0.005)
        if event == "abort":
            abort_sequence = 0xA6
            setup = bytes([0x21, 1, 0, abort_sequence, 2, 0, 0, 0])
            crypto.inspect(args.inspect_port, "usb-control " + setup.hex())
            if barrier is not None:
                rsa_pause(args, 0)
            response = piv.response()
            assert response[7:10] == bytes([0x40, CMD_ABORTED, 0]) and len(response) == 10, "RSA ABORT published an old result"
            piv.begin(CCID_ABORT, b"", sequence=abort_sequence)
            ack = piv.response()
            assert ack[0] == 0x81 and ack[7:10] == b"\0\0\0", "ABORT bulk handshake failed"
            survivor = piv
        else:
            injected = crypto.inspect(args.inspect_port, event)
            assert injected["in_flight"] == "true", "USB event missed RSA"
            if barrier is not None:
                rsa_pause(args, 0)
            if event == "usb-disconnect": crypto.inspect(args.inspect_port, "usb-connect")
            after = wait_ready(args)
            assert after["power_ups"] == before["power_ups"], "RSA bus reset rebooted the MCU"
            fresh = Ccid(args.ccid_port, args.inspect_port, activate=False)
            fresh.assert_auth_cleared()
            fresh.authorize()
            survivor = fresh
        public = survivor.public()
        next_message = message + b" next session"
        survivor.apdu(0x20, 0, 0x80, b"123456\xff\xff")
        body, _ = survivor.apdu(0x87, 7, 0x9C, survivor.sign_body(next_message))
        signature = crypto.parse_tlv(crypto.parse_tlv(body)[0x7C])[0x82]
        public.verify(signature, next_message, crypto.padding.PKCS1v15(), crypto.hashes.SHA256())
        print(json.dumps({"case": "rsa_" + operation + "_" + event, "worker_live": True,
                          "new_signature_verified": True, "authorization_cleared": event != "abort"}), flush=True)
    finally:
        piv.sock.close()
        if fresh: fresh.sock.close()


def rsa_pause(args, value=None):
    command = (f"read {args.rsa_barrier:x} 4" if value is None else
               f"plant {args.rsa_barrier:x} {value.to_bytes(4, 'little').hex()}")
    with socket.create_connection(("127.0.0.1", args.inspect_port), timeout=20) as link:
        link.sendall(command.encode() + b"\n")
        reply = link.makefile("rb").readline(4096).decode().strip()
    assert reply.startswith("ok "), reply
    return reply


class Hid(crypto.Hid):
    def ctap(self, command, fields):
        self.begin(command, fields)
        body = self.response()
        assert body[0] == 0, f"CTAP {command:#x} status {body[0]:#x}"
        return (crypto.decode(body[1:]) if len(body) > 1 else None), {}

    def __init__(self, port, inspect_port):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=RECOVERY_TIMEOUT_S)
        self.inspect_port = inspect_port
        self.cid = b"\xff" * 4
        nonce = b"session!"
        self.send(0x86, nonce)
        report = crypto.receive(self.sock, 64)
        while report[4] == 0xBB:
            report = crypto.receive(self.sock, 64)
        assert report[:7] == self.cid + b"\x86\0\x11", f"late response during new INIT: cid={report[:4].hex()} command={report[4]:#x}"
        assert report[7:15] == nonce
        self.cid = report[15:19]

    def begin(self, command, fields):
        self.deadline = time.monotonic() + RECOVERY_TIMEOUT_S
        crypto.inspect(self.inspect_port, "transport-begin")
        self.send(0x90, bytes([command]) + crypto.enc(fields))

    def processing(self):
        report = crypto.receive(self.sock, 64)
        assert report[:4] == self.cid and report[4:8] == b"\xbb\0\x01\x01", "operation completed before the event barrier"

    def response(self):
        while True:
            assert time.monotonic() < self.deadline, "CTAPHID kept sending keepalives without worker progress"
            report = crypto.receive(self.sock, 64)
            assert report[:4] == self.cid, f"response belongs to another session: {report[:7].hex()}"
            if report[4] == 0xBB:
                continue
            assert report[4] == 0x90, f"unexpected HID response {report[4]:#x}"
            size = int.from_bytes(report[5:7], "big")
            body = bytearray(report[7:])
            for seq in range(128):
                if len(body) >= size:
                    return bytes(body[:size])
                report = crypto.receive(self.sock, 64)
                assert report[:4] == self.cid and report[4] == seq, "response continuation changed session"
                body.extend(report[5:])
            raise AssertionError("HID response exceeds the continuation limit")

    def live_worker(self):
        response, _ = self.ctap(6, {1: 2, 2: 1})
        assert response[3] == 8, "worker did not answer clientPIN getRetries"


def wait_ready(args):
    return crypto.wait_ready(args.inspect_port)


def mldsa_bus(args, event):
    label, algorithm, _, public_type, _, _ = SETS[args.mldsa_set]
    hid = Hid(args.fido_port, args.inspect_port)
    fresh = None
    try:
        rp = "tz-reset.example"
        response, _ = hid.ctap(1, {1: crypto.CLIENT_DATA_HASH, 2: {"id": rp},
                                  3: {"id": b"reset", "name": "reset"},
                                  4: [{"alg": algorithm, "type": "public-key"}]})
        auth = response[2]
        size = int.from_bytes(auth[53:55], "big")
        credential = auth[55:55 + size]
        cose = crypto.decode(auth[55 + size:])
        public = public_type.from_public_bytes(cose[-1])
        fields = {1: rp, 2: crypto.CLIENT_DATA_HASH, 3: [{"id": credential, "type": "public-key"}]}
        before = crypto.inspect(args.inspect_port, "status")
        hid.begin(2, fields)
        hid.processing()
        injected = crypto.inspect(args.inspect_port, event)
        assert injected["in_flight"] == "true", "event missed the in-flight crypto operation"
        if event == "usb-disconnect":
            crypto.inspect(args.inspect_port, "usb-connect")
        after = wait_ready(args)
        assert after["power_ups"] == before["power_ups"], "bus event rebooted the MCU and hid the session defect"
        fresh = Hid(args.fido_port, args.inspect_port)
        fresh.live_worker()
        fields[2] = crypto.hashlib.sha256(crypto.CLIENT_DATA_HASH + event.encode()).digest()
        response, _ = fresh.ctap(2, fields)
        public.verify(response[3], response[2] + fields[2])
        print(json.dumps({"case": event, "algorithm": label, "worker_live": True, "new_session_signature_verified": True, "power_ups": after["power_ups"]}), flush=True)
    finally:
        hid.sock.close()
        if fresh:
            fresh.sock.close()


def mldsa_cancel(args):
    label, algorithm, _, public_type, _, _ = SETS[args.mldsa_set]
    hid = Hid(args.fido_port, args.inspect_port)
    try:
        rp = "tz-session.example"
        response, _ = hid.ctap(1, {
            1: crypto.CLIENT_DATA_HASH, 2: {"id": rp},
            3: {"id": b"session", "name": "session"},
            4: [{"alg": algorithm, "type": "public-key"}],
        })
        auth_data = response[2]
        size = int.from_bytes(auth_data[53:55], "big")
        credential = auth_data[55:55 + size]
        cose = crypto.decode(auth_data[55 + size:])
        public = public_type.from_public_bytes(cose[-1])
        fields = {1: rp, 2: crypto.CLIENT_DATA_HASH, 3: [{"id": credential, "type": "public-key"}]}
        hid.begin(2, fields)
        hid.processing()
        hid.send(CTAPHID_CANCEL, b"")
        body = hid.response()
        if body[0] == 0:
            completed = crypto.decode(body[1:])
            public.verify(completed[3], completed[2] + crypto.CLIENT_DATA_HASH)
            print(f"{label} returned a verified signature after CANCEL", flush=True)
        assert body == bytes([KEEPALIVE_CANCEL]), f"CANCEL must refuse the original request, got CTAP {body[0]:#x}"
        hid.live_worker()
        fields[2] = crypto.hashlib.sha256(crypto.CLIENT_DATA_HASH + b"after cancel").digest()
        response, _ = hid.ctap(2, fields)
        public.verify(response[3], response[2] + fields[2])
        print(json.dumps({"case": "mldsa_cancel", "algorithm": label, "cancel_status": KEEPALIVE_CANCEL, "worker_live": True, "next_signature_verified": True}), flush=True)
    finally:
        hid.sock.close()


def fido_authorization_reset(args):
    hid = Hid(args.fido_port, args.inspect_port)
    fresh = None
    try:
        rp = "tz-token.example"
        response, _ = hid.ctap(1, {1: crypto.CLIENT_DATA_HASH, 2: {"id": rp},
                                  3: {"id": b"token", "name": "token"},
                                  4: [{"alg": -50, "type": "public-key"}]})
        auth = response[2]
        size = int.from_bytes(auth[53:55], "big")
        credential = auth[55:55 + size]
        agreement, _ = hid.ctap(6, {1: 2, 2: 2})
        proto = Protocol2(agreement[1][-2], agreement[1][-3])
        pin = b"1234"
        encrypted = proto.encrypt(pin + b"\0" * (64 - len(pin)))
        hid.ctap(6, {1: 2, 2: 3, 3: proto.cose(), 4: proto.authenticate(encrypted), 5: encrypted})
        granted, _ = hid.ctap(6, {1: 2, 2: 9, 3: proto.cose(), 6: proto.encrypt(crypto.hashlib.sha256(pin).digest()[:16]), 9: 0x10})
        token = proto.decrypt(granted[2])
        blob = b"\x80" + crypto.hashlib.sha256(b"\x80").digest()[:16]
        mac_data = b"\xff" * 32 + b"\x0c\0" + b"\0" * 4 + crypto.hashlib.sha256(blob).digest()
        write = {2: blob, 3: 0, 4: len(blob), 5: hmac.new(token, mac_data, crypto.hashlib.sha256).digest(), 6: 2}
        hid.ctap(0x0C, write)
        hid.begin(2, {1: rp, 2: crypto.CLIENT_DATA_HASH, 3: [{"id": credential, "type": "public-key"}]})
        hid.processing()
        injected = crypto.inspect(args.inspect_port, "usb-reset")
        assert injected["in_flight"] == "true"
        wait_ready(args)
        fresh = Hid(args.fido_port, args.inspect_port)
        fresh.begin(0x0C, write)
        reply = fresh.response()
        assert reply[0] == 0x33, f"old PIN/UV token survived reset: CTAP {reply[0]:#x}"
        fresh.live_worker()
        print(json.dumps({"case": "fido_token_reset", "old_token_refused": True, "pin_retries_unchanged": True}), flush=True)
    finally:
        hid.sock.close()
        if fresh: fresh.sock.close()


def card_reset(args):
    old = Ccid(args.ccid_port, args.inspect_port)
    fresh = None
    try:
        old.authorize()
        generation = crypto.tlv(0xAC, crypto.tlv(0x80, b"\x07"))
        old.begin(0x6F, bytes([0, 0x47, 0, 0x9C, len(generation)]) + generation)
        old.processing()
        fresh = Ccid(args.ccid_port, args.inspect_port, activate=False)
        fresh.call(0x63, b"")
        fresh.call(0x62, b"")
        fresh.assert_auth_cleared()
        fresh.authorize()
        public = fresh.public()
        message = b"RSA after ICC reset"
        body, _ = fresh.apdu(0x87, 7, 0x9C, fresh.sign_body(message))
        public.verify(crypto.parse_tlv(crypto.parse_tlv(body)[0x7C])[0x82], message,
                      crypto.padding.PKCS1v15(), crypto.hashes.SHA256())
        print(json.dumps({"case": "ccid_card_reset", "authorization_cleared": True, "new_signature_verified": True}), flush=True)
    finally:
        old.sock.close()
        if fresh: fresh.sock.close()


def reset_window(args):
    from emu import OP_REPLUG
    from replug import CTAP_RESET, RESET_WINDOW_S

    with socket.create_connection(("127.0.0.1", args.ccid_port), timeout=RECOVERY_TIMEOUT_S) as link:
        link.sendall(bytes([OP_REPLUG]) + bytes(4))
        crypto.receive(link, int.from_bytes(crypto.receive(link, 4), "big"))
    started = wait_ready(args)
    hid = Hid(args.fido_port, args.inspect_port)
    try:
        def request_reset():
            hid.deadline = time.monotonic() + RECOVERY_TIMEOUT_S
            hid.send(0x90, bytes([CTAP_RESET]))
            return hid.response()[0]

        assert request_reset() == 0, "reset immediately after USB attachment was refused"
        deadline = time.monotonic() + RECOVERY_TIMEOUT_S
        late_ns = int((RESET_WINDOW_S + 3) * 1_000_000_000)
        while True:
            state = crypto.inspect(args.inspect_port, "status")
            assert state["dead"] == "false" and state["power_ups"] == started["power_ups"]
            elapsed = int(state["emulated_ns"]) - int(started["emulated_ns"])
            if elapsed >= late_ns:
                break
            assert time.monotonic() < deadline, "image clock stopped before the reset window expired"
            time.sleep(0.01)
        assert request_reset() == 0x30, "reset after the image-clock window was accepted"
        hid.live_worker()
        print(json.dumps({"case": "reset_window", "early_reset_accepted": True,
                          "late_reset_refused": True, "image_elapsed_s": elapsed / 1_000_000_000}), flush=True)
    finally:
        hid.sock.close()


def interleaved_reads(args):
    for cycle in range(3):
        old = Ccid(args.ccid_port, args.inspect_port)
        card = hid = None
        try:
            old.authorize()
            before = crypto.inspect(args.inspect_port, "status")
            reset = crypto.inspect(args.inspect_port, "usb-reset")
            assert reset["power_ups"] == before["power_ups"]
            wait_ready(args)
            card = Ccid(args.ccid_port, args.inspect_port)
            card.assert_auth_cleared()
            card.apdu(0xA4, 4, 0, bytes.fromhex("d27600012401"))
            expected, _ = card.apdu(0xCA, 0, 0x6E)
            assert expected[0] == 0x6E and len(expected) > 250
            hid = Hid(args.fido_port, args.inspect_port)
            for _ in range(8):
                hid.begin(4, {})
                card.begin(0x6F, bytes.fromhex("00ca006e00"))
                answer = hid.response()
                assert answer[0] == 0 and "FIDO_2_1" in crypto.decode(answer[1:])[1]
                message = card.response()
                assert message[7] & 0xC0 == 0, message[7:10].hex()
                status = message[-2:]
                body = bytearray(message[10:-2])
                for _ in range(32):
                    if status[0] != 0x61:
                        break
                    card.begin(0x6F, bytes([0, 0xC0, 0, 0, status[1]]))
                    message = card.response()
                    assert message[7] & 0xC0 == 0, message[7:10].hex()
                    status = message[-2:]
                    body.extend(message[10:-2])
                assert status == bytes.fromhex("9000"), status.hex()
                assert body == expected, "interleaved response changed or lost a continuation"
            after = crypto.inspect(args.inspect_port, "status")
            assert after["dead"] == "false" and after["power_ups"] == before["power_ups"]
            print(json.dumps({"case": "interleaved_reads", "cycle": cycle + 1,
                              "authorization_cleared": True, "complete_reply_pairs": 8}), flush=True)
        finally:
            old.sock.close()
            if card: card.sock.close()
            if hid: hid.sock.close()


CASES = {
    "mldsa_cancel": mldsa_cancel,
    "mldsa_reset": lambda args: mldsa_bus(args, "usb-reset"),
    "mldsa_disconnect": lambda args: mldsa_bus(args, "usb-disconnect"),
    "rsa_abort": lambda args: rsa_event(args, "abort"),
    "rsa_reset": lambda args: rsa_event(args, "usb-reset"),
    "rsa_disconnect": lambda args: rsa_event(args, "usb-disconnect"),
    "rsa_sign_abort": lambda args: rsa_event(args, "abort", "sign"),
    "rsa_sign_reset": lambda args: rsa_event(args, "usb-reset", "sign"),
    "rsa_sign_disconnect": lambda args: rsa_event(args, "usb-disconnect", "sign"),
    "card_reset": card_reset,
    "fido_token_reset": fido_authorization_reset,
    "interleaved_reads": interleaved_reads,
}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fido-port", type=int, required=True)
    parser.add_argument("--ccid-port", type=int, required=True)
    parser.add_argument("--inspect-port", type=int, required=True)
    parser.add_argument("--case", choices=["all", *CASES, "reset_window"], default="all")
    parser.add_argument("--mldsa-set", type=int, choices=SETS, default=87)
    parser.add_argument("--rsa-barrier", type=lambda value: int(value, 16), help="private-operation marker in a disposable image")
    args = parser.parse_args()
    wait_ready(args)
    available = {**CASES, "reset_window": reset_window}
    selected = CASES if args.case == "all" else {args.case: available[args.case]}
    for name, case in selected.items():
        parameters = SETS if args.case == "all" and name in ("mldsa_cancel", "mldsa_reset", "mldsa_disconnect") else [args.mldsa_set]
        for parameter in parameters:
            args.mldsa_set = parameter
            case(args)
    print("PASS: crypto session boundaries, recovery and authorization reset", flush=True)
