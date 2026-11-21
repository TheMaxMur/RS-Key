# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Execute synthetic histories through the same PIV APDUs as the USB suite."""

from dataclasses import asdict
import importlib.util
from pathlib import Path

from piv_history import Failure, Kind, OBJECTS, SLOTS, payload

spec = importlib.util.spec_from_file_location("piv_reset_suite", Path(__file__).with_name("102_piv_factory_reset.py"))
reset_suite = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reset_suite)
piv_suite = reset_suite.piv_suite


class Refusal(Exception):
    def __init__(self, failure):
        super().__init__(str(asdict(failure)))
        self.failure = failure


class CheckedPiv(piv_suite.Piv):
    def __init__(self, connection, capture):
        super().__init__(connection)
        self.pin = piv_suite.DEFAULT_PIN
        self.phase = "history"
        self.capture = capture

    def apdu(self, ins, p1, p2, data=b"", want=0x9000, le=False):
        body, status = self.raw(ins, p1, p2, data, le)
        if want is not None and status != want:
            cause = self.capture()
            raise Refusal(Failure(self.phase, ins, status, cause))
        return body, status

    def verify_pin(self, pin=None, want=0x9000):
        return super().verify_pin(self.pin if pin is None else pin, want)

    def select(self):
        return self.apdu(0xA4, 4, 0, bytes(piv_suite.PIV_AID))[0]


def execute(connection, seed, operations, reboot, capture=lambda: (), progress=lambda row: None):
    piv = CheckedPiv(connection, capture)
    objects = {}
    keys = set()
    piv.select()
    piv.verify_pin()
    piv.auth_mgm()
    previous_f9 = reset_suite.attestation_key(piv)
    for operation in operations:
        progress({"operation": operation.encode(), "state": "started"})
        piv.select()
        piv.verify_pin()
        piv.auth_mgm()
        if operation.kind in (Kind.PUT, Kind.DELETE_OBJECT):
            value = payload(seed, operation) if operation.kind == Kind.PUT else b""
            object_id = OBJECTS[operation.argument]
            piv.apdu(piv_suite.INS_PUT_DATA, 0x3F, 0xFF,
                     piv_suite.tlv(0x5C, object_id) + piv_suite.tlv(0x53, value))
            if value:
                objects[object_id] = value
            else:
                objects.pop(object_id, None)
        elif operation.kind == Kind.EC:
            point = piv.slot_public_point(operation.argument, piv_suite.ALGO_ECCP256)
            piv_suite.test_sign(piv, operation.argument, piv_suite.ALGO_ECCP256, point)
            keys.add(operation.argument)
        elif operation.kind == Kind.RSA:
            piv_suite.test_rsa(piv)
            keys.add(piv_suite.SLOT_9C)
        elif operation.kind == Kind.DELETE_KEY:
            wanted = 0x9000 if operation.argument in keys else 0x6A88
            piv.apdu(0xF6, 0xFF, operation.argument, want=wanted)
            keys.discard(operation.argument)
        elif operation.kind == Kind.PIN:
            new_pin = f"{operation.argument:06d}".encode() + b"\xff\xff"
            piv.apdu(piv_suite.INS_CHANGE_PIN, 0, 0x80, piv.pin + new_pin)
            piv.pin = new_pin
            piv.verify_pin()
        elif operation.kind == Kind.RETRY:
            piv.verify_pin(b"00000000", want=0x63C2)
            piv.verify_pin()
            piv.apdu(piv_suite.INS_RESET_RETRY, 0, 0x80, b"0000000099999999", want=0x63C2)
            piv.apdu(piv_suite.INS_RESET_RETRY, 0, 0x80, piv_suite.DEFAULT_PUK + piv.pin)
            piv.verify_pin()
        elif operation.kind == Kind.SELECT:
            piv.select()
        elif operation.kind == Kind.REBOOT:
            piv.conn = reboot(piv.conn)
        progress({"operation_id": operation.id, "state": "completed"})
    piv.select()
    for object_id, expected in objects.items():
        body, _ = piv.apdu(piv_suite.INS_GET_DATA, 0x3F, 0xFF, piv_suite.tlv(0x5C, object_id), le=True)
        assert piv_suite.parse_tlv(body)[0x53] == expected, "history object changed before RESET"
    for expected in reset_suite.BLOCKING_STATUSES:
        piv.verify_pin(b"00000000", want=expected)
        piv.apdu(piv_suite.INS_RESET_RETRY, 0, 0x80, b"0000000099999999", want=expected)
    for reference in (0x80, 0x81):
        body, _ = piv.apdu(piv_suite.INS_GET_METADATA, 0, reference, le=True)
        assert piv_suite.parse_tlv(body)[reset_suite.RETRY_METADATA_TAG] == bytes((3, 0))
    piv.phase = "reset"
    piv.apdu(piv_suite.INS_RESET, 0, 0)
    piv.phase = "oracle"
    for reference in (0x80, 0x81):
        body, _ = piv.apdu(piv_suite.INS_GET_METADATA, 0, reference, le=True)
        assert piv_suite.parse_tlv(body)[reset_suite.RETRY_METADATA_TAG] == reset_suite.FACTORY_RETRY_COUNTS
    piv.pin = piv_suite.DEFAULT_PIN
    piv.verify_pin()
    piv.auth_mgm()
    for slot in SLOTS:
        piv.apdu(piv_suite.INS_GET_METADATA, 0, slot, want=0x6A88, le=True)
    for object_id in OBJECTS:
        piv.apdu(piv_suite.INS_GET_DATA, 0x3F, 0xFF, piv_suite.tlv(0x5C, object_id), want=0x6A82, le=True)
    assert reset_suite.attestation_key(piv) != previous_f9, "RESET retained F9"
    progress({"factory_reset": "9000", "factory_retry_pairs_before_VERIFY": True,
              "keys_and_objects_removed": True, "new_F9_self_signature_verified": True})
    return piv.conn
