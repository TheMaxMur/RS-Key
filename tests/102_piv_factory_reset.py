#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Destructive PIV factory RESET stress with public failure diagnostics.

Overwrites PIV keys, PIN and objects. Use a disposable RS-Key no-touch key, or
run through tests/emu.py. The final reset leaves PIV at its factory defaults.
"""

import argparse
import importlib.util
import json
from pathlib import Path
import time

spec = importlib.util.spec_from_file_location("piv_suite", Path(__file__).with_name("80_piv.py"))
piv_suite = importlib.util.module_from_spec(spec)
spec.loader.exec_module(piv_suite)

NEW_PIN = b"654321\xff\xff"
CHURN_BYTES = 3046


def attestation_key(piv):
    body, _ = piv.apdu(piv_suite.INS_GET_DATA, 0x3F, 0xFF,
                       piv_suite.tlv(0x5C, piv_suite.OBJ_ATTEST), le=True)
    der = piv_suite.parse_tlv(piv_suite.parse_tlv(body)[0x53])[0x70]
    cert = piv_suite.load_der_x509_certificate(der)
    public = cert.public_key()
    public.verify(cert.signature, cert.tbs_certificate_bytes,
                  piv_suite.ec.ECDSA(cert.signature_hash_algorithm))
    return public.public_bytes(piv_suite.serialization.Encoding.X962,
                               piv_suite.serialization.PublicFormat.UncompressedPoint)


def record_reset_failure(piv):
    for label, ins, p2 in (("PIN", piv_suite.INS_VERIFY, 0x80),
                          ("management", piv_suite.INS_GET_METADATA, 0x9B),
                          ("F9", piv_suite.INS_GET_METADATA, 0xF9),
                          ("9A", piv_suite.INS_GET_METADATA, piv_suite.SLOT_9A),
                          ("9C", piv_suite.INS_GET_METADATA, piv_suite.SLOT_9C)):
        try:
            body, status = piv.raw(ins, 0, p2)
            print(json.dumps({"after_failed_RESET": label, "status": f"{status:04X}",
                              "response_bytes": len(body)}), flush=True)
        except Exception as error:
            print(json.dumps({"after_failed_RESET": label,
                              "transport_error": type(error).__name__}), flush=True)


def cycle(piv, run, churn, rsa):
    started = time.monotonic()
    piv.select()
    piv.verify_pin()
    piv.auth_mgm()
    previous_f9 = attestation_key(piv)
    point = piv.slot_public_point(piv_suite.SLOT_9A, piv_suite.ALGO_ECCP256)
    piv_suite.test_sign(piv, piv_suite.SLOT_9A, piv_suite.ALGO_ECCP256, point)
    if rsa:
        piv_suite.test_rsa(piv)
    for write in range(churn):
        value = (run.to_bytes(4, "big") + write.to_bytes(4, "big")) * (CHURN_BYTES // 8 + 1)
        value = value[:CHURN_BYTES]
        piv.apdu(piv_suite.INS_PUT_DATA, 0x3F, 0xFF,
                 piv_suite.tlv(0x5C, piv_suite.OBJ_POOL) + piv_suite.tlv(0x53, value))
    if churn:
        body, _ = piv.apdu(piv_suite.INS_GET_DATA, 0x3F, 0xFF,
                           piv_suite.tlv(0x5C, piv_suite.OBJ_POOL), le=True)
        assert piv_suite.parse_tlv(body)[0x53] == value, "object was not live before RESET"
    piv.apdu(piv_suite.INS_CHANGE_PIN, 0, 0x80, piv_suite.DEFAULT_PIN + NEW_PIN)
    piv.verify_pin(NEW_PIN)
    for _ in range(8):
        _, pin_status = piv.verify_pin(b"00000000", want=None)
        _, puk_status = piv.raw(piv_suite.INS_RESET_RETRY, 0, 0x80, b"0000000099999999")
    assert (pin_status, puk_status) == (0x6983, 0x6983), (pin_status, puk_status)
    reset_started = time.monotonic()
    _, status = piv.raw(piv_suite.INS_RESET, 0, 0)
    print(json.dumps({"run": run, "RESET": f"{status:04X}",
                      "reset_seconds": round(time.monotonic() - reset_started, 3)}), flush=True)
    if status != 0x9000:
        record_reset_failure(piv)
    assert status == 0x9000, f"factory RESET returned {status:04X}"
    piv.verify_pin(piv_suite.DEFAULT_PIN)
    piv.auth_mgm()
    piv.apdu(piv_suite.INS_GET_METADATA, 0, piv_suite.SLOT_9A, want=0x6A88, le=True)
    if rsa:
        piv.apdu(piv_suite.INS_GET_METADATA, 0, piv_suite.SLOT_9C, want=0x6A88, le=True)
    piv.apdu(piv_suite.INS_GET_DATA, 0x3F, 0xFF,
             piv_suite.tlv(0x5C, piv_suite.OBJ_POOL), want=0x6A82, le=True)
    assert attestation_key(piv) != previous_f9, "RESET retained the preceding F9 key"
    print(json.dumps({"run": run, "factory_defaults": True, "slot_keys_removed": True,
                      "new_F9_self_signature_verified": True,
                      "churn_writes": churn, "seconds": round(time.monotonic() - started, 3)}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--churn", type=int, default=4)
    parser.add_argument("--rsa", action="store_true")
    args = parser.parse_args()
    assert 1 <= args.runs <= 1000 and 0 <= args.churn <= 1000
    reader = piv_suite.find_reader(require_marker=True)
    assert reader is not None, "no selected RS-Key reader"
    connection = reader.createConnection()
    connection.connect()
    try:
        piv = piv_suite.Piv(connection)
        for run in range(1, args.runs + 1):
            cycle(piv, run, args.churn, args.rsa)
    finally:
        connection.disconnect()
    print("PASS: PIV factory RESET stress", flush=True)


if __name__ == "__main__":
    main()
