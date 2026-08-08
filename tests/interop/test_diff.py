# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Host tests for the differential engine — no hardware.

Exercises the allow-list classification (`divergences`), the snapshot compare
(`diff`), and the precise normalizers (`normalize`). Run:

    nix develop -c python -m pytest tests/interop/test_diff.py -q
"""
import divergences as dv
import diff
import normalize as nz


# ── divergences.classify ─────────────────────────────────────────────────────

def test_unknown_path_equal_is_match():
    assert dv.classify("openpgp.card.aid_len", "6", "6")["bucket"] == dv.MATCH


def test_unknown_path_differ_is_unexpected():
    r = dv.classify("fido.getinfo.options.clientPin", True, False)
    assert r["bucket"] == dv.UNEXPECTED  # clientPin must match — it's a real gap


def test_ignore_drops_per_device_randomness():
    assert dv.classify("piv.slot.9a.pubkey", "AA", "BB")["bucket"] == dv.ALLOWED


def test_tolerance_counter():
    assert dv.classify("piv.pinRetries", 3, 3)["bucket"] == dv.MATCH
    assert dv.classify("piv.pinRetries", 3, 8)["bucket"] == dv.ALLOWED


def test_expectdiff_serial_ok_and_violation():
    ok = dv.classify("usb.serialNumber", "12345678", "rs-key-0001")
    assert ok["bucket"] == dv.ALLOWED
    bad = dv.classify("usb.serialNumber", "12345678", "not-the-fixed-string")
    assert bad["bucket"] == dv.RULE_VIOLATION
    assert "rsk=" in bad["detail"]


def test_expectdiff_aaguid_pins_rsk_side():
    ok = dv.classify("fido.getinfo.aaguid", "abc", "2479c7bf-6b30-5683-9ec8-0e8171a918b7")
    assert ok["bucket"] == dv.ALLOWED
    drift = dv.classify("fido.getinfo.aaguid", "abc", "00000000-dead-beef-0000-000000000000")
    assert drift["bucket"] == dv.RULE_VIOLATION


def test_versions_superset_allows_u2f_drop_but_flags_real_gap():
    allowed = dv.classify(
        "fido.getinfo.versions",
        ["U2F_V2", "FIDO_2_0", "FIDO_2_1"],
        ["FIDO_2_0", "FIDO_2_1", "FIDO_2_3"],
    )
    assert allowed["bucket"] == dv.ALLOWED  # U2F_V2 drop is excluded
    gap = dv.classify(
        "fido.getinfo.versions",
        ["FIDO_2_0", "FIDO_2_1", "FIDO_2_9"],  # real has a version rsk lacks
        ["FIDO_2_0", "FIDO_2_1"],
    )
    assert gap["bucket"] == dv.UNEXPECTED
    assert "FIDO_2_9" in gap["detail"]


def test_extensions_superset_ok_when_rsk_richer():
    r = dv.classify(
        "fido.getinfo.extensions",
        ["credProtect", "hmac-secret"],
        ["credProtect", "hmac-secret", "largeBlobKey", "thirdPartyPayment"],
    )
    assert r["bucket"] == dv.ALLOWED


def test_transports_usb_only_is_allowed():
    r = dv.classify("fido.getinfo.transports", ["nfc", "usb"], ["usb"])
    assert r["bucket"] == dv.ALLOWED


def test_certifications_absent_on_rsk_is_allowed():
    # A real YubiKey advertises FIDO/FIPS certification levels; RS-Key does not,
    # so the whole field is missing on the rsk side — an expected divergence.
    top = dv.classify("fido.getinfo.certifications", "{...}", dv.MISSING)
    assert top["bucket"] == dv.ALLOWED


# ── diff.compare over synthetic snapshots ────────────────────────────────────

def _snap(label, parsed):
    return {"meta": {"label": label, "ykman_serial": label, "fw": "5.7.4"},
            "cells": {"c": {"parsed": parsed}}}


def test_compare_clean_when_only_allowlisted_diffs():
    real = _snap("real", {
        "usb.serialNumber": "12345678",
        "usb.bcdDevice": "0x0507",
        "fido.getinfo.aaguid": "yubico-aaguid",
        "oath.count": 64,
        "fido.getinfo.options.clientPin": True,
    })
    rsk = _snap("rsk", {
        "usb.serialNumber": "rs-key-0001",
        "usb.bcdDevice": "0x081b",
        "fido.getinfo.aaguid": "2479c7bf-6b30-5683-9ec8-0e8171a918b7",
        "oath.count": 64,
        "fido.getinfo.options.clientPin": True,
    })
    results = diff.compare(real, rsk)
    c = diff.summarize(results)
    assert c[dv.UNEXPECTED] == 0 and c[dv.RULE_VIOLATION] == 0
    assert c[dv.ALLOWED] == 3 and c[dv.MATCH] == 2


def test_compare_flags_a_real_fidelity_gap():
    real = _snap("real", {"oath.count": 64, "fido.getinfo.options.clientPin": True})
    rsk = _snap("rsk", {"oath.count": 63, "fido.getinfo.options.clientPin": False})
    results = diff.compare(real, rsk)
    c = diff.summarize(results)
    assert c[dv.UNEXPECTED] == 2  # count mismatch + clientPin mismatch
    assert diff._gaps(results)


def test_missing_field_on_one_side_surfaces():
    real = _snap("real", {"openpgp.someQuirk": "x"})
    rsk = _snap("rsk", {})
    results = diff.compare(real, rsk)
    row = next(r for r in results if r["path"] == "openpgp.someQuirk")
    assert row["rsk"] == dv.MISSING and row["bucket"] == dv.UNEXPECTED


# ── normalize precise parsers ────────────────────────────────────────────────

def test_fido_getinfo_cbor_normalizes_key_fields():
    cbor = {
        0x01: ["FIDO_2_0", "FIDO_2_1"],
        0x03: bytes.fromhex("2479c7bf6b3056839ec80e8171a918b7"),
        0x04: {"rk": True, "alwaysUv": True, "clientPin": True},
        0x05: 7609,
        0x0A: [{"alg": -7, "type": "public-key"}, {"alg": -8, "type": "public-key"}],
        0x0E: 0x050704,
    }
    out = nz.fido_getinfo(cbor)
    assert out["fido.getinfo.aaguid"] == "2479c7bf-6b30-5683-9ec8-0e8171a918b7"
    assert out["fido.getinfo.options.alwaysUv"] is True
    assert out["fido.getinfo.maxMsgSize"] == 7609
    assert out["fido.getinfo.algorithms"] == sorted(["-7", "-8"])
    assert out["fido.getinfo.versions"] == ["FIDO_2_0", "FIDO_2_1"]


def test_mgmt_deviceinfo_tlv():
    # total-len byte, then TLVs: usbSupported=0x023b, serial=12345678, formFactor=1, version=5.7.4
    serial = (12345678).to_bytes(4, "big")
    body = (bytes([0x01, 0x02, 0x02, 0x3B]) + bytes([0x02, 0x04]) + serial
            + bytes([0x04, 0x01, 0x01]) + bytes([0x05, 0x03, 5, 7, 4]))
    blob = bytes([len(body)]) + body
    out = nz.mgmt_deviceinfo(blob)
    assert out["mgmt.usbSupported"] == 0x023B
    assert out["mgmt.serial"] == 12345678
    assert out["mgmt.formFactor"] == 1
    assert out["mgmt.version"] == "5.7.4"


def test_kv_lines_scrapes_prose():
    out = nz.kv_lines("Device type: YubiKey 5C NFC\nSerial number: 12345678\n", "ykman.info")
    assert out["ykman.info.device_type"] == "YubiKey 5C NFC"
    assert out["ykman.info.serial_number"] == "12345678"
