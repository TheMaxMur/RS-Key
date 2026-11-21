# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Host tests for the differential engine — no hardware.

Exercises the allow-list classification (`divergences`), the snapshot compare
(`diff`), and the precise normalizers (`normalize`). Run:

    nix develop -c python -m pytest tests/interop/test_diff.py -q
"""
import pytest

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


def test_only_the_radio_separates_the_transport_lists():
    r = dv.classify(
        "fido.getinfo.transports",
        ["nfc", "usb", "smart-card"],
        ["usb", "smart-card"],
    )
    assert r["bucket"] == dv.ALLOWED


def test_dropping_smart_card_from_the_transports_violates_the_rule():
    """The rule has to notice the list it is about: `usb` alone was ALLOWED under
    the old pin, and it is what getInfo said while the FIDO AID answered on CCID."""
    r = dv.classify("fido.getinfo.transports", ["nfc", "usb", "smart-card"], ["usb"])
    assert r["bucket"] == dv.RULE_VIOLATION


def test_vendor_prototype_ids_are_allowed_only_as_an_empty_list():
    """Issue #111: a 64-bit id in getInfo fails Yubico's Android SDK outright, so the
    pin has to refuse the seven ids RS-Key used to list, not just any difference."""
    key = "fido.getinfo.vendorPrototypeConfigCommands"
    assert dv.classify(key, None, [])["bucket"] == dv.ALLOWED
    listed = [0x03E43F56B34285E2, 0x1831A40F04A25ED9]
    assert dv.classify(key, None, listed)["bucket"] == dv.RULE_VIOLATION


def test_certifications_absent_on_rsk_is_allowed():
    # A real YubiKey advertises FIDO/FIPS certification levels; RS-Key does not,
    # so the whole field is missing on the rsk side — an expected divergence.
    top = dv.classify("fido.getinfo.certifications", "{...}", dv.MISSING)
    assert top["bucket"] == dv.ALLOWED


# The labels the capture's tools print, ykman 5.9.1's (`ykman/piv.py`, `_cli/oath.py`,
# `openpgp.py`) and gpg-card 2.5's `Card firmware`, turned into paths by `kv_lines`: the
# rules are held to the paths the capture really produces.
TOOL_VERSION_LINES = [("piv", "PIV version: {}"), ("oath", "OATH version: {}"),
                      ("openpgp", "Application version: {}"),
                      ("openpgp.gpg", "Card firmware ....: {}")]


@pytest.mark.parametrize("ns, line", TOOL_VERSION_LINES)
def test_a_firmware_version_skew_on_a_tool_surface_is_allowed(ns, line):
    """RS-Key reports FW_VERSION there; a reference on other firmware, or a
    `FW_VERSION=X.Y.Z` build, differs without being a fidelity gap."""
    [(path, real)] = nz.kv_lines(line.format("5.8.0"), ns).items()
    [(_, rsk)] = nz.kv_lines(line.format("5.8.1"), ns).items()
    assert dv.classify(path, real, rsk)["bucket"] == dv.ALLOWED


@pytest.mark.parametrize("path, real, rsk", [
    ("mgmt.version", "5.8.0", "5.8.1"),
    ("fido.getinfo.firmwareVersion", 0x050800, 0x050801),
])
def test_a_firmware_version_skew_on_a_raw_surface_is_allowed(path, real, rsk):
    assert dv.classify(path, real, rsk)["bucket"] == dv.ALLOWED


# Every surface RS-Key reports FW_VERSION on, with a well-formed reference value.
VERSION_SURFACES = [
    ("fido.getinfo.firmwareVersion", 0x050800),
    ("mgmt.version", "5.8.0"),
    ("piv.piv_version", "5.8.0"),
    ("oath.oath_version", "5.8.0"),
    ("openpgp.application_version", "5.8.0"),
    ("openpgp.gpg.card_firmware", "5.8.0"),
]


@pytest.mark.parametrize("path, real", VERSION_SURFACES)
def test_a_firmware_version_missing_on_one_side_violates_the_rule(path, real):
    """The value may skew, the field may not vanish: a surface that stops reporting a
    version has regressed, and a `Tolerance` would have filed that as ALLOWED."""
    assert dv.classify(path, real, dv.MISSING)["bucket"] == dv.RULE_VIOLATION


@pytest.mark.parametrize("path, real", VERSION_SURFACES)
def test_a_value_that_is_not_a_version_violates_the_rule(path, real):
    """The shape is the whole pin, so its anchors matter: pico-openpgp's two-part `4.6`,
    which the old rule wanted on the RS-Key side, is not a firmware version."""
    assert dv.classify(path, real, "4.6")["bucket"] == dv.RULE_VIOLATION


# ── diff.compare over synthetic snapshots ────────────────────────────────────

def _snap(label, parsed):
    return {"meta": {"label": label, "ykman_serial": label, "fw": "5.8.0"},
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
        0x0E: 0x050800,
    }
    out = nz.fido_getinfo(cbor)
    assert out["fido.getinfo.aaguid"] == "2479c7bf-6b30-5683-9ec8-0e8171a918b7"
    assert out["fido.getinfo.options.alwaysUv"] is True
    assert out["fido.getinfo.maxMsgSize"] == 7609
    assert out["fido.getinfo.algorithms"] == sorted(["-7", "-8"])
    assert out["fido.getinfo.versions"] == ["FIDO_2_0", "FIDO_2_1"]


def test_mgmt_deviceinfo_tlv():
    # total-len byte, then TLVs: usbSupported=0x023b, serial=12345678, formFactor=1, version=5.8.0
    serial = (12345678).to_bytes(4, "big")
    body = (bytes([0x01, 0x02, 0x02, 0x3B]) + bytes([0x02, 0x04]) + serial
            + bytes([0x04, 0x01, 0x01]) + bytes([0x05, 0x03, 5, 8, 0]))
    blob = bytes([len(body)]) + body
    out = nz.mgmt_deviceinfo(blob)
    assert out["mgmt.usbSupported"] == 0x023B
    assert out["mgmt.serial"] == 12345678
    assert out["mgmt.formFactor"] == 1
    assert out["mgmt.version"] == "5.8.0"


def test_kv_lines_scrapes_prose():
    out = nz.kv_lines("Device type: YubiKey 5C NFC\nSerial number: 12345678\n", "ykman.info")
    assert out["ykman.info.device_type"] == "YubiKey 5C NFC"
    assert out["ykman.info.serial_number"] == "12345678"


# ── diff --cells ─────────────────────────────────────────────────────────────

def _labelled(label, **cells):
    return {"meta": {"label": label}, "cells": cells}


def test_cells_keeps_only_the_named_cells():
    s = _labelled("real", a={"status": "ok", "parsed": {"x": 1}}, b={"status": "ok", "parsed": {"y": 2}})
    assert list(diff.restrict(s, ["a"])["cells"]) == ["a"]


def test_cells_refuses_a_cell_the_snapshot_did_not_capture():
    # The emulator has no USB stack, so its descriptor cell skips. Named anyway,
    # the comparison would run over whatever the other side happened to hold.
    s = _labelled("rsk", usb_descriptors={"status": "skip", "parsed": {}})
    with pytest.raises(SystemExit):
        diff.restrict(s, ["usb_descriptors"])
    with pytest.raises(SystemExit):
        diff.restrict(s, ["mgmt_tlv"])


def test_the_58_references_new_members_have_rules_of_their_own():
    # A YubiKey 5.8.0 advertises these too, so the `key_0x*` catch-all (whose real
    # side must be absent) would call every difference in them a rule violation.
    assert dv.classify("fido.getinfo.key_0x1a", ["nfc", "smart-card", "usb"],
                       ["smart-card", "usb"])["bucket"] == dv.ALLOWED
    assert dv.classify("fido.getinfo.key_0x1a", ["smart-card", "usb"],
                       ["smart-card"])["bucket"] == dv.RULE_VIOLATION
    assert dv.classify("fido.getinfo.key_0x1f", ["2", "3"],
                       ["1", "2", "255", "3"])["bucket"] == dv.ALLOWED
    assert dv.classify("fido.getinfo.key_0x1f", ["2", "3"], ["3"])["bucket"] == dv.RULE_VIOLATION


def test_previewsign_is_the_one_extension_rsk_may_lack():
    real = ["credProtect", "hmac-secret", "previewSign"]
    assert dv.classify("fido.getinfo.extensions", real,
                       ["credProtect", "hmac-secret"])["bucket"] == dv.ALLOWED
    assert dv.classify("fido.getinfo.extensions", real,
                       ["credProtect", "previewSign"])["bucket"] == dv.UNEXPECTED


def test_cells_refuses_an_empty_list():
    # `--cells ,` compares zero fields and would report clean.
    with pytest.raises(SystemExit):
        diff.restrict(_labelled("real", a={"status": "ok", "parsed": {"x": 1}}), [])


def test_a_member_both_keys_carry_is_compared_not_excused():
    # RS-Key's extras are allowed while the reference lacks them. When it carries
    # one too (5.8.0 has 0x18-0x1F), a difference is RS-Key's gap, reported as
    # such, instead of a violation that blames the reference for having it.
    assert dv.classify("fido.getinfo.key_0x2a", dv.MISSING, 7)["bucket"] == dv.ALLOWED
    r = dv.classify("fido.getinfo.key_0x1d", 63, 64)
    assert r["bucket"] == dv.UNEXPECTED and "reference carries" in r["detail"]
    assert dv.classify("fido.getinfo.key_0x1d", 63, 63)["bucket"] == dv.MATCH


def test_capacity_pins_are_anchored():
    assert dv.classify("fido.getinfo.maxCredBlobLength", 32, 128)["bucket"] == dv.ALLOWED
    assert dv.classify("fido.getinfo.maxCredBlobLength", 32, 1280)["bucket"] == dv.RULE_VIOLATION
