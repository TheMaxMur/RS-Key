# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""`rsk fido attestation import` — the chain-size pre-flight.

Run from tools/:  python -m pytest rsk/test_fido.py
ATT_CHAIN_MAX is a copy of a firmware constant, and it has drifted once already:
it stayed at a flat 2048 when the device's ceiling moved to what a flash record
actually holds, so a chain in the gap passed here and came back as a bare CTAP
error. Nothing asserted either the bound or the number (audit run-34 #9), so pin
both — the second against the Rust definitions, which is where the drift starts.
"""
import pathlib
import re
import sys
import types

# rsk.fido tries python-fido2 and handles the ImportError; loading the real
# extension aborts the nix interpreter on macOS 27 (libffi).
sys.modules.setdefault("hid", types.ModuleType("hid"))
sys.modules.setdefault("fido2", types.ModuleType("fido2"))

import pytest  # noqa: E402

from rsk import fido  # noqa: E402

CRATES = pathlib.Path(__file__).resolve().parents[2] / "crates"


def _rust_const(path, name):
    m = re.search(rf"const {name}: usize = ([^;]+);", (CRATES / path).read_text())
    assert m, f"{name} not found in {path}"
    return m.group(1).strip()


def _rust_int(path, name):
    """A Rust `usize` const that is plain arithmetic over literals."""
    expr = _rust_const(path, name)
    assert re.fullmatch(r"[\d+\-*()\s]+", expr), f"{name} is not plain arithmetic: {expr}"
    return eval(expr)  # noqa: S307 — the pattern above admits digits and + - * ( ) only


def test_att_chain_max_still_matches_the_firmware():
    store = (int(_rust_const("rsk-fs/src/lib.rs", "MAX_VALUE_BYTES"))
             - 1 - 2 * int(_rust_const("rsk-fido/src/cert.rs", "ATT_CHAIN_MAX_CERTS")))
    mac = (_rust_int("rsk-fido/src/vendor.rs", "MAX_RAW_SUBPARA")
           - _rust_int("rsk-fido/src/vendor.rs", "ATT_SUBPARA_OVERHEAD"))
    # The cap is the tightest of THREE ceilings. Two are plain arithmetic and are
    # re-derived here; the third — room for the worst-case makeCredential inside
    # maxMsgSize — is a multi-term Rust expression held by a build-time assert in
    # cert.rs, and is slack today. Assert the Rust side still names all three, so
    # dropping one fails here rather than silently widening the cap.
    expr = _rust_const("rsk-fido/src/cert.rs", "ATT_CHAIN_MAX")
    assert expr == "min3(CHAIN_CAP_STORE, CHAIN_CAP_MAC, CHAIN_CAP_RESPONSE)", expr
    assert fido.ATT_CHAIN_MAX == min(store, mac)
    # If the response ceiling ever became the binding one this mirror would be too
    # generous and the CLI would forward a chain the device refuses — a loud
    # InvalidParameter, not a silent overrun, but fix the mirror if it happens.
    assert min(store, mac) == mac, "the MAC scratch is expected to bind"


def _drive(monkeypatch, chain_len):
    """Run `attestation import` up to its first device bind, which it must not
    reach when the chain is too large."""
    bound = []
    monkeypatch.setattr(fido, "_att_scalar", lambda p: bytes(32))
    monkeypatch.setattr(fido, "_att_chain", lambda p: b"\x30" * chain_len)

    def connect_fido(exclusive=False):
        bound.append(exclusive)
        raise _Stop

    monkeypatch.setattr("rsk.common.connect_fido", connect_fido)
    return bound


class _Stop(Exception):
    pass


def test_an_oversized_chain_is_refused_before_the_device_is_touched(monkeypatch, capsys):
    bound = _drive(monkeypatch, fido.ATT_CHAIN_MAX + 1)
    with pytest.raises(SystemExit):
        fido.att_import(types.SimpleNamespace(key="k.pem", chain="c.pem", pin=None))
    assert bound == []
    err = capsys.readouterr().err
    assert "chain too large" in err and str(fido.ATT_CHAIN_MAX) in err


def test_a_chain_at_the_limit_is_accepted(monkeypatch):
    # The boundary itself must pass: an off-by-one here refuses a chain the device
    # stores, which reads as a device fault rather than a host bug.
    bound = _drive(monkeypatch, fido.ATT_CHAIN_MAX)
    with pytest.raises(_Stop):
        fido.att_import(types.SimpleNamespace(key="k.pem", chain="c.pem", pin=None))
    assert bound == [True]
