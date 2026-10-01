# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""`rsk fido attestation import` — the chain-size pre-flight — and `status`.

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


def _policy_args(**changes):
    fields = dict(min_length=None, rp_id=None, force_change=False, complexity=False, pin=None)
    fields.update(changes)
    return types.SimpleNamespace(**fields)


def test_pin_policy_read_does_not_request_a_pin(monkeypatch, capsys):
    info = types.SimpleNamespace(min_pin_length=6, pin_complexity_policy=True, force_pin_change=True)
    monkeypatch.setattr(fido, "_ctap", lambda **kw: types.SimpleNamespace(get_info=lambda: info))
    monkeypatch.setattr(fido, "resolve_pin", lambda *a, **kw: pytest.fail("read requested a PIN"))
    fido.pin_policy(_policy_args())
    out = capsys.readouterr().out
    assert "6 code points" in out and "enabled" in out and "required: yes" in out


def test_pin_policy_write_requires_a_configured_pin(monkeypatch):
    monkeypatch.setattr(fido, "_ctap", lambda **kw: types.SimpleNamespace(
        info=types.SimpleNamespace(options={"clientPin": False})))
    with pytest.raises(SystemExit):
        fido.pin_policy(_policy_args(complexity=True))


def test_pin_policy_write_authenticates_and_keeps_omitted_rp_list(monkeypatch):
    calls = []
    protocol, token = object(), b"test token"
    info = types.SimpleNamespace(min_pin_length=6, pin_complexity_policy=True,
                                 force_pin_change=False, options={"clientPin": True})
    ctap = types.SimpleNamespace(info=info, get_info=lambda: info)
    monkeypatch.setattr(fido, "_ctap", lambda **kw: ctap)
    monkeypatch.setattr(fido, "resolve_pin", lambda *a, **kw: "test PIN")
    class Pin:
        PERMISSION = types.SimpleNamespace(AUTHENTICATOR_CFG=32)
        def __init__(self, device):
            assert device is ctap
            self.protocol = protocol
        def get_pin_token(self, pin, permission):
            calls.append((pin, permission))
            return token
    class Config:
        def __init__(self, device, proto, grant):
            assert (device, proto, grant) == (ctap, protocol, token)
        def set_min_pin_length(self, **params):
            calls.append(params)
    monkeypatch.setattr(fido, "ClientPin", Pin, raising=False)
    monkeypatch.setattr(fido, "Config", Config, raising=False)
    fido.pin_policy(_policy_args(min_length=6, complexity=True))
    assert calls == [("test PIN", 32), dict(min_pin_length=6, rp_ids=None,
                                          force_change_pin=False, pin_complexity_policy=True)]


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


def _status(monkeypatch, capsys, answer):
    """`attestation status`'s output against a device whose ATT_STATE is `answer`;
    a SystemExit fails the caller's test, so returning is the exit status 0."""
    monkeypatch.setattr("rsk.common.connect_fido", lambda exclusive=False: (None, 0))
    monkeypatch.setattr("rsk.backup._vendor", lambda dev, cid, fields: (0, answer))
    fido.att_status(types.SimpleNamespace())
    return capsys.readouterr().out


def test_an_org_key_without_a_chain_hash_is_reported_not_a_crash(monkeypatch, capsys):
    # The device leaves the hash out for a chain past today's cap, which firmware
    # before 0.4.11 could store; reading m[2] raised KeyError at the operator.
    out = _status(monkeypatch, capsys, {1: True})
    assert out.startswith("org attestation : installed\nchain           : missing")
    assert f"{fido.ATT_CHAIN_MAX}-byte cap" in out
    assert "`rsk fido attestation import`" in out
    assert "chain hash" not in out


HASH = bytes(range(32))


@pytest.mark.parametrize("answer, record", [
    ({1: True, 2: HASH}, {"installed": True, "chain_unusable": False, "chain_sha256": HASH.hex()}),
    ({1: True}, {"installed": True, "chain_unusable": True}),
    ({1: False}, {"installed": False, "chain_unusable": False}),
    ({1: False, 2: HASH}, {"installed": False, "chain_unusable": False}),
])
def test_an_att_state_answer_names_a_chain_the_device_cannot_use(answer, record):
    assert fido._org_attestation(answer) == record


@pytest.mark.parametrize("answer, printed", [
    ({1: True, 2: bytes.fromhex("9f2c")}, "org attestation : installed\nchain hash      : 9f2c\n"),
    ({1: False}, "org attestation : not installed (self-signed device cert in use)\n"),
])
def test_the_other_answers_print_as_before(monkeypatch, capsys, answer, printed):
    assert _status(monkeypatch, capsys, answer) == printed
