# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Unit tests for rsk.common — the PIN-entry, confirmation and connect chokepoints.

Run from tools/:  python -m pytest rsk/test_common.py
Every gated command routes its PIN through resolve_pin, so the precedence
(flag > prompt), the PIN-free skip, and the required/non-TTY guards are the
behaviour the whole CLI's consistency rests on — pin them here. No device.
`confirm` and `connect_fido`'s refusal are the other two: which commands call
them is asserted in test_refuse_to_guess.py, what they do is asserted here.
"""
import argparse
import sys
import types

# connect_fido imports rsk.ctaphid, which sys.exits at import without hidapi.
sys.modules.setdefault("hid", types.ModuleType("hid"))

import pytest  # noqa: E402

from rsk import common  # noqa: E402


def _args(pin=None):
    return argparse.Namespace(pin=pin)


def _stub_tty(monkeypatch, *, tty=True, entered="hunter2"):
    """Force isatty() and capture/script the getpass prompt; returns the call log."""
    calls = []

    class _Stdin:
        def isatty(self):
            return tty

    def _getpass(prompt="FIDO2 PIN: "):
        calls.append(prompt)
        return entered

    monkeypatch.setattr(common.sys, "stdin", _Stdin())
    monkeypatch.setattr(common, "getpass", _getpass)
    return calls


def test_flag_wins_and_never_prompts(monkeypatch):
    calls = _stub_tty(monkeypatch, entered="from-prompt")
    # --pin given: returned verbatim, the prompt is never reached…
    assert common.resolve_pin(_args("1234"), has_pin=True) == "1234"
    # …even when the device is PIN-free or a PIN is "required" (flag is explicit).
    assert common.resolve_pin(_args("1234"), has_pin=False, required=True) == "1234"
    assert calls == []


def test_pin_free_device_skips_the_prompt(monkeypatch):
    calls = _stub_tty(monkeypatch)
    assert common.resolve_pin(_args(), has_pin=False) is None
    assert calls == []  # a touch-only device is never asked for a PIN


def test_has_pin_prompts_interactively(monkeypatch):
    calls = _stub_tty(monkeypatch, entered="s3cret")
    assert common.resolve_pin(_args(), has_pin=True) == "s3cret"
    assert len(calls) == 1


def test_unknown_has_pin_still_prompts_on_a_tty(monkeypatch):
    _stub_tty(monkeypatch, entered="abcd")
    assert common.resolve_pin(_args(), has_pin=None) == "abcd"


def test_custom_prompt_is_used(monkeypatch):
    calls = _stub_tty(monkeypatch, entered="old")
    common.resolve_pin(_args(), has_pin=True, prompt="Current PIN: ")
    assert calls == ["Current PIN: "]


def test_empty_input_is_none(monkeypatch):
    _stub_tty(monkeypatch, entered="")
    assert common.resolve_pin(_args(), has_pin=True) is None


def test_required_dies_when_device_has_no_pin(monkeypatch):
    _stub_tty(monkeypatch)
    with pytest.raises(SystemExit):
        common.resolve_pin(_args(), has_pin=False, required=True)


def test_required_dies_on_empty_input(monkeypatch):
    _stub_tty(monkeypatch, entered="")
    with pytest.raises(SystemExit):
        common.resolve_pin(_args(), has_pin=True, required=True)


def test_non_tty_returns_none_without_prompting(monkeypatch):
    calls = _stub_tty(monkeypatch, tty=False)
    assert common.resolve_pin(_args(), has_pin=True) is None
    assert calls == []  # piped stdin: fall through to the device-side error path


def test_non_tty_required_dies(monkeypatch):
    _stub_tty(monkeypatch, tty=False)
    with pytest.raises(SystemExit):
        common.resolve_pin(_args(), has_pin=True, required=True)


# --- sanitize: a counterfeit device must not inject terminal escapes ----------
# inventory/status/fido print device-controlled strings (USB descriptor, getInfo
# versions, resident-cred rpId/user.name) raw; sanitize is the one chokepoint.

def test_sanitize_strips_ansi_osc_escapes():
    # ESC (0x1b) + BEL (0x07) drive OSC/CSI: window-title set, screen clear, OSC-52.
    out = common.sanitize("\x1b]0;pwn\x07\x1b[2Jok\x1b]52;c;AAAA\x07")
    assert "\x1b" not in out and "\x07" not in out
    assert out.endswith("ok�]52;c;AAAA�")


def test_sanitize_strips_bidi_override():
    # U+202E RIGHT-TO-LEFT OVERRIDE — Trojan-Source visual reordering (Cf).
    assert "‮" not in common.sanitize("alice‮0.2_ODIF")


def test_sanitize_preserves_benign_text():
    assert common.sanitize("FIDO_2_0, U2F_V2") == "FIDO_2_0, U2F_V2"


def test_sanitize_coerces_non_str():
    assert common.sanitize(None) == "None"


# --- sanitize_join: a hostile getInfo `versions` must not crash the CLI --------
# status/inventory join device-controlled `versions` for display; a counterfeit
# device can answer with non-strings, a scalar, or None instead of a str list.

def test_sanitize_join_normal_list():
    assert common.sanitize_join(["FIDO_2_0", "U2F_V2"]) == "FIDO_2_0, U2F_V2"


def test_sanitize_join_non_string_elements():
    # CBOR ints instead of text: must coerce, not raise TypeError.
    assert common.sanitize_join([1, 2]) == "1, 2"


def test_sanitize_join_scalar_and_none():
    # A bare int / None where a list is expected: no "not iterable" crash.
    assert common.sanitize_join(5) == "5"
    assert common.sanitize_join(None) == ""


def test_sanitize_join_strips_escapes_in_elements():
    assert "\x1b" not in common.sanitize_join(["ok", "\x1b]0;pwn\x07"])


# --- clientPIN error reporting: a wrong PIN reads as "wrong PIN", not a
# python-fido2 traceback (rsk fido set-pin / list-passkeys) --------------------

def test_pin_error_message_wrong_pin():
    assert common.pin_error_message(common.CTAP_PIN_INVALID) == "wrong PIN"


def test_pin_error_message_wrong_pin_with_retries():
    msg = common.pin_error_message(common.CTAP_PIN_INVALID, 7)
    assert "wrong PIN" in msg and "7" in msg


def test_pin_error_message_blocked_variants():
    assert "unplug" in common.pin_error_message(common.CTAP_PIN_AUTH_BLOCKED)
    assert "reset" in common.pin_error_message(common.CTAP_PIN_BLOCKED)


def test_pin_error_message_policy():
    assert "rejected" in common.pin_error_message(common.CTAP_PIN_POLICY_VIOLATION)


def test_pin_error_message_unknown_is_none():
    assert common.pin_error_message(0x99) is None


class _FakeCp:
    """Duck of fido2's ClientPin.get_pin_retries; an Exception value is raised."""

    def __init__(self, retries):
        self._r = retries

    def get_pin_retries(self):
        if isinstance(self._r, Exception):
            raise self._r
        return self._r


def _exc(code):
    return types.SimpleNamespace(code=code)  # duck of fido2 CtapError (.code)


def test_die_ctap_pin_error_wrong_pin_shows_retries(capsys):
    with pytest.raises(SystemExit):
        common.die_ctap_pin_error(_exc(common.CTAP_PIN_INVALID), _FakeCp((5, None)))
    err = capsys.readouterr().err
    assert "wrong PIN" in err and "5" in err
    assert "Traceback" not in err


def test_die_ctap_pin_error_retries_as_bare_int(capsys):
    with pytest.raises(SystemExit):
        common.die_ctap_pin_error(_exc(common.CTAP_PIN_INVALID), _FakeCp(3))
    assert "3" in capsys.readouterr().err


def test_die_ctap_pin_error_no_cp_omits_retries(capsys):
    with pytest.raises(SystemExit):
        common.die_ctap_pin_error(_exc(common.CTAP_PIN_INVALID), None)
    assert capsys.readouterr().err.strip() == "error: wrong PIN"


def test_die_ctap_pin_error_retries_query_failure_is_tolerated(capsys):
    with pytest.raises(SystemExit):
        common.die_ctap_pin_error(_exc(common.CTAP_PIN_INVALID), _FakeCp(OSError("boom")))
    assert "wrong PIN" in capsys.readouterr().err  # no crash, retry-less fallback


def test_die_ctap_pin_error_unknown_code_reports_hex(capsys):
    with pytest.raises(SystemExit):
        common.die_ctap_pin_error(_exc(0x99), None)
    err = capsys.readouterr().err
    assert "PIN operation failed" in err and "0x99" in err


# A counterfeit device can return the PIN_RETRIES field as a text string (python-fido2
# does not coerce it); it must NOT reach the terminal — only an int count is trusted.

def test_pin_error_message_drops_non_int_retries():
    evil = "\x1b]0;pwn\x07"  # OSC window-title escape smuggled as the "retry count"
    assert common.pin_error_message(common.CTAP_PIN_INVALID, evil) == "wrong PIN"
    assert "\x1b" not in common.pin_error_message(common.CTAP_PIN_INVALID, evil)
    assert common.pin_error_message(common.CTAP_PIN_INVALID, 5).endswith("before it blocks")


def test_die_ctap_pin_error_hostile_string_retries_not_printed(capsys):
    evil = "\x1b]52;c;ZXZpbA==\x07"  # OSC-52 clipboard write
    with pytest.raises(SystemExit):
        common.die_ctap_pin_error(_exc(common.CTAP_PIN_INVALID), _FakeCp((evil, None)))
    err = capsys.readouterr().err
    assert err.strip() == "error: wrong PIN"
    assert "\x1b" not in err


# --- confirm: the typed gate in front of every irreversible write -------------
# secure-boot revoke/harden/enable/lock, `otp lock-page58`, `openpgp reset` and
# `offboard` all funnel through here. Making the body a no-op left the whole
# suite green (audit run-34 #9), so pin the accept and the refuse.

def _typed(monkeypatch, text):
    monkeypatch.setattr("builtins.input", lambda prompt="": text)


def test_confirm_accepts_the_exact_token(monkeypatch):
    _typed(monkeypatch, "REVOKE-BOOTKEY")
    common.confirm("REVOKE-BOOTKEY")  # returns; anything else must raise


def test_confirm_tolerates_surrounding_whitespace(monkeypatch):
    _typed(monkeypatch, "  LOCK-SECURE-BOOT \n")
    common.confirm("LOCK-SECURE-BOOT")


@pytest.mark.parametrize("typed", ["", "y", "yes", "revoke-bootkey", "REVOKE-BOOTKEY!",
                                   "REVOKE", "REVOKE-BOOTKEY REVOKE-BOOTKEY"])
def test_confirm_refuses_anything_but_the_token(monkeypatch, typed, capsys):
    _typed(monkeypatch, typed)
    with pytest.raises(SystemExit):
        common.confirm("REVOKE-BOOTKEY")
    assert "confirmation mismatch" in capsys.readouterr().err


def test_confirm_shows_the_token_it_wants(monkeypatch, capsys):
    _typed(monkeypatch, "ENABLE-SECURE-BOOT")
    common.confirm("ENABLE-SECURE-BOOT")
    out = capsys.readouterr().out
    assert "irreversible" in out and "ENABLE-SECURE-BOOT" in out


# --- connect_fido: refuse to guess between two attached keys ------------------
# The CCID half of this is test_ccid_select.py; this is the HID half.

def _found(monkeypatch, n):
    from rsk import ctaphid

    class _Dev:
        def open_path(self, path):
            pass

    monkeypatch.setattr(ctaphid, "find_all", lambda: [{"path": f"p{i}".encode()}
                                                      for i in range(n)])
    monkeypatch.setattr(ctaphid, "hid", types.SimpleNamespace(device=_Dev))
    monkeypatch.setattr(ctaphid, "ctaphid_init", lambda dev: b"cid0")


def test_connect_fido_refuses_two_devices_when_exclusive(monkeypatch, capsys):
    _found(monkeypatch, 2)
    with pytest.raises(SystemExit):
        common.connect_fido(exclusive=True)
    assert "cannot act on the wrong device" in capsys.readouterr().err


def test_connect_fido_still_guesses_for_the_read_only_callers(monkeypatch):
    # `rsk status` and friends stay non-exclusive: refusing there would be a
    # regression for anyone with two keys plugged in.
    _found(monkeypatch, 2)
    _, cid = common.connect_fido()
    assert cid == b"cid0"


def test_connect_fido_with_one_device_is_unaffected(monkeypatch):
    _found(monkeypatch, 1)
    _, cid = common.connect_fido(exclusive=True)
    assert cid == b"cid0"


def test_connect_fido_with_no_device_refuses(monkeypatch, capsys):
    _found(monkeypatch, 0)
    with pytest.raises(SystemExit):
        common.connect_fido()
    assert "no FIDO HID device" in capsys.readouterr().err
