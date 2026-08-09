#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Run the vendored upstream suites against RS-Key, with every divergence named.

`third_party/` holds two ecosystems' own conformance suites — pico-fido's and
pico-openpgp/Gnuk's. They are somebody else's tests under somebody else's
license, so nothing here edits them: the run is steered from outside by a pytest
plugin, and everything RS-Key deliberately does not do for them is listed in
[`DIVERGENCES`] with its reason.

A listed test is `xfail(strict=True)`, not a skip. If it starts passing, the run
*fails* and says which entry to delete — because an allow-list that silently
absorbs a fixed divergence is how it rots, and this repo has already been bitten
by one that did (`tests/interop`).

    python tests/third_party.py fido            # the pico-fido suite
    python tests/third_party.py openpgp         # the OpenPGP card suite
    python tests/third_party.py all -- -x       # everything; extra pytest args

Both suites want a device that answers like a flashed no-touch build. Against
`tools/emu` that means `--usbip` on a Linux host (they use python-fido2's and
pyscard's own transports, which want real USB), and `pcscd` carrying the
`ccid-rs-key` reader list for the card half.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import emu  # noqa: E402  (needs the path above)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Each suite, and whether the emulator's socket shim can stand in for its
# transport. `openpgp` reaches the card through pyscard alone, so the card socket
# is enough — no PC/SC, no USB, no root, which is what lets it run anywhere.
# `fido` is driven by python-fido2's own HID transport, which wants a real device:
# that one needs `--usbip`.
SUITES = {
    "fido": ("third_party/pico-fido-tests/pico-fido", False),
    "openpgp": ("third_party/openpgp-card-tests", True),
}

# What RS-Key deliberately does not do the way these suites expect. The key is a
# substring of the pytest node id; the value is why, in one line, aimed at
# whoever finds the entry in three years.
#
# Only *deliberate* divergences belong here. A test failing because RS-Key is
# wrong is a bug, and putting it here hides it.
DIVERGENCES: dict[str, dict[str, str]] = {
    "fido": {
        # Not about RS-Key at all: the suite calls its own `Device.doGA()` with an
        # `options=` argument that helper does not take, so it raises TypeError
        # before a byte reaches the device. (Its sibling `test_option_uv` never
        # gets there — it is gated on the `uv` option, which this build does not
        # advertise.) Upstream defect; nothing to fix here.
        "test_021_authenticate.py::test_option_up": "the suite's own doGA() takes no options= argument",
        # The emulator answers faster than the transport's keepalive interval, so
        # there is nothing to count. A board doing on-card RSA does emit them —
        # `tests/50_touch_latency.py` is where that is measured.
        "test_055_hid.py::TestHID::test_keep_alive": "no command here is slow enough to stream a keepalive",
        # CTAP 2.1 §6.1.2: `up` is implicitly true for makeCredential and an
        # explicit `up: true` is accepted — only `up: false` is INVALID_OPTION.
        # The FIDO conformance tool checks both (MakeCredential Req-6, P-3/F-1)
        # and RS-Key passes it; the suite asserts the opposite for `up: true`.
        "test_000_getinfo.py::test_Check_up_option": "CTAP 2.1 accepts an explicit up:true; only up:false is INVALID_OPTION",
        # CTAP 2.1 §6.5.5.5, verbatim: "If a PIN has already been set,
        # authenticator returns CTAP2_ERR_PIN_AUTH_INVALID error". The suite wants
        # NOT_ALLOWED, which is the CTAP 2.0 answer.
        "test_010_pin.py::test_set_pin_twice": "§6.5.5.5 makes a second setPIN PIN_AUTH_INVALID, not NOT_ALLOWED",
        # CTAP 2.1 zero-length-pinUvAuthParam probe: PIN_INVALID when a PIN is set,
        # PIN_NOT_SET when it is not. The suite wants PIN_AUTH_INVALID — again the
        # 2.0 answer. Both halves are pinned by `conformance::pin`.
        "test_010_pin.py::test_zero_length_pin_auth": "the CTAP 2.1 probe answers PIN_INVALID, not PIN_AUTH_INVALID",
        # RS-Key advertises `makeCredUvNotRqd`, under which CTAP 2.1 §6.1.2 lets a
        # NON-discoverable credential be made on presence alone. The suite asserts
        # PUAT_REQUIRED unconditionally, without reading the option.
        "test_010_pin.py::test_get_no_pin_auth": "makeCredUvNotRqd: a non-discoverable credential needs no token",
        "test_010_pin.py::test_make_credential_no_pin": "makeCredUvNotRqd: a non-discoverable credential needs no token",
        # The test calls `device.reboot()` when it sees PIN_AUTH_BLOCKED and then
        # asserts PIN_AUTH_BLOCKED again — a ladder that only holds while that
        # reboot does nothing. Given a real power cycle (which the runner supplies,
        # see `_install_reboot`), the consecutive-mismatch counter clears at
        # attempt 4 exactly as §6.5.5.7 requires, and the next answer is
        # PIN_INVALID.
        "test_010_pin.py::test_lockout": "asserts a lockout its own reboot() is supposed to clear",
        # CTAP 2.1 §6.2.2: user identifiable information "MUST NOT be returned if
        # user verification is not done by the authenticator". This assertion runs
        # without UV, so `id` alone is the whole permitted entity.
        "test_022_discoverable.py::test_rk_maximum_list_capacity_per_rp_nodisplay": "§6.2.2 forbids returning user name/displayName without UV",
        # The request's keyAgreement is an all-zero point, which is not on P-256.
        # Refusing it (INVALID_PARAMETER) before deriving anything is the
        # invalid-curve defence; reaching the saltAuth check first would mean doing
        # ECDH with an attacker-chosen off-curve point.
        "test_035_hmac_secret.py::test_bad_auth": "the off-curve keyAgreement is refused before the salt MAC is looked at",
        # After the card reset the test performs, no applet is selected, so a bare
        # LIST is 6A82 (file not found) rather than 6982. Dropping the selection on
        # a power transition is deliberate — it is what makes a second local
        # process re-authenticate (ApduHandler::reset_card).
        "test_070_oath.py::test_auth": "a card reset deselects the applet, so LIST without SELECT is 6A82",
        "test_070_oath.py::test_noauth": "a card reset deselects the applet, so LIST without SELECT is 6A82",
        # These send CALCULATE with a bare `74` tag — no length byte, no value —
        # which is not a TLV. With the encoded empty challenge `74 00` that ykman
        # actually sends, RS-Key answers the suite's own expected codes byte for
        # byte (`45 d9 0f 25` for the IMF case).
        "test_070_oath.py::test_bothoath": "the challenge TLV is sent truncated (`74` with no length)",
        "test_070_oath.py::test_imf_overwrite": "the challenge TLV is sent truncated (`74` with no length)",
        "test_070_oath.py::test_imf_more": "the challenge TLV is sent truncated (`74` with no length)",
    },
    # All nine are one question, and the spec answers it twice, differently.
    #
    # §4.4.1: "Simple DOs (S) return only the value with GET DATA. Constructed DOs
    # (C, marked yellow) are returned INCLUDING THEIR TAG AND LENGTH."
    # §7.2.6, worked example: `00 CA 00 65 00` → `5B 0B … 5F2D 02 … 5F35 01 31`,
    # with no `65` wrapper at all.
    #
    # RS-Key follows §4.4.1 and sends the wrapper (`7a 05 93 03 …`); the
    # Gnuk-derived suite follows the §7.2.6 example and expects the children alone.
    # GnuPG 2.4.8 reads our card completely — every field of `gpg --card-status`,
    # including everything inside DO 6E — so both framings are live in the wild and
    # the dominant client copes with either.
    #
    # Listed rather than "fixed" because moving to the other reading is a wire
    # change: a `bcdDevice` bump and every reader of these DOs (`tools/tui`'s
    # `ber_find`, `tools/rsk`, the trusted display's OpenPGP screens) revisited.
    # That is the maintainer's call on an ambiguous spec, not a test's.
    "openpgp": {
        "::test_ds_counter": "§4.4.1 vs §7.2.6: we send DO 7A with its own tag; the example omits it",
        "::test_app_data": "§4.4.1 vs §7.2.6: we send DO 6E with its own tag; the example omits it",
        # This one asks a second question too: with the wrapper gone we would send
        # `5b 00 5f 2d 00 5f 35 00`, and the suite wants an unset cardholder DO to
        # be empty rather than to carry empty children. §4.4.1 allows a zero-length
        # Name; whether it must be absent is unstated.
        "::test_name_lang_sex": "§4.4.1 vs §7.2.6 wrapper, plus: unset cardholder children present vs absent",
    },
}


class Plugin:
    """Steers a vendored suite from outside: the power cycle it cannot ask for,
    and the divergences it does not know about."""

    def __init__(self, suite):
        self.suite = suite
        self.marked = []

    def pytest_configure(self, config):
        _install_power_cycle()
        _install_reboot()
        config.addinivalue_line("markers", "rsk_divergence: expected, and why")

    def pytest_collection_modifyitems(self, items):
        import pytest

        for item in items:
            for pattern, reason in DIVERGENCES[self.suite].items():
                if pattern in item.nodeid:
                    item.add_marker(
                        pytest.mark.xfail(reason=f"RS-Key: {reason}", strict=True)
                    )
                    self.marked.append((item.nodeid, reason))
                    break

    def pytest_terminal_summary(self, terminalreporter):
        if not self.marked:
            return
        terminalreporter.write_sep("=", "RS-Key divergences (expected, xfail)")
        for nodeid, reason in self.marked:
            terminalreporter.write_line(f"  {nodeid}\n      {reason}")


def _install_power_cycle():
    """Let `authenticatorReset` through.

    RS-Key accepts a reset only inside the CTAP 2.1 §6.6 power-up window, which
    an operator reopens by unplugging; pico-fido has no such window, so its
    fixtures reset whenever they like and every one of them would fail. On a
    board that gap is a human with a USB port. Against the emulator it is one
    message on the card socket, so the suite gets what it would have got from a
    person — rather than an allow-list entry per fixture, which would mark 60
    tests as divergent when the divergence is a single rule.
    """
    try:
        from fido2.ctap2.base import Ctap2
    except ImportError:
        return  # the card suite has no CTAP2 in it

    original = Ctap2.reset

    def reset(self, *args, **kwargs):
        emu.power_cycle()
        return original(self, *args, **kwargs)

    Ctap2.reset = reset


def _install_reboot():
    """Answer the suite's "Please reboot authenticator and hit enter".

    pico-fido's `Device.reboot()` prompts an operator and waits five seconds; the
    tests that call it are checking state a power cycle clears — RS-Key's
    three-wrong-PINs-per-boot soft lock, which is exactly what the prompt is for.
    Left unanswered it times out and the device never actually rebooted, so those
    tests measure a lockout that was never lifted.

    The same operator stand-in the reset gets, for the same reason: a power cycle
    is one message on the card socket here.
    """
    conftest = sys.modules.get("conftest")
    device = getattr(conftest, "Device", None)
    if device is None or not hasattr(device, "reboot"):
        return

    original = device.reboot

    def reboot(self, *args, **kwargs):
        emu.power_cycle()
        return original(self, *args, **kwargs)

    device.reboot = reboot


def run(suite, extra):
    import pytest

    rel, shim = SUITES[suite]
    if shim:
        emu.install()
    print(f"== {suite}: {rel}{' (over the emulator socket)' if shim else ''}")
    return pytest.main([os.path.join(ROOT, rel), *extra], plugins=[Plugin(suite)])


def main():
    args = sys.argv[1:]
    which = args[0] if args and not args[0].startswith("-") else "all"
    extra = [a for a in args[1:] if a != "--"]
    if which not in (*SUITES, "all"):
        sys.exit(f"usage: {sys.argv[0]} [{'|'.join(SUITES)}|all] [pytest args…]")

    codes = {s: run(s, extra) for s in (SUITES if which == "all" else [which])}
    for suite, code in codes.items():
        print(f"{suite}: pytest exit {code}")
    sys.exit(max(int(c) for c in codes.values()))


if __name__ == "__main__":
    main()
