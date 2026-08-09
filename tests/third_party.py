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
    },
    "openpgp": {},
}


class Plugin:
    """Steers a vendored suite from outside: the power cycle it cannot ask for,
    and the divergences it does not know about."""

    def __init__(self, suite):
        self.suite = suite
        self.marked = []

    def pytest_configure(self, config):
        _install_power_cycle()
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
