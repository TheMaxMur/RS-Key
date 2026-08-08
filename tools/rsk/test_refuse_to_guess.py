# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Every command that writes binds exactly one device — asserted at the callers.

Run from tools/:  python -m pytest rsk/test_refuse_to_guess.py
`test_ccid_select.py` and `test_common.py` pin what the two connect helpers *do*
when asked to refuse. Nothing pinned who asks, so deleting `exclusive=True` from
all 19 call sites at once left the whole suite green (audit run-34 #9).

Two layers, because neither is enough alone. The inventory reads source text, so
a module that never loads here is still covered — but a correct call site it can
see may still be unreachable. The driven cases then run real entry points through
their own argparse wiring and assert the bind each one actually performs.

Both layers key on *how* a device is opened, so `RAW_OPENS` lists the sites that
use neither helper. Neither can catch a guard being deleted from one of those —
the parse is identical with and without it — so those live on driven tests in
their own module (audit run-37).
"""
import argparse
import ast
import pathlib
import sys
import types

# Same reason as test_offboard.py: this file touches no device, and loading the
# real hidapi/python-fido2 extensions aborts the nix interpreter on macOS 27
# (libffi trampolines). The `from fido2.… import …` lines then raise ImportError,
# which rsk.fido handles.
sys.modules.setdefault("hid", types.ModuleType("hid"))
sys.modules.setdefault("fido2", types.ModuleType("fido2"))

import pytest  # noqa: E402

from rsk import (audit, backup, ccid, common, fido, hw, inventory, led, lock,  # noqa: E402
                 offboard, openpgp, otp)

PKG = pathlib.Path(__file__).parent

#: Every `connect_fido()` / `ccid.connect()` / `_ctap()` call in the package, as
#: {module: [(enclosing def, callee, the `exclusive=` expression)]}. `None` is a
#: deliberate first-match read. A new site fails this test until it is listed,
#: which is the point: choosing the entry is the security decision, so it is made
#: here and not left to whoever adds the next subcommand.
SITES = {
    "audit": [
        ("cmd_log", "connect_fido", None),
        ("cmd_status", "connect_fido", None),
        ("_audit_set", "connect_fido", "True"),
        ("cmd_verify", "connect_fido", "True"),
    ],
    "backup": [
        ("cmd_status", "connect_fido", None),
        ("cmd_export", "connect_fido", "True"),
        ("cmd_restore", "connect_fido", "True"),
        ("cmd_finalize", "connect_fido", "True"),
    ],
    "bench": [
        ("measure", "ccid.connect", None),
    ],
    "fido": [
        ("set_pin", "_ctap", "True"),
        ("list_passkeys", "_ctap", None),
        ("att_import", "connect_fido", "True"),
        ("att_clear", "connect_fido", "True"),
        ("att_status", "connect_fido", None),
    ],
    "hw": [
        ("_run_ccid", "ccid.connect", "True"),
        ("_run_fido", "connect_fido", "True"),
    ],
    "inventory": [
        ("cmd_verify", "connect_fido", "True"),
    ],
    "led": [
        ("_run_ccid", "ccid.connect", "_writes(args)"),
        ("_run_fido", "connect_fido", "_writes(args)"),
    ],
    "lock": [
        ("cmd_status", "connect_fido", None),
        ("cmd_enable", "connect_fido", "True"),
        ("cmd_unlock", "connect_fido", "True"),
        ("cmd_disable", "connect_fido", "True"),
    ],
    "offboard": [
        ("_serial", "ccid.connect", "True"),
        ("_require_journalling", "connect_fido", "True"),
        ("run", "connect_fido", "True"),
    ],
    "openpgp": [
        ("reset", "ccid.connect", "True"),
    ],
    "otp": [
        ("lock_page58", "ccid.connect", "True"),
        ("rollback_require", "ccid.connect", "True"),
    ],
    "status": [
        ("_secure_boot", "ccid.connect", None),
    ],
}

#: Every raw `hid.device()` open, as {module: [(enclosing def, why it may)]}.
#: These reach a device without either connect helper, so the inventory above is
#: blind to them — which is how `offboard._await_replug`'s hand-rolled two-key
#: refusal, guarding the tree's most destructive command, stayed deletable with
#: the whole suite green (audit run-37). Listing a site is not a guard; it is the
#: record that its exemption was decided, so the next one has to state its case.
RAW_OPENS = {
    "common": [("connect_fido", "the open behind the refusal itself")],
    "ctaphid": [("_declares_fido", "passive report-descriptor probe, no session")],
    "identify": [("_identify_one",
                  "walks every key on purpose — telling them apart IS the command")],
    "inventory": [("_hid_records", "one record per attached key: a report, never a write")],
    "offboard": [("_await_replug", "guarded by its own two-key refusal, driven by "
                                   "test_await_replug_will_not_bind_one_of_two_keys")],
    "status": [("_fido", "first-match read, like its `ccid.connect` sibling above")],
}

#: The sites above that take the first match, restated so the rule is readable
#: without diffing the inventory: a read may guess, a write may not.
GUESSING = {
    ("audit", "cmd_log"), ("audit", "cmd_status"), ("backup", "cmd_status"),
    ("bench", "measure"), ("fido", "att_status"), ("fido", "list_passkeys"),
    ("lock", "cmd_status"),
    ("status", "_secure_boot"),
}


def _is_raw_hid_open(f):
    """`hid.device()` / `ctaphid.hid.device()` — a device opened with neither helper."""
    return (isinstance(f, ast.Attribute) and f.attr == "device"
            and ((isinstance(f.value, ast.Name) and f.value.id == "hid")
                 or (isinstance(f.value, ast.Attribute) and f.value.attr == "hid")))


class _ConnectSites(ast.NodeVisitor):
    """Collect connect-helper calls and raw HID opens with the def they sit in."""

    def __init__(self):
        self.stack, self.sites, self.opens = [], [], []

    def visit_FunctionDef(self, node):
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_Call(self, node):
        f = node.func
        if isinstance(f, ast.Name) and f.id in ("connect_fido", "_ctap"):
            # `_ctap` is a THIRD selector — python-fido2's own enumeration, whose
            # order macOS leaves unspecified — so it is classified here too.
            callee = f.id
        elif (isinstance(f, ast.Attribute) and f.attr == "connect"
              and isinstance(f.value, ast.Name) and f.value.id == "ccid"):
            callee = "ccid.connect"
        elif _is_raw_hid_open(f):
            self.opens.append(self.stack[-1] if self.stack else "<module>")
            return self.generic_visit(node)
        else:
            return self.generic_visit(node)
        kw = next((k for k in node.keywords if k.arg == "exclusive"), None)
        self.sites.append((self.stack[-1] if self.stack else "<module>", callee,
                           ast.unparse(kw.value) if kw else None))
        self.generic_visit(node)


def _visit(path):
    v = _ConnectSites()
    v.visit(ast.parse(path.read_text()))
    return v


def _modules():
    for p in sorted(PKG.glob("*.py")):
        if not p.name.startswith("test_"):
            yield p.stem, _visit(p)


def _inventory():
    return {stem: v.sites for stem, v in _modules() if v.sites}


def test_every_connect_site_is_classified():
    assert _inventory() == SITES


def test_every_raw_hid_open_is_classified():
    """The connect helpers are not the only way to reach a device, and the sites
    that bypass them are exactly where a hand-rolled guard hides."""
    found = {stem: v.opens for stem, v in _modules() if v.opens}
    assert found == {mod: [fn for fn, _ in sites] for mod, sites in RAW_OPENS.items()}


def test_only_the_annotated_reads_take_the_first_match():
    guessing = {(mod, fn) for mod, sites in _inventory().items()
                for fn, _, exclusive in sites if exclusive is None}
    assert guessing == GUESSING


# --- the same invariant, driven through the real entry points -----------------

class _Bound(Exception):
    """Raised by the recording stubs to stop a command at its first bind."""


@pytest.fixture
def bind(monkeypatch):
    """Replace both connect helpers with recorders that stop the command dead.

    `connect_fido` is imported by name, so each module's own attribute is what its
    callers resolve; `ccid.connect` is an attribute call, so the one in `rsk.ccid`
    covers every caller of it."""
    seen = []

    def hid_connect(exclusive=False):
        seen.append(("connect_fido", exclusive))
        raise _Bound

    def ccid_connect(substr=None, exclusive=False):
        seen.append(("ccid.connect", exclusive))
        raise _Bound

    for mod in (audit, backup, hw, inventory, led, lock, offboard):
        monkeypatch.setattr(mod, "connect_fido", hid_connect)
    # fido.py imports it inside the function body, so it resolves from `common`.
    monkeypatch.setattr(common, "connect_fido", hid_connect)
    monkeypatch.setattr(ccid, "connect", ccid_connect)
    # `attestation import` reads both files before it binds; the bind is the subject.
    monkeypatch.setattr(fido, "_att_scalar", lambda p: bytes(32))
    monkeypatch.setattr(fido, "_att_chain", lambda p: b"\x30\x00")
    return seen


def _parse(mod, argv):
    """Real defaults and real subcommand wiring, without importing `__main__`
    (which pulls in the modules that abort here)."""
    p = argparse.ArgumentParser(prog="rsk")
    mod.register(p.add_subparsers(dest="group", required=True))
    return p.parse_args(argv)


PHRASE = backup.to_bip39(bytes(32))[0]

#: (module, argv, the bind that command must make). The writes are the finding;
#: the reads are here so a later "make everything exclusive" sweep cannot quietly
#: regress the two-keys-attached case for `status`-shaped commands.
DRIVEN = [
    (audit, ["audit", "enable"], ("connect_fido", True)),
    (audit, ["audit", "disable"], ("connect_fido", True)),
    (audit, ["audit", "verify"], ("connect_fido", True)),
    (audit, ["audit", "log"], ("connect_fido", False)),
    (audit, ["audit", "status"], ("connect_fido", False)),
    (backup, ["backup", "export"], ("connect_fido", True)),
    (backup, ["backup", "restore", "--mnemonic", PHRASE], ("connect_fido", True)),
    (backup, ["backup", "finalize"], ("connect_fido", True)),
    (backup, ["backup", "status"], ("connect_fido", False)),
    (fido, ["fido", "attestation", "import", "--key", "k.pem", "--chain", "c.pem"],
     ("connect_fido", True)),
    (fido, ["fido", "attestation", "clear"], ("connect_fido", True)),
    (fido, ["fido", "attestation", "status"], ("connect_fido", False)),
    (hw, ["hw", "--product", "x"], ("ccid.connect", True)),
    (inventory, ["inventory", "verify"], ("connect_fido", True)),
    (hw, ["hw", "--transport", "fido", "--product", "x"], ("connect_fido", True)),
    (led, ["led", "--color", "red"], ("ccid.connect", True)),
    (led, ["led", "--transport", "fido", "--color", "red"], ("connect_fido", True)),
    (led, ["led", "--get"], ("ccid.connect", False)),
    (led, ["led", "--transport", "fido", "--get"], ("connect_fido", False)),
    # --get alongside a set flag shows, so it does not write — and so it may guess.
    (led, ["led", "--get", "--color", "red"], ("ccid.connect", False)),
    (lock, ["lock", "enable"], ("connect_fido", True)),
    (lock, ["lock", "unlock"], ("connect_fido", True)),
    (lock, ["lock", "disable"], ("connect_fido", True)),
    (lock, ["lock", "status"], ("connect_fido", False)),
    (offboard, ["offboard"], ("ccid.connect", True)),
    (openpgp, ["openpgp", "reset"], ("ccid.connect", True)),
    (otp, ["otp", "lock-page58"], ("ccid.connect", True)),
    (otp, ["otp", "rollback-require"], ("ccid.connect", True)),
]


@pytest.mark.parametrize("mod,argv,expected", DRIVEN,
                         ids=[" ".join(a) for _, a, _ in DRIVEN])
def test_command_binds_the_device_it_should(bind, mod, argv, expected):
    args = _parse(mod, argv)
    with pytest.raises(_Bound):
        args.func(args)
    assert bind == [expected], f"{' '.join(argv)} bound {bind}, expected {[expected]}"


def test_every_write_reaches_a_driven_case():
    """The inventory is complete; reachability is only proved for what `DRIVEN`
    runs. Keep that difference visible, so a module added with an undriven write
    fails here rather than resting on the source-text half alone."""
    driven = {mod.__name__.rsplit(".", 1)[-1] for mod, _, _ in DRIVEN}
    writes = {mod for mod, sites in SITES.items()
              for fn, _, _ in sites if (mod, fn) not in GUESSING}
    assert writes - driven == set()
