# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""The `rsk` CLI's argument and machine-readable-output contracts (no device).

Run from tools/:  python -m pytest rsk/test_cli_contract.py
Phase 6 asks a host tool's invalid arguments and its machine-readable output to
be measured where a caller meets them. The docs-command table already proves a
*documented* line parses; nothing drove an invalid one, so the non-zero exit and
the usage on stderr were unpinned. The two `--json` streams are documented for
scripts (`status` for the TUI, `inventory list`'s one object per line), and
nothing parsed them or proved the human prose stays out of the JSON stream.
"""
import json
import sys
import types

# Same reason as test_refuse_to_guess.py: importing rsk.__main__ pulls in every
# subcommand module, and loading the real hidapi/python-fido2 extensions aborts
# the nix interpreter on macOS 27 (libffi trampolines).
sys.modules.setdefault("hid", types.ModuleType("hid"))
sys.modules.setdefault("fido2", types.ModuleType("fido2"))

import pytest  # noqa: E402

from rsk import __version__, inventory, status  # noqa: E402
from rsk.__main__ import main  # noqa: E402


def _main(argv, monkeypatch):
    """Run the real entry point over `argv`, as `python -m rsk` would."""
    monkeypatch.setattr(sys, "argv", ["rsk", *argv])
    main()


# --- invalid arguments --------------------------------------------------------

@pytest.mark.parametrize("argv", [
    [],                    # no group
    ["frobnicate"],        # unknown group
    ["status", "--nope"],  # unknown flag on a real subcommand
    ["inventory"],         # a group whose subcommand is required, missing
], ids=lambda a: "rsk " + " ".join(a))
def test_an_invalid_invocation_exits_two_with_usage(argv, monkeypatch, capsys):
    with pytest.raises(SystemExit) as exit_:
        _main(argv, monkeypatch)
    assert exit_.value.code == 2, f"rsk {' '.join(argv)} did not refuse"
    err = capsys.readouterr().err
    assert "usage:" in err, err


def test_version_prints_the_package_version_and_exits_zero(monkeypatch, capsys):
    with pytest.raises(SystemExit) as exit_:
        _main(["--version"], monkeypatch)
    assert exit_.value.code == 0
    assert capsys.readouterr().out.strip() == f"rsk {__version__}"


# --- machine-readable output --------------------------------------------------

def test_status_json_is_one_object_and_no_prose(monkeypatch, capsys):
    rec = {"fido": {"present": False}, "secure_boot": None, "serial": None}
    monkeypatch.setattr(status, "gather", lambda: rec)
    status.run(types.SimpleNamespace(json=True))
    out = capsys.readouterr().out
    assert out.count("\n") == 1, out
    assert json.loads(out) == rec


def test_inventory_json_stream_is_pure_json_lines(monkeypatch, capsys):
    """`--json` is documented as one object per line for scripting, so the
    several-keys note the human path prints must not enter the stream."""
    recs = [
        {"transport": "ccid", "serial": "aabbccdd"},
        {"transport": "hid", "product": "RS-Key", "fw": "5.8.0"},
    ]
    monkeypatch.setattr(inventory, "gather", lambda: recs)

    inventory.cmd_list(types.SimpleNamespace(json=True))
    out = capsys.readouterr().out
    lines = out.splitlines()
    assert len(lines) == len(recs), out
    assert [json.loads(line) for line in lines] == recs
    assert "note:" not in out

    # Positive control: the same records on the human path DO carry the note, so
    # the assertion above is about the `--json` branch and not an absent note.
    inventory.cmd_list(types.SimpleNamespace(json=False))
    assert "note:" in capsys.readouterr().out
