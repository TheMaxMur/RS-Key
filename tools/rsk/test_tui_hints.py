# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Every `rsk …` hint in the TUI's sources must name a subcommand the CLI has.

Run from tools/:  python -m pytest rsk/test_tui_hints.py
The TUI leaves writes to the CLI and says which command to run, in Rust string
literals nothing compared with the parser: its org-attestation note sent users
to `rsk fido attest`, which argparse rejects. Only the subcommand path is held —
the hints elide arguments (`…`) and list alternatives (`import | clear`) — so a
real command named for the wrong job, as `rsk otp` once was for OTP slots, passes.
"""
import pathlib
import re
import sys
import types

# Same reason as test_docs_commands.py: loading the real hidapi/python-fido2
# extensions aborts the nix interpreter on macOS 27 (libffi trampolines).
sys.modules.setdefault("hid", types.ModuleType("hid"))
sys.modules.setdefault("fido2", types.ModuleType("fido2"))

import pytest  # noqa: E402

from rsk.test_docs_commands import _parser  # noqa: E402

TUI_SRC = pathlib.Path(__file__).resolve().parents[1] / "tui" / "src"
WORD = r"[a-z][a-z0-9-]*"
HINT = re.compile(rf"(?:\b|(?<=\\[nt]))rsk((?: {WORD})+)((?:\s*\|\s*{WORD})*)")


def _hints():
    """(where, argv) for every `rsk …` hint, one per `a | b` alternative."""
    found = []
    for path in sorted(TUI_SRC.glob("*.rs")):
        if path.stem.endswith("_tests"):
            continue
        for n, line in enumerate(path.read_text().splitlines(), 1):
            for m in HINT.finditer(line):
                *head, last = m.group(1).split()
                for alt in [last, *m.group(2).replace("|", " ").split()]:
                    found.append((f"tools/tui/src/{path.name}:{n}", [*head, alt]))
    return found


CASES = _hints()


def test_the_extractor_finds_the_hints():
    """A scanner that silently matches nothing would pass every case below."""
    assert len(CASES) >= 10, CASES
    assert any(argv[:2] == ["lock", "disable"] for _, argv in CASES)


@pytest.mark.parametrize("where,argv", CASES, ids=[f"{w} {' '.join(a)}" for w, a in CASES])
def test_a_tui_hint_names_a_real_subcommand(where, argv):
    # `--help` exits 0 once the path resolves, and prose after a leaf command is
    # left over as extras; a name argparse does not know exits 2 before that.
    with pytest.raises(SystemExit) as exit_:
        _parser().parse_args([*argv, "--help"])
    assert exit_.value.code == 0, f"{where}: `rsk {' '.join(argv)}` is not a command"
