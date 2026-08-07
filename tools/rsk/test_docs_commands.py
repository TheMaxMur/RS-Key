# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Every `rsk …` line inside a docs shell block must actually parse.

Run from tools/:  python -m pytest rsk/test_docs_commands.py
A fenced `sh` block is the copy-paste surface — an instruction, not prose — so a
command argparse rejects is a broken instruction, and nothing was comparing the
two. Two shipped that way: production.md's burn ritual called
`rsk secure-boot load-key` with no `otp.json`, and signing-keys.md's key-loss row
dropped it from the `--slot` form, six lines below the same file spelling it
correctly.

Prose mentions stay out of scope deliberately: naming a command mid-sentence
without every argument is fine. A block someone pastes into a shell is not.
"""
import argparse
import pathlib
import re
import shlex
import sys
import types

# Same reason as test_refuse_to_guess.py: this file touches no device, and
# loading the real hidapi/python-fido2 extensions aborts the nix interpreter on
# macOS 27 (libffi trampolines).
sys.modules.setdefault("hid", types.ModuleType("hid"))
sys.modules.setdefault("fido2", types.ModuleType("fido2"))

import pytest  # noqa: E402

from rsk.__main__ import GROUPS  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parents[2]
SOURCES = sorted(REPO.glob("docs/**/*.md")) + [REPO / "README.md"]
SHELL_FENCE = re.compile(r"^```(sh|bash|console)\s*$")
PLACEHOLDER = re.compile(r"<[^>]+>")
# A doc line is one command, not a pipeline; keep the `rsk` part of it.
TAIL = re.compile(r"\s+(\||;|&&|#)")


def _parser():
    """The real CLI parser, assembled the way `__main__.main` assembles it."""
    p = argparse.ArgumentParser(prog="rsk")
    sub = p.add_subparsers(dest="group", required=True, metavar="<group>")
    for mod in GROUPS:
        mod.register(sub)
    return p


def _documented():
    """(where, argv) for every `rsk …` line inside a shell fence."""
    found, in_shell = [], False
    for path in SOURCES:
        pending, start = "", 0
        for n, raw in enumerate(path.read_text().splitlines(), 1):
            if raw.startswith("```"):
                in_shell = bool(SHELL_FENCE.match(raw)) if not in_shell else False
                continue
            if not in_shell:
                continue
            line = raw.strip()
            if pending:  # a `\`-continued command from the line before
                line, pending = pending + " " + line, ""
            elif not (line == "rsk" or line.startswith("rsk ")):
                continue
            else:
                start = n
            if line.endswith("\\"):
                pending = line[:-1].strip()
                continue
            cmd = TAIL.split(line, maxsplit=1)[0].strip()
            if "…" in cmd or "..." in cmd:  # an elision, not a command
                continue
            argv = shlex.split(cmd)[1:]
            # `rsk <group> --help` names no command: a placeholder anywhere in
            # the subcommand path (everything before the first flag) makes the
            # line a template. A placeholder in an *argument* is still checkable
            # — `1` satisfies both a path and an `int`.
            path_tokens = argv[:next((i for i, a in enumerate(argv)
                                      if a.startswith("-")), len(argv))]
            if any(PLACEHOLDER.fullmatch(t) for t in path_tokens):
                continue
            found.append((f"{path.relative_to(REPO)}:{start}",
                          [PLACEHOLDER.sub("1", a) for a in argv]))
    return found


CASES = _documented()


def test_the_extractor_finds_the_commands():
    """A scanner that silently matches nothing would pass every case below."""
    assert len(CASES) >= 20, f"only {len(CASES)} `rsk` commands found in the docs"
    assert any(w.startswith("docs/production.md") for w, _ in CASES)


@pytest.mark.parametrize("where,argv", CASES, ids=[w for w, _ in CASES])
def test_documented_command_parses(where, argv):
    try:
        _parser().parse_args(argv)
    except SystemExit as exit_:
        # 0 is `--help`, which is a real thing to document; 2 is argparse
        # refusing the line someone was told to paste.
        if exit_.code:
            pytest.fail(f"{where}: `rsk {' '.join(argv)}` does not parse")
