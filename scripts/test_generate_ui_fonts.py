# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `generate_ui_fonts.py` was verified against, kept.

The row it guards is the one thing standing between the panel's committed coverage
tables and the fonts they claim to come from, and it arrived with no table at all --
the same shape `crate_graph.py` had, and the same shape four guards before it had.
Nothing in `scripts/` names a generator whose `--check` mode is the gate row, so its
whole check could have been deleted with the suite green.

Every case drives the **script**, as a subprocess, with `--check`, the way
`check.sh` spells it -- not `generated_text()` behind it. A guard falsified through
its own function is exactly the hole this repo keeps shipping: the wiring is what
goes untested, and the wiring is what breaks. The generator runs in ~0.2 s, so
fidelity costs nothing here.

Both directions, because a row that cannot go green gets deleted as fast as one that
cannot go red: the clean copy passes, this checkout passes, and each mutation below
names the message it must produce.
"""

import os
import pathlib
import shutil
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/generate_ui_fonts.py"
OUTPUT = ROOT / "third_party/ibm-plex/font_data.rs"
STALE = "is stale; run scripts/generate_ui_fonts.py"


def check(tree, drop_env=(), **env):
    """Drive the row as `check.sh` does: the script, `--check`, rooted at `tree`."""
    environment = dict(os.environ, **env)
    for name in drop_env:
        environment.pop(name, None)
    return subprocess.run(
        [sys.executable, str(tree / "scripts/generate_ui_fonts.py"), "--check"],
        capture_output=True,
        text=True,
        env=environment,
    )


def generate(tree):
    """The write mode, so the pair can be asserted to agree."""
    return subprocess.run(
        [sys.executable, str(tree / "scripts/generate_ui_fonts.py")],
        capture_output=True,
        text=True,
    )


@pytest.fixture
def tree(tmp_path):
    """The two paths the row reads, copied, so no mutation touches the real tree.

    `ROOT` is derived from the script's own location, so a copy under `tmp/scripts`
    roots the whole run at `tmp` without the script needing a flag for it.
    """
    (tmp_path / "scripts").mkdir()
    shutil.copy(SCRIPT, tmp_path / "scripts/generate_ui_fonts.py")
    (tmp_path / "third_party/ibm-plex").mkdir(parents=True)
    shutil.copy(OUTPUT, tmp_path / "third_party/ibm-plex/font_data.rs")
    return tmp_path


def data(tree):
    return tree / "third_party/ibm-plex/font_data.rs"


def edit(tree, old, new, count=1):
    p = data(tree)
    text = p.read_text()
    assert old in text, f"the fixture no longer contains {old!r}"
    p.write_text(text.replace(old, new, count))


def test_this_checkout_is_green():
    """The row as `check.sh` runs it, against the committed tables."""
    done = check(ROOT)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "IBM Plex UI font data is current" in done.stdout


def test_the_clean_copy_is_green(tree):
    """The control: a fixture that is already red proves nothing about the cases."""
    done = check(tree)
    assert done.returncode == 0, done.stdout + done.stderr


def test_write_and_check_agree(tree):
    """A generator whose two modes disagree is a row that can never be satisfied."""
    data(tree).unlink()
    assert generate(tree).returncode == 0
    assert check(tree).returncode == 0


def test_a_flipped_coverage_byte_is_stale(tree):
    """The payload: one nibble of one glyph, which is what a hand edit looks like."""
    text = data(tree).read_text()
    first = text.index("0x")
    edit(tree, text[first : first + 4], "0x5A" if text[first : first + 4] != "0x5A" else "0xA5")
    done = check(tree)
    assert done.returncode == 1
    assert STALE in done.stdout


def test_a_changed_glyph_metric_is_stale(tree):
    """The other half of the file: the records that index into the payload."""
    edit(tree, "advance:", "advance: 1 +", 1)
    assert check(tree).returncode == 1


def test_a_deleted_role_is_stale(tree):
    """A whole face removed -- the shape a bad rebase leaves behind."""
    text = data(tree).read_text()
    start = text.index("const MONO_SMALL_DATA")
    edit(tree, text[start:], "")
    done = check(tree)
    assert done.returncode == 1
    assert STALE in done.stdout


def test_an_edited_font_digest_is_stale(tree):
    """The header records which font files the tables came from. It is checked too."""
    text = data(tree).read_text()
    line = next(l for l in text.splitlines() if "sha256:" in l)
    edit(tree, line, line[: line.index("sha256:")] + "sha256: 0" * 1)
    done = check(tree)
    assert done.returncode == 1
    assert STALE in done.stdout


def test_an_edited_raster_stack_line_is_stale(tree):
    """Recording FreeType and Raqm is decoration unless the row compares it too."""
    text = data(tree).read_text()
    line = next(l for l in text.splitlines() if l.startswith("// Pillow "))
    edit(tree, line, "// Pillow 0.0.0, FreeType 0.0.0, Raqm 0.0.0")
    done = check(tree)
    assert done.returncode == 1
    assert STALE in done.stdout


def test_a_deleted_output_is_stale(tree):
    """Absent is not the same code path as different, and it is the likelier one."""
    data(tree).unlink()
    done = check(tree)
    assert done.returncode == 1
    assert STALE in done.stdout


def test_a_changed_charset_is_stale(tree):
    """The tie in the other direction: the generator moving is a stale row too.

    Without this the table only proves the committed file cannot be hand-edited --
    not that it still describes what the generator would emit today.
    """
    script = tree / "scripts/generate_ui_fonts.py"
    script.write_text(script.read_text().replace('range(0x20, 0x7F)', 'range(0x20, 0x7E)'))
    done = check(tree)
    assert done.returncode == 1
    assert STALE in done.stdout


def test_an_unset_font_dir_is_refused(tree):
    """Not silently green: the row must say the environment is wrong, and fail."""
    done = check(tree, drop_env=("IBM_PLEX_SANS_DIR",))
    assert done.returncode != 0
    assert "IBM_PLEX_SANS_DIR is not set" in done.stderr


def test_a_font_dir_without_the_files_is_refused(tree, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    done = check(tree, IBM_PLEX_SANS_DIR=str(empty), IBM_PLEX_MONO_DIR=str(empty))
    assert done.returncode != 0
    assert "font is missing" in done.stderr


def test_check_sh_runs_the_row():
    """The rule the guard cannot state about itself -- and the one that has failed."""
    text = (ROOT / "scripts/check.sh").read_text()
    assert "scripts/generate_ui_fonts.py --check" in text
