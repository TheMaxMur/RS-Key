# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `toolchain_gate.py` is verified against.

Same discipline as its siblings: for every rule, one mutation that must make the
row RED, and controls that must leave it GREEN. Two of those controls are the
point of the table rather than decoration.

The FIRST is the one this gate would most easily get wrong. Every `flake.lock`
node carries a `lastModified` beside its `rev`, and the obvious implementation —
hash the node, compare the hash — reddens on a plain re-fetch, where the
timestamp moves and the revision does not. A row that goes red on a no-op refresh
is a row somebody switches off, so `test_a_refetch_that_moves_only_lastmodified`
drives exactly that and demands EXIT=0.

The second is the shape this tree keeps shipping guards with: a parser that has
stopped matching finds nothing, loops over nothing and exits 0. So a `flake.lock`
whose format moved out from under the reader has to be RED and not green
(`test_a_lock_the_parser_cannot_read_is_red`), and both floors are driven from
BELOW rather than asserted from above.

Every fixture edit asserts its anchor resolved, so a fixture that has drifted
fails loudly instead of mutating nothing. The floors are PARAMETERS of `audit`
and not globals a case reaches in and lowers.
"""

import json
import pathlib
import subprocess
import sys

import pytest

import gate_lines
import toolchain_gate as gate

pytestmark = pytest.mark.assurance

ROOT = pathlib.Path(__file__).resolve().parent.parent

NIXPKGS_REV = "331800de5053fcebacf6813adb5db9c9dca22a0c"
FENIX_REV = "3a556b6fbd42412b6f3f0ea8d35959b1826f86ff"
SDL_REV = "50ab793786d9de88ee30ec4e4c24fb4236fc2674"
UTILS_REV = "11707dc2f618dd54ca8739b309ec4fc024de578b"
CORTEX_M = "8ec610d8f49840a5b376c69663b6369e71f4b34484b9b2eb29fb918d92516cb9"


def lock(last_modified=1780243769):
    """The lock, with nixpkgs's `lastModified` as a parameter — see the control."""
    return {
        "nodes": {
            "root": {
                "inputs": {
                    "fenix": "fenix",
                    "flake-utils": "flake-utils",
                    "nixpkgs": "nixpkgs",
                    "nixpkgs-sdl2": "nixpkgs-sdl2",
                }
            },
            "fenix": {"locked": {"lastModified": 1780824777, "rev": FENIX_REV, "type": "github"}},
            "flake-utils": {"locked": {"lastModified": 1731533236, "rev": UTILS_REV, "type": "github"}},
            "nixpkgs": {"locked": {"lastModified": last_modified, "rev": NIXPKGS_REV, "type": "github"}},
            "nixpkgs-sdl2": {"locked": {"lastModified": 1751274312, "rev": SDL_REV, "type": "github"}},
        },
        "root": "root",
        "version": 7,
    }


CARGO = f"""\
version = 4

[[package]]
name = "cortex-m"
version = "0.7.7"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{CORTEX_M}"

[[package]]
name = "firmware"
version = "0.1.0"
"""

PLATFORM = """\
[[assumption]]
id = "PLAT-TOOL-003"
class = "tool-tcb"
statement = "Kani/CBMC is sound for the arithmetic its harnesses bound."
status = "pending"

[[assumption]]
id = "PLAT-TOOL-004"
class = "tool-tcb"
statement = "TLC is sound for the finite configurations it checks."
status = "discharged"
"""

WORKFLOW_A = """\
name: ci
jobs:
  kani:
    env:
      KANI_VERSION: "0.67.0"
    steps:
      - run: cargo install --locked kani-verifier --version "$KANI_VERSION"
"""

WORKFLOW_B = """\
name: deep-checks
jobs:
  proofs:
    env:
      KANI_VERSION: "0.67.0"
    steps:
      - run: echo "$KANI_VERSION"
  shrink:
    env:
      KANI_VERSION: "0.67.0"
    steps:
      - run: echo "$KANI_VERSION"
"""

#: The tree the FFI derivation reads. Three of its lines are the case rather than
#: scenery: the doc comment and the commented-out block both spell a whole
#: `extern "C" {` and neither is a boundary, and the ABI is a STRING LITERAL the
#: lexer blanks — a reader that pattern-matched `extern "C"` on the lexed text
#: would find none of this and every case below would pass on an empty set.
CRATE_LIB = '''\\
// SPDX-License-Identifier: AGPL-3.0-only

//! The modexp backend. On the host there is no `unsafe extern "C" { fn ghost(); }`
//! at all, which this line says and does not do.

// unsafe extern "C" {
//     fn commented_out(x: *mut u32);
// }

#[cfg(target_os = "none")]
unsafe extern "C" {
    fn modexp(out: *mut u32, base: *const u32);
    fn crt(out: *mut u32);
}
'''

APP_MAIN = """\\
// SPDX-License-Identifier: AGPL-3.0-only

unsafe extern "C" {
    static __kv_start: u32;
}

fn start() -> u32 {
    core::ptr::addr_of!(__kv_start) as u32
}
"""

CRATE_BUILD = '''\\
// SPDX-License-Identifier: AGPL-3.0-only

fn main() {
    cc::Build::new()
        .file("csrc/core.c")
        .file("csrc/core.S")
        .compile("core");
}
'''

#: A vendored crate whose `extern` block is its author's boundary and not this
#: tree's. Green, and it is the only thing that says the exclusion still applies.
VENDORED = """\\
unsafe extern "C" {
    fn vendored_thing(x: *mut u32);
}
"""

PAGE = """\
# Supply chain

Prose the gate must not touch.

<!-- toolchain-tcb:start -->
<!-- toolchain-tcb:end -->

More prose.
"""

REGISTRY = f"""\
# SPDX-License-Identifier: AGPL-3.0-only

[[tool]]
name = "rustc"
role = "compiler"
provenance = "flake.lock:fenix"
pin = "{FENIX_REV}"
statement = "Compiles every first-party crate in the image."

[[tool]]
name = "arm-none-eabi-gcc"
role = "compiler"
provenance = "flake.lock:nixpkgs"
pin = "{NIXPKGS_REV}"
statement = "Compiles the C modexp core."

[[tool]]
name = "arm-none-eabi-as"
role = "assembler"
provenance = "flake.lock:nixpkgs"
pin = "{NIXPKGS_REV}"
statement = "Assembles rsk-rsa's hand-written ARM asm."

[[tool]]
name = "flip-link"
role = "linker"
provenance = "flake.lock:nixpkgs"
pin = "{NIXPKGS_REV}"
statement = "The linker .cargo/config.toml names."

[[tool]]
name = "picotool"
role = "packager"
provenance = "flake.lock:nixpkgs"
pin = "{NIXPKGS_REV}"
statement = "Writes the partition table and the published UF2."

[[tool]]
name = "tlaplus"
role = "checker"
provenance = "flake.lock:nixpkgs"
pin = "{NIXPKGS_REV}"
statement = "TLC, and the jar formal/run-tlc.sh runs."

[[tool]]
name = "jre8"
role = "runtime"
provenance = "flake.lock:nixpkgs"
pin = "{NIXPKGS_REV}"
statement = "The JVM TLC runs on."

[[tool]]
name = "cortex-m"
role = "assembler"
provenance = "Cargo.lock:cortex-m"
pin = "{CORTEX_M}"
statement = "A prebuilt asm blob, the second DWARF producer of the image."

[[tool]]
name = "cargo-kani"
role = "prover"
provenance = "workflow:.github/workflows/ci.yml:KANI_VERSION"
pin = "0.67.0"
statement = "Runs every #[kani::proof] harness."

[[tool]]
name = "cbmc"
role = "checker"
provenance = "unpinned"
pin = "PLAT-TOOL-003"
statement = "The model checker cargo-kani downloads with its own bundle."

[[not_tcb]]
input = "nixpkgs-sdl2"
reason = "SDL2 alone, for the tools/emu display window."

[[not_tcb]]
input = "flake-utils"
reason = "eachDefaultSystem plumbing; it emits no binary into any build."

[[boundary]]
id = "import:crate/src/lib.rs:modexp"
provider = "arm-none-eabi-gcc"
statement = "The modexp entry point, defined in csrc/core.c."

[[boundary]]
id = "import:crate/src/lib.rs:crt"
provider = "arm-none-eabi-gcc"
statement = "CRT signing, defined in csrc/core.c."

[[boundary]]
id = "import:app/src/main.rs:__kv_start"
provider = "flip-link"
statement = "A linker symbol whose ADDRESS is the datum, not a function."

[[boundary]]
id = "unit:crate/csrc/core.c"
provider = "arm-none-eabi-gcc"
statement = "The C half, compiled straight into the image."

[[boundary]]
id = "unit:crate/csrc/core.S"
provider = "arm-none-eabi-as"
statement = "The hand-written assembly half."
"""

#: Lowered with the fixture, which carries 10 tools, 9 resolved pins and 5
#: boundaries. Handed to `audit` rather than monkeypatched: both arms of each
#: floor have to be drivable without editing the number the run is judged by.
RESOLVED_FLOOR = 6
ROLE_FLOOR = 4
BOUNDARY_FLOOR = 4


class Tree:
    def __init__(self, root):
        self.root = root
        self.write(gate.REGISTRY, REGISTRY)
        self.write(gate.CARGO_LOCK, CARGO)
        self.write(gate.PLATFORM, PLATFORM)
        self.write(gate.WORKFLOWS / "ci.yml", WORKFLOW_A)
        self.write(gate.WORKFLOWS / "deep-checks.yml", WORKFLOW_B)
        self.write(gate.PAGE, PAGE)
        self.write("crate/src/lib.rs", CRATE_LIB)
        self.write("crate/build.rs", CRATE_BUILD)
        self.write("app/src/main.rs", APP_MAIN)
        self.write("third_party/vendor/src/lib.rs", VENDORED)
        self.write_lock()
        # `gate_lines.tree_files` asks git what the tree is and has no fallback,
        # so a fixture the FFI derivation can read is one git can list. No commit
        # and no `add`: `--others --exclude-standard` is what makes a file just
        # written by a case visible on the same run.
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        self.regenerate()

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def write_lock(self, last_modified=1780243769):
        """The lock, with the timestamp the control moves as a parameter."""
        self.write(gate.FLAKE_LOCK, json.dumps(lock(last_modified), indent=2))

    def edit(self, rel, old, new):
        """Replace `old` once, failing loudly if the fixture no longer says it."""
        path = self.root / rel
        text = path.read_text(encoding="utf-8")
        assert text.count(old) == 1, f"{rel} does not say {old!r} exactly once"
        path.write_text(text.replace(old, new), encoding="utf-8")

    def regenerate(self):
        """Put the page's region back to what the generator writes."""
        assert gate.run(self.root, write=True) == 0

    def problems(self, **kwargs):
        kwargs.setdefault("resolved_floor", RESOLVED_FLOOR)
        kwargs.setdefault("role_floor", ROLE_FLOOR)
        kwargs.setdefault("boundary_floor", BOUNDARY_FLOOR)
        return gate.audit(self.root, **kwargs)[0]

    def process(self, *argv):
        """The gate as `scripts/check.sh` runs it: a real process whose exit code
        is the verdict. `audit()` returning a list is what fourteen of this
        tree's thirty gates asserted instead, and a table that drives the helper
        cannot see a `main` that has stopped reaching it."""
        driver = (
            f"import functools, pathlib, sys;"
            f" sys.path.insert(0, {str(ROOT / 'scripts')!r});"
            f" import toolchain_gate as gate;"
            f" gate.ROOT = pathlib.Path({str(self.root)!r});"
            # The floors and nothing else, for the reason the module constants
            # give: they are measured against the real tree, and a default
            # argument is bound at def time so reassigning the constant here
            # would change the docstring's number and not the run's.
            f" gate.audit = functools.partial(gate.audit,"
            f" resolved_floor={RESOLVED_FLOOR}, role_floor={ROLE_FLOOR},"
            f" boundary_floor={BOUNDARY_FLOOR});"
            f" raise SystemExit(gate.main({list(argv)!r}))"
        )
        return subprocess.run(
            [sys.executable, "-c", driver], capture_output=True, text=True
        )


@pytest.fixture
def tree(tmp_path):
    return Tree(tmp_path)


def only(problems, needle):
    """The one problem carrying `needle`, so a case cannot pass on a stray."""
    hits = [p for p in problems if needle in p]
    assert len(hits) == 1, f"{needle!r} matched {hits} of {problems}"
    return hits[0]


# ---- the baseline, and the two controls --------------------------------------


def test_the_fixture_is_green(tree):
    """Every mutation below is meaningless if the unmutated tree is not clean."""
    assert tree.problems() == []


def test_a_refetch_that_moves_only_lastmodified(tree):
    """THE control. A plain `nix flake update` refetch moves the timestamp and
    not the revision, and a gate that hashed the node would go red on it — which
    is a row nobody keeps. Only `locked.rev` is read, so this is green by
    construction, and this case is what holds it that way."""
    before = (tree.root / gate.PAGE).read_text(encoding="utf-8")
    tree.write_lock(last_modified=1780243770)
    assert tree.problems() == []
    # And the printed page does not move either: a timestamp in the region would
    # make every refetch a docs diff.
    assert (tree.root / gate.PAGE).read_text(encoding="utf-8") == before


def test_a_new_correctly_pinned_tool_is_green(tree):
    """The registry has to be extensible without a code edit, or it stops growing."""
    tree.edit(
        gate.REGISTRY,
        '[[not_tcb]]\ninput = "nixpkgs-sdl2"',
        f'[[tool]]\nname = "rust-lld"\nrole = "linker"\n'
        f'provenance = "flake.lock:fenix"\npin = "{FENIX_REV}"\n'
        f'statement = "The linker flip-link shells out to."\n\n'
        f'[[not_tcb]]\ninput = "nixpkgs-sdl2"',
    )
    tree.regenerate()
    assert tree.problems() == []


# ---- rule 1: flake.lock ------------------------------------------------------


def test_a_pin_the_flake_node_does_not_carry_is_red(tree):
    """M1. Both values in the message: a mismatch nobody can read is one that gets
    'fixed' by editing whichever number is nearer."""
    tree.edit(gate.REGISTRY, f'pin = "{FENIX_REV}"', f'pin = "{"d" * 40}"')
    problem = only(tree.problems(), "`rustc` pins fenix at")
    assert "d" * 40 in problem and FENIX_REV in problem


def test_a_flake_input_that_is_not_a_root_input_is_red(tree):
    tree.edit(gate.REGISTRY, 'provenance = "flake.lock:fenix"', 'provenance = "flake.lock:fenixx"')
    assert only(tree.problems(), "input `fenixx`, which is not a root input")


def test_a_lock_the_parser_cannot_read_is_red(tree):
    """The family this tree ships guards with: a reader that stops matching finds
    nothing and passes everything. Driven by renaming the root node's key, which
    is the smallest format move that empties the derivation."""
    data = lock()
    data["nodes"]["root"]["inputs"] = {}
    tree.write(gate.FLAKE_LOCK, json.dumps(data))
    assert only(tree.problems(), "no root input resolved")


# ---- rule 2: Cargo.lock ------------------------------------------------------


def test_a_pin_the_cargo_checksum_does_not_carry_is_red(tree):
    tree.edit(gate.REGISTRY, f'pin = "{CORTEX_M}"', f'pin = "{"0" * 64}"')
    problem = only(tree.problems(), "`cortex-m` pins cortex-m at")
    assert CORTEX_M in problem and "0" * 64 in problem


def test_a_cargo_package_that_is_not_locked_is_red(tree):
    tree.edit(gate.REGISTRY, 'provenance = "Cargo.lock:cortex-m"', 'provenance = "Cargo.lock:cortex-n"')
    assert only(tree.problems(), "package `cortex-n`, which is locked 0 time(s)")


def test_a_cargo_package_locked_twice_is_red(tree):
    """Two versions of one name make `pin` ambiguous, and picking the first is how
    a rule silently starts answering about the wrong artifact."""
    tree.edit(
        gate.CARGO_LOCK,
        '[[package]]\nname = "firmware"',
        f'[[package]]\nname = "cortex-m"\nversion = "0.7.6"\nchecksum = "{"1" * 64}"\n\n'
        '[[package]]\nname = "firmware"',
    )
    assert only(tree.problems(), "locked 2 time(s) with a checksum")


# ---- rule 3: the workflow env: pin -------------------------------------------


def test_one_of_the_workflow_sites_disagreeing_is_red(tree):
    """M2: `KANI_VERSION` is written three times across two files, so an edit to
    any one of them has to be visible here. The message has to NAME the
    disagreeing file, or the reader is left grepping — and it names the file's
    OWN spread too, because deep-checks.yml assigns the variable twice and this
    mutation moves one of the two. `scripts/kani_gate.py` asks the same question
    of the same files now; what is this rule's alone is holding them to the
    registry's `pin`, which the mutation below drives."""
    tree.edit(gate.WORKFLOWS / "deep-checks.yml", 'KANI_VERSION: "0.67.0"\n    steps:\n      - run: echo "$KANI_VERSION"\n  shrink', 'KANI_VERSION: "0.68.0"\n    steps:\n      - run: echo "$KANI_VERSION"\n  shrink')
    problem = only(tree.problems(), "disagree")
    assert ".github/workflows/deep-checks.yml (0.67.0, 0.68.0)" in problem
    assert "written 3 time(s) across 2 workflow file(s)" in problem
    assert ".github/workflows/ci.yml" not in problem


def test_the_named_workflows_own_value_disagreeing_is_red(tree):
    """The near half of the same rule: the file the provenance points at."""
    tree.edit(gate.WORKFLOWS / "ci.yml", 'KANI_VERSION: "0.67.0"', 'KANI_VERSION: "0.69.0"')
    problem = only(tree.problems(), "pins KANI_VERSION at 0.67.0")
    assert "['0.69.0']" in problem


def test_an_assignment_outside_an_env_block_is_red(tree):
    """A `with:` key of the same name is an argument, not a pin. A line match
    would have counted it and reported the workflow as pinning something."""
    tree.edit(gate.WORKFLOWS / "ci.yml", "    env:\n      KANI_VERSION", "    with:\n      KANI_VERSION")
    assert only(tree.problems(), "no `env:` block")


def test_a_commented_out_pin_is_not_a_pin(tree):
    """The `gate_lines.runs` lesson one file over: a `#` in front of a line is not
    an assignment, and counting one is how a guard reads a dead row as live."""
    tree.edit(gate.WORKFLOWS / "ci.yml", '      KANI_VERSION: "0.67.0"', '      # KANI_VERSION: "0.67.0"')
    assert only(tree.problems(), "no `env:` block")


# ---- rule 4: the `unpinned` escape -------------------------------------------


def test_unpinned_against_a_closed_obligation_is_red(tree):
    """M3. The direction that matters: the obligation gets marked discharged while
    the tool it covers is still pinned by nothing."""
    tree.edit(gate.REGISTRY, 'pin = "PLAT-TOOL-003"', 'pin = "PLAT-TOOL-004"')
    problem = only(tree.problems(), "`cbmc` is unpinned against PLAT-TOOL-004")
    assert "'discharged'" in problem and "not 'pending'" in problem


def test_unpinned_against_a_missing_obligation_is_red(tree):
    tree.edit(gate.REGISTRY, 'pin = "PLAT-TOOL-003"', 'pin = "PLAT-TOOL-009"')
    assert only(tree.problems(), "has no such row")


def test_unpinned_against_something_that_is_not_an_obligation_is_red(tree):
    """Without the id shape, `pin = "we'll get to it"` satisfies the rule."""
    tree.edit(gate.REGISTRY, 'pin = "PLAT-TOOL-003"', 'pin = "TODO"')
    assert only(tree.problems(), "not a PLAT-TOOL* id")


# ---- rule 5: the flake's root inputs, both ways -------------------------------


def test_a_root_input_with_no_row_at_all_is_red(tree):
    """M4. Delete the only row that names an input and the registry understates
    its own contract with every remaining row still correct."""
    tree.edit(gate.REGISTRY, '[[not_tcb]]\ninput = "flake-utils"\nreason = "eachDefaultSystem plumbing; it emits no binary into any build."\n', "")
    assert only(tree.problems(), "root input `flake-utils` is in no tool's provenance")


def test_a_not_tcb_row_for_an_input_that_is_gone_is_red(tree):
    tree.edit(gate.REGISTRY, 'input = "flake-utils"', 'input = "flake-utilities"')
    assert only(tree.problems(), "not-TCB `flake-utilities` is not a root input")


def test_an_input_that_is_both_in_and_out_of_the_tcb_is_red(tree):
    tree.edit(gate.REGISTRY, 'input = "nixpkgs-sdl2"', 'input = "nixpkgs"')
    assert only(tree.problems(), "cannot be out of the TCB and pin a tool in it")


def test_a_not_tcb_row_with_no_reason_is_red(tree):
    """A bare exclusion is the gap parked under a different heading."""
    tree.edit(gate.REGISTRY, 'reason = "eachDefaultSystem plumbing; it emits no binary into any build."', 'reason = ""')
    assert only(tree.problems(), "states no reason")


# ---- the schema --------------------------------------------------------------


def test_a_derived_value_stored_on_a_row_is_red(tree):
    """The `evidence_gate` discipline: an eighth key is where a derived value
    starts being stored, and a stored derived value is the rot."""
    tree.edit(gate.REGISTRY, 'name = "rustc"', 'name = "rustc"\nversion = "1.96.0"')
    assert only(tree.problems(), "carries ['version']")


def test_a_role_outside_the_vocabulary_is_red(tree):
    """An open vocabulary lets a criterion category be covered by a word nobody
    agreed on."""
    # `runtime` and not `compiler`: the fixture grew a second compiler when the
    # FFI rows needed one to name as a producer, and `edit` takes one occurrence.
    tree.edit(gate.REGISTRY, 'role = "runtime"', 'role = "buildy-thing"')
    assert only(tree.problems(), "'buildy-thing', which is not one of")


def test_a_provenance_in_no_known_form_is_red(tree):
    tree.edit(gate.REGISTRY, 'provenance = "unpinned"', 'provenance = "the usual place"')
    assert only(tree.problems(), "which is none of")


def test_a_tool_registered_twice_is_red(tree):
    tree.edit(gate.REGISTRY, 'name = "jre8"', 'name = "tlaplus"')
    assert only(tree.problems(), "`tlaplus` is registered twice")


# ---- the structural rules ----------------------------------------------------


def test_a_criterion_category_no_tool_answers_for_is_red(tree):
    """`linker` printed as covered by an empty set is the overclaim the table
    exists to prevent, and every per-row rule stays green through it."""
    tree.edit(gate.REGISTRY, 'role = "linker"', 'role = "packager"')
    tree.regenerate()
    assert only(tree.problems(), "no registered tool answers for the criterion's `linker`")


def test_a_category_in_none_of_the_three_maps_is_red(tree, monkeypatch):
    """The map has to PARTITION the criterion. Dropping `bootrom` from the
    unreachable list would take it out of the printed table with no other rule
    noticing — a category silently not mentioned reads as one not needed."""
    monkeypatch.setattr(gate, "UNREACHABLE", {k: v for k, v in gate.UNREACHABLE.items() if k != "bootrom"})
    assert only(tree.problems(), "a category in neither map")


def test_a_roster_that_resolves_nothing_is_red(tree):
    """Driven from BELOW: every per-row rule above is satisfied by a roster that
    opens no file, and rule 4's escape is satisfied by a roster of nothing but
    escapes."""
    assert only(
        tree.problems(resolved_floor=10),
        "pin(s) resolved against a file, under the measured 10",
    )


def test_a_roster_collapsed_onto_one_role_is_red(tree):
    assert only(tree.problems(role_floor=8), "role(s) carried, under the measured 8")


# ---- rule 6: the FFI boundaries, both ways -----------------------------------


def test_a_new_import_the_registry_does_not_claim_is_red(tree):
    """The direction that matters: a crossing arrives in the tree and no row
    describes it. Every other rule here reads the registry, so a boundary that
    exists only in the source is invisible to all of them."""
    tree.write("crate/src/hsm.rs", 'unsafe extern "C" {\n    fn hsm_sign(x: *mut u32);\n}\n')
    assert only(tree.problems(), "declares boundary `import:crate/src/hsm.rs:hsm_sign`")


def test_an_export_is_a_boundary_too(tree):
    """The half no floor holds, because this tree exports nothing across a C ABI
    — so if this case goes, the `export:` reader can stop matching and the
    boundary count is unchanged. Both spellings, since `#[unsafe(no_mangle)]` and
    the definition are separate readers that must agree on one id."""
    tree.write(
        "crate/src/hook.rs",
        "#[unsafe(no_mangle)]\npub extern \"C\" fn rsk_callback(x: u32) -> u32 {\n    x\n}\n",
    )
    assert only(tree.problems(), "boundary `export:crate/src/hook.rs:rsk_callback`")


def test_a_no_mangle_without_an_extern_abi_is_an_export(tree):
    """The `#[no_mangle]` reader's own case, and the reason it exists beside the
    definition reader: `#[unsafe(no_mangle)] pub extern "C" fn` is found by BOTH,
    so a case written that way leaves this half deletable with the suite green.
    A plain `#[no_mangle] pub fn` — what `#[entry]` expands to — is found only
    here, and it still exports a symbol for a foreign caller to bind."""
    tree.write("crate/src/entry.rs", "#[no_mangle]\npub fn rsk_entry() -> u32 {\n    0\n}\n")
    assert only(tree.problems(), "boundary `export:crate/src/entry.rs:rsk_entry`")


def test_a_pipe_in_a_derived_value_does_not_spill_the_row(tree):
    """The cell rule, driven and not asserted. A `|` inside a cell ends it and the
    row spills into the wrong columns — a defect this tree has shipped — and a
    file name is the one derived value that can legally carry one."""
    tree.write("crate/src/od|d.rs", 'unsafe extern "C" {\n    fn odd_sym(x: *mut u32);\n}\n')
    tree.edit(
        gate.REGISTRY,
        '[[boundary]]\nid = "unit:crate/csrc/core.c"',
        '[[boundary]]\nid = "import:crate/src/od|d.rs:odd_sym"\n'
        'provider = "arm-none-eabi-gcc"\nstatement = "A path carrying a pipe."\n\n'
        '[[boundary]]\nid = "unit:crate/csrc/core.c"',
    )
    tree.regenerate()
    assert tree.problems() == []
    row = next(
        line
        for line in (tree.root / gate.PAGE).read_text(encoding="utf-8").splitlines()
        if "odd_sym" in line
    )
    assert r"crate/src/od\|d.rs" in row
    # Four columns is five structural pipes; an escaped one is not structural.
    assert row.count("|") - row.count("\\|") == 5, row


def test_a_new_translation_unit_is_a_boundary(tree):
    """`.file(…)` and not `rerun-if-changed`: a build.rs that starts compiling a
    second C file has added foreign machine code to the image."""
    tree.edit("crate/build.rs", '.file("csrc/core.S")', '.file("csrc/core.S")\n        .file("csrc/extra.c")')
    assert only(tree.problems(), "declares boundary `unit:crate/csrc/extra.c`")


def test_a_row_for_a_crossing_that_is_gone_is_red(tree):
    """The other direction. A row outliving what it described is how a registry
    starts saying more than the tree does, and the fix reads as deleting it —
    which is why the message has to say the reader might be the broken half."""
    tree.edit(
        gate.REGISTRY,
        'id = "import:crate/src/lib.rs:crt"',
        'id = "import:crate/src/lib.rs:crt_v2"',
    )
    assert only(
        tree.problems(),
        "boundary `import:crate/src/lib.rs:crt_v2` is claimed by a row and no"
        " derivation produces it",
    )


def test_a_boundary_whose_provider_is_not_a_registered_tool_is_red(tree):
    """The join to the pinned closure. Without it the rows are a list of names
    beside the table rather than part of it."""
    tree.edit(gate.REGISTRY, 'provider = "arm-none-eabi-as"', 'provider = "some-assembler"')
    assert only(tree.problems(), "names provider `some-assembler`")


def test_a_boundary_produced_by_a_tool_outside_the_criterion_is_red(tree):
    """`picotool` is in the TCB and produces no foreign half of anything. A
    provider only checked for existence would take it."""
    tree.edit(gate.REGISTRY, 'provider = "flip-link"', 'provider = "picotool"')
    assert only(tree.problems(), "whose role is 'packager'")


def test_a_boundary_claimed_twice_is_red(tree):
    tree.edit(
        gate.REGISTRY,
        'id = "unit:crate/csrc/core.S"',
        'id = "unit:crate/csrc/core.c"',
    )
    assert only(tree.problems(), "`unit:crate/csrc/core.c` is claimed twice")


def test_a_derived_value_stored_on_a_boundary_is_red(tree):
    """Same discipline as a `[[tool]]`: which file the crossing is in and what
    guards it are DERIVED, and a stored copy of either is the rot."""
    tree.edit(
        gate.REGISTRY,
        'id = "unit:crate/csrc/core.c"',
        'id = "unit:crate/csrc/core.c"\ncompiled_by = "crate/build.rs"',
    )
    assert only(tree.problems(), "carries ['compiled_by']")


def test_a_boundary_with_no_id_is_red(tree):
    """A row with no `id` claims nothing, and a claim nothing holds is a crossing
    read by a human and then dropped on the floor."""
    tree.edit(gate.REGISTRY, 'id = "unit:crate/csrc/core.S"', 'name = "core.S"')
    problems = tree.problems()
    assert only(problems, "a [[boundary]] with no `id`")
    # And the boundary it MEANT to claim is now unclaimed — the shape rule and
    # the both-ways rule catching the same edit from opposite ends.
    assert only(problems, "declares boundary `unit:crate/csrc/core.S`")


def test_a_cc_file_argument_that_is_not_a_literal_is_red(tree):
    """The unit reader takes the path out of the call, so a call it cannot read
    is a translation unit nobody enumerated — not a call to skip quietly."""
    tree.edit("crate/build.rs", '.file("csrc/core.S")', ".file(chosen_asm())")
    problems = tree.problems()
    assert only(problems, "a `.file(…)` whose argument is not a plain string literal")
    assert only(problems, "boundary `unit:crate/csrc/core.S` is claimed by a row")


def test_a_boundary_with_no_statement_is_red(tree):
    tree.edit(
        gate.REGISTRY,
        'statement = "The hand-written assembly half."',
        'statement = ""',
    )
    assert only(tree.problems(), "is missing ['statement']")


def test_a_derivation_that_has_stopped_matching_is_red(tree):
    """Driven from BELOW, like both floors above it. The unclaimed-candidate rule
    finds nothing when the reader finds nothing, so it cannot be the guard on the
    reader; and a registry emptied in the same commit takes the other direction
    with it."""
    assert only(
        tree.problems(boundary_floor=6),
        "boundary(s) derived from the tree, under the measured 6",
    )


def test_a_commented_out_extern_block_is_not_a_boundary(tree):
    """The control that is not decoration. `CRATE_LIB` spells a whole
    `extern "C" {` twice in text a compiler never reads — a doc comment and a
    commented-out block — and a reader over raw source produces two boundaries
    nothing can claim, which reads as a registry that is short."""
    assert tree.problems() == []
    found = gate.boundary_candidates(tree.root, [])
    assert "import:crate/src/lib.rs:commented_out" not in found
    assert "import:crate/src/lib.rs:ghost" not in found
    assert "import:crate/src/lib.rs:modexp" in found


def test_a_vendored_extern_block_is_not_this_trees_boundary(tree):
    """A green control with a live derivation behind it: the vendored file IS
    read by `tree_files` and IS an `extern` block, and it is out because
    `third_party/` is somebody else's boundary — not because nothing looked."""
    assert "vendored_thing" in (tree.root / "third_party/vendor/src/lib.rs").read_text()
    assert not [k for k in gate.boundary_candidates(tree.root, []) if "third_party" in k]


def test_the_guard_a_boundary_sits_under_reaches_the_page(tree):
    """The `#[cfg]` is the host/image split, and it is DERIVED — the registry has
    no field for it. Bracket-matched rather than line-walked, so a `cfg` broken
    over lines is still read whole."""
    tree.edit(
        "crate/src/lib.rs",
        '#[cfg(target_os = "none")]',
        '#[cfg(all(\n    target_os = "none",\n    feature = "asm"\n))]',
    )
    tree.regenerate()
    page = (tree.root / gate.PAGE).read_text(encoding="utf-8")
    assert '#[cfg(all( target_os = "none", feature = "asm" ))]' in page
    assert "app/src/main.rs, extern \"C\", unconditional" in page


def test_the_region_names_every_boundary(tree):
    """The print half of rule 6: a set derived and held and then not published is
    a claim only a reader of this file can check."""
    page = (tree.root / gate.PAGE).read_text(encoding="utf-8")
    for boundary in ("modexp", "crt", "__kv_start", "core.c", "core.S"):
        assert boundary in page, boundary
    assert "`arm-none-eabi-as`" in page


# ---- rule 7: the generated region --------------------------------------------


def test_a_hand_edit_inside_the_region_is_red(tree):
    """The whole of rule 6: the page is a byte diff, not a description."""
    tree.edit(gate.PAGE, "| `cbmc` | checker |", "| `cbmc` | pinned-and-fine |")
    assert only(tree.problems(), "is not what the generator writes")


def test_the_prose_outside_the_region_survives_a_write(tree):
    """A generator that ate the page around its region would be caught by nothing
    else here — every rule above reads the registry, not the page."""
    page = (tree.root / gate.PAGE).read_text(encoding="utf-8")
    assert "Prose the gate must not touch." in page and page.endswith("More prose.\n")


def test_the_region_carries_the_disclaimer_and_so_does_the_docstring(tree):
    """The claim boundary is the deliverable, not a comment on it: a reader of the
    published page has to see the same limits as a reader of the gate. Both
    copies are asserted because dropping either leaves the other true."""
    page = (tree.root / gate.PAGE).read_text(encoding="utf-8")
    for said in ("does not prove", "narHash", "which actually"):
        assert said in page, said
        assert said in gate.__doc__, said
    # Reflowed, because a needle that a line wrap can break is a rule that fails
    # on formatting instead of on meaning.
    flat = " ".join(gate.__doc__.split())
    assert "LLVM passes and the bootrom have no machine-readable source" in flat


def test_the_region_names_every_criterion_category(tree):
    """Three lists, six names, printed. A category that falls out of all three is
    caught by `test_a_category_in_none_of_the_three_maps_is_red`; this is the
    other end — that what the maps hold actually reaches the page."""
    page = (tree.root / gate.PAGE).read_text(encoding="utf-8")
    missing = [c for c in gate.CRITERION if f"**{c}**" not in page]
    assert not missing, missing


# ---- the row that runs it ----------------------------------------------------


def test_check_assurance_sh_runs_this_gate():
    """A guard nothing invokes can be deleted with the suite still green, and the
    row is the half `test_gate_scripts.py` covers by glob only for `GATES`. Read
    through `gate_lines.runs`, so a `#` in front of the row does not count."""
    assert gate_lines.runs((ROOT / "scripts/check-assurance.sh").read_text(), "scripts/toolchain_gate.py")


def test_the_real_registry_is_green():
    """The table above runs on a fixture; this is the tree. Without it every case
    could pass over a synthetic registry while the shipped one is red."""
    assert gate.audit(ROOT)[0] == []


def test_the_process_exits_zero_on_the_real_tree():
    """`main`, in a process, on the tree — the whole of what `check.sh` asserts.
    Every case above calls `audit` and would pass over a `main` that had stopped
    reaching it."""
    done = subprocess.run(
        [sys.executable, str(ROOT / "scripts/toolchain_gate.py")],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert done.returncode == 0, done.stderr
    assert "4 of 6 TCB categories enumerated" in done.stdout


def test_the_process_goes_red_on_a_boundary_nothing_claims(tree):
    """Direction one, through the entry point rather than the helper."""
    tree.write("crate/src/hsm.rs", 'unsafe extern "C" {\n    fn hsm_sign(x: *mut u32);\n}\n')
    done = tree.process()
    assert done.returncode == 1, done.stdout
    assert "import:crate/src/hsm.rs:hsm_sign" in done.stderr


def test_the_process_goes_red_on_a_row_for_a_crossing_that_is_gone(tree):
    """Direction two, same way."""
    tree.edit(
        gate.REGISTRY,
        'id = "unit:crate/csrc/core.S"',
        'id = "unit:crate/csrc/core_v2.S"',
    )
    done = tree.process()
    assert done.returncode == 1, done.stdout
    assert "unit:crate/csrc/core_v2.S" in done.stderr


def test_the_process_stays_green_on_an_unmutated_fixture(tree):
    """The control for both of those: the same driver, the same tree, exit 0 —
    so a red above is the mutation and not the harness."""
    done = tree.process()
    assert done.returncode == 0, done.stderr
    assert "5 FFI boundary(s) derived from the tree and claimed" in done.stdout
