# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The union `fuzz-union.py` computes, verified over synthetic reports.

The reporter's whole claim is one sentence — a `(file, line)` counts once and is
covered when ANY target counted it above zero — and every way of getting that
wrong looks like a plausible percentage rather than a crash: a line two targets
miss landing in the covered count, a non-repository path inflating the
denominator, a coordinate double-counted because it was `DA:` twice. So the
cases below are all on a `tmp_path` fixture and none reads the real
`fuzz/coverage/`, which is a retained local run rather than a property of the
checkout.

The script is loaded the way its sibling `test_fuzz_dimensions.py` loads
`fuzz-dimensions.py`: the file name is not an importable identifier.
"""

import importlib.util
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("fuzz_union", HERE / "fuzz-union.py")
fu = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fu)


def lcov(*blocks):
    """An LCOV text from `(source path, [(line, count), ...])` blocks."""
    out = []
    for path, das in blocks:
        out.append(f"SF:{path}")
        out.extend(f"DA:{line},{count}" for line, count in das)
        out.append("end_of_record")
    return "\n".join(out) + "\n"


def src(root, rel):
    """The absolute SF path a report uses for `rel` under repository `root`."""
    return str(root / rel)


def write(root, reports):
    """Write `{target: lcov text}` under `<root>/fuzz/coverage/`; return that dir.

    Neither `crates/` nor `third_party/` need exist — an LCOV names a build's
    sources, not this checkout's, so the fixture writes only the reports.
    """
    coverage = root / "fuzz" / "coverage"
    for name, text in reports.items():
        (coverage / name).mkdir(parents=True)
        (coverage / name / "coverage.lcov").write_text(text)
    return coverage


def test_repo_rel_keeps_only_the_four_repository_trees():
    assert fu.repo_rel("/r/crates/a.rs", "/r") == "crates/a.rs"
    assert fu.repo_rel("/r/firmware/src/main.rs", "/r") == "firmware/src/main.rs"
    assert fu.repo_rel("/r/third_party/vendor/src/lib.rs", "/r") == "third_party/vendor/src/lib.rs"
    assert fu.repo_rel("/r/tools/emu/src/main.rs", "/r") == "tools/emu/src/main.rs"
    assert fu.repo_rel("/r/fuzz/fuzz_targets/x.rs", "/r") is None
    assert fu.repo_rel("/other/crates/a.rs", "/r") is None
    assert fu.repo_rel("/r", "/r") is None


def test_a_line_covered_in_only_one_target_is_covered(tmp_path):
    root = tmp_path / "repo"
    coverage = write(root, {
        "a": lcov((src(root, "crates/x.rs"), [(10, 0)])),
        "b": lcov((src(root, "crates/x.rs"), [(10, 3)])),
    })
    hits = fu.union(coverage, root)
    assert hits[("crates/x.rs", 10)] is True
    assert fu.summarize(hits) == (1, 1, {"crates": (1, 1)})


def test_a_line_no_target_covers_stays_in_the_denominator(tmp_path):
    root = tmp_path / "repo"
    coverage = write(root, {
        "a": lcov((src(root, "crates/x.rs"), [(11, 0)])),
        "b": lcov((src(root, "crates/x.rs"), [(11, 0)])),
    })
    covered, total, _ = fu.summarize(fu.union(coverage, root))
    assert (covered, total) == (0, 1)


def test_a_coordinate_is_counted_once(tmp_path):
    root = tmp_path / "repo"
    coverage = write(root, {
        "a": lcov((src(root, "crates/x.rs"), [(10, 0), (10, 0)])),
        "b": lcov((src(root, "crates/x.rs"), [(10, 5)])),
    })
    hits = fu.union(coverage, root)
    assert list(hits) == [("crates/x.rs", 10)]
    assert fu.summarize(hits)[1] == 1


def test_only_repository_sources_are_in_scope(tmp_path):
    root = tmp_path / "repo"
    coverage = write(root, {
        "a": lcov(
            (src(root, "crates/x.rs"), [(1, 1)]),
            (src(root, "fuzz/fuzz_targets/x.rs"), [(2, 1)]),
            (src(root, "docs/x.rs"), [(3, 1)]),
            ("/home/u/.cargo/git/checkouts/embassy/src/lib.rs", [(4, 1)]),
            ("/usr/lib/rustlib/src/rust/library/std.rs", [(5, 1)]),
        ),
    })
    assert list(fu.union(coverage, root)) == [("crates/x.rs", 1)]


def test_malformed_da_lines_are_skipped_and_the_rest_is_read(tmp_path):
    root = tmp_path / "repo"
    coverage = write(root, {
        "a": "\n".join([
            f"SF:{src(root, 'crates/x.rs')}",
            "DA:notanint,3",
            "DA:7",
            "DA:8,oops",
            "DA:9,2",
            "end_of_record",
        ]) + "\n",
    })
    assert list(fu.union(coverage, root)) == [("crates/x.rs", 9)]


def test_an_optional_checksum_field_is_ignored():
    assert list(fu.parse_lcov("SF:/r/crates/x.rs\nDA:4,9,checksum\n")) == [("/r/crates/x.rs", 4, 9)]


def test_a_da_before_any_sf_is_not_read():
    assert list(fu.parse_lcov("DA:1,1\n")) == []


def test_no_reports_is_non_zero(tmp_path):
    empty = tmp_path / "coverage"
    empty.mkdir()
    assert fu.main(["--coverage", str(empty), "--root", str(tmp_path / "repo")]) == 1


def test_only_non_repository_records_is_non_zero(tmp_path):
    root = tmp_path / "repo"
    coverage = write(root, {"a": lcov(("/usr/lib/std.rs", [(1, 1)]))})
    assert fu.main(["--coverage", str(coverage), "--root", str(root)]) == 1


def test_an_unreadable_report_is_non_zero(tmp_path):
    root = tmp_path / "repo"
    coverage = write(root, {"a": lcov((src(root, "crates/x.rs"), [(1, 0)]))})
    report = coverage / "a" / "coverage.lcov"
    report.unlink()
    report.mkdir()
    assert fu.main(["--coverage", str(coverage), "--root", str(root)]) == 1


def test_main_prints_the_union_the_breakdown_and_the_metadata(tmp_path, capsys):
    root = tmp_path / "repo"
    coverage = write(root, {
        "a": lcov((src(root, "crates/x.rs"), [(1, 1), (2, 0)])),
        "b": lcov(
            (src(root, "crates/x.rs"), [(1, 0), (2, 0)]),
            (src(root, "third_party/y.rs"), [(5, 7)]),
        ),
    })
    (coverage / "config.txt").write_text("default\n")
    (coverage / "source-commit.txt").write_text("deadbeef\n")
    assert fu.main(["--coverage", str(coverage), "--root", str(root)]) == 0
    out = capsys.readouterr().out
    assert "2/3 = 66.67%" in out
    assert "crates: 1/2 = 50.00%" in out
    assert "third_party: 1/1 = 100.00%" in out
    assert "config: default" in out
    assert "source commit: deadbeef" in out


def test_a_covered_line_alone_still_prints_the_control_number(tmp_path, capsys):
    """The CONTROL for the case above: a whole fixture at 1/1 and no metadata."""
    root = tmp_path / "repo"
    coverage = write(root, {"a": lcov((src(root, "crates/x.rs"), [(1, 1)]))})
    assert fu.main(["--coverage", str(coverage), "--root", str(root)]) == 0
    assert "1/1 = 100.00%" in capsys.readouterr().out
