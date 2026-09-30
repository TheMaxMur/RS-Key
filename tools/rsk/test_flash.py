# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""`rsk flash`: every check refuses before picotool runs, and each one is the check
docs/supply-chain.md publishes.

Run from tools/:  python -m pytest rsk/test_flash.py
No cosign, gh, picotool or board: the three tools are stand-ins that record their
argv, so each case asserts what ran, in which order, and that nothing was written
past a refusal.
"""
import hashlib
import pathlib
import re
import sys
import types

# The same reason as test_refuse_to_guess.py: nothing here touches a device.
sys.modules.setdefault("hid", types.ModuleType("hid"))

import pytest  # noqa: E402

from rsk import flash  # noqa: E402

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
NAME = "rs-key-v9.9.9-default.uf2"
IMAGE = b"UF2\nnot really an image\n"
#: The Fulcio certificate's identity, less the ref the signing run was started from.
SIGNER = "https://github.com/TheMaxMur/RS-Key/.github/workflows/release-build.yml"


@pytest.fixture
def release(tmp_path):
    """A download directory as a release leaves it: the image, SHA256SUMS in the
    release job's `./` form, and the bundle."""
    (tmp_path / NAME).write_bytes(IMAGE)
    digest = hashlib.sha256(IMAGE).hexdigest()
    (tmp_path / flash.SUMS).write_text(
        f"{'0' * 64}  ./rs-key-v9.9.9-sbom.cdx.json\n{digest}  ./{NAME}\n")
    (tmp_path / flash.BUNDLE).write_text("{}")
    return tmp_path


class Tools:
    """cosign, gh and picotool as stand-ins; `ran` holds each call in order. Given a
    `signer`, cosign answers by matching the identity regexp it was passed against it,
    and the repository it was pinned to against the certificate's `repository`;
    given the ref a run was `attested` at, gh answers by the `--source-ref` it was
    passed, and with none it takes any ref, as gh does. `gh_says` is the error a gh
    too old for a flag prints, and makes gh fail with it."""

    def __init__(self, monkeypatch, cosign=0, gh=0, have=("cosign", "gh", "picotool"),
                 reboot=0, signer=None, attested=None, gh_says=None, repository=flash.REPO):
        self.ran, self.rc, self.signer = [], {"cosign": cosign, "gh": gh}, signer
        self.attested, self.gh_says, self.repository = attested, gh_says, repository
        monkeypatch.setattr(flash.shutil, "which",
                            lambda tool: f"/bin/{tool}" if tool in have else None)
        monkeypatch.setattr(flash, "_run", self._run)
        monkeypatch.setattr(flash, "require_bootsel", lambda: self.ran.append(("bootsel",)))

        def picotool(*argv, check=True):
            self.ran.append(("picotool", *argv))
            rc = reboot if argv[0] == "reboot" else 0
            return types.SimpleNamespace(returncode=rc, stdout="", stderr="")

        monkeypatch.setattr(flash, "picotool", picotool)

    def _run(self, argv):
        tool = pathlib.PurePath(argv[0]).name
        self.ran.append((tool, *argv[1:]))
        rc = self.rc[tool]
        if tool == "cosign" and self.signer is not None:
            # cosign's check is Go's MatchString of the regexp against the SAN: a search.
            wanted = argv[argv.index("--certificate-identity-regexp") + 1]
            rc = 0 if re.search(wanted, self.signer) else 1
            # And an exact comparison with GithubWorkflowRepository, when it is given one.
            if "--certificate-github-workflow-repository" in argv:
                pinned = argv[argv.index("--certificate-github-workflow-repository") + 1]
                rc = rc or (0 if pinned == self.repository else 1)
        if tool == "gh" and self.attested is not None and "--source-ref" in argv:
            rc = 0 if argv[argv.index("--source-ref") + 1] == self.attested else 1
        if tool == "gh" and self.gh_says is not None:
            return types.SimpleNamespace(returncode=1, stdout="", stderr=self.gh_says)
        return types.SimpleNamespace(returncode=rc, stdout="",
                                     stderr=f"{tool} said no\x1b[31m")

    def names(self):
        return [call[0] for call in self.ran]

    def wrote(self):
        return [call for call in self.ran if call[0] == "picotool"]


def flash_it(path, **kw):
    args = {"uf2": str(path), "dry_run": False, "local_build": False, **kw}
    flash.run(types.SimpleNamespace(**args))


def test_a_good_release_is_verified_then_loaded_and_rebooted(release, monkeypatch, capsys):
    tools = Tools(monkeypatch)
    flash_it(release / NAME)
    image, sums, bundle = (str(release / n) for n in (NAME, flash.SUMS, flash.BUNDLE))
    assert tools.ran == [
        ("cosign", "verify-blob", "--bundle", bundle,
         "--certificate-identity-regexp", flash.IDENTITY_REGEXP,
         "--certificate-oidc-issuer", flash.OIDC_ISSUER,
         flash.REPOSITORY_PIN, flash.REPO, sums),
        ("gh", "attestation", "verify", image, "--repo", flash.REPO,
         "--signer-workflow", flash.SIGNER_WORKFLOW, "--source-ref", "refs/tags/v9.9.9"),
        ("bootsel",),
        ("picotool", "load", "-v", image),
        ("picotool", "reboot"),
    ]
    out = capsys.readouterr().out
    assert "Rekor entry checked" in out and "sha256 matches" in out
    assert "rebooted into the new image" in out


def test_a_signature_that_does_not_verify_writes_nothing(release, monkeypatch, capsys):
    tools = Tools(monkeypatch, cosign=1)
    with pytest.raises(SystemExit):
        flash_it(release / NAME)
    assert tools.names() == ["cosign"]
    err = capsys.readouterr().err
    assert "does not verify" in err and "cosign said no" in err
    assert "\x1b" not in err  # the verifier's words are sanitized


@pytest.mark.parametrize("signer", [
    f"{SIGNER}@refs/heads/main",
    f"{SIGNER.replace('github.com', 'githubXcom')}@refs/tags/v9.9.9",
], ids=["branch-ref", "host-dot"])
def test_a_signature_from_elsewhere_writes_nothing(release, monkeypatch, capsys, signer):
    """Releases are cut from tags. SHA256SUMS signed by release-build.yml at a branch,
    as a release run dispatched from `main` would sign it, fails the identity rsk
    hands cosign, and so does a host one character off `github.com`, which a bare
    `.` in the regexp let through. Nothing is written either way."""
    tools = Tools(monkeypatch, signer=signer)
    with pytest.raises(SystemExit):
        flash_it(release / NAME)
    assert tools.names() == ["cosign"]
    assert "does not verify" in capsys.readouterr().err


def test_a_signature_from_a_tag_run_is_flashed(release, monkeypatch):
    """The control: the same stand-in passes the identity a tag-built release
    carries, so the case above is refused for its ref, not for the match."""
    tools = Tools(monkeypatch, signer=f"{SIGNER}@refs/tags/v9.9.9")
    flash_it(release / NAME)
    assert [call[1] for call in tools.wrote()] == ["load", "reboot"]


def test_a_signature_from_another_repository_writes_nothing(release, monkeypatch, capsys):
    """The identity names `release-build.yml`, a reusable workflow any repository can
    call: a run in `someone/RS-Key` that calls it signs as exactly that identity. The
    certificate still records the repository that ran it, and rsk pins that."""
    tools = Tools(monkeypatch, signer=f"{SIGNER}@refs/tags/v9.9.9", repository="someone/RS-Key")
    with pytest.raises(SystemExit):
        flash_it(release / NAME)
    assert tools.names() == ["cosign"]
    assert "does not verify" in capsys.readouterr().err


def test_an_image_whose_sha_differs_writes_nothing(release, monkeypatch, capsys):
    (release / NAME).write_bytes(IMAGE + b"one more byte")
    tools = Tools(monkeypatch)
    with pytest.raises(SystemExit):
        flash_it(release / NAME)
    assert tools.names() == ["cosign"]
    assert "is not the" in capsys.readouterr().err


def test_an_image_the_sums_do_not_list_writes_nothing(release, monkeypatch, capsys):
    (release / NAME).rename(release / "firmware.uf2")
    tools = Tools(monkeypatch)
    with pytest.raises(SystemExit):
        flash_it(release / "firmware.uf2")
    assert tools.names() == ["cosign"]
    assert "lists no firmware.uf2" in capsys.readouterr().err


def test_a_name_listed_twice_with_two_digests_writes_nothing(release, monkeypatch, capsys):
    with open(release / flash.SUMS, "a") as f:
        f.write(f"{'1' * 64} *{NAME}\n")
    tools = Tools(monkeypatch)
    with pytest.raises(SystemExit):
        flash_it(release / NAME)
    assert tools.wrote() == []
    assert "twice" in capsys.readouterr().err


@pytest.mark.parametrize("gone", [flash.SUMS, flash.BUNDLE])
def test_a_missing_sums_or_bundle_refuses_before_any_tool(release, monkeypatch, capsys, gone):
    (release / gone).unlink()
    tools = Tools(monkeypatch)
    with pytest.raises(SystemExit):
        flash_it(release / NAME)
    assert tools.ran == []
    err = capsys.readouterr().err
    assert f"{gone} not found" in err and "--local-build" in err


def test_a_missing_image_refuses(release, monkeypatch, capsys):
    tools = Tools(monkeypatch)
    with pytest.raises(SystemExit):
        flash_it(release / "rs-key-v9.9.9-16mb.uf2")
    assert tools.ran == []
    assert "no such image" in capsys.readouterr().err


def test_no_cosign_refuses_and_says_how_to_get_it(release, monkeypatch, capsys):
    tools = Tools(monkeypatch, have=("gh", "picotool"))
    with pytest.raises(SystemExit):
        flash_it(release / NAME)
    assert tools.ran == []
    err = capsys.readouterr().err
    assert "cosign not found" in err and flash.COSIGN_HELP in err


def test_no_gh_skips_the_provenance_and_says_so(release, monkeypatch, capsys):
    tools = Tools(monkeypatch, have=("cosign", "picotool"))
    flash_it(release / NAME)
    assert tools.names() == ["cosign", "bootsel", "picotool", "picotool"]
    assert "provenance was NOT checked" in capsys.readouterr().err


def test_a_failing_attestation_writes_nothing(release, monkeypatch, capsys):
    tools = Tools(monkeypatch, gh=1)
    with pytest.raises(SystemExit):
        flash_it(release / NAME)
    assert tools.names() == ["cosign", "gh"]
    assert "gh attestation verify failed" in capsys.readouterr().err


@pytest.mark.parametrize("attested", ["refs/heads/main", "refs/tags/v9.9.8"],
                         ids=["branch-run", "another-tag"])
def test_an_attestation_from_another_ref_writes_nothing(release, monkeypatch, capsys, attested):
    """`--signer-workflow` names the workflow file and takes it at any ref, so the
    run is pinned to the release's tag with `--source-ref`: provenance from a
    branch run, or from another release's run, is refused."""
    tools = Tools(monkeypatch, attested=attested)
    with pytest.raises(SystemExit):
        flash_it(release / NAME)
    assert tools.names() == ["cosign", "gh"]
    assert "gh attestation verify failed" in capsys.readouterr().err


def test_a_gh_too_old_for_the_pin_is_told_to_upgrade(release, monkeypatch, capsys):
    """A gh from before `--source-ref` fails on the flag, and "gh attestation verify
    failed" reads as a release that failed its check. It is told what is missing
    instead, and nothing is written."""
    tools = Tools(monkeypatch, gh_says="unknown flag: --source-ref\n\nUsage:  gh attestation verify\n")
    with pytest.raises(SystemExit):
        flash_it(release / NAME)
    assert tools.names() == ["cosign", "gh"]
    err = capsys.readouterr().err
    assert "upgrade the GitHub CLI" in err and "refs/tags/v9.9.9" in err
    assert "verify failed" not in err


def test_an_attestation_from_the_release_tag_is_flashed(release, monkeypatch, capsys):
    """The control: the same stand-in passes a run at the tag SHA256SUMS names."""
    tools = Tools(monkeypatch, attested="refs/tags/v9.9.9")
    flash_it(release / NAME)
    assert [call[1] for call in tools.wrote()] == ["load", "reboot"]
    assert "at refs/tags/v9.9.9 (attestation)" in capsys.readouterr().out


def test_sums_that_name_no_tag_write_nothing(release, monkeypatch, capsys):
    """The tag is the SBOM's, so SHA256SUMS without one names no ref to pin the
    provenance to; gh is not run on a guess."""
    (release / flash.SUMS).write_text(f"{hashlib.sha256(IMAGE).hexdigest()}  ./{NAME}\n")
    tools = Tools(monkeypatch)
    with pytest.raises(SystemExit):
        flash_it(release / NAME)
    assert tools.names() == ["cosign"]
    assert "names no release tag" in capsys.readouterr().err


def test_sums_that_name_two_tags_write_nothing(release, monkeypatch, capsys):
    with open(release / flash.SUMS, "a") as f:
        f.write(f"{'1' * 64}  ./rs-key-v9.9.8-sbom.cdx.json\n")
    tools = Tools(monkeypatch)
    with pytest.raises(SystemExit):
        flash_it(release / NAME)
    assert tools.names() == ["cosign"]
    assert "more than one release tag (v9.9.8, v9.9.9)" in capsys.readouterr().err


@pytest.mark.parametrize("tag", ["v1.0.0-rc1", "v1.2.3-sbom"])
def test_the_run_is_pinned_to_the_whole_tag(tmp_path, monkeypatch, tag):
    """Why the tag is read off the SBOM's name: a pre-release tag carries a `-`, so
    `rs-key-<tag>-<flavor>.uf2` cannot say where it ends, and a tag may even carry
    `-sbom`. Every other case here runs at `v9.9.9`, which neither exercises."""
    name = f"rs-key-{tag}-default.uf2"
    (tmp_path / name).write_bytes(IMAGE)
    (tmp_path / flash.SUMS).write_text(f"{'0' * 64}  ./rs-key-{tag}-sbom.cdx.json\n"
                                       f"{hashlib.sha256(IMAGE).hexdigest()}  ./{name}\n")
    (tmp_path / flash.BUNDLE).write_text("{}")
    tools = Tools(monkeypatch, attested=f"refs/tags/{tag}")
    flash_it(tmp_path / name)
    assert tools.ran[1][-2:] == ("--source-ref", f"refs/tags/{tag}")
    assert [call[1] for call in tools.wrote()] == ["load", "reboot"]


def test_without_gh_the_tag_is_not_read(release, monkeypatch, capsys):
    """The tag pins gh's check and nothing else, so with no gh a SHA256SUMS naming
    none is not refused for it: the image flashes with the warning any image gets
    when the provenance is not checked."""
    (release / flash.SUMS).write_text(f"{hashlib.sha256(IMAGE).hexdigest()}  ./{NAME}\n")
    tools = Tools(monkeypatch, have=("cosign", "picotool"))
    flash_it(release / NAME)
    assert tools.names() == ["cosign", "bootsel", "picotool", "picotool"]
    assert "provenance was NOT checked" in capsys.readouterr().err


def test_a_local_build_needs_the_flag_and_gets_a_warning(tmp_path, monkeypatch, capsys):
    (tmp_path / "firmware.uf2").write_bytes(IMAGE)
    tools = Tools(monkeypatch)
    with pytest.raises(SystemExit):
        flash_it(tmp_path / "firmware.uf2")
    assert tools.ran == []
    capsys.readouterr()
    flash_it(tmp_path / "firmware.uf2", local_build=True)
    assert tools.names() == ["bootsel", "picotool", "picotool"]
    assert "nothing checked" in capsys.readouterr().err


def test_a_dry_run_verifies_and_writes_nothing(release, monkeypatch, capsys):
    tools = Tools(monkeypatch)
    flash_it(release / NAME, dry_run=True)
    assert tools.names() == ["cosign", "gh"]
    assert "picotool load -v" in capsys.readouterr().out


def test_a_second_board_in_bootsel_writes_nothing(release, monkeypatch):
    tools = Tools(monkeypatch)

    def refuse():
        raise SystemExit("more than one RP-series device in BOOTSEL mode")

    monkeypatch.setattr(flash, "require_bootsel", refuse)
    with pytest.raises(SystemExit):
        flash_it(release / NAME)
    assert tools.wrote() == []


def test_a_failed_reboot_is_not_reported_as_done(release, monkeypatch, capsys):
    Tools(monkeypatch, reboot=1)
    with pytest.raises(SystemExit):
        flash_it(release / NAME)
    captured = capsys.readouterr()
    assert "written, but `picotool reboot` failed" in captured.err
    assert "rebooted" not in captured.out


def test_the_checks_are_the_ones_the_page_publishes():
    """The identity, issuer, signing repository, repo, signer workflow and source ref
    are docs/supply-chain.md's verify commands, so the tool cannot check less than
    the page tells a reader to. releases.md says rsk runs its step 1, so that
    command carries the same identity and the same repository pin."""
    pin = f"{flash.REPOSITORY_PIN} {flash.REPO}"
    page = (REPO_ROOT / "docs/supply-chain.md").read_text(encoding="utf-8")
    assert f"--certificate-identity-regexp '{flash.IDENTITY_REGEXP}'" in page
    assert f"--certificate-oidc-issuer {flash.OIDC_ISSUER}" in page
    assert pin in page
    assert re.search(rf"--repo {re.escape(flash.REPO)}\s", page)
    assert f"--signer-workflow {flash.SIGNER_WORKFLOW}" in page
    assert f"--source-ref {flash.SOURCE_REF.format(tag='<tag>')}" in page
    assert f"--bundle {flash.BUNDLE}" in page
    releases = (REPO_ROOT / "docs/releases.md").read_text(encoding="utf-8")
    assert f"--certificate-identity-regexp '{flash.IDENTITY_REGEXP}'" in releases
    assert pin in releases
