# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Upstream wire bytes must reach their intended command and applet harness."""
import json
import subprocess
import tarfile

import pytest

import external_corpus as corpus
import gate_lines


def test_opensk_generic_value_reaches_each_command():
    seeds = [(target, data) for target, name, data in corpus.records()
             if name.startswith("opensk-0-")]
    assert seeds == [("fido_cbor", bytes.fromhex(value))
                     for value in ("011903e8", "021903e8", "061903e8")]


def test_canokey_apdu_bytes_survive_framing_and_long_inputs_reach_parser():
    seeds = {(target, name): data for target, name, data in corpus.records()
             if name.startswith("canokey-")}
    witness = "canokey-applet0-piv.10.txt"
    assert seeds["apdu", witness] == bytes.fromhex("00cb3fff055c035fc10f")
    assert seeds["piv_apdu", witness] == bytes.fromhex("0a00cb3fff055c035fc10f")
    assert any(target == "apdu" and len(data) > 254
               for (target, _), data in seeds.items())
    for (target, name), data in seeds.items():
        if target in corpus.APPLETS.values():
            assert 0 < data[0] < 255
            assert data[0] == len(data) - 1
            assert data[1:] == seeds["apdu", name]


def test_corrupted_archive_is_refused_before_replay(tmp_path, monkeypatch):
    (tmp_path / "google.tar.gz").write_bytes(b"wrong corpus")
    monkeypatch.setattr(corpus, "SOURCE", tmp_path)
    with pytest.raises(ValueError, match="checksum differs: google.tar.gz"):
        next(corpus.records())


def test_google_parameters_and_raw_hid_reach_their_protocol():
    seeds = {(target, name): data for target, name, data in corpus.records()
             if name.startswith("google-")}
    with tarfile.open(corpus.SOURCE / "google.tar.gz") as archive:
        for group, command in (("Cbor_MakeCredentialParameters", 0x01),
                               ("Cbor_GetAssertionParameters", 0x02),
                               ("Cbor_ClientPinParameters", 0x06)):
            member = next(m for m in archive.getmembers() if m.name.startswith(group + "/"))
            assert seeds["fido_cbor", "google-" + member.name.replace("/", "-")] == (
                bytes([command]) + archive.extractfile(member).read())
        member = next(m for m in archive.getmembers() if m.name.startswith("CtapHidRawData/"))
        assert seeds["ctaphid", "google-" + member.name.split("/")[1]] == archive.extractfile(member).read()


def test_a_replay_failure_reaches_the_runner(tmp_path, monkeypatch, capsys):
    binary = tmp_path / "fido_cbor"
    binary.write_text("#!/bin/sh\necho 'external corpus mutation witness'\nexit 77\n")
    binary.chmod(0o755)
    manifest = tmp_path / "artifacts.json"
    manifest.write_text(json.dumps({"reason": "compiler-artifact", "target": {"name": "fido_cbor"},
                                    "executable": str(binary)}))
    monkeypatch.setattr(corpus, "ROOT", tmp_path)
    monkeypatch.setattr(corpus, "prepare", lambda _: {"fido_cbor": 1})
    with pytest.raises(subprocess.CalledProcessError) as error:
        corpus.replay(manifest)
    assert error.value.returncode == 77
    assert "external corpus mutation witness" in capsys.readouterr().out


def test_check_sh_replays_through_the_existing_fuzz_row():
    check = (corpus.ROOT / "scripts/check.sh").read_text()
    assert gate_lines.runs(check, 'scripts/external_corpus.py --replay "$manifest"')
    assert gate_lines.runs(check, 'fuzz_targets_are_alive')
