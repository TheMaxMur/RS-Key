# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Upstream wire bytes must reach their intended command and applet harness."""
import json
import hashlib
import subprocess
import tarfile

import pytest

import external_corpus as corpus
import gate_lines


def test_assertion_sequences_retain_independently_encoded_wire_bytes():
    seeds = {(target, name): data for target, name, data in corpus.records()
             if name.startswith("rs-key-assertion-capacity-")}
    assert len(seeds) == 7
    witness = seeds["fido_session", "rs-key-assertion-capacity-1"]
    assert hashlib.sha256(witness).hexdigest() == (
        "1034d8225314a0a6b4c5e8ee45c9c78e1288b932751b5e7bf0f9f1c65b57527b")
    assert witness[:3] == bytes.fromhex("140083")
    assert len({data for data in seeds.values()}) == 7


def test_backup_sequences_cover_churn_load_and_recovery_cuts():
    seeds = {(target, name): data for target, name, data in corpus.records()
             if name.startswith("rs-key-backup-")}
    assert {target for target, _ in seeds} == {"power_cut"}
    assert {data[1] for data in seeds.values()} == {0, 24, 31, 45, 63}
    assert {int.from_bytes(data[2:4], "big") for data in seeds.values()} == {
        0, 64, 116, 256, 700, 2047, 4211, 4212, 4716, 65535}
    assert {int.from_bytes(data[4:6], "big") for data in seeds.values()} == {0, 17, 700}
    assert seeds["power_cut", "rs-key-backup-0-64-17"] == bytes.fromhex("e0000040001133")
    assert seeds["power_cut", "rs-key-backup-24-256-17"] == bytes.fromhex("e0180100001133")


def test_oath_mark_faults_retain_both_fault_modes_and_flow_selection():
    seeds = [(target, data) for target, name, data in corpus.records()
             if name.startswith("rs-key-oath-mark-read-")]
    assert {target for target, _ in seeds} == {"oath_apdu"}
    assert {data for _, data in seeds} == {
        bytes([selector | mode, position, 1])
        for selector in range(24) for position in range(3) for mode in (0, 0x40)}
    assert bytes([8, 0, 1]) in {data for _, data in seeds}
    assert bytes([8 | 0x40, 0, 1]) in {data for _, data in seeds}
    assert all(data[-1] & 1 for _, data in seeds), "the semantic flow must execute"


def test_journal_sequences_keep_operations_windows_and_both_cut_positions_independent():
    seeds = {(target, name): data for target, name, data in corpus.records()
             if name.startswith("rs-key-journal-")}
    assert {target for target, _ in seeds} == {"power_cut"}
    assert {data for data in seeds.values()} == {
        bytes([mode, settings]) + cut.to_bytes(2, "big") + recovery.to_bytes(2, "big")
        for mode in (0xD0, 0xD1) for settings in (0, 1, 48, 49)
        for cut in (0, 17, 64, 65535) for recovery in (0, 17, 65535)}
    assert seeds["power_cut", "rs-key-journal-209-0-17-17"] == bytes.fromhex("d10000110011")


def test_openpgp_histories_keep_command_state_churn_and_both_cuts_independent():
    seeds = {(target, name): data for target, name, data in corpus.records()
             if name.startswith("rs-key-openpgp-")}
    assert {target for target, _ in seeds} == {"power_cut"}
    assert {data for data in seeds.values()} == {
        bytes([mode, command]) + cut.to_bytes(2, "big")
        + recovery.to_bytes(2, "big") + bytes([churn])
        for mode in (0xC0, 0xC1, 0xC2, 0xC3) for command in range(6)
        for churn in (0, 17) for cut in (0, 17, 256, 65535)
        for recovery in (0, 17, 65535)}
    assert seeds["power_cut", "rs-key-openpgp-194-3-17-256-17"] == bytes.fromhex("c2030100001111")


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
