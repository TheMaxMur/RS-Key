# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Discovery failures survive in captures without touching an actual device."""
import pytest

import oracle
from oracle_lib.trace import recover


@pytest.mark.parametrize("failure", ["inventory", "absent", "ambiguous", "open"])
def test_capture_records_discovery_and_open_failures_as_timed_host_cases(tmp_path, monkeypatch, failure):
    descriptor = {"id": "selected", "profile": "rsk", "path_hex": "01", "serial_number": "17"}
    calls = []
    def inventory():
        calls.append("inventory")
        if failure == "inventory":
            raise PermissionError("synthetic discovery denied")
        return {"hid": [] if failure == "absent" else [descriptor] * (2 if failure == "ambiguous" else 1), "readers": []}
    def open_hid(*args, **kwargs):
        calls.append("open")
        raise PermissionError("synthetic interface claimed or disappeared")
    monkeypatch.setattr(oracle, "inventory", inventory)
    monkeypatch.setattr(oracle, "Hid", open_hid)
    target = tmp_path / "failed"
    assert oracle.main(["capture", "--out", str(target), "--hid", "selected", "--suite", "fido"]) == 2
    run = recover(target)
    failures = [row for row in run["cases"] if row["verdict"] == "fail"]
    assert failures and run["execution_outcome"] == "runner_error"
    assert all(row["observation_layer"] == "host_api" for row in run["exchanges"])
    assert all(row["timing"]["api_duration_ns"] >= 0 for row in run["exchanges"])
    assert calls == ["inventory", "open"] if failure == "open" else calls == ["inventory"]


@pytest.mark.parametrize("explicit", [False, True])
def test_wallet_profile_cannot_load_a_trusted_extension_or_open_an_interface(tmp_path, monkeypatch, explicit):
    script = tmp_path / "trusted.py"
    script.write_text("raise AssertionError('extension code must not be loaded on a wallet profile')\n")
    calls = []
    descriptor = {"id": "selected", "profile": "trezor", "path_hex": "01", "serial_number": "wallet"}
    def inventory():
        calls.append("inventory")
        return {"hid": [descriptor], "readers": []}
    def forbidden(*args, **kwargs):
        pytest.fail("no wallet interface or trusted extension may be opened")
    monkeypatch.setattr(oracle, "inventory", inventory)
    monkeypatch.setattr(oracle, "Hid", forbidden)
    monkeypatch.setattr(oracle.runpy, "run_path", forbidden)
    target = tmp_path / "wallet-script"
    args = ["capture", "--out", str(target), "--hid", "selected", "--script", str(script)]
    assert oracle.main(args + (["--profile", "trezor"] if explicit else [])) == 2
    assert calls == ([] if explicit else ["inventory"])
    run = recover(target)
    assert run["execution_outcome"] == "runner_error"
    assert not any(row["command"].startswith("open.") for row in run["exchanges"])
