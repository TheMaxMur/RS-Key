# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Trusted setup runs once before samples and cannot run on a wallet profile."""
import pytest

import oracle
from oracle_lib.runner import Session
from oracle_lib.trace import Trace


def test_extension_configures_before_each_sample_uses_the_same_driver_then_releases_first(tmp_path, monkeypatch):
    calls = []
    class Driver:
        def close(self):
            calls.append("release stimulus")
    class Interface:
        def close(self):
            calls.append("close interface")
    def configure(session):
        calls.append("configure")
        session.button_stimulus = Driver()
    def run(session):
        calls.append("sample " + str(session.trace.sample))
    def load(path):
        calls.append("load")
        return {"configure": configure, "run": run}
    monkeypatch.setattr(oracle.runpy, "run_path", load)
    script = tmp_path / "driver.py"
    script.write_text("# offline trusted adapter fixture\n")
    trace = Trace(tmp_path / "extension", {})
    session = Session(trace, hid=Interface(), profile="rsk")
    extension = oracle.load_extension(session, script)
    for sample in range(3):
        trace.sample = sample
        extension(session)
    session.close()
    trace.finish()
    assert calls == ["load", "configure", "sample 0", "sample 1", "sample 2", "release stimulus", "close interface"]


def test_wallet_rejects_extension_before_code_loading_even_if_called_directly(tmp_path, monkeypatch):
    monkeypatch.setattr(oracle.runpy, "run_path", lambda path: pytest.fail("wallet extension must never be loaded"))
    trace = Trace(tmp_path / "wallet-extension", {})
    with pytest.raises(ValueError, match="wallet profile excludes"):
        oracle.load_extension(Session(trace, profile="trezor"), tmp_path / "never-loaded.py")
    trace.finish()


@pytest.mark.parametrize("module", [{}, {"run": 0}, {"run": lambda session: None, "configure": 0}])
def test_extension_contract_errors_are_explicit(tmp_path, monkeypatch, module):
    monkeypatch.setattr(oracle.runpy, "run_path", lambda path: module)
    trace = Trace(tmp_path / "extension-error", {})
    with pytest.raises(ValueError, match="must"):
        oracle.load_extension(Session(trace, profile="rsk"), tmp_path / "not-read-after-error.py")
    trace.finish()
