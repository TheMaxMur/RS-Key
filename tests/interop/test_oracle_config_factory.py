# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Factory configuration rejection preserves independently held credential keys."""
import pytest

import oracle
from oracle_lib import binding, config_factory
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Trace
from test_oracle_config_matrix import Peer as PolicyPeer


class Peer(PolicyPeer):
    def configuration(self, fields):
        if self.defect == "unset-PIN-config-bypass" and self.pin_value is None:
            self.always = True
            return 0
        return super().configuration(fields)


@pytest.mark.parametrize("defect", [None, "unset-PIN-config-bypass"])
def test_factory_unset_PIN_never_authorizes_configuration_by_absence(tmp_path, monkeypatch, defect):
    peer = Peer(defect)
    trace = Trace(tmp_path / "CONFIG-factory", {})
    session = Session(trace, hid=peer, card=peer, profile="rsk", options=Options(exercise=True, touch=True, pin="fixture-PIN",
        allow_effects=("applet_reset", "pin_change", "config_change", "reboot")))
    monkeypatch.setattr(binding, "check_pair", lambda session: None)
    monkeypatch.setattr(config_factory, "snapshot", lambda *args: None)
    monkeypatch.setattr(config_factory, "preserved", lambda *args: None)
    oracle.execute(session, ["config-factory"])
    trace.finish()
    failures = [row["reason"] for row in trace.cases if row["verdict"] == "fail"]
    if defect:
        assert any("protocol/authorization ordering" in reason for reason in failures), failures
        assert session.broken
    else:
        assert trace.cases and all(row["verdict"] == "pass" for row in trace.cases), failures
        assert peer.pin_value == "fixture-PIN" and not peer.always
