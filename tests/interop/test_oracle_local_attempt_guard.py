# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""A local MC/GA PIN mismatch stops the same reference on both CTAP routes."""
import pytest

from oracle_lib import codec
from oracle_lib.runner import CtapRoute, Options, Session
from oracle_lib.trace import Reply, Trace


class Peer:
    layer = "offline_ctap"

    def __init__(self):
        self.requests = []

    def transfer(self, *args):
        if len(args) == 4:
            _, data, _, observe = args
            output, status = b"\x3f", 0x3f
        else:
            wire, _, observe = args
            data, output, status = wire[5:5 + wire[4]], b"\x3f\x90\x00", 0x9000
        self.requests.append(data)
        observe("tx", data)
        observe("rx", output)
        return Reply(output, "applet_error" if status == 0x3f else "success", status)


@pytest.mark.parametrize("route", list(CtapRoute))
@pytest.mark.parametrize("command", [1, 2])
@pytest.mark.parametrize("always", [False, True])
def test_unplanned_local_failure_blocks_a_second_PIN_consuming_request(tmp_path, route, command, always):
    peer = Peer()
    trace = Trace(tmp_path / "local-attempt", {})
    session = Session(trace, hid=peer, card=peer, profile="rsk")
    session.values["fido.info"] = {4: {"alwaysUv": always}}
    request = {7 if command == 1 else 5: {} if always else {"uv": True}}
    with session.route(route):
        for ordinal in range(2):
            with session.case("local-PIN-unplanned." + str(ordinal)):
                assert session.ctap(command, request).status == 0x3f
    trace.finish()
    assert len(peer.requests) == 1
    assert trace.cases[1]["applicability"] == "blocked_by_precondition"
    assert "PIN reference already refused" in trace.cases[1]["reason"]


@pytest.mark.parametrize("route", list(CtapRoute))
def test_declared_local_budget_and_host_auth_have_distinct_paths(tmp_path, route):
    peer = Peer()
    trace = Trace(tmp_path / "local-budget", {})
    session = Session(trace, hid=peer, card=peer, profile="rsk", options=Options(exercise=True, allow_effects=("pin_attempts",)))
    with session.route(route):
        with session.case("local-PIN-bounded", effects=("pin_attempts",)):
            with session.attempts("fido.pin", 2):
                session.ctap(2, {5: {"uv": True}})
                session.ctap(1, {7: {"uv": True}})
                session.ctap(2, {5: {"uv": True}})
        assert len(peer.requests) == 2
        with session.case("host-auth-is-not-another-local-PIN"):
            session.ctap(2, {5: {"uv": True}, 6: b"host-MAC"})
        with session.case("parser-refusal-does-not-prompt-for-PIN"):
            session.ctap(2, raw=codec.encode({5: {"uv": "true"}}))
    trace.finish()
    assert len(peer.requests) == 4
    assert "budget exhausted" in trace.cases[0]["reason"]


@pytest.mark.parametrize("route", list(CtapRoute))
def test_successful_policy_change_cannot_leave_an_old_non_UV_attempt_policy(tmp_path, route):
    class PolicyPeer(Peer):
        def transfer(self, *args):
            if len(args) == 4:
                _, data, _, observe = args
                card = False
            else:
                wire, _, observe = args
                data, card = wire[5:5 + wire[4]], True
            if data[0] == 13:
                self.requests.append(data)
                output = b"\x00\x90\x00" if card else b"\x00"
                observe("tx", data)
                observe("rx", output)
                return Reply(output, status=0x9000 if card else 0)
            return super().transfer(*args)
    peer = PolicyPeer()
    trace = Trace(tmp_path / "local-policy-change", {})
    session = Session(trace, hid=peer, card=peer, profile="rsk")
    session.values["fido.info"] = {4: {"alwaysUv": False}}
    with session.route(route):
        with session.case("change-policy"):
            session.ctap(13, {1: 2})
        for ordinal in range(2):
            with session.case("new-policy-local-PIN." + str(ordinal)):
                session.ctap(2, {5: {"uv": False}})
    trace.finish()
    assert len([wire for wire in peer.requests if wire[0] == 2]) == 1
    assert trace.cases[-1]["applicability"] == "blocked_by_precondition"


def test_negative_recovery_compares_pre_request_versions_when_getInfo_refreshes_cache(tmp_path, monkeypatch):
    from oracle_lib import negative
    class VersionPeer:
        layer = "offline_ctap"
        def transfer(self, command, wire, deadline, observe):
            output = b"\x14" if wire[0] != 4 else b"\x00" + codec.encode({1: ["FIDO_2_3"]})
            observe("tx", wire)
            observe("rx", output)
            return Reply(output, "applet_error" if output[0] else "success", output[0])
    trace = Trace(tmp_path / "negative-version-control", {})
    session = Session(trace, hid=VersionPeer(), profile="rsk", options=Options(exercise=True))
    session.values["fido.info"] = {1: ["FIDO_2_1"]}
    monkeypatch.setattr(negative, "ctap_inputs", lambda: [negative.CtapInput("one-parser-fault", 1, b"\xa0", ("F11",))])
    negative.fido(session)
    trace.finish()
    assert trace.cases[0]["verdict"] == "fail" and "recovery versions" in trace.cases[0]["reason"]


@pytest.mark.parametrize("route", list(CtapRoute))
@pytest.mark.parametrize("sub", [2, 3, 4, 7, 8, 9, 10, 14, 12])
@pytest.mark.parametrize("uv", [False, True, None])
def test_device_PIN_gated_vendor_commands_stop_before_repeated_local_entry(tmp_path, route, sub, uv):
    peer = Peer()
    trace = Trace(tmp_path / "vendor-local-PIN", {})
    session = Session(trace, hid=peer, card=peer, profile="rsk", options=Options(features=("display", "strict-config")))
    session.values["fido.info"] = {4: {"clientPin": False, **({"uv": uv} if uv is not None else {})}}
    with session.route(route):
        for ordinal in range(2):
            with session.case("vendor.local-PIN." + str(ordinal)):
                session.ctap(0x41, {1: sub, 2: {1: 1}})
    trace.finish()
    assert len(peer.requests) == 1
    assert trace.cases[1]["applicability"] == "blocked_by_precondition"


@pytest.mark.parametrize("route", list(CtapRoute))
def test_ungated_vendor_status_MSE_and_config_are_not_local_PIN_comparisons(tmp_path, route):
    peer = Peer()
    trace = Trace(tmp_path / "vendor-public-control", {})
    session = Session(trace, hid=peer, card=peer, profile="rsk")
    session.values["fido.info"] = {4: {"clientPin": False, "uv": True}}
    session.failed_auth.add("fido.pin")
    with session.route(route):
        for sub, target in ((1, 0), (5, 0), (11, 0), (13, 1), (15, 0), (14, 2), (12, 2)):
            with session.case(f"vendor.public.sub-{sub}.target-{target}"):
                session.check("public request is transmitted despite a stopped local PIN", session.ctap(0x41, {1: sub, 2: {1: target}}).status, 0x3f)
    trace.finish()
    assert len(peer.requests) == 7 and all(row["verdict"] == "pass" for row in trace.cases)
