# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Binding failures stop execution before a neighboring key supplies evidence."""
import pytest

from oracle_lib import binding, codec, transport
from oracle_lib.lifecycle import Action, change
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Outcome, Reply, Trace, TransferError


class Identity:
    layer = "synthetic"

    def __init__(self, serial):
        self.serial, self.controls = serial, 0

    def identity(self):
        body = codec.tlv(2, self.serial.to_bytes(4, "big"))
        return bytes([len(body)]) + body

    def transfer(self, *args):
        if isinstance(args[0], int):
            command, data, deadline, observe = args
            assert command == 0x42
            output, status = self.identity(), None
        else:
            data, deadline, observe = args
            assert data[1] in (0xA4, 0x1D)
            output, status = (self.identity() if data[1] == 0x1D else b"") + b"\x90\x00", 0x9000
        observe("tx", data)
        observe("rx", output)
        return Reply(output, status=status)

    def control(self, action, deadline, observe):
        self.controls += 1
        return Reply(b"")


@pytest.mark.parametrize("changed", [False, True])
def test_reconnect_rechecks_original_protocol_serial(tmp_path, changed):
    trace = Trace(tmp_path / "binding", {})
    hid, card = Identity(17), Identity(17)
    session = Session(trace, hid=hid, card=card, profile="rsk")
    binding.confirm(session)
    assert session.values["same_instance_confirmed"]
    if changed:
        hid.serial = card.serial = 18
    with session.case("reconnect"):
        change(session, Action.RECONNECT)
        session.check("newly bound pair usable", session.values.get("same_instance_confirmed"))
    trace.finish()
    row = trace.cases[-1]
    if changed:
        assert row["verdict"] == "fail" and "retain original protocol identity" in row["reason"]
        assert session.broken and "same_instance_confirmed" not in session.values
    else:
        assert row["verdict"] == "pass" and not session.broken
    assert card.controls == 1


def test_initial_mixed_interfaces_abort_capture(tmp_path):
    trace = Trace(tmp_path / "mixed", {})
    session = Session(trace, hid=Identity(17), card=Identity(18), profile="rsk")
    with pytest.raises(ValueError, match="capture aborted"):
        binding.confirm(session)
    trace.finish()
    assert session.broken and trace.cases[-1]["verdict"] == "fail"


@pytest.mark.parametrize("count", [0, 1, 2])
def test_replug_uses_unique_serial_and_interface_without_fallback(monkeypatch, count):
    expected = dict(serial_number="17", vendor_id=1, product_id=2, interface_number=3, profile="rsk", id="old")
    correct = {**expected, "id": "new"}
    others = [{**correct, "serial_number": "18"}, {**correct, "interface_number": 4}]
    monkeypatch.setattr(transport, "inventory", lambda: {"hid": [*others, *[correct.copy() for _ in range(count)]]})
    if count == 1:
        assert binding.rebind(expected, "hid")["id"] == "new"
    else:
        with pytest.raises(TransferError, match="absent or ambiguous") as caught:
            binding.rebind(expected, "hid")
        assert caught.value.outcome == Outcome.HOST_REJECTED


def test_missing_secondary_rebind_backend_blocks_before_power_action(tmp_path):
    trace = Trace(tmp_path / "preflight", {})
    card = Identity(17)
    session = Session(trace, card=card, options=Options(exercise=True, operator=True, allow_effects=("reboot",)))
    session.keyboard = object()
    with session.case("power", effects=("reboot",)):
        change(session, Action.POWER_CYCLE)
    trace.finish()
    assert card.controls == 0 and trace.cases[0]["applicability"] == "blocked_by_precondition"


def test_USB_reconnect_reopens_HID_and_allocates_before_identity_check(tmp_path):
    trace = Trace(tmp_path / "USB-binding", {})
    hid, card = Identity(17), Identity(17)
    session = Session(trace, hid=hid, card=card, profile="rsk")
    binding.confirm(session)
    calls = []
    hid.reopen = lambda operator: calls.append("reopen") or {"serial_number": "17"}
    hid.initialize = lambda trace, timeout: calls.append("INIT")
    with session.case("USB-reconnect"):
        change(session, Action.USB_RECONNECT)
        session.check("pair remains bound", session.values.get("same_instance_confirmed"))
    trace.finish()
    assert calls == ["reopen", "INIT"] and trace.cases[-1]["verdict"] == "pass"


@pytest.mark.parametrize("phase", ["probe", "cleanup", "verify"])
def test_SELECT_preserves_the_callers_explicit_phase(tmp_path, phase):
    trace = Trace(tmp_path / "phase", {})
    session = Session(trace, card=Identity(17))
    with session.case("SELECT-phase"):
        trace.phase = phase
        session.select("piv")
        session.check("caller phase retained", trace.phase, phase)
    trace.finish()
    assert trace.exchanges[0]["phase"] == ("setup" if phase == "probe" else phase)
