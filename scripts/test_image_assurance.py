# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Refused image commands cannot leak an accumulated response body."""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def laboratory(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "tests"))
    monkeypatch.syspath_prepend(str(ROOT / "tools/emu"))
    spec = importlib.util.spec_from_file_location("image_assurance", ROOT / "tools/emu/image_assurance.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    device = module.Device.__new__(module.Device)
    device.hid = object()
    device.cid = bytes(4)
    device.image = None
    return module, device


@pytest.mark.parametrize("chained", [False, True])
def test_apdu_refusal_does_not_return_direct_or_chained_plaintext(laboratory, chained):
    _, device = laboratory
    replies = iter([([0x5A], 0x61, 1), ([0xA5], 0x69, 0x82)] if chained else
                   [([0x5A], 0x69, 0x82)])

    class Card:
        def transmit(self, command):
            return next(replies)

    device.card = Card()
    with pytest.raises(AssertionError, match="APDU refusal 6982 returned"):
        device.apdu(bytes.fromhex("0087119d"), 0x6982)


def test_ctap_refusal_does_not_return_a_decodable_partial_map(laboratory, monkeypatch):
    module, device = laboratory
    monkeypatch.setattr(module, "send_cbor", lambda *args: b"\x33\xa0")
    with pytest.raises(AssertionError, match="CTAP refusal returned a partial response"):
        device.ctap(2, expected=0x33)


def test_empty_refusals_and_successful_payloads_still_pass(laboratory, monkeypatch):
    module, device = laboratory

    class Card:
        def transmit(self, command):
            return [], 0x69, 0x82

    device.card = Card()
    assert device.apdu(bytes.fromhex("0087119d"), 0x6982) == b""
    monkeypatch.setattr(module, "send_cbor", lambda *args: b"\x33")
    assert device.ctap(2, expected=0x33) is None
    monkeypatch.setattr(module, "send_cbor", lambda *args: b"\x00\xa0")
    assert device.ctap(2) == {}


@pytest.mark.parametrize("state", [b"\x02\x00", b"\x02\x01"])
def test_image_boot_checks_ready_without_issuing_a_setup_command(laboratory, monkeypatch, state):
    _, device = laboratory
    commands = []

    class Card:
        def transmit(self, command):
            commands.append(bytes(command))
            return list(state), 0x90, 0

    device.card = Card()
    monkeypatch.setattr(device, "select", lambda aid: None)
    if state[1]:
        device.check_storage_ready()
    else:
        with pytest.raises(AssertionError, match="automatic storage boot failed"):
            device.check_storage_ready()
    assert commands == [bytes.fromhex("801e080000")]


@pytest.mark.parametrize("nonsecure", [None, 150, 99])
def test_measured_operations_refuse_an_ns_stack_underflow(laboratory, monkeypatch, nonsecure):
    _, device = laboratory
    measurement = "core0_low=100 core0_min=150 core1_low=200 core1_min=250"
    if nonsecure is not None:
        measurement += f" ns0_low=100 ns0_min={nonsecure}"
    calls = []

    def inspect(command):
        calls.append(command)
        return measurement if command == "end" else "cycle=0"

    monkeypatch.setattr(device, "inspect", inspect)
    report = {}
    if nonsecure == 99:
        with pytest.raises(AssertionError, match="sample"):
            device.measured("sample", lambda: 42, report)
    else:
        assert device.measured("sample", lambda: 42, report) == 42
    assert calls == ["begin", "end"]
    if nonsecure is not None:
        assert report["sample"]["ns0_min"] == nonsecure


@pytest.mark.parametrize("wall,image_ns,changes,error", [
    (121, 11_000_000_000, {}, None),
    (1200, 0, {}, "host watchdog"),
    (1, 120_000_000_000, {}, "image deadline"),
    (1, 1, {"dead": "true"}, "image faulted"),
    (1, 1, {"power_ups": "2"}, "image rebooted"),
    (1, -1, {}, "clock moved backwards"),
])
def test_image_ctap_has_independent_image_and_host_bounds(laboratory, monkeypatch, wall, image_ns, changes, error):
    module, device = laboratory
    clock = {"wall": 0}
    state = {"dead": "false", "power_ups": "1", "emulated_ns": "0"}
    monkeypatch.setattr(module.time, "monotonic", lambda: clock["wall"])
    monkeypatch.setattr(device, "inspect", lambda command: " ".join(f"{k}={v}" for k, v in state.items()))
    deadline = module.ImageDeadline(device)
    clock["wall"] = wall
    state.update(changes, emulated_ns=str(image_ns))
    if error:
        with pytest.raises(AssertionError, match=error):
            deadline.check()
    else:
        deadline.check()


def test_image_clock_cannot_go_backwards_after_initial_progress(laboratory, monkeypatch):
    module, device = laboratory
    states = iter([0, 10, 9])
    monkeypatch.setattr(device, "inspect", lambda command:
                        f"dead=false power_ups=1 emulated_ns={next(states)}")
    deadline = module.ImageDeadline(device)
    deadline.check()
    with pytest.raises(AssertionError, match="clock moved backwards"):
        deadline.check()


def test_inspection_cannot_outlive_the_host_watchdog(laboratory, monkeypatch):
    module, device = laboratory
    clock = {"wall": 0}
    monkeypatch.setattr(module.time, "monotonic", lambda: clock["wall"])
    monkeypatch.setattr(device, "inspect", lambda command: "dead=false power_ups=1 emulated_ns=0")
    deadline = module.ImageDeadline(device)

    def inspect(command):
        clock["wall"] = module.CTAP_HOST_TIMEOUT_S
        return "dead=false power_ups=1 emulated_ns=0"

    monkeypatch.setattr(device, "inspect", inspect)
    with pytest.raises(AssertionError, match="host watchdog"):
        deadline.check()


@pytest.mark.parametrize("custom_deadline", [False, True])
def test_native_keepalive_wall_bound_is_replaced_only_when_requested(laboratory, monkeypatch, custom_deadline):
    module, device = laboratory
    times = iter([0, 121])
    monkeypatch.setattr(module.time, "monotonic", lambda: next(times))
    frames = [device.cid + b"\xbb\x00\x01\x01", device.cid + b"\x90\x00\x02\x00\xa0"]

    class Hid:
        def write(self, payload):
            pass

        def read(self, length, timeout_ms):
            return list(frames.pop(0).ljust(64, b"\x00"))

    device.hid = Hid()
    if custom_deadline:
        assert module.send_cbor(device.hid, device.cid, b"\x04", check_deadline=lambda: None) == b"\x00\xa0"
    else:
        with pytest.raises(IOError, match="keepalives past the deadline"):
            module.send_cbor(device.hid, device.cid, b"\x04")


@pytest.mark.parametrize("continuation", [False, True])
def test_image_deadline_checks_the_final_hid_read(laboratory, monkeypatch, continuation):
    module, device = laboratory
    device.image = True
    clock = {"ns": 0}
    answer = b"\x00" + (b"\xa0" * 69 if continuation else b"\xa0")
    frames = [device.cid + bytes([0x90]) + len(answer).to_bytes(2, "big") + answer[:57]]
    if continuation:
        frames.append(device.cid + b"\x00" + answer[57:])

    class Hid:
        def write(self, payload):
            pass

        def read(self, length, timeout_ms):
            frame = frames.pop(0)
            if not frames:
                clock["ns"] = module.CTAP_IMAGE_TIMEOUT_NS
            return list(frame.ljust(64, b"\x00"))

    device.hid = Hid()
    monkeypatch.setattr(device, "inspect", lambda command:
                        "elapsed_ns=1 keepalives=0 max_gap_ns=1" if command == "transport-end" else
                        f"dead=false power_ups=1 emulated_ns={clock['ns']}")
    with pytest.raises(AssertionError, match="CTAP image deadline expired"):
        device.ctap(4)


def test_a_falsy_deadline_callable_still_runs(laboratory):
    module, device = laboratory

    class Deadline:
        def __bool__(self):
            return False

        def __call__(self):
            raise AssertionError("custom clock expired")

    class Hid:
        def write(self, payload):
            pass

        def read(self, length, timeout_ms):
            raise AssertionError("expired operation reached a HID read")

    with pytest.raises(AssertionError, match="custom clock expired"):
        module.send_cbor(Hid(), device.cid, b"\x04", check_deadline=Deadline())


def test_image_ctap_keeps_all_transport_measurements_in_the_operation(laboratory, monkeypatch):
    module, device = laboratory
    device.image = True
    commands = []

    def inspect(command):
        commands.append(command)
        if command == "status":
            return "dead=false power_ups=1 emulated_ns=0"
        if command == "transport-end":
            return "elapsed_ns=100 keepalives=0 max_gap_ns=100"
        return "core0_low=100 core0_min=150 core1_low=200 core1_min=250"

    def send(*args, check_deadline):
        check_deadline()
        return b"\x00\xa0"

    monkeypatch.setattr(device, "inspect", inspect)
    monkeypatch.setattr(module, "send_cbor", send)
    report = {}
    device.measured("sample", lambda: (device.ctap(4), device.ctap(6)), report)
    assert [row["command"] for row in report["sample_ctap"]] == [4, 6]
    assert all(row["max_gap_ns"] == 100 for row in report["sample_ctap"])
    assert commands.count("transport-begin") == commands.count("transport-end") == 2


@pytest.mark.parametrize("gap", [499_999_999, 500_000_000, 500_000_001])
def test_image_ctap_refuses_usb_starvation(laboratory, monkeypatch, gap):
    module, device = laboratory
    device.image = True
    monkeypatch.setattr(module, "send_cbor", lambda *args, **kwargs: b"\x00\xa0")
    monkeypatch.setattr(device, "inspect", lambda command:
                        f"elapsed_ns={gap} keepalives=0 max_gap_ns={gap}" if command == "transport-end" else
                        "dead=false power_ups=1 emulated_ns=0")
    if gap > module.USB_MAX_GAP_NS:
        with pytest.raises(AssertionError, match="starved USB"):
            device.ctap(4)
    else:
        assert device.ctap(4) == {}


def test_stack_measurement_cleanup_preserves_the_operation_failure(laboratory, monkeypatch):
    _, device = laboratory

    def inspect(command):
        if command == "end":
            raise OSError("inspection stopped")
        return ""

    def operation():
        raise AssertionError("command oracle failed")

    monkeypatch.setattr(device, "inspect", inspect)
    report = {}
    with pytest.raises(AssertionError, match="command oracle failed"):
        device.measured("sample", operation, report)
    assert report["sample_measurement_error"] == "inspection stopped"
