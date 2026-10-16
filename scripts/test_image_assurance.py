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
