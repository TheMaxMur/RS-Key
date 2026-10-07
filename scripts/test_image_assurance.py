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
