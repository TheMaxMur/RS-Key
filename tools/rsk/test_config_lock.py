# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""`rsk hw` and `rsk led` on a device whose configuration lock refuses their write.

Run from tools/:  python -m pytest rsk/test_config_lock.py
With the lock set, a phy or LED write without its code is refused: `6986` over
CCID (the rescue WRITE 1C/01, the vendor SET LED) and CTAP2_ERR_NOT_ALLOWED
(`0x30`) over the FIDO CONFIG_WRITE. Each of the four writes must name the lock,
keep that code, and say what clears it, and every other answer keeps its own
message. The device is a stand-in that records what it was sent.
"""
import sys
import types

# The same reason as test_otp_lock.py: nothing here touches a device.
sys.modules.setdefault("hid", types.ModuleType("hid"))

import pytest  # noqa: E402

from rsk import ccid, common, hw, led  # noqa: E402

PHY = bytes([hw.TAG_LED_GPIO, 1, 16])


class Card:
    """The rescue and vendor applets as far as `hw` and `led` reach them. `write`
    is the status word the phy WRITE or the SET LED answers."""

    def __init__(self, write):
        self.write, self.sent = write, []

    def transmit(self, apdu):
        self.sent.append(list(apdu))
        if apdu[:2] == [0x00, 0xA4]:
            return [], 0x90, 0x00
        if apdu[:3] == [0x80, 0x1E, 0x01]:
            return list(PHY), 0x90, 0x00
        if apdu[:2] == [0x00, 0x11]:
            return [0] * led.CONF_LEN, 0x90, 0x00
        if apdu[:3] == [0x80, 0x1C, 0x01] or apdu[:2] == [0x00, 0x10]:
            return [], *self.write
        return [], 0x90, 0x00  # the reboot a successful phy write ends with

    def rebooted(self):
        return any(a[:2] == [0x00, 0x1F] for a in self.sent)


def ccid_run(monkeypatch, mod, card):
    monkeypatch.setattr(ccid, "connect", lambda **_: card)
    mod.run(hw_args() if mod is hw else led_args())


def fido_run(monkeypatch, mod, write_status):
    """Drive the FIDO path: CONFIG_READ answers a record, CONFIG_WRITE `write_status`."""
    sent = []
    record = PHY if mod is hw else bytes(led.CONF_LEN)

    def vendor(dev, cid, fields):
        sent.append(fields[1])
        if fields[1] == mod.CONFIG_READ:
            return 0, {1: record}
        return write_status, None

    monkeypatch.setattr(mod, "connect_fido", lambda exclusive=False: (object(), b"cid0"))
    monkeypatch.setattr(mod, "_vendor", vendor)
    monkeypatch.setattr(mod, "device_has_pin", lambda dev, cid: False)
    args = hw_args(transport="fido") if mod is hw else led_args(transport="fido")
    mod.run(args)
    return sent


def hw_args(**kw):
    base = dict(led_pin=22, led_driver=None, led_order=None, led_num=None,
                touch_timeout=None, manufacturer=None, product=None, get=False,
                no_reboot=False, transport="ccid", pin=None)
    return types.SimpleNamespace(**{**base, **kw})


def led_args(**kw):
    base = dict(status="idle", brightness=None, color="red", effect=None, speed=None,
                steady=False, blink=False, get=False, transport="ccid", pin=None)
    return types.SimpleNamespace(**{**base, **kw})


def said(capsys):
    return capsys.readouterr().err


def assert_names_the_lock(err, record, code):
    assert f"{record} write refused ({code})" in err, err
    assert "configuration lock is set" in err and common.CLEAR_CONFIG_LOCK in err, err


def test_hw_over_ccid_names_the_lock_and_does_not_reboot(monkeypatch, capsys):
    card = Card((0x69, 0x86))
    with pytest.raises(SystemExit):
        ccid_run(monkeypatch, hw, card)
    assert_names_the_lock(said(capsys), "phy", "6986")
    assert not card.rebooted()


def test_hw_over_fido_names_the_lock(monkeypatch, capsys):
    with pytest.raises(SystemExit):
        fido_run(monkeypatch, hw, 0x30)
    assert_names_the_lock(said(capsys), "phy", "0x30")


def test_led_over_ccid_names_the_lock(monkeypatch, capsys):
    with pytest.raises(SystemExit):
        ccid_run(monkeypatch, led, Card((0x69, 0x86)))
    assert_names_the_lock(said(capsys), "LED", "6986")


def test_led_over_fido_names_the_lock(monkeypatch, capsys):
    with pytest.raises(SystemExit):
        fido_run(monkeypatch, led, 0x30)
    assert_names_the_lock(said(capsys), "LED", "0x30")


@pytest.mark.parametrize("mod", [hw, led])
def test_another_ccid_refusal_keeps_its_own_message(monkeypatch, capsys, mod):
    with pytest.raises(SystemExit) as e:
        ccid_run(monkeypatch, mod, Card((0x6F, 0x00)))
    text = f"{e.value.code}{said(capsys)}"
    assert "6F00" in text and "configuration lock" not in text


@pytest.mark.parametrize("mod", [hw, led])
def test_another_fido_refusal_keeps_its_own_message(monkeypatch, capsys, mod):
    with pytest.raises(SystemExit):
        fido_run(monkeypatch, mod, 0x27)
    err = said(capsys)
    assert "denied" in err and "configuration lock" not in err


@pytest.mark.parametrize("mod", [hw, led])
def test_an_unlocked_device_is_written_as_before(monkeypatch, capsys, mod):
    ccid_run(monkeypatch, mod, Card((0x90, 0x00)))
    assert "configuration lock" not in said(capsys)
    assert fido_run(monkeypatch, mod, 0) == [mod.CONFIG_READ, mod.CONFIG_WRITE]
