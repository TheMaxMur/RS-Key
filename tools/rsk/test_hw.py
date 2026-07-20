# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Unit tests for the pure logic in rsk.hw (no device).

Run from tools/:  python -m pytest rsk/test_hw.py
The phy read-modify-write is the brick-risk: it must preserve every existing tag
(USB identity, options) while changing only the LED fields, and serialize a record
the firmware parser accepts. Pin that here.
"""
from rsk import hw


def test_tlv_roundtrip():
    tlvs = [(hw.TAG_LED_GPIO, b"\x16"), (0x06, b"\x00\x08"), (hw.TAG_LED_ORDER, b"\x01")]
    assert hw._parse_tlv(hw._serialize_tlv(tlvs)) == tlvs


def test_parse_truncated_tail_is_dropped():
    # A final TLV whose length runs past the buffer ends the parse (no overread),
    # mirroring the firmware parser.
    assert hw._parse_tlv(bytes([0x06, 2, 0x00, 0x00, hw.TAG_LED_GPIO, 4, 1, 2])) == [
        (0x06, b"\x00\x00")
    ]


def test_upsert_replaces_in_place_preserving_others():
    # A record PicoForge might leave: VIDPID + product + zero OPTS, plus an old pin.
    tlvs = [
        (0x00, bytes([0x10, 0x50, 0x04, 0x07])),       # VIDPID
        (0x09, b"YubiKey RSK\x00"),                    # USB_PRODUCT
        (0x06, b"\x00\x00"),                           # OPTS
        (hw.TAG_LED_GPIO, b"\x10"),                    # existing pin 16
    ]
    hw._upsert(tlvs, hw.TAG_LED_GPIO, 22)
    hw._upsert(tlvs, hw.TAG_LED_DRIVER, hw.DRIVERS["ws2812"])
    hw._upsert(tlvs, hw.TAG_LED_ORDER, hw.ORDERS["grb"])
    by = dict(tlvs)
    # LED fields set / replaced...
    assert by[hw.TAG_LED_GPIO] == b"\x16"
    assert by[hw.TAG_LED_DRIVER] == bytes([3])
    assert by[hw.TAG_LED_ORDER] == bytes([1])
    # ...and the unrelated identity/options tags are untouched.
    assert by[0x00] == bytes([0x10, 0x50, 0x04, 0x07])
    assert by[0x09] == b"YubiKey RSK\x00"
    assert by[0x06] == b"\x00\x00"
    # The existing pin TLV was replaced in place, not duplicated.
    assert sum(1 for t, _ in tlvs if t == hw.TAG_LED_GPIO) == 1
    # New tags appended after the originals (order preserved).
    assert [t for t, _ in tlvs] == [0x00, 0x09, 0x06, hw.TAG_LED_GPIO,
                                    hw.TAG_LED_DRIVER, hw.TAG_LED_ORDER]


def test_upsert_appends_when_absent():
    tlvs = [(0x06, b"\x00\x00")]
    hw._upsert(tlvs, hw.TAG_LED_DRIVER, hw.DRIVERS["gpio"])
    assert tlvs == [(0x06, b"\x00\x00"), (hw.TAG_LED_DRIVER, b"\x01")]


def test_upsert_str_encodes_nul_terminated_and_preserves_others():
    # Setting the USB identity strings must not disturb existing LED tags, and the
    # value carries the trailing NUL the firmware parser expects.
    tlvs = [(hw.TAG_LED_GPIO, b"\x16"), (hw.TAG_LED_ORDER, b"\x01")]
    hw._upsert_str(tlvs, hw.TAG_USB_MANUFACTURER, "Yubico")
    hw._upsert_str(tlvs, hw.TAG_USB_PRODUCT, "YubiKey RSK OTP+FIDO+CCID")
    by = dict(tlvs)
    assert by[hw.TAG_USB_MANUFACTURER] == b"Yubico\x00"
    assert by[hw.TAG_USB_PRODUCT] == b"YubiKey RSK OTP+FIDO+CCID\x00"
    assert by[hw.TAG_LED_GPIO] == b"\x16"
    # A second set replaces in place, not duplicates.
    hw._upsert_str(tlvs, hw.TAG_USB_MANUFACTURER, "Acme")
    assert dict(tlvs)[hw.TAG_USB_MANUFACTURER] == b"Acme\x00"
    assert sum(1 for t, _ in tlvs if t == hw.TAG_USB_MANUFACTURER) == 1
    # The whole record round-trips through the firmware-shaped parser.
    assert hw._parse_tlv(hw._serialize_tlv(tlvs)) == tlvs


def test_upsert_str_rejects_oversize_and_empty():
    for bad in ["x" * 33, ""]:
        try:
            hw._upsert_str([], hw.TAG_USB_MANUFACTURER, bad)
        except SystemExit:
            continue
        raise AssertionError(f"string {bad!r} was not rejected")


def test_driver_and_order_maps_match_firmware():
    # PicoForge LedDriverType numbering, and the RS-Key order values.
    assert hw.DRIVERS == {"gpio": 1, "pimoroni": 2, "ws2812": 3}
    assert hw.ORDERS == {"rgb": 0, "grb": 1}


class _Args:
    """Minimal argparse.Namespace stand-in for _apply_args."""

    def __init__(self, **kw):
        defaults = dict(
            led_pin=None,
            led_driver=None,
            led_order=None,
            led_num=None,
            touch_timeout=None,
            manufacturer=None,
            product=None,
        )
        defaults.update(kw)
        self.__dict__.update(defaults)


def test_apply_args_upserts_only_the_set_fields_preserving_others():
    # A record carrying USB identity (tag 0x06) + an existing touch timeout.
    tlvs = [(0x06, b"\x10\x50\x04\x07"), (hw.TAG_PRESENCE_TIMEOUT, b"\x1e")]
    hw._apply_args(tlvs, _Args(led_pin=22, touch_timeout=45))
    by = {t: v for t, v in tlvs}
    assert by[0x06] == b"\x10\x50\x04\x07"  # identity preserved
    assert by[hw.TAG_LED_GPIO] == b"\x16"  # new pin appended
    assert by[hw.TAG_PRESENCE_TIMEOUT] == b"\x2d"  # 30 -> 45, replaced in place


def test_apply_args_rejects_out_of_range():
    import pytest

    for bad in (_Args(led_pin=30), _Args(touch_timeout=0), _Args(led_num=256)):
        with pytest.raises(SystemExit):
            hw._apply_args([], bad)


def test_would_set_distinguishes_read_from_write():
    assert not hw._would_set(_Args())
    assert hw._would_set(_Args(touch_timeout=45))
