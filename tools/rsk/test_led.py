# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Unit tests for the pure logic in rsk.led (no device).

Run from tools/:  python -m pytest rsk/test_led.py
The FIDO transport writes the WHOLE 17-byte block, so _apply_block must change
only the addressed status and leave the others intact (a wrong offset would
recolour or blank an unrelated status). Pin that here.
"""
from rsk import led


class _Args:
    def __init__(self, **kw):
        d = dict(
            status="idle",
            brightness=None,
            color=None,
            effect=None,
            speed=None,
            steady=False,
            blink=False,
            get=False,
        )
        d.update(kw)
        self.__dict__.update(d)


def test_writes_decides_the_exclusive_connect():
    # `_writes` is what makes a configuring run refuse to guess between two
    # attached keys while a read still takes the first match. Nothing else
    # enforces that split, so deleting the predicate would otherwise stay green.
    assert not led._writes(_Args())  # no change asked for
    assert not led._writes(_Args(get=True))
    assert led._writes(_Args(color="red"))
    assert led._writes(_Args(steady=True))
    # --get wins over a set argument: the command shows, so it does not write.
    assert not led._writes(_Args(color="red", get=True))


def test_apply_block_touches_only_the_addressed_status():
    block = bytearray(led.CONF_LEN)  # all zero
    led._apply_block(block, _Args(status="touch", color="blue", brightness=200))
    off = led._status_offset(led.STATUSES["touch"])
    assert block[off + 1] == led.COLORS["blue"]
    assert block[off + 2] == 200
    # Every other byte is still zero (no bleed into other statuses / steady).
    touched = {off + 1, off + 2}
    assert all(b == 0 for i, b in enumerate(block) if i not in touched)


def test_apply_block_steady_and_blink_toggle_byte0():
    b = bytearray(led.CONF_LEN)
    led._apply_block(b, _Args(steady=True))
    assert b[led.BLOCK_OFF_STEADY] == 1
    led._apply_block(b, _Args(blink=True))
    assert b[led.BLOCK_OFF_STEADY] == 0


def test_apply_block_rejects_out_of_range():
    import pytest

    for bad in (_Args(brightness=256), _Args(speed=-1)):
        with pytest.raises(SystemExit):
            led._apply_block(bytearray(led.CONF_LEN), bad)
