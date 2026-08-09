"""
card_test_personalize_reset.py - test resetting personalization of card

Copyright (C) 2016, 2018, 2019  g10 Code GmbH
Author: NIIBE Yutaka <gniibe@fsij.org>

This file is a part of Gnuk, a GnuPG USB Token implementation.

Gnuk is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Gnuk is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from struct import pack
from re import match, DOTALL
from util import *
from card_const import *
from constants_for_test import *
import pytest

class Test_Personalize_Reset(object):
    def test_verify_pw3_0_test(self, card):
        v = card.verify(3, PW3_TEST0)
        assert v

    def test_login_put(self, card):
        r = card.cmd_put_data(0x00, 0x5e, b"")
        assert r

    def test_name_put(self, card):
        r = card.cmd_put_data(0x00, 0x5b, b"")
        assert r

    def test_lang_put(self, card):
        r = card.cmd_put_data(0x5f, 0x2d, b"")
        assert r

    def test_sex_put(self, card):
        try:
            # Gnuk
            r = card.cmd_put_data(0x5f, 0x35, b"")
        except ValueError:
            # OpenPGP card which doesn't allow b""
            r = card.cmd_put_data(0x5f, 0x35, b"9")
        assert r

    def test_url_put(self, card):
        r = card.cmd_put_data(0x5f, 0x50, b"")
        assert r

    def test_pw1_status_put(self, card):
        r = card.cmd_put_data(0x00, 0xc4, b"\x00")
        assert r

    def test_setup_pw3_0(self, card):
        r = card.change_passwd(3, PW3_TEST0, FACTORY_PASSPHRASE_PW3)
        assert r

    def test_verify_pw3_0(self, card):
        v = card.verify(3, FACTORY_PASSPHRASE_PW3)
        assert v

    def test_setup_pw1_0(self, card):
        r = card.change_passwd(1, PW1_TEST4, FACTORY_PASSPHRASE_PW1)
        assert r

    def test_verify_pw1_0(self, card):
        v = card.verify(1, FACTORY_PASSPHRASE_PW1)
        assert v

    def test_verify_pw1_0_2(self, card):
        v = card.verify(2, FACTORY_PASSPHRASE_PW1)
        assert v

    def test_delete_reset_code(self, card):
        if card.is_yubikey:
            pytest.skip("Yubikey raises 6a80 error for data object D3")
        else:
            r = card.cmd_put_data(0x00, 0xd3, b"")
            assert r

    def test_restore_reset_code(self, card):
        # This module deletes D3 while resetting personalization.  Restore it
        # because the session-scoped card fixture is used by later suites.
        assert card.verify(3, FACTORY_PASSPHRASE_PW3)
        assert card.setup_reset_code(RESETCODE_TEST)

    def test_restore_pw1_status(self, card):
        r = card.cmd_put_data(0x00, 0xc4, b"\x01")
        assert r
