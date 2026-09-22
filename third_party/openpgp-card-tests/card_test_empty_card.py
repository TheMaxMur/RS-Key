"""
test_empty_card.py - test empty card

Copyright (C) 2016, 2018  g10 Code GmbH
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

from binascii import hexlify
from re import match, DOTALL
from struct import pack
from util import *
from card_const import *
import pytest

EMPTY_60=bytes(60)

def test_login(card):
    login = get_data_object(card, 0x5e)
    assert check_null(login)

"""
def test_name(card):
    name = get_data_object(card, 0x5b)
    assert check_null(name)

def test_lang(card):
    lang = get_data_object(card, 0x5f2d)
    assert check_null(lang)

def test_sex(card):
    sex = get_data_object(card, 0x5f35)
    assert check_null(sex)
"""

def test_name_lang_sex(card):
    name = b""
    lang = b""
    lang_de = b"de"
    sex = b"9"
    sex_alt = b"0"
    expected = b'\x5b' + pack('B', len(name)) + name \
               +  b'\x5f\x2d' + pack('B', len(lang)) + lang \
               + b'\x5f\x35' + pack('B', len(sex)) + sex_alt
    expected_de = b'\x5b' + pack('B', len(name)) + name \
               +  b'\x5f\x2d' + pack('B', len(lang_de)) + lang_de \
               + b'\x5f\x35' + pack('B', len(sex)) + sex
    expected_de_alt = b'\x5b' + pack('B', len(name)) + name \
               +  b'\x5f\x2d' + pack('B', len(lang_de)) + lang_de \
               + b'\x5f\x35' + pack('B', len(sex_alt)) + sex_alt
    name_lang_sex = get_data_object(card, 0x65)
    assert name_lang_sex == b'' or name_lang_sex == expected \
        or name_lang_sex == expected_de or name_lang_sex == expected_de_alt

def test_app_data(card):
    if card.is_yubikey:
        pytest.skip("Yubikey raises 6e82 error for composed data object 6E")
    else:
        app_data = get_data_object(card, 0x6e)
        hist_len = app_data[20]
        # FIXME: parse and check DO of C0, C1, C2, C3, C4, and C6
        assert app_data[0:8] == b"\x4f\x10\xd2\x76\x00\x01\x24\x01" and \
            app_data[18:18+2] == b"\x5f\x52"

def test_url(card):
    url = get_data_object(card, 0x5f50)
    assert check_null(url)

def test_ds_counter(card):
    c = get_data_object(card, 0x7a)
    assert c == b'\x93\x03\x00\x00\x00'

def test_pw1_status(card):
    s = get_data_object(card, 0xc4)
    assert match(b'....\x03[\x00\x03]\x03', s, DOTALL)

def test_fingerprint_all(card):
    if card.is_yubikey:
        pytest.skip("Yubikey returns 6B00 when no key")
    else:
        fprlist = get_data_object(card, 0xC5)
    assert fprlist == None or fprlist == EMPTY_60

def test_fingerprint_1(card):
    if card.is_yubikey:
        pytest.skip("Yubikey returns 6B00 when no key")
    else:
        fpr = get_data_object(card, 0xC7)
    assert check_null(fpr)

def test_fingerprint_2(card):
    if card.is_yubikey:
        pytest.skip("Yubikey returns 6B00 when no key")
    else:
        fpr = get_data_object(card, 0xC8)
    assert check_null(fpr)

def test_fingerprint_3(card):
    if card.is_yubikey:
        pytest.skip("Yubikey returns 6B00 when no key")
    else:
        fpr = get_data_object(card, 0xC9)
    assert check_null(fpr)

def test_ca_fingerprint_all(card):
    if card.is_yubikey:
        pytest.skip("Yubikey returns 6B00 when no key")
    else:
        cafprlist = get_data_object(card, 0xC6)
    assert cafprlist == None or cafprlist == EMPTY_60

def test_ca_fingerprint_1(card):
    if card.is_yubikey:
        pytest.skip("Yubikey returns 6B00 when no key")
    else:
        cafp = get_data_object(card, 0xCA)
    assert check_null(cafp)

def test_ca_fingerprint_2(card):
    if card.is_yubikey:
        pytest.skip("Yubikey returns 6B00 when no key")
    else:
        cafp = get_data_object(card, 0xCB)
    assert check_null(cafp)

def test_ca_fingerprint_3(card):
    if card.is_yubikey:
        pytest.skip("Yubikey returns 6B00 when no key")
    else:
        cafp = get_data_object(card, 0xCC)
    assert check_null(cafp)

def test_timestamp_all(card):
    if card.is_yubikey:
        pytest.skip("Yubikey returns 6B00 when no key")
    else:
        t = get_data_object(card, 0xCD)
    assert t == None or t == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

def test_timestamp_1(card):
    if card.is_yubikey:
        pytest.skip("Yubikey returns 6B00 when no key")
    else:
        t = get_data_object(card, 0xCE)
    assert check_null(t)

def test_timestamp_2(card):
    if card.is_yubikey:
        pytest.skip("Yubikey returns 6B00 when no key")
    else:
        t = get_data_object(card, 0xCF)
    assert check_null(t)

def test_timestamp_3(card):
    if card.is_yubikey:
        pytest.skip("Yubikey returns 6B00 when no key")
    else:
        t = get_data_object(card, 0xD0)
    assert check_null(t)

def test_verify_pw1_1(card):
    v = card.cmd_verify(1, FACTORY_PASSPHRASE_PW1)
    assert v

def test_verify_pw1_2(card):
    v = card.cmd_verify(2, FACTORY_PASSPHRASE_PW1)
    assert v

def test_verify_pw3(card):
    v = card.cmd_verify(3, FACTORY_PASSPHRASE_PW3)
    assert v

def test_historical_bytes(card):
    h = get_data_object(card, 0x5f52)
    if card.is_yubikey:
        assert h == b'\x00\x73\x00\x00\x80\x05\x90\x00' or \
            h == b'\x00\x73\x00\x00\xe0\x05\x90\x00'
    else:
        assert h == b'\x001\xc5s\xc0\x01@\x05\x90\x00' or \
            h == b'\x00\x31\x84\x73\x80\x01\x80\x00\x90\x00' or \
            h == b'\x00\x31\x84\x73\x80\x01\x80\x05\x90\x00' or \
            h == b'\x00\x31\xf5\x73\xc0\x01\x60\x05\x90\x00' or \
            h == b'\x00\x31\x84\x73\x80\x01\xC0\x05\x90\x00'

def test_extended_capabilities(card):
    if card.is_yubikey:
        pytest.skip("Yubikey returns 6B00 when no key")
    else:
        a = get_data_object(card, 0xc0)
        assert a == None or match(b'[\x70\x7F\x75\x77]\x00\x00.[\x00\x08]\x00\x08\x00[\x00\x01][\x00\x01]', a)

def test_key_attributes_1(card):
    if card.is_yubikey:
        a = None
    else:
        a = get_data_object(card, 0xc1)
        # RS-Key: saved before the assertion, so test_091_reset_attr restores it either way
        card.save_algo_attribute(1, a or KEY_ATTRIBUTES_RSA2K)
        assert a == None or a == b'\x01\x08\x00\x00\x20\x00' or a == b'\x16\x2b\x06\x01\x04\x01\xda\x47\x0f\x01'
    if not a:
        a = KEY_ATTRIBUTES_RSA2K
    card.save_algo_attribute(1, a)
    if card.is_yubikey:
        pytest.skip("Yubikey returns 6B00 when no key")

def test_key_attributes_2(card):
    if card.is_yubikey:
        a = None
    else:
        a = get_data_object(card, 0xc2)
        # RS-Key: saved before the assertion, so test_091_reset_attr restores it either way
        card.save_algo_attribute(2, a or KEY_ATTRIBUTES_RSA2K)
        assert a == None or a == b'\x01\x08\x00\x00\x20\x00' or a == b'\x12\x2b\x06\x01\x04\x01\x97\x55\x01\x05\x01'
    if not a:
        a = KEY_ATTRIBUTES_RSA2K
    card.save_algo_attribute(2, a)
    if card.is_yubikey:
        pytest.skip("Yubikey returns 6B00 when no key")

def test_key_attributes_3(card):
    if card.is_yubikey:
        a = None
    else:
        a = get_data_object(card, 0xc3)
        # RS-Key: saved before the assertion, so test_091_reset_attr restores it either way
        card.save_algo_attribute(3, a or KEY_ATTRIBUTES_RSA2K)
        assert a == None or a == b'\x01\x08\x00\x00\x20\x00' or a == b'\x16\x2b\x06\x01\x04\x01\xda\x47\x0f\x01'
    if not a:
        a = KEY_ATTRIBUTES_RSA2K
    card.save_algo_attribute(3, a)
    if card.is_yubikey:
        pytest.skip("Yubikey returns 6B00 when no key")

def test_public_key_1(card):
    with pytest.raises(Exception) as excinfo:
        pk = card.cmd_get_public_key(1)
    if card.is_yubikey:
        assert excinfo.value.args[0] == "6581"
    else:
        assert excinfo.value.args[0] == "6a88"

def test_public_key_2(card):
    with pytest.raises(Exception) as excinfo:
        pk = card.cmd_get_public_key(2)
    if card.is_yubikey:
        assert excinfo.value.args[0] == "6581"
    else:
        assert excinfo.value.args[0] == "6a88"

def test_public_key_3(card):
    with pytest.raises(Exception) as excinfo:
        pk = card.cmd_get_public_key(3)
    if card.is_yubikey:
        assert excinfo.value.args[0] == "6581"
    else:
        assert excinfo.value.args[0] == "6a88"

def test_AID(card):
    a = get_data_object(card, 0x4f)
    print()
    print("OpenPGP card version: %d.%d" % (a[6], a[7]))
    print("Card Manufacturer:  ", hexlify(a[8:10]).decode("UTF-8"))
    print("Card serial:    ", hexlify(a[10:14]).decode("UTF-8"))
    assert match(b'\xd2\x76\x00\x01\\$\x01........\x00\x00', a, DOTALL)
