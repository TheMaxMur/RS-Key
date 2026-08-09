"""
openpgp_card.py - a library for OpenPGP card

Copyright (C) 2011, 2012, 2013, 2015, 2016, 2018, 2019
              Free Software Initiative of Japan
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

from struct import pack, unpack
from kdf_calc import kdf_calc
from card_const import FACTORY_PASSPHRASE_PW1, FACTORY_PASSPHRASE_PW3

def iso7816_compose(ins, p1, p2, data, cls=0x00, le=None):
    data_len = len(data)
    if data_len == 0:
        if not le:
            return pack('>BBBB', cls, ins, p1, p2)
        elif le < 256:
            return pack('>BBBBB', cls, ins, p1, p2, le)
        else:
            return pack('>BBBBBH', cls, ins, p1, p2, 0, le)
    else:
        if not le:
            if data_len <= 255:
                return pack('>BBBBB', cls, ins, p1, p2, data_len) + data
            else:
                return pack('>BBBBBH', cls, ins, p1, p2, 0, data_len) \
                    + data
        else:
            if data_len <= 255 and le < 256:
                return pack('>BBBBB', cls, ins, p1, p2, data_len) \
                    + data + pack('>B', le)
            else:
                return pack('>BBBBBH', cls, ins, p1, p2, 0, data_len) \
                    + data + pack('>H', le)

class OpenPGP_Card(object):
    def __init__(self, reader):
        """
        __init__(reader) -> None
        Initialize a OpenPGP card with a CardReader.
        reader: CardReader object.
        """

        self.supported_key_attrlist = [ [], [], [] ]
        self.__reader = reader
        self.attr = [ None, None, None ]
        self.__kdf_iters = None
        self.__kdf_salt_user = None
        self.__kdf_salt_reset = None
        self.__kdf_salt_admin = None
        self.is_gnuk = False
        self.is_yubikey = False
        self.kdf_required = False

        self.initialize_kdf()

    def add_to_key_attrlist(self, no, attr):
        self.supported_key_attrlist[no].append(attr)

    def initialize_kdf(self):
        try:
            self.kdf_data = self.cmd_get_data(0x00, 0xf9)
            if not self.kdf_data:
                self.kdf_data = b""
            self.kdf_supported = True
        except:
            self.kdf_data = b""
            self.kdf_supported = True

    def configure_kdf(self, kdf_config):
        old_kdf_iters = self.__kdf_iters
        old_kdf_salt_user = self.__kdf_salt_user
        old_kdf_salt_admin = self.__kdf_salt_admin

        self.kdf_data = kdf_config
        r = self.cmd_put_data(0x00, 0xf9, kdf_config)
        if self.kdf_data == b"" or self.kdf_data == b"\x81\x01\x00":
            self.__kdf_iters = None
            self.__kdf_salt_user = None
            self.__kdf_salt_reset = None
            self.__kdf_salt_admin = None
        else:
            algo, subalgo, iters, salt_user, salt_reset, salt_admin, hash_user, hash_admin = parse_kdf_data(self.kdf_data)
            self.__kdf_iters = iters
            self.__kdf_salt_user = salt_user
            self.__kdf_salt_reset = salt_reset
            self.__kdf_salt_admin = salt_admin

        if not self.is_gnuk and not self.is_yubikey:
            def kdf_value(pin, who, iterations, salt_user, salt_admin):
                if not iterations:
                    return pin
                salt = salt_admin if who == 3 and salt_admin else salt_user
                return kdf_calc(pin, salt, iterations)

            old_pw1 = kdf_value(FACTORY_PASSPHRASE_PW1, 1,
                                old_kdf_iters, old_kdf_salt_user, old_kdf_salt_admin)
            new_pw1 = kdf_value(FACTORY_PASSPHRASE_PW1, 1,
                                self.__kdf_iters, self.__kdf_salt_user, self.__kdf_salt_admin)
            self.cmd_change_reference_data(1, old_pw1 + new_pw1)

            old_pw3 = kdf_value(FACTORY_PASSPHRASE_PW3, 3,
                                old_kdf_iters, old_kdf_salt_user, old_kdf_salt_admin)
            new_pw3 = kdf_value(FACTORY_PASSPHRASE_PW3, 3,
                                self.__kdf_iters, self.__kdf_salt_user, self.__kdf_salt_admin)
            self.cmd_change_reference_data(3, old_pw3 + new_pw3)
        return r

    def save_algo_attribute(self, keyno, attr):
        self.attr[keyno - 1] = attr

    def saved_attribute(self, keyno):
        return self.attr[keyno - 1]

    # Higher layer VERIFY possibly using KDF Data Object
    def verify(self, who, passwd):
        if self.__kdf_iters:
            salt = self.__kdf_salt_user
            if who == 3 and self.__kdf_salt_admin:
                    salt = self.__kdf_salt_admin
            pw_hash = kdf_calc(passwd, salt, self.__kdf_iters)
            return self.cmd_verify(who, pw_hash)
        else:
            return self.cmd_verify(who, passwd)

    def deauthenticate(self, who):
        cmd_data = iso7816_compose(0x20, 0xff, 0x80+who, b'')
        sw = self.__reader.send_cmd(cmd_data)
        if len(sw) != 2:
            raise ValueError(sw)
        if not (sw[0] == 0x90 and sw[1] == 0x00):
            raise ValueError("%02x%02x" % (sw[0], sw[1]))
        return True

    # Higher layer CHANGE_PASSWD possibly using KDF Data Object
    # KDF_CHANGE: 0 no-change, -1 to be cleared, 1 to be configured
    def change_passwd(self, who, passwd_old, passwd_new, kdf_change=0):
        if self.__kdf_iters:
            salt = self.__kdf_salt_user
            if who == 3 and self.__kdf_salt_admin:
                    salt = self.__kdf_salt_admin
            if kdf_change <= 0:
                hash_old = kdf_calc(passwd_old, salt, self.__kdf_iters)
            else:
                hash_old = passwd_old
            if kdf_change >= 0:
                hash_new = kdf_calc(passwd_new, salt, self.__kdf_iters)
            else:
                hash_new = passwd_new
            return self.cmd_change_reference_data(who, hash_old + hash_new)
        else:
            return self.cmd_change_reference_data(who, passwd_old + passwd_new)

    # Higher layer SETUP_RESET_CODE possibly using KDF Data Object
    def setup_reset_code(self, resetcode):
        if self.__kdf_iters:
            salt = self.__kdf_salt_user
            if self.__kdf_salt_reset:
                    salt = self.__kdf_salt_user
            reset_hash = kdf_calc(resetcode, salt, self.__kdf_iters)
            return self.cmd_put_data(0x00, 0xd3, reset_hash)
        else:
            return self.cmd_put_data(0x00, 0xd3, resetcode)

    # Higher layer reset passwd possibly using KDF Data Object
    def reset_passwd_by_resetcode(self, resetcode, pw1):
        if self.__kdf_iters:
            salt = self.__kdf_salt_user
            if self.__kdf_salt_reset:
                    salt = self.__kdf_salt_user
            reset_hash = kdf_calc(resetcode, salt, self.__kdf_iters)
            pw1_hash = kdf_calc(pw1, self.__kdf_salt_user, self.__kdf_iters)
            return self.cmd_reset_retry_counter(0, 0x81, reset_hash + pw1_hash)
        else:
            return self.cmd_reset_retry_counter(0, 0x81, resetcode + pw1)

    # Higher layer reset passwd possibly using KDF Data Object
    def reset_passwd_by_admin(self, pw1):
        if self.__kdf_iters:
            pw1_hash = kdf_calc(pw1, self.__kdf_salt_user, self.__kdf_iters)
            return self.cmd_reset_retry_counter(2, 0x81, pw1_hash)
        else:
            return self.cmd_reset_retry_counter(2, 0x81, pw1)

    def cmd_get_response(self, expected_len):
        result = b""
        while True:
            cmd_data = iso7816_compose(0xc0, 0x00, 0x00, b'') + pack('>B', expected_len)
            response = self.__reader.send_cmd(cmd_data)
            result += response[:-2]
            sw = response[-2:]
            if sw[0] == 0x90 and sw[1] == 0x00:
                return result
            elif sw[0] != 0x61:
                raise ValueError("%02x%02x" % (sw[0], sw[1]))
            else:
                expected_len = sw[1]

    def cmd_verify(self, who, passwd):
        cmd_data = iso7816_compose(0x20, 0x00, 0x80+who, passwd)
        sw = self.__reader.send_cmd(cmd_data)
        if len(sw) != 2:
            raise ValueError(sw)
        if not (sw[0] == 0x90 and sw[1] == 0x00):
            raise ValueError("%02x%02x" % (sw[0], sw[1]))
        return True

    def cmd_read_binary(self, fileid):
        cmd_data = iso7816_compose(0xb0, 0x80+fileid, 0x00, b'')
        sw = self.__reader.send_cmd(cmd_data)
        if len(sw) != 2:
            raise ValueError(sw)
        if sw[0] != 0x61:
            raise ValueError("%02x%02x" % (sw[0], sw[1]))
        return self.cmd_get_response(sw[1])

    def cmd_write_binary(self, fileid, data, is_update):
        count = 0
        data_len = len(data)
        if is_update:
            ins = 0xd6
        else:
            ins = 0xd0
        while count*256 < data_len:
            if count == 0:
                if len(data) < 128:
                    cmd_data0 = iso7816_compose(ins, 0x80+fileid, 0x00, data[:128])
                    cmd_data1 = None
                else:
                    cmd_data0 = iso7816_compose(ins, 0x80+fileid, 0x00, data[:128], 0x10)
                    cmd_data1 = iso7816_compose(ins, 0x80+fileid, 0x00, data[128:256])
            else:
                if len(data[256*count:256*count+128]) < 128:
                    cmd_data0 = iso7816_compose(ins, count, 0x00, data[256*count:256*count+128])
                    cmd_data1 = None
                else:
                    cmd_data0 = iso7816_compose(ins, count, 0x00, data[256*count:256*count+128], 0x10)
                    cmd_data1 = iso7816_compose(ins, count, 0x00, data[256*count+128:256*(count+1)])
            sw = self.__reader.send_cmd(cmd_data0)
            if len(sw) != 2:
                raise ValueError("cmd_write_binary 0")
            if not (sw[0] == 0x90 and sw[1] == 0x00):
                raise ValueError("cmd_write_binary 0", "%02x%02x" % (sw[0], sw[1]))
            if cmd_data1:
                sw = self.__reader.send_cmd(cmd_data1)
                if len(sw) != 2:
                    raise ValueError("cmd_write_binary 1", sw)
                if not (sw[0] == 0x90 and sw[1] == 0x00):
                    raise ValueError("cmd_write_binary 1", "%02x%02x" % (sw[0], sw[1]))
            count += 1

    def cmd_select_openpgp(self):
        cmd_data = iso7816_compose(0xa4, 0x04, 0x00, b"\xD2\x76\x00\x01\x24\x01")
        r = self.__reader.send_cmd(cmd_data)
        if len(r) < 2:
            raise ValueError(r)
        sw = r[-2:]
        r = r[0:-2]
        if sw[0] == 0x61:
            self.cmd_get_response(sw[1])
            return True
        if not (sw[0] == 0x90 and sw[1] == 0x00):
            raise ValueError("%02x%02x" % (sw[0], sw[1]))
        return True

    def cmd_get_data(self, tagh, tagl):
        if tagh == 0 and tagl == 0xfa and (not self.is_gnuk):
            # Special DO with larger data
            cmd_data = iso7816_compose(0xca, tagh, tagl, b"", le=1024)
        elif self.is_yubikey:
            cmd_data = iso7816_compose(0xca, tagh, tagl, b"")
        else:
            cmd_data = iso7816_compose(0xca, tagh, tagl, b"", le=254)
        response = self.__reader.send_cmd(cmd_data)
        if len(response) < 2:
            raise ValueError(response)
        body = response[:-2]
        sw = response[-2:]
        if sw[0] == 0x61:
            return body + self.cmd_get_response(sw[1])
        elif sw[0] == 0x90 and sw[1] == 0x00:
            return body
        if sw[0] == 0x6a and sw[1] == 0x88:
            return None
        else:
            raise ValueError("%02x%02x" % (sw[0], sw[1]))

    def cmd_change_reference_data(self, who, data):
        cmd_data = iso7816_compose(0x24, 0x00, 0x80+who, data)
        sw = self.__reader.send_cmd(cmd_data)
        if len(sw) != 2:
            raise ValueError(sw)
        if not (sw[0] == 0x90 and sw[1] == 0x00):
            raise ValueError("%02x%02x" % (sw[0], sw[1]))
        return True

    def cmd_put_data(self, tagh, tagl, content):
        cmd_data = iso7816_compose(0xda, tagh, tagl, content)
        sw = self.__reader.send_cmd(cmd_data)
        if len(sw) != 2:
            raise ValueError(sw)
        if not (sw[0] == 0x90 and sw[1] == 0x00):
            raise ValueError("%02x%02x" % (sw[0], sw[1]))
        return True

    def cmd_put_data_odd(self, tagh, tagl, content):
        if (not self.is_gnuk) or len(content) <= 128:
            cmd_data = iso7816_compose(0xdb, tagh, tagl, content)
            sw = self.__reader.send_cmd(cmd_data)
        else:
            cmd_data0 = iso7816_compose(0xdb, tagh, tagl, content[:128], 0x10)
            cmd_data1 = iso7816_compose(0xdb, tagh, tagl, content[128:])
            sw = self.__reader.send_cmd(cmd_data0)
            if len(sw) != 2:
                raise ValueError(sw)
            if not (sw[0] == 0x90 and sw[1] == 0x00):
                raise ValueError("%02x%02x" % (sw[0], sw[1]))
            sw = self.__reader.send_cmd(cmd_data1)
        if len(sw) != 2:
            raise ValueError(sw)
        if not (sw[0] == 0x90 and sw[1] == 0x00):
            raise ValueError("%02x%02x" % (sw[0], sw[1]))
        return True

    def cmd_reset_retry_counter(self, how, who, data):
        cmd_data = iso7816_compose(0x2c, how, who, data)
        sw = self.__reader.send_cmd(cmd_data)
        if len(sw) != 2:
            raise ValueError(sw)
        if not (sw[0] == 0x90 and sw[1] == 0x00):
            raise ValueError("%02x%02x" % (sw[0], sw[1]))
        return True

    def cmd_pso(self, p1, p2, data):
        if not self.is_gnuk:
            cmd_data = iso7816_compose(0x2a, p1, p2, data, le=256)
            r = self.__reader.send_cmd(cmd_data)
            if len(r) < 2:
                raise ValueError(r)
            sw = r[-2:]
            r = r[0:-2]
            if sw[0] == 0x61:
                return self.cmd_get_response(sw[1])
            elif sw[0] == 0x90 and sw[1] == 0x00:
                return r
            else:
                raise ValueError("%02x%02x" % (sw[0], sw[1]))
        else:
            if len(data) > 128:
                cmd_data0 = iso7816_compose(0x2a, p1, p2, data[:128], 0x10)
                cmd_data1 = iso7816_compose(0x2a, p1, p2, data[128:])
                sw = self.__reader.send_cmd(cmd_data0)
                if len(sw) != 2:
                    raise ValueError(sw)
                if not (sw[0] == 0x90 and sw[1] == 0x00):
                    raise ValueError("%02x%02x" % (sw[0], sw[1]))
                sw = self.__reader.send_cmd(cmd_data1)
                if len(sw) != 2:
                    raise ValueError(sw)
                elif sw[0] != 0x61:
                    raise ValueError("%02x%02x" % (sw[0], sw[1]))
                return self.cmd_get_response(sw[1])
            else:
                cmd_data = iso7816_compose(0x2a, p1, p2, data)
                sw = self.__reader.send_cmd(cmd_data)
                if len(sw) != 2:
                    raise ValueError(sw)
                if sw[0] == 0x90 and sw[1] == 0x00:
                    return b""
                elif sw[0] != 0x61:
                    raise ValueError("%02x%02x" % (sw[0], sw[1]))
                return self.cmd_get_response(sw[1])

    def cmd_internal_authenticate(self, data):
        if not self.is_gnuk:
            cmd_data = iso7816_compose(0x88, 0, 0, data, le=256)
        else:
            cmd_data = iso7816_compose(0x88, 0, 0, data)
        r = self.__reader.send_cmd(cmd_data)
        if len(r) < 2:
            raise ValueError(r)
        sw = r[-2:]
        r = r[0:-2]
        if sw[0] == 0x61:
            return self.cmd_get_response(sw[1])
        elif sw[0] == 0x90 and sw[1] == 0x00:
            return r
        else:
            raise ValueError("%02x%02x" % (sw[0], sw[1]))

    def cmd_genkey(self, keyno):
        if keyno == 1:
            data = b'\xb6\x00'
        elif keyno == 2:
            data = b'\xb8\x00'
        else:
            data = b'\xa4\x00'
        if not self.is_gnuk:
            cmd_data = iso7816_compose(0x47, 0x80, 0, data, le=512)
        else:
            cmd_data = iso7816_compose(0x47, 0x80, 0, data)
        sw = self.__reader.send_cmd(cmd_data)
        if len(sw) < 2:
            raise ValueError(sw)
        body = sw[:-2]
        status = sw[-2:]
        if status[0] == 0x61:
            pk = body + self.cmd_get_response(status[1])
        elif status[0] == 0x90 and status[1] == 0x00:
            pk = body
        else:
            raise ValueError("%02x%02x" % (status[0], status[1]))
        return pk

    def cmd_get_public_key(self, keyno):
        if keyno == 1:
            data = b'\xb6\x00'
        elif keyno == 2:
            data = b'\xb8\x00'
        else:
            data = b'\xa4\x00'
        if not self.is_gnuk:
            cmd_data = iso7816_compose(0x47, 0x81, 0, data, le=512)
        else:
            cmd_data = iso7816_compose(0x47, 0x81, 0, data)
        r = self.__reader.send_cmd(cmd_data)
        if len(r) < 2:
            raise ValueError(r)
        sw = r[-2:]
        r = r[0:-2]
        if sw[0] == 0x61:
            pk = self.cmd_get_response(sw[1])
        elif sw[0] == 0x90 and sw[1] == 0x00:
            pk = r
        else:
            raise ValueError("%02x%02x" % (sw[0], sw[1]))
        return pk

    def cmd_put_data_remove(self, tagh, tagl):
        cmd_data = iso7816_compose(0xda, tagh, tagl, b"")
        sw = self.__reader.send_cmd(cmd_data)
        if sw[0] != 0x90 and sw[1] != 0x00:
            raise ValueError("%02x%02x" % (sw[0], sw[1]))

    def cmd_put_data_key_import_remove(self, keyno):
        if keyno == 1:
            keyspec = b"\xb6\x00"      # SIG
        elif keyno == 2:
            keyspec = b"\xb8\x00"      # DEC
        else:
            keyspec = b"\xa4\x00"      # AUT
        cmd_data = iso7816_compose(0xdb, 0x3f, 0xff, b"\x4d\x02" +  keyspec)
        sw = self.__reader.send_cmd(cmd_data)
        if sw[0] != 0x90 and sw[1] != 0x00:
            raise ValueError("%02x%02x" % (sw[0], sw[1]))

    def cmd_get_challenge(self):
        cmd_data = iso7816_compose(0x84, 0x00, 0x00, '')
        sw = self.__reader.send_cmd(cmd_data)
        if len(sw) != 2:
            raise ValueError(sw)
        if sw[0] != 0x61:
            raise ValueError("%02x%02x" % (sw[0], sw[1]))
        return self.cmd_get_response(sw[1])

    def cmd_external_authenticate(self, keyno, signed):
        cmd_data = iso7816_compose(0x82, 0x00, keyno, signed[0:128], cls=0x10)
        sw = self.__reader.send_cmd(cmd_data)
        if len(sw) != 2:
            raise ValueError(sw)
        if not (sw[0] == 0x90 and sw[1] == 0x00):
            raise ValueError("%02x%02x" % (sw[0], sw[1]))
        cmd_data = iso7816_compose(0x82, 0x00, keyno, signed[128:])
        sw = self.__reader.send_cmd(cmd_data)
        if len(sw) != 2:
            raise ValueError(sw)
        if not (sw[0] == 0x90 and sw[1] == 0x00):
            raise ValueError("%02x%02x" % (sw[0], sw[1]))

def parse_kdf_data(kdf_data):
    if len(kdf_data) == 90:
        single_salt = True
    elif len(kdf_data) == 110:
        single_salt = False
    else:
        raise ValueError("length does not much", kdf_data)

    if kdf_data[0:2] != b'\x81\x01':
        raise ValueError("data does not much")
    algo = kdf_data[2]
    if kdf_data[3:5] != b'\x82\x01':
        raise ValueError("data does not much")
    subalgo = kdf_data[5]
    if kdf_data[6:8] != b'\x83\x04':
        raise ValueError("data does not much")
    iters = unpack(">I", kdf_data[8:12])[0]
    if kdf_data[12:14] != b'\x84\x08':
        raise ValueError("data does not much")
    salt = kdf_data[14:22]
    if single_salt:
        salt_reset = None
        salt_admin = None
        if kdf_data[22:24] != b'\x87\x20':
            raise ValueError("data does not much")
        hash_user = kdf_data[24:56]
        if kdf_data[56:58] != b'\x88\x20':
            raise ValueError("data does not much")
        hash_admin = kdf_data[58:90]
    else:
        if kdf_data[22:24] != b'\x85\x08':
            raise ValueError("data does not much")
        salt_reset = kdf_data[24:32]
        if kdf_data[32:34] != b'\x86\x08':
            raise ValueError("data does not much")
        salt_admin = kdf_data[34:42]
        if kdf_data[42:44] != b'\x87\x20':
            raise ValueError("data does not much")
        hash_user = kdf_data[44:76]
        if kdf_data[76:78] != b'\x88\x20':
            raise ValueError("data does not much")
        hash_admin = kdf_data[78:110]
    return ( algo, subalgo, iters, salt, salt_reset, salt_admin,
             hash_user, hash_admin )
