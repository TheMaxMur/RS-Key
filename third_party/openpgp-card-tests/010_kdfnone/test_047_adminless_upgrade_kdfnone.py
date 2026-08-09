"""Explicitly opt an existing admin-full card into admin-less mode."""

from card_const import FACTORY_PASSPHRASE_PW1, FACTORY_PASSPHRASE_PW3
from constants_for_test import PW1_TEST0, PW3_TEST0
from skip_if_kdfreq import *


class Test_Card_Adminless_Upgrade:
    def test_set_existing_admin_password(self, card):
        assert card.change_passwd(3, FACTORY_PASSPHRASE_PW3, PW3_TEST0)

    def test_set_existing_user_password(self, card):
        assert card.change_passwd(1, FACTORY_PASSPHRASE_PW1, PW1_TEST0)

    def test_enable_adminless(self, card):
        assert card.change_passwd(3, PW3_TEST0, PW1_TEST0)

    def test_pw1_authorizes_admin_operation(self, card):
        assert card.deauthenticate(1)
        assert card.verify(1, PW1_TEST0)
        assert card.cmd_put_data(0x00, 0x5e, b"adminless")

    def test_pw3_accepts_user_password(self, card):
        assert card.verify(3, PW1_TEST0)

    def test_distinct_pw3_disables_adminless(self, card):
        assert card.change_passwd(3, PW1_TEST0, PW3_TEST0)
        assert card.deauthenticate(1)
        assert card.deauthenticate(3)
        assert card.verify(1, PW1_TEST0)
        try:
            card.cmd_put_data(0x00, 0x5e, b"adminfull")
        except ValueError as e:
            assert e.args[0] == "6982"
        else:
            raise AssertionError("PW1 unexpectedly retained admin authorization")

    def test_pw3_authorizes_admin_after_disable(self, card):
        assert card.verify(3, PW3_TEST0)
        assert card.cmd_put_data(0x00, 0x5e, b"adminfull")

    def test_restore_adminfull_factory_passwords(self, card):
        assert card.change_passwd(3, PW3_TEST0, FACTORY_PASSPHRASE_PW3)
        assert card.change_passwd(1, PW1_TEST0, FACTORY_PASSPHRASE_PW1)
