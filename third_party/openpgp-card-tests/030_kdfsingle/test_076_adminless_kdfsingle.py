from card_test_reset_pw3 import *
from card_const import FACTORY_PASSPHRASE_PW3


def test_restore_adminfull_mode(card):
    r = card.change_passwd(3, FACTORY_PASSPHRASE_PW3,
                           FACTORY_PASSPHRASE_PW3)
    assert r
