# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

import pytest

from rsk import ccid, otp_status


class Card:
    def __init__(self, identity=b'\x01\x02\x08\x06' + bytes(8), state=b'\x01\x02\x00\x00'):
        self.identity, self.state = identity, state
        self.closed = False
        self.calls = []

    def createConnection(self):
        return self

    def connect(self):
        pass

    def disconnect(self):
        self.closed = True

    def __str__(self):
        return 'Yubico YubiKey OTP+FIDO+CCID (rs-key-0001) 00 00'

    def transmit(self, apdu):
        self.calls.append(apdu)
        if apdu[1] == 0xA4:
            return list(self.identity), 0x90, 0
        assert apdu == [0x80, 0x1E, 0x09, 0, 0]
        return list(self.state), 0x90, 0


def test_linux_friendly_name_is_not_the_identity(monkeypatch, capsys):
    card, foreign = Card(), Card(identity=b'')
    monkeypatch.setattr(ccid, 'readers', lambda: [foreign, card])
    otp_status.run(None)
    assert 'sealed:' in capsys.readouterr().out
    assert card.closed and foreign.closed
    assert all(c[1] in (0xA4, 0x1E) for c in card.calls + foreign.calls)


def test_multiple_rescue_responders_are_not_guessed(monkeypatch):
    cards = [Card(), Card()]
    monkeypatch.setattr(ccid, 'readers', lambda: cards)
    with pytest.raises(SystemExit):
        otp_status.connect()
    assert all(c.closed for c in cards)


@pytest.mark.parametrize('state', [b'', b'\x02\x02\x00\x00', b'\x01\xff\x00\x00', b'\x01\x02\x00\x00\x00'])
def test_malformed_status_is_not_success(state):
    with pytest.raises(SystemExit):
        otp_status.read_status(Card(state=state))


def test_pending_migration_names_required_pin_use(monkeypatch, capsys):
    card = Card(state=b'\x01\x03\x00\x09')
    monkeypatch.setattr(ccid, 'readers', lambda: [card])
    with pytest.raises(SystemExit) as error:
        otp_status.run(None)
    text = capsys.readouterr().out
    assert error.value.code == 2 and 'FIDO' in text and 'OATH' in text
    assert card.closed and all(c[1] in (0xA4, 0x1E) for c in card.calls)


def test_unavailable_reader_does_not_hide_the_working_responder(monkeypatch):
    class Unavailable(Card):
        def connect(self):
            raise OSError("reader unavailable")

        def disconnect(self):
            raise OSError("never connected")

    card = Card()
    monkeypatch.setattr(ccid, "readers", lambda: [Unavailable(), card])
    otp_status.run(None)
    assert card.closed


def test_partial_latch_never_claims_full_redundancy_or_attempts_another_burn(monkeypatch, capsys):
    card = Card(state=b'\x01\x0a\x00\x00')
    monkeypatch.setattr(ccid, 'readers', lambda: [card])
    with pytest.raises(SystemExit) as error:
        otp_status.run(None)
    assert error.value.code == 2
    assert 'redundancy incomplete' in capsys.readouterr().out
    assert all(c[1] in (0xA4, 0x1E) for c in card.calls)


def test_torn_access_lock_is_a_recovery_error_not_sealed(monkeypatch, capsys):
    card = Card(state=b'\x01\x0b\xff\xfe')
    monkeypatch.setattr(ccid, 'readers', lambda: [card])
    with pytest.raises(SystemExit) as error:
        otp_status.run(None)
    assert error.value.code == 2
    text = capsys.readouterr().out
    assert 'recovery required' in text and 'sealed' not in text
    assert all(c[1] in (0xA4, 0x1E) for c in card.calls)
