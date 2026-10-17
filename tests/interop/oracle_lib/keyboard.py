# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Observe unsolicited keyboard reports without inventing a request or touch time."""
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .otp import crc16, otp_value, slot_request, slot_select
from .trace import Outcome, TransferError

MODHEX = "cbdefghijklnrtuv"
US = {**{index + 4: chr(index + 97) for index in range(26)},
      **{index + 30: value for index, value in enumerate("1234567890")},
      0x28: "\r", 0x2B: "\t", 0x2C: " ", 0x2D: "-", 0x2E: "="}


class Keyboard:
    def __init__(self, descriptor, clock, backend=None):
        self.clock = clock
        self.descriptor = descriptor
        if backend is None:
            import hid
            backend = hid.device()
            backend.open_path(bytes.fromhex(descriptor["path_hex"]))
        self.backend = backend

    def reports(self, deadline, emit):
        seen, previous = False, self.clock()
        while self.clock() < deadline:
            frame = bytes(self.backend.read(64, 100))
            if frame:
                previous, seen = self.clock(), True
                emit(frame, previous)
            elif seen and self.clock() - previous > 1000000000:
                return
        if not seen:
            raise TransferError("no keyboard report before observation deadline", Outcome.DEADLINE)

    def close(self):
        self.backend.close()

    def reopen(self, operator=False):
        from .binding import rebind
        descriptor = rebind(self.descriptor, "otp_hid", operator)
        self.close()
        self.__init__(descriptor, self.clock)
        return descriptor


def decode(reports):
    previous, text, pressed = set(), [], []
    for raw in reports:
        if len(raw) == 9 and raw[0] == 0:
            raw = raw[1:]
        if len(raw) != 8 or raw[1] != 0:
            raise ValueError("keyboard capture requires boot-keyboard reports")
        current = set(raw[2:]) - {0}
        if any(key < 4 for key in current):
            raise ValueError("keyboard reported rollover/error")
        for key in raw[2:]:
            if key and key not in previous:
                pressed.append((raw[0], key))
                if key not in US or raw[0] & ~0x22:
                    raise ValueError("key/modifier outside declared US fixture layout")
                value = US[key]
                text.append(value.upper() if raw[0] & 0x22 and value.isalpha() else value)
        previous = current
    if previous:
        raise ValueError("keyboard capture ended with a key held")
    return "".join(text), pressed


def receive(session, gesture, comparison="exact"):
    session.require(getattr(session, "keyboard", None) is not None, "select --keyboard-hid for unsolicited reports", "excluded_by_mode")
    session.require(session.options.operator, "keyboard gesture scenarios require --operator")
    started = session.trace.now()
    session.trace.emit("interaction", action=gesture, stage="requested", source="runner", observed_touch_ns=None)
    print("oracle: perform " + gesture + " on the selected key", file=sys.stderr)
    frames, timestamps = [], []
    def emit(raw, timestamp):
        frames.append(raw)
        timestamps.append(timestamp)
        event = session.trace.emit("io_event", session_id="keyboard", exchange_id=None,
                                   observation_layer="hid_report", direction="rx", unsolicited=True,
                                   hex=raw.hex(), length=len(raw), observed_ns=timestamp)
        session.event_evidence = event["event_id"]
    session.keyboard.reports(started + int(session.options.timeout * 1000000000), emit)
    text, pressed = decode(frames)
    session.observe("keyboard_text", text, comparison)
    session.observe("keyboard_key_presses", pressed, comparison)
    session.observe("keyboard_timing", {"listen_started_ns": started, "first_report_ns": timestamps[0],
                                        "last_report_ns": timestamps[-1], "output_duration_ns": timestamps[-1] - timestamps[0],
                                        "gesture_started_ns": None, "gesture_to_first_report_ns": None}, "presence")
    return text


def run(session):
    from yubikit.yubiotp import HotpSlotConfiguration, StaticPasswordSlotConfiguration, YubiOtpSlotConfiguration
    slot = session.options.otp_slot
    write = 1 if slot == 1 else 3
    gesture = "short press" if slot == 1 else "long press"
    for mode in ("yubico", "hotp6", "hotp8", "static"):
        for append in (False, True):
            for pacing in (0, 1, 2, 3):
                with session.case(f"otp.typing.slot-{slot}.{mode}.CR-{append}.pacing-{pacing}",
                                  ("Y09" if mode == "yubico" else "Y10" if mode.startswith("hotp") else "Y11", "Y12", "G11"),
                                  effects=(f"replace_otp_slot_{slot}", "keyboard_output")):
                    session.require(getattr(session, "keyboard", None) is not None and session.options.operator, "keyboard capture requires explicit interface and --operator")
                    slot_select(session)
                    key, uid, fixed = session.fixture("keyboard.key", 20), session.fixture("keyboard.uid", 6), session.fixture("keyboard.fixed", 6)
                    if mode == "yubico":
                        config = YubiOtpSlotConfiguration(fixed, uid, key[:16])
                    elif mode.startswith("hotp"):
                        config = HotpSlotConfiguration(key).digits8(mode == "hotp8")
                    else:
                        config = StaticPasswordSlotConfiguration(b"\x0b\x08\x0f\x0f\x12")
                    config.append_cr(append).pacing(bool(pacing & 1), bool(pacing & 2))
                    created = False
                    try:
                        slot_request(session, write, config.get_config() + bytes(6))
                        created = True
                        previous = None
                        for counter in range(3):
                            text = receive(session, gesture, "presence" if mode == "yubico" else "exact")
                            value = text[:-1] if append else text
                            if append:
                                session.check("configured carriage return", text[-1:], "\r")
                            if mode == "static":
                                session.check("static password exact text", value, "hello")
                            elif mode.startswith("hotp"):
                                digits = 8 if mode == "hotp8" else 6
                                session.check("typed HOTP known answer", value, str(otp_value(key, counter.to_bytes(8, "big"), "sha1", digits)).zfill(digits))
                            else:
                                session.check("Yubico OTP width", len(value), 44)
                                encoded = bytes((MODHEX.index(value[index]) << 4) | MODHEX.index(value[index + 1]) for index in range(0, 44, 2))
                                session.check("typed Yubico public ID", encoded[:6], fixed)
                                decryptor = Cipher(algorithms.AES(key[:16]), modes.ECB()).decryptor()
                                plain = decryptor.update(encoded[6:]) + decryptor.finalize()
                                session.check("typed OTP fixture UID", plain[:6], uid)
                                session.check("typed OTP CRC residue", crc16(plain), 0xF0B8)
                                sequence = (int.from_bytes(plain[6:8], "little"), plain[11])
                                session.check("typed OTP counters never repeat", previous is None or sequence > previous)
                                previous = sequence
                    finally:
                        if created and not session.broken:
                            session.trace.phase = "cleanup"
                            slot_request(session, write, bytes(58))
