# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Typed HOTP/Yubico positions survive updates, swaps and observed interruptions."""
from contextlib import ExitStack
from itertools import combinations, product

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import keyboard
from .lifecycle import Action, change
from .otp import crc16, otp_value
from .otp_commands import Mode, Route, address, checksum, configure, fixture, merged, mutate

MODES = (Mode.HOTP6, Mode.HOTP8, Mode.YUBICO)


def configuration(session, slot, mode, initial=0, access=b"code-A"):
    body = bytearray(configure(session.fixture(f"OTP.typed.key.{slot}", 20), mode, access))
    body[:6] = session.fixture(f"OTP.typed.public-id.{slot}", 6)
    if mode in (Mode.HOTP6, Mode.HOTP8):
        body[20:22] = initial.to_bytes(2, "big")
    return checksum(body)


def expected_hotp(config, factor):
    digits = 8 if config[47] & 2 else 6
    return str(otp_value(config[22:38] + config[16:20], factor.to_bytes(8, "big"), "sha1", digits)).zfill(digits)


def ticket(session, slot, config, position):
    text = keyboard.receive(session, keyboard.gesture(session, slot), "presence" if not config[46] & 64 else "exact")
    value = text[:-1] if config[46] & 32 else text
    if config[46] & 32:
        session.check("typed ticket retains its configured final CR", text[-1:], "\r")
    if config[46] & 64:
        session.check("typed HOTP has the exact persisted moving factor", value, expected_hotp(config, position))
        return
    session.check("typed Yubico ticket has the complete public and encrypted block", len(value), 44)
    raw = bytes((keyboard.MODHEX.index(value[index]) << 4) | keyboard.MODHEX.index(value[index + 1]) for index in range(0, 44, 2))
    session.check("typed Yubico public identity follows its slot record", raw[:6], config[:6])
    worker = Cipher(algorithms.AES(config[22:38]), modes.ECB()).decryptor()
    plain = worker.update(raw[6:]) + worker.finalize()
    session.check("typed Yubico private identity follows its slot record", plain[:6], config[16:22])
    session.check("typed Yubico block has the correct CRC", crc16(plain), 0xf0b8)
    actual = int.from_bytes(plain[6:8], "little"), plain[11]
    session.check("typed Yubico use/session position has the exact profiled lifetime", actual, position)
    session.observe("Yubico_timestamp_random", {"uptime_half_seconds": int.from_bytes(plain[8:11], "little"), "random": plain[12:14]}, "presence")


def ready(session, mode):
    session.require(session.profile == "rsk", "typed counter/gesture profiles require RS-Key", "excluded_by_profile")
    session.require(session.keyboard is not None and session.options.operator, "typed counters need the selected keyboard and explicit operator")
    if mode == Mode.YUBICO:
        change(session, Action.POWER_CYCLE)


def lifetimes(session):
    for slot, mode, action in product(range(1, 5), MODES, Action):
        for initial in ((0, 1, 65535) if mode != Mode.YUBICO else (0,)):
            with session.case(f"otp.typed.counter.slot-{slot}.{mode.name}.initial-{initial}.{action.value}", ("Y01", "Y02", "Y09", "Y10", "Y12", "Y14", "X11", "G14"), effects=("otp_extra_slots", "keyboard_output", "reboot") if slot > 2 else (f"replace_otp_slot_{slot}", "keyboard_output", "reboot"), parameters={"slot": slot, "mode": mode.name, "initial": initial}):
                ready(session, mode)
                config = configuration(session, slot, mode, initial)
                with fixture(session, Route.CARD, slot, config):
                    ticket(session, slot, config, (1, 0) if mode == Mode.YUBICO else initial)
                    ticket(session, slot, config, (1, 1) if mode == Mode.YUBICO else initial + 1)
                    change(session, action)
                    session.select("otp")
                    position = (2, 0) if action == Action.POWER_CYCLE else (1, 2)
                    ticket(session, slot, config, position if mode == Mode.YUBICO else initial + 2)


def mutations(session):
    for slot, mode, operation in product(range(1, 5), MODES, ("UPDATE", "CONFIGURE", "refused-UPDATE", "refused-CONFIGURE", "refused-DELETE")):
        with session.case(f"otp.typed.mutation.slot-{slot}.{mode.name}.{operation}", ("Y02", "Y03", "Y04", "Y06", "Y09", "Y10", "Y14", "X11", "G10", "G13", "G14"), effects=("otp_extra_slots", "keyboard_output", "reboot") if slot > 2 else (f"replace_otp_slot_{slot}", "keyboard_output", "reboot"), parameters={"slot": slot, "mode": mode.name, "mutation": operation}):
            ready(session, mode)
            config = configuration(session, slot, mode, 65535)
            with fixture(session, Route.CARD, slot, config) as state:
                ticket(session, slot, config, (1, 0) if mode == Mode.YUBICO else 65535)
                change(session, Action.POWER_CYCLE)
                session.select("otp")
                ticket(session, slot, config, (2, 0) if mode == Mode.YUBICO else 65536)
                ticket(session, slot, config, (2, 1) if mode == Mode.YUBICO else 65537)
                update = operation.endswith("UPDATE")
                proposed = bytearray(config)
                proposed[38:44] = b"code-B"
                proposed[46] |= 32
                proposed = checksum(proposed)
                refused = operation.startswith("refused")
                data = bytes(52) if operation == "refused-DELETE" else proposed
                command, offset = address(slot, update=update)
                final = config if refused else merged(config, proposed) if update else proposed
                mutate(session, Route.CARD, command, data + (b"wrong!" if refused else b"code-A"), offset,
                    0x6982 if refused else 0x9000, not refused, committed=lambda: state.update(config=final))
                position = (1, 2) if operation == "CONFIGURE" else (2, 2)
                ticket(session, slot, final, position if mode == Mode.YUBICO else 65535 if operation == "CONFIGURE" else 65538)


def swaps(session):
    for (first, second), mode in product(combinations(range(1, 5), 2), MODES):
        with session.case(f"otp.typed.SWAP.{first}-{second}.{mode.name}", ("Y02", "Y03", "Y05", "Y06", "Y09", "Y10", "Y14", "G09", "G14"), effects=("otp_both_slots", "otp_extra_slots", "keyboard_output", "reboot"), parameters={"slots": [first, second], "mode": mode.name}):
            ready(session, mode)
            configs = {slot: configuration(session, slot, mode, 100 * slot) for slot in (first, second)}
            with ExitStack() as stack:
                states = {slot: stack.enter_context(fixture(session, Route.CARD, slot, configs[slot])) for slot in (first, second)}
                counts = {first: 2, second: 3}
                for slot in (first, second):
                    for index in range(counts[slot]):
                        ticket(session, slot, configs[slot], (1, index) if mode == Mode.YUBICO else 100 * slot + index)
                def committed():
                    states[first]["config"], states[second]["config"] = states[second]["config"], states[first]["config"]
                for number in (1, 2):
                    mutate(session, Route.CARD, 6, bytes([first - 1, second - 2]) + b"code-A", committed=committed)
                    for slot in (first, second):
                        previous = (second if slot == first else first) if number == 1 else slot
                        ticket(session, slot, states[slot]["config"], (1, counts[previous] + number - 1) if mode == Mode.YUBICO else 100 * previous + counts[previous] + number - 1)


def interruptions(session):
    for slot, mode, action in product(range(1, 5), MODES, (Action.USB_RECONNECT, Action.POWER_CYCLE)):
        with session.case(f"otp.typed.partial-observation.slot-{slot}.{mode.name}.{action.value}", ("Y09", "Y10", "Y11", "Y12", "Y14", "X11", "G11", "G12", "G14"), effects=("otp_extra_slots", "keyboard_output", "reboot") if slot > 2 else (f"replace_otp_slot_{slot}", "keyboard_output", "reboot"), parameters={"slot": slot, "mode": mode.name, "capture_limit": 1}):
            ready(session, mode)
            config = configuration(session, slot, mode)
            with fixture(session, Route.CARD, slot, config):
                ticket(session, slot, config, (1, 0) if mode == Mode.YUBICO else 0)
                frames, timestamps, _ = keyboard.listen(session, keyboard.gesture(session, slot), max_reports=1)
                text, pressed = keyboard.decode(frames, allow_held=True)
                session.check("partial observation contains an actual press", bool(text) and bool(pressed) and bool(timestamps))
                session.observe("partial_output", {"text": text, "reports": len(frames), "device_output_interrupted": None,
                    "scope": "host stopped observing before release; subsequent connection action has its own observed/reported interval"})
                change(session, action)
                session.select("otp")
                ticket(session, slot, config, ((2, 0) if action == Action.POWER_CYCLE else (1, 2)) if mode == Mode.YUBICO else 2)


def run(session):
    lifetimes(session)
    mutations(session)
    swaps(session)
    interruptions(session)
    session_wrap(session)


def session_wrap(session):
    for slot in range(1, 5):
        with session.case(f"otp.typed.Yubico-session-wrap.slot-{slot}", ("Y09", "Y12", "Y14", "G04", "G14"), effects=("otp_extra_slots", "keyboard_output", "reboot") if slot > 2 else (f"replace_otp_slot_{slot}", "keyboard_output", "reboot"), parameters={"slot": slot, "typed_positions": 257}):
            ready(session, Mode.YUBICO)
            config = configuration(session, slot, Mode.YUBICO)
            with fixture(session, Route.CARD, slot, config):
                for index in range(257):
                    ticket(session, slot, config, (1 + index // 256, index % 256))
