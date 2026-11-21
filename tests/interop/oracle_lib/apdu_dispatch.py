# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Raw CCID distinguishes an unanswered class from an applet status word."""
from itertools import product

from . import codec
from .apdu_matrix import collect
from .ccid_matrix import message, raw
from .openpgp_lifecycle import fixture_session
from .runner import AIDS
from .timers import wait

READS = {"piv": (0xfd, 0, 0, b""), "openpgp": (0xca, 0, 0x4f, b""), "oath": (0xa1, 0, 0, b""),
    "otp": (3, 0, 0, b""), "management": (0x1d, 0, 0, b""), "vendor": (2, 0, 0, b""),
    "rescue": (0x1e, 8, 0, b""), "fido": (0x11, 0, 0, b"")}
CHAIN_BYTES = 3072
DO_BYTES = 2048


def require(session):
    session.require(session.profile == "rsk", "CCID class/chain grammar requires RS-Key", "excluded_by_profile")
    session.require(session.card is not None and hasattr(session.card, "raw"), "raw CCID is required to observe empty data blocks independently of PC/SC", "excluded_by_mode")


def exchange(session, apdu):
    sequence = session.card.sequence
    session.card.sequence = (sequence + 1) & 255
    reply = raw(session, message(body=apdu, sequence=sequence), session.options.timeout)
    data = reply.data
    session.check("APDU raw reply has the matching slot and sequence", (data[5], data[6]), (0, sequence))
    session.check("raw CCID length describes exactly the observed body", int.from_bytes(data[1:5], "little"), len(data) - 10)
    return data


def body(session, wire):
    data = exchange(session, wire)
    session.check("complete APDU is framed as a successful CCID DataBlock", (data[0], data[7] & 0xc0), (0x80, 0))
    return data[10:]


def control(session, applet):
    session.select(applet, required=True)
    ins, p1, p2, data = READS[applet]
    return body(session, codec.apdu(ins, p1, p2, data, cla=0x80 if applet == "rescue" else 0))


def classes(session):
    for applet, cla, selecting in product(READS, range(256), (False, True)):
        with session.case(f"transport.APDU.class.{applet}.{cla:02x}.SELECT-{selecting}",
                ("T11", "T12", "G04", "G10", "G12", "G14"), effects=("malformed_known_command",)):
            require(session)
            before = control(session, applet)
            ins, p1, p2, data = (0xa4, 4, 0, AIDS[applet]) if selecting else READS[applet]
            result = body(session, codec.apdu(ins, p1, p2, data, cla=cla))
            if cla & 0x10:
                session.check("chaining class acknowledges a segment without executing it", result, b"\x90\x00")
            elif cla not in (0, 4, 0x80, 0x84):
                session.check("unserved class has an actual empty DataBlock and no invented status", result, b"")
            elif not selecting and (cla in (4, 0x84) or applet == "rescue" and cla != 0x80):
                session.check("served but unsupported class has the applet class status", result, b"\x6e\x00")
            elif not selecting:
                session.check("basic class reaches the same command and value", result, before)
            else:
                session.check("served SELECT is acknowledged", result[-2:], b"\x90\x00")
            session.check("SELECT abandons a class probe and preserves the public control", control(session, applet), before)


def malformed():
    for size in range(4):
        yield f"header-{size}", b"\x00\x7e\x00\x00"[:size], True
    for label, tail in (("short-Lc-underflow", b"\x02x"), ("short-extra-tail", b"\x01xyz"),
            ("extended-Lc-underflow", b"\x00\x00\x02x"), ("extended-extra-tail", b"\x00\x00\x01xyzq"),
            ("extended-missing-length", b"\x00\x01xq")):
        yield label, b"\x00\x7e\x00\x00" + tail, False


def grammar(session):
    for applet in READS:
        for label, wire, reader_error in malformed():
            with session.case(f"transport.APDU.malformed.{applet}.{label}", ("T11", "G03", "G05", "G14"), effects=("malformed_known_command",)):
                require(session)
                before = control(session, applet)
                data = exchange(session, wire)
                expected = (0x81, 0x40, 1, b"") if reader_error else (0x80, 0, 0, b"\x67\x00")
                session.check("short reader envelope and malformed APDU have distinct refusal layers", (data[0], data[7] & 0xc0, data[8], data[10:]), expected)
                session.check("malformed APDU preserves selected command data", control(session, applet), before)
        for ins, cla in product((0x7e, 0x7f), (0, 0x80)):
            with session.case(f"transport.APDU.unknown-INS.{applet}.{ins:02x}.{cla:02x}", ("T11", "G04", "G14")):
                require(session)
                before = control(session, applet)
                expected = b"\x6e\x00" if applet == "rescue" and cla == 0 else b"\x6d\x00"
                session.check("known profile's unsupported instruction is distinct from class refusal", body(session, codec.apdu(ins, cla=cla)), expected)
                session.check("unsupported instruction preserves command data", control(session, applet), before)


def chains(session):
    for total, final in product((0, 1, DO_BYTES - 1, DO_BYTES, DO_BYTES + 1, CHAIN_BYTES - 1, CHAIN_BYTES, CHAIN_BYTES + 1), (False, True)):
        with session.case(f"transport.APDU.chain-ceiling.total-{total}.final-{final}", ("T12", "O07", "G03", "G11", "G14"), effects=("write_and_restore_openpgp_DO",)):
            require(session)
            sdk = fixture_session(session)
            original = sdk.get_data(0x5e)
            value = session.fixture("APDU.chain-limit", total)
            try:
                sent, last = 0, None
                pieces = [value[offset:offset + 255] for offset in range(0, total, 255)] or [b""]
                for index, piece in enumerate(pieces):
                    terminal = final and index == len(pieces) - 1
                    last = session.apdu(codec.apdu(0xda, 0, 0x5e, piece, cla=0 if terminal else 0x10))
                    sent += len(piece)
                    expected = 0x6700 if sent > CHAIN_BYTES or sent == CHAIN_BYTES and not terminal else 0x6a80 if terminal and total > DO_BYTES else 0x9000
                    session.check("incoming chain ceiling is independent of final object dispatch", last.status, expected)
                    if expected != 0x9000:
                        break
                session.select("openpgp")
                committed = final and total <= DO_BYTES
                session.check("only a complete in-bounds chain can change the owned DO", collect(session, session.apdu(codec.apdu(0xca, 0, 0x5e))), value if committed else original)
                session.check("completed/abandoned chain does not absorb another command", session.apdu(codec.apdu(0x84, le=8)).status, 0x9000)
            finally:
                if not session.broken:
                    session.trace.phase = "cleanup"
                    session.select("openpgp")
                    sdk.verify_admin(session.options.openpgp_admin)
                    sdk.put_data(0x5e, original)
    for defect in ("INS", "P1", "P2", "CLA", "same-SELECT", "other-SELECT", "invalid-SELECT", "unserved-class", "idle", "repeated-final"):
        with session.case("transport.APDU.chain-abandonment." + defect, ("T12", "O07", "G10", "G11", "G12", "G14"), effects=("write_and_restore_openpgp_DO",)):
            require(session)
            sdk = fixture_session(session)
            original, prefix, suffix = sdk.get_data(0x5e), b"oracle-prefix", b"oracle-suffix"
            try:
                session.card_value(session.apdu(codec.apdu(0xda, 0, 0x5e, prefix, cla=0x10)))
                if defect.endswith("SELECT"):
                    aid = AIDS["piv"] if defect == "other-SELECT" else b"\xff" * 5 if defect == "invalid-SELECT" else AIDS["openpgp"]
                    session.check("SELECT is an explicit chain escape even when its AID is refused", session.apdu(codec.apdu(0xa4, 4, data=aid)).status, 0x6a82 if defect == "invalid-SELECT" else 0x9000)
                    session.select("openpgp")
                    session.check("abandoned chain leaves owned value intact", sdk.get_data(0x5e), original)
                elif defect in ("INS", "P1", "P2", "CLA"):
                    header = [0xda, 0, 0x5e, 0]
                    index = {"INS": 0, "P1": 1, "P2": 2, "CLA": 3}[defect]
                    header[index] ^= 0x80 if defect == "CLA" else 1
                    result = session.apdu(codec.apdu(*header[:3], suffix, cla=header[3]))
                    session.check("mismatched final segment is refused and never dispatched", result.status, 0x6883)
                    session.check("mismatch preserves complete old value", sdk.get_data(0x5e), original)
                else:
                    if defect == "unserved-class":
                        session.check("unanswered class cannot abandon an existing command chain", body(session, codec.apdu(0x7e, cla=0x40)), b"")
                    elif defect == "idle":
                        wait(session, 1.1)
                    session.card_value(session.apdu(codec.apdu(0xda, 0, 0x5e, suffix)))
                    session.check("matching final segment receives only its own accumulated prefix", sdk.get_data(0x5e), prefix + suffix)
                    if defect == "repeated-final":
                        session.card_value(session.apdu(codec.apdu(0xda, 0, 0x5e, suffix)))
                        session.check("a repeated final APDU is a standalone write", sdk.get_data(0x5e), suffix)
            finally:
                if not session.broken:
                    session.trace.phase = "cleanup"
                    session.select("openpgp")
                    sdk.verify_admin(session.options.openpgp_admin)
                    sdk.put_data(0x5e, original)


def run(session):
    classes(session)
    grammar(session)
    chains(session)
