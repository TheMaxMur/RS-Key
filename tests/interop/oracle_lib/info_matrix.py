# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Discovery declarations and key agreement lifetimes have executable controls."""
from cryptography.hazmat.primitives.asymmetric import ec

from .fido import info
from .fido_fixtures import credential
from .lifecycle import Action, change
from .transport import HID_INIT


def stable(value):
    return {key: item for key, item in value.items() if key not in (25, 30)}


def shape(session, value):
    session.check("getInfo is a map with integer keys", type(value) is dict and all(type(key) is int for key in value))
    for key in (1, 2, 6, 9):
        if key in value:
            session.check(f"getInfo list {key} has no duplicate entries", len(value[key]), len(set(value[key])))
    session.check("versions are nonempty strings", bool(value.get(1)) and all(type(item) is str and item for item in value[1]))
    session.check("AAGUID has its fixed width", len(value.get(3, b"")), 16)
    options = value.get(4, {})
    session.check("options have boolean values", type(options) is dict and all(type(item) is bool for item in options.values()))
    session.check("PIN/UV protocols use supported values", bool(value.get(6)) and set(value[6]).issubset({1, 2}))
    session.check("advertised message size is positive", type(value.get(5)) is int and value[5] > 0)
    algorithms = value.get(10, [])
    session.check("algorithm declarations are complete", bool(algorithms) and all(row.get("type") == "public-key" and type(row.get("alg")) is int for row in algorithms))
    session.check("algorithm declarations are distinct", len(algorithms), len({row["alg"] for row in algorithms}))
    if "uv" in options:
        session.check("configured local UV implies a configured PIN", not options["uv"] or options.get("clientPin") is True)
    session.check("large-blob extension designs are mutually exclusive", not {"largeBlob", "largeBlobKey"}.issubset(set(value.get(2, []))))
    if options.get("largeBlobs"):
        session.check("large-blob command reports its store bound", type(value.get(11)) is int and value[11] >= 17)
    if "largeBlob" in value.get(2, []):
        session.check("extension-only blob build omits the command option", "largeBlobs" not in options)
    if session.profile == "rsk":
        session.check("RS-Key version strings follow the defined CTAP names", "FIDO_2_3" in value[1] and "FIDO_2_2" not in value[1])
        session.check("U2F advertisement follows its active UV gate", "U2F_V2" in value[1], not options.get("alwaysUv") or options.get("uv", False))
        session.check("PIN floor and byte ceiling are coherent", 4 <= value.get(13, 0) <= value.get(29, 0) == 63)
        session.check("read-only encrypted member widths are complete", all(len(value[key]) == 32 for key in (25, 30) if key in value))


def agreement(session, version):
    value = session.ctap_value(session.ctap(6, {1: version, 2: 2}))[1]
    session.check("key agreement COSE identity", (value.get(1), value.get(3), value.get(-1)), (2, -25, 1))
    session.check("key agreement coordinates have fixed width", (len(value.get(-2, b"")), len(value.get(-3, b""))), (32, 32))
    ec.EllipticCurvePublicNumbers(int.from_bytes(value[-2], "big"), int.from_bytes(value[-3], "big"), ec.SECP256R1()).public_key()
    session.check("agreement point lies on the selected curve", True)
    return value


def discovery(session):
    for payload in (b"", b"\xa0", b"\x00", b"\xff", b"\xa0\x00"):
        with session.case("fido.getInfo.consistency.body-" + (payload.hex() or "absent"), ("F01", "G01", "G05", "G14")):
            value = session.ctap_value(session.ctap(4))
            shape(session, value)
            result = session.ctap_value(session.ctap(4, raw=payload))
            session.check("getInfo trailing body has no command semantics", stable(result), stable(value))
            session.observe("getInfo", value)


def lifetimes(session):
    for action in ("same-protocol", "other-protocol", "INIT", "same-SELECT", "other-SELECT", *Action):
        label = action.value if isinstance(action, Action) else action
        with session.case("fido.key-agreement.lifetime." + label, ("F03", "F09", "X01", "X11", "G14"),
                effects=("create_fido_credential", "reboot") if action == Action.POWER_CYCLE else ("create_fido_credential",), touch=True):
            session.require(session.profile == "rsk", "key agreement connection contract requires RS-Key", "excluded_by_profile")
            session.require({1, 2}.issubset(info(session).get(6, [])), "both PIN protocols needed", "unsupported_confirmed")
            with credential(session, session.current.name) as fixture:
                first = agreement(session, 1)
                if action == "INIT":
                    session.require(session.hid is not None and hasattr(session.hid, "cid"), "raw HID INIT unavailable", "excluded_by_mode")
                    nonce = session.fixture("agreement.INIT", 8)
                    session.check("INIT control nonce", session.hid_call(HID_INIT, nonce).data[:8], nonce)
                elif action in ("same-SELECT", "other-SELECT"):
                    session.select("fido")
                    session.select("fido" if action == "same-SELECT" else "piv")
                elif isinstance(action, Action):
                    change(session, action)
                after = agreement(session, 2 if action == "other-protocol" else 1)
                session.check("agreement lifetime follows power rather than host session", after != first, action == Action.POWER_CYCLE)
                fixture.assertion(session)


def run(session):
    discovery(session)
    lifetimes(session)
