# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Establish cross-interface serial agreement before state-sharing scenarios."""
import os

from . import codec


def confirm(session):
    if session.hid is None or session.card is None:
        return
    with session.case("binding.HID-card.serial-agreement", ("T01",)):
        check_pair(session)
    if session.trace.cases[-1]["verdict"] != "pass":
        session.broken = True
        raise ValueError("selected interfaces could not be bound to one instance; capture aborted")


def check_pair(session):
    session.values.pop("same_instance_confirmed", None)
    session.require(session.profile in ("rsk", "yubikey"), "multi-interface binding requires a confirmed identity protocol", "unknown")
    hid = session.hid_call(0x42, name="binding.HID.DeviceInfo")
    session.check("HID identity request completed", hid.protocol, "success")
    session.select("management")
    card = session.card_value(session.apdu(codec.apdu(0x1D), "binding.card.DeviceInfo"))
    for body in (hid.data, card):
        session.check("binding DeviceInfo length", bool(body) and body[0] == len(body) - 1)
    hid_serial = dict(codec.parse_tlv(hid.data[1:])).get(2)
    card_serial = dict(codec.parse_tlv(card[1:])).get(2)
    session.check("both interfaces expose a serial", hid_serial is not None and len(hid_serial) == 4 and card_serial is not None)
    session.check("HID and card protocol serial agreement", hid_serial, card_serial)
    previous = session.values.get("binding.serial")
    if previous is not None:
        session.check("reconnected interfaces retain original protocol identity", hid_serial, previous)
    session.values["binding.serial"] = hid_serial
    session.values["same_instance_confirmed"] = True
    session.observe("binding_basis", "protocol serial agreement and explicit interface selectors; not cryptographic device authentication")


def rebind(descriptor, surface, operator=False):
    from .transport import inventory, select_hid
    from .trace import Outcome, TransferError
    available = inventory()[surface]
    serial = descriptor.get("serial_number")
    matches = [item for item in available if serial and item.get("serial_number") == serial
               and all(item.get(key) == descriptor.get(key) for key in ("vendor_id", "product_id", "interface_number", "profile"))]
    if serial:
        if len(matches) != 1:
            raise TransferError("replug binding is absent or ambiguous; no neighboring-device fallback", Outcome.HOST_REJECTED)
        return matches[0]
    if not operator:
        raise TransferError("serial-less interface requires an explicit new selector", Outcome.HOST_REJECTED)
    import sys
    for item in available:
        print(f"oracle: rebind candidate {item['id']} {item.get('product_string')}", file=sys.stderr)
    selected = select_hid(available, input("oracle: exact selector for the replugged test interface: ").strip())
    if selected["profile"] != descriptor["profile"]:
        raise TransferError("replug changed device family", Outcome.HOST_REJECTED)
    return selected


def require_pair(session):
    session.require(session.values.get("same_instance_confirmed") is True,
                    "cross-interface case requires the recorded binding identity check")


def prove_credential(session, retained):
    from .fido import auth_data, verified
    policy = session.ctap_value(session.ctap(4))
    session.check("identity continuity control does not ask an unproved device for local PIN entry", not policy.get(4, {}).get("alwaysUv"))
    query = retained.query(session, authenticate=False, options={"up": False, "uv": False})
    query[2] = os.urandom(32)
    value = session.ctap_value(session.ctap(2, query))
    signed = auth_data(value[2])
    session.check("rebound interface retains the fixture RP binding", signed["rp_hash"], retained.parsed["rp_hash"])
    verified(session, "rebound USB identity proves the original private credential before any PIN/config write", retained.key, retained.algorithm, value[3], value[2] + query[2])
