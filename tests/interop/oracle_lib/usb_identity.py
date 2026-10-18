# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Changed USB identities rebind only predeclared states and prove the retained key."""
from dataclasses import dataclass
from enum import Enum
import os
import time

from . import codec, phy_records, usb_ccid
from .binding import check_pair, require_pair, prove_credential
from .fido import info
from .fido_fixtures import credential
from .management_cases import read as management_read
from .runner import AIDS, CtapRoute
from .trace import Outcome, Reply, TransferError
from .transport import Hid, device_kind
from .vendor_cases import vendor

CCID, FIDO, KEYBOARD = 1, 4, 8
ALL_INTERFACES, MANAGEABLE = 31, CCID | FIDO
MASKS = range(256)
ATR_RSKEY = bytes.fromhex("3bfc1300008131fe158073c021c05652532d4b65794b")
ATR_YUBIKEY = bytes.fromhex("3bfd1300008131fe158073c021c057597562694b657940")


class Apply(Enum):
    RESCUE = "rescue-staged"
    FIDO = "FIDO-auto"


def surfaces(mask):
    effective = mask if mask & MANAGEABLE else ALL_INTERFACES
    return tuple(name for bit, name in ((KEYBOARD, "keyboard"), (FIDO, "hid"), (CCID, "card")) if effective & bit)


@dataclass(frozen=True)
class Identity:
    vid: int
    pid: int
    serial: str
    product: str
    manufacturer: str
    mask: int

    def matches(self, observed):
        roles = surfaces(self.mask)
        return (all(observed[key] == value for key, value in (("vendor_id", self.vid), ("product_id", self.pid),
            ("serial_number", self.serial), ("product_string", self.product), ("manufacturer_string", self.manufacturer)))
            and tuple(observed["classes"]) == tuple(usb_ccid.CCID_CLASS if role == "card" else 3 for role in roles)
            and observed["interface_numbers"] == list(range(len(roles))))


def read_device(device):
    import usb.util
    configuration = device.get_active_configuration()
    interfaces = sorted((interface for interface in configuration if not interface.bAlternateSetting), key=lambda interface: interface.bInterfaceNumber)
    classes = tuple(interface.bInterfaceClass for interface in interfaces)
    if any(value not in (3, usb_ccid.CCID_CLASS) for value in classes):
        raise TransferError("transition found an unexpected USB interface class", Outcome.HOST_REJECTED)
    strings = {name: usb.util.get_string(device, getattr(device, index)) if getattr(device, index) else "" for name, index in
        (("serial_number", "iSerialNumber"), ("product_string", "iProduct"), ("manufacturer_string", "iManufacturer"))}
    return {"vendor_id": device.idVendor, "product_id": device.idProduct, **strings, "bus": device.bus, "address": device.address,
        "configuration": configuration.bConfigurationValue, "interface_numbers": [interface.bInterfaceNumber for interface in interfaces],
        "classes": list(classes)}


def hid_inventory():
    import hid
    available = []
    for descriptor in hid.enumerate():
        path = descriptor["path"]
        path = path if isinstance(path, bytes) else os.fsencode(path)
        available.append({**{key: value for key, value in descriptor.items() if key != "path"}, "path_hex": path.hex()})
    return available


def read_candidates(identities):
    import usb.core
    found = []
    for vid, pid in dict.fromkeys((item.vid, item.pid) for item in identities):
        if vid == 0x534c:
            raise TransferError("wallet VID cannot be a transition target", Outcome.HOST_REJECTED)
        for device in usb.core.find(find_all=True, idVendor=vid, idProduct=pid):
            observed = read_device(device)
            if device_kind(observed) == "trezor":
                continue
            if any(item.serial == observed["serial_number"] for item in identities):
                found.append((device, observed))
    return found


def usb_status(session, device, timeout=None):
    def transfer(deadline, observe):
        import usb.core
        try:
            raw = bytes(device.ctrl_transfer(0x80, 0, 0, 0, 2, timeout=usb_ccid.timeout_ms(deadline, session.trace.now)))
        except usb.core.USBError as error:
            raise usb_ccid.usb_error(error) from error
        observe("rx", raw, api="libusb.standard.GET_STATUS", recipient="device")
        if len(raw) != 2:
            raise TransferError("standard device GET_STATUS did not return exactly two bytes", protocol="malformed_response")
        return Reply(raw)
    return session._exchange("usb", "usb_control", "transition.GET_STATUS", b"\x80\x00\x00\x00\x00\x00\x02\x00", session.options.timeout if timeout is None else timeout, transfer)


def detached(session, device):
    deadline = session.trace.now() + int(session.options.timeout * 1000000000)
    while session.trace.now() < deadline:
        try:
            usb_status(session, device, max(0.001, (deadline - session.trace.now()) / 1000000000))
        except TransferError as error:
            if error.outcome == Outcome.DISCONNECTED:
                session.check("changed PHY acknowledgment precedes observed USB removal", True)
                return
            raise
        time.sleep(0.05)
    session.check("changed PHY must actually disconnect the old USB instance", False)


def unique_hid(available, identity, number, usage_page):
    matches = [item for item in available if (item.get("vendor_id"), item.get("product_id"), item.get("serial_number"), item.get("interface_number"), item.get("usage_page")) ==
        (identity.vid, identity.pid, identity.serial, number, usage_page) and device_kind(item) != "trezor"]
    if len(matches) != 1:
        raise TransferError("transition HID selector is absent or ambiguous; no neighboring-device fallback", Outcome.HOST_REJECTED)
    return matches[0]


def open_bound(session, identities, retained):
    session.recovering = True
    session.values.pop("same_instance_confirmed", None)
    try:
        for name in ("hid", "card", "otp_hid", "keyboard"):
            interface = getattr(session, name)
            if interface is not None:
                interface.close()
                setattr(session, name, None)
        deadline = session.trace.now() + int(session.options.timeout * 1000000000)
        while True:
            found = []
            def enumerate_bound(deadline, observe):
                found.extend(read_candidates(identities))
                return Reply(b"")
            session._exchange("usb", "host_api", "transition.enumerate-predeclared-identities", b"", session.options.timeout, enumerate_bound)
            if len(found) > 1:
                raise TransferError("USB transition serial is ambiguous across predeclared identities; no neighboring-device fallback", Outcome.HOST_REJECTED)
            if found:
                device, observed = found[0]
                matching = [item for item in identities if item.matches(observed)]
                session.check("USB device matches a predeclared identity and interface topology", bool(matching))
                identity = matching[0]
                break
            if session.trace.now() >= deadline:
                raise TransferError("predeclared USB transition target did not re-enumerate before its deadline", Outcome.DEADLINE)
            time.sleep(0.05)
        roles = surfaces(identity.mask)
        descriptor = {**observed, "interface_number": roles.index("card") if "card" in roles else None, "profile": device_kind(observed)}
        relevant = []
        while any(role != "card" for role in roles):
            def enumerate_hid(deadline, observe):
                relevant.clear()
                relevant.extend(item for item in hid_inventory() if (item.get("vendor_id"), item.get("product_id"), item.get("serial_number")) == (identity.vid, identity.pid, identity.serial))
                return Reply(b"")
            session._exchange("usb", "host_api", "transition.enumerate-HID-usages", b"", session.options.timeout, enumerate_hid)
            counts = (sum(item.get("usage_page") == 0xf1d0 for item in relevant), sum((item.get("usage_page"), item.get("usage")) == (1, 6) for item in relevant))
            if counts == (int("hid" in roles), int("keyboard" in roles)):
                break
            if session.trace.now() >= deadline:
                raise TransferError("predeclared HID usage interfaces stayed absent or ambiguous", Outcome.HOST_REJECTED)
            time.sleep(0.05)
        session.check("USB transition exposes exactly the expected FIDO usage interface", sum(item.get("usage_page") == 0xf1d0 for item in relevant), int("hid" in roles))
        session.check("USB transition exposes exactly the expected keyboard usage interface", sum((item.get("usage_page"), item.get("usage")) == (1, 6) for item in relevant), int("keyboard" in roles))
        if "keyboard" in roles:
            unique_hid(relevant, identity, roles.index("keyboard"), 1)
        if "hid" in roles:
            selected = unique_hid(relevant, identity, roles.index("hid"), 0xf1d0)
            session.hid = Hid(selected, session.trace.now)
            session.hid.initialize(session.trace, session.options.timeout)
        if "card" in roles:
            session.card = usb_ccid.UsbCard(descriptor, session.trace.now, backend=device, operator=session.options.operator)
            session.card.initialize(session.trace, session.options.timeout)
        session.applet = None
        session.values.pop("fido.info", None)
        with session.route(CtapRoute.HID if session.hid is not None else CtapRoute.CARD):
            if session.ctap_route == CtapRoute.CARD:
                session.select("fido", required=True)
            prove_credential(session, retained)
        session.broken = False
        session.values.pop("halt_reason", None)
        if session.card is not None and session.hid is not None:
            check_pair(session)
        session.trace.emit("device_bound", session_id="usb-transition", device=observed,
            binding_evidence="unique predeclared VID/PID/serial/product/manufacturer/interfaces, HID usage and original private credential signature")
        session.observe("USB_transition_state", observed, "presence")
        return device, identity
    except BaseException:
        session.broken = True
        session.values["halt_reason"] = "USB transition identity is unproved; no restoration write was sent to an unproved device"
        raise
    finally:
        session.recovering = False


def ctap_vendor(session, subcommand, parameters):
    with session.route(CtapRoute.HID if session.hid is not None else CtapRoute.CARD):
        if session.ctap_route == CtapRoute.CARD:
            session.select("fido", required=True)
        return vendor(session, subcommand, parameters, authenticated=True)


def phy(session):
    return dict(codec.parse_tlv(session.ctap_value(ctap_vendor(session, 13, {1: 1}))[1]))


def warm_reboot(session):
    if session.hid is not None:
        session.card_value(session.hid_call(3, codec.apdu(0xa4, 4, data=AIDS["vendor"])))
        session.card_value(session.hid_call(3, codec.apdu(0x1f)))
    else:
        session.select("vendor", required=True)
        session.card_value(session.apdu(codec.apdu(0x1f)))


def public_identity(session, identity):
    if session.card is None:
        session.observe("CCID_identity_visibility", "interface is deliberately absent; ATR/OpenPGP identity cannot be read on HID alone")
        return
    session.check("CCID ATR follows the effective VID identity", session.card.atr, ATR_YUBIKEY if identity.vid == 0x1050 else ATR_RSKEY)
    management = management_read(session, "card")
    if int.from_bytes(management[3], "big") & 8:
        session.select("openpgp", required=True)
        aid = session.card_value(session.apdu(codec.apdu(0xca, 0, 0x4f)))
        session.check("OpenPGP identity is a complete AID", len(aid), 16)
        session.check("OpenPGP manufacturer follows effective VID", aid[8:10], b"\x00\x06" if identity.vid == 0x1050 else b"\xff\xfe")
        stable = aid[:8] + aid[10:]
        previous = session.values.setdefault("usb.identity.OpenPGP.serial-and-version", stable)
        session.check("changing USB identity preserves OpenPGP version and serial", stable, previous)


def transition(session, device, identity, payload, retained, *, staged=False):
    if staged:
        from .rescue_cases import active, request
        old = read_device(device)
        expected = phy_records.overlay(phy(session), payload)
        active(session)
        request(session, 0x1c, 1, data=payload)
        session.check("rescue stages the complete requested PHY before applying USB identity", phy(session), expected)
        session.check("rescue-staged identity leaves the currently enumerated descriptors unchanged", read_device(device), old)
        warm_reboot(session)
    else:
        session.ctap_value(ctap_vendor(session, 12, {1: 1, 2: payload}))
    detached(session, device)
    return open_bound(session, (identity,), retained)


def run(session):
    for mode in Apply:
        for mask in MASKS:
            with session.case(f"rsk.USB.identity-and-mask.{mode.value}.{mask:02x}", ("M03", "V09", "R03", "X08", "X11", "G11", "G12", "G14"),
                    effects=("config_change", "reboot", "session_recovery", "create_fido_credential"), touch=True,
                    parameters={"stored_USB_mask": mask, "effective_surfaces": surfaces(mask), "surviving_restoration_surface": "HID" if "hid" in surfaces(mask) else "CCID"}):
                session.require(session.profile == "rsk", "USB identity transitions require RS-Key", "excluded_by_profile")
                session.require(session.options.operator and isinstance(session.card, usb_ccid.UsbCard) and session.hid is not None, "USB transition needs both exact native CCID and FIDO HID selectors and operator")
                session.require(session.otp_hid is None and session.keyboard is None, "USB identity suite owns only the selected FIDO/CCID handles; run it without OTP/keyboard handles", "excluded_by_mode")
                require_pair(session)
                session.require(not info(session).get(4, {}).get("alwaysUv"), "transition continuity uses a silent UV-optional private credential")
                management = management_read(session, "card")
                session.require(management.get(10) == b"\x00", "USB identity fixture requires a known unlocked shared configuration")
                session.require(int.from_bytes(management[3], "big") & 512, "FIDO application must stay enabled for the surviving HID restoration path")
                session.require(not session.ctap_value(vendor(session, 5)).get(3), "USB boot transitions require an unwrapped persistent seed; an unknown lock key cannot authorize restoration")
                before = phy_records.read(session)
                device = session.card.device
                observed = read_device(device)
                session.require(bool(observed["serial_number"]), "USB identity transition needs an observed unique serial; no serial-less automatic fallback")
                baseline = Identity(observed["vendor_id"], observed["product_id"], observed["serial_number"], observed["product_string"], observed["manufacturer_string"], before.get(11, bytes([ALL_INTERFACES]))[0])
                session.require("hid" in surfaces(baseline.mask), "USB transition baseline needs its explicitly selected FIDO HID interface")
                selected_hid = session.hid.descriptor
                session.require((selected_hid.get("vendor_id"), selected_hid.get("product_id"), selected_hid.get("serial_number"), selected_hid.get("interface_number")) ==
                    (baseline.vid, baseline.pid, baseline.serial, surfaces(baseline.mask).index("hid")), "initial native CCID and HID selectors must share the observed USB identity before any write")
                session.require(baseline.matches(observed), "current USB descriptors do not match the declared RS-Key interface-order profile")
                public_identity(session, baseline)
                vid, pid = (0x1050, 0x0407) if (baseline.vid, baseline.pid) == (0x1209, 0xf1d2) else (0x1209, 0xf1d2)
                target = Identity(vid, pid, baseline.serial, "RS-Key Oracle Test", "Oracle", mask)
                found = []
                def preflight(deadline, observe):
                    found.extend(read_candidates((baseline, target)))
                    return Reply(b"")
                session._exchange("usb", "host_api", "transition.preflight-unique-identities", b"", session.options.timeout, preflight)
                session.require(len(found) == 1 and (found[0][1]["bus"], found[0][1]["address"]) == (observed["bus"], observed["address"]),
                    "predeclared transition identities must resolve uniquely to the selected physical USB instance before any write")
                desired = {**before, 0: vid.to_bytes(2, "big") + pid.to_bytes(2, "big"), 6: (int.from_bytes(before[6], "big") ^ 8).to_bytes(2, "big"),
                    9: target.product.encode() + b"\x00", 11: bytes([mask]), 15: target.manufacturer.encode() + b"\x00"}
                restore = {**before, **({0: baseline.vid.to_bytes(2, "big") + baseline.pid.to_bytes(2, "big")} if 0 not in before else {}),
                    **({11: bytes([baseline.mask])} if 11 not in before else {})}
                restore_wire = b"".join(phy_records.tlv(tag, value) for tag, value in {**restore, **{tag: b"\x00" for tag in (9, 15) if tag not in before}}.items())
                payload = b"".join(phy_records.tlv(tag, value) for tag, value in desired.items())
                with credential(session, session.current.name, extensions={"credProtect": 1}) as retained:
                    attempted = False
                    try:
                        attempted = True
                        device, _ = transition(session, device, target, payload, retained, staged=mode == Apply.RESCUE)
                        public_identity(session, target)
                        session.check("rebound PHY retains every requested field despite changed USB identity/interfaces", phy(session), desired)
                    finally:
                        if attempted:
                            try:
                                if session.broken:
                                    device, _ = open_bound(session, (baseline, target), retained)
                                session.trace.phase = "cleanup"
                                current = phy(session)
                                if current != restore:
                                    device, _ = transition(session, device, baseline, restore_wire, retained)
                                elif not baseline.matches(read_device(device)):
                                    warm_reboot(session)
                                    detached(session, device)
                                    device, _ = open_bound(session, (baseline,), retained)
                                session.check("USB identity and interface topology return to the observed baseline", baseline.matches(read_device(device)))
                                public_identity(session, baseline)
                                session.check("complete original PHY fields and observed default identity are restored", phy(session), restore)
                                if 0 not in before or 11 not in before:
                                    session.observe("cleanup_limit", {"retained_default_overrides": sorted(set(restore) - set(before)),
                                        "reason": "numeric PHY fields cannot be deleted; observed original USB identity and known default mask remain as explicit overrides"})
                            except BaseException:
                                session.broken = True
                                session.values["halt_reason"] = "USB identity/PHY restoration was not verified; no following mutation is permitted"
                                raise
