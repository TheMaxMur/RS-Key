# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Native fake USB endpoints change descriptors only on a real modeled reboot."""
import pytest
import usb.core
import usb.util

import oracle
from oracle_lib import codec, usb_ccid, usb_identity
from oracle_lib.runner import AIDS, Options, Session
from oracle_lib.trace import Outcome, Reply, Trace, TransferError
from test_oracle_config_matrix import Peer as PinPeer
from test_oracle_expanded import apdu_parts
from test_oracle_phy_records import Card as PhyPeer
from test_oracle_usb_ccid import Device, Endpoint, response


class Interface:
    bAlternateSetting = 0

    def __init__(self, device, index, role):
        self.bInterfaceNumber = index
        self.bInterfaceClass = 0x0b if role == "card" else 3
        self.endpoints = [Bulk(device, 0x81), Bulk(device, 2)] if role == "card" else []

    def __iter__(self):
        return iter(self.endpoints)


class Configuration:
    bConfigurationValue = 1

    def __init__(self, device, roles):
        self.interfaces = [Interface(device, index, role) for index, role in enumerate(roles)]

    def __iter__(self):
        return iter(self.interfaces)

    def __getitem__(self, pair):
        return self.interfaces[pair[0]]


def roles(mask):
    if mask & 5 == 0:
        mask = 31
    return [name for bit, name in ((8, "keyboard"), (4, "hid"), (1, "card")) if mask & bit]


class Usb(Device):
    def __init__(self, model, address):
        super().__init__()
        self.model, self.alive, self.address = model, True, address
        fields = model.phy.fields
        vid_pid = fields.get(0, model.defaults[0])
        self.idVendor, self.idProduct = int.from_bytes(vid_pid[:2], "big"), int.from_bytes(vid_pid[2:], "big")
        self.strings = {1: fields.get(15, model.defaults[15]).rstrip(b"\x00").decode(), 2: fields.get(9, model.defaults[9]).rstrip(b"\x00").decode(), 3: "offline-key"}
        self.roles = roles(31 if model.fault == "mask-ignored" else fields.get(11, b"\x1f")[0])
        self.configuration = Configuration(self, self.roles)

    def is_kernel_driver_active(self, interface):
        assert self.roles[interface] == "card"
        return False

    def get_active_configuration(self):
        if not self.alive:
            raise usb.core.USBError("old USB device disconnected", error_code=-4, errno=19)
        return self.configuration

    def ctrl_transfer(self, request_type, request, value, index, size, timeout):
        assert (request_type, request, value, index, size) == (0x80, 0, 0, 0, 2) and timeout > 0
        if self.model.pending:
            self.model.reboot()
        if not self.alive:
            raise usb.core.USBError("old USB device disconnected", error_code=-4, errno=19)
        return b"\x00\x00"


class Bulk(Endpoint):
    def write(self, wire, timeout):
        wire = bytes(wire)
        self.device.writes.append((wire, timeout))
        if wire[0] == 0x6f:
            body = self.device.model.apdu(wire[10:]).data
        else:
            label = "3bfd1300008131fe158073c021c057597562694b657940" if self.device.idVendor == 0x1050 and self.device.model.fault != "ATR-stuck-RS-Key" else "3bfc1300008131fe158073c021c05652532d4b65794b"
            body = bytes.fromhex(label) if wire[0] == 0x62 else b""
        packet = response(0x80 if wire[0] in (0x6f, 0x62) else 0x81, wire[6], body)
        self.device.queue.extend(packet[at:at + 64] for at in range(0, len(packet), 64))
        return len(wire)


class Model:
    def __init__(self, fault, sparse=False):
        self.fault, self.phy, self.pin = fault, PhyPeer(), PinPeer()
        self.phy.fields[15] = b"Original manufacturer\x00"
        self.defaults = {tag: self.phy.fields[tag] for tag in (0, 9, 15)}
        if sparse:
            for tag in self.defaults:
                self.phy.fields.pop(tag)
            self.phy.fields.pop(11)
        self.selected, self.pending, self.address = "fido", False, 7
        self.writes, self.silent_queries = [], 0
        self.cached_silent = None
        self.device = Usb(self, self.address)
        self.initial = dict(self.phy.fields)

    def reboot(self):
        self.pending = False
        self.device.alive = False
        self.address += 1
        self.device = Usb(self, self.address)
        if self.fault == "identity-loses-key":
            self.pin.records.clear()

    def cbor(self, wire):
        if wire[0] == 0x41:
            fields = codec.decode(wire[1:])
            assert fields[1] in (5, 12, 13)
            if fields[1] == 5:
                return Reply(b"\x00" + codec.encode({1: False, 2: True, 3: False}), status=0)
            if fields[1] == 12:
                payload = fields[2][2]
                self.writes.append(("FIDO", payload))
                self.phy.transfer(codec.apdu(0x1c, 1, data=payload, cla=0x80), 0, lambda *args: None)
                if self.fault == "restore-corrupts-PHY" and self.phy.fields[0] == self.defaults[0]:
                    self.phy.fields[4] = b"\x22"
                self.pending = True
                return Reply(b"\x00", status=0)
            body = b"".join(bytes([tag, len(value)]) + value for tag, value in sorted(self.phy.fields.items()))
            return Reply(b"\x00" + codec.encode({1: body, 2: {4: 17, 12: 3, 8: 30}}), status=0)
        if wire[0] == 2:
            fields = codec.decode(wire[1:])
            if fields.get(5, {}).get("up") is False:
                self.silent_queries += 1
                assert 6 not in fields, "unproved rebound key must never receive a PIN token"
                if self.fault == "replays-old-continuity-proof" and self.cached_silent is not None:
                    return self.cached_silent
                self.cached_silent = self.pin.transfer(0x10, wire, 0, lambda *args: None)
                return self.cached_silent
        return self.pin.transfer(0x10, wire, 0, lambda *args: None)

    def apdu(self, wire):
        ins, p1, p2, data = apdu_parts(wire)
        if ins == 0xa4:
            self.selected = next(name for name, aid in AIDS.items() if data == aid)
            return Reply(b"\x90\x00", status=0x9000)
        if self.selected == "management":
            assert ins == 0x1d
            fields = codec.tlv(2, (17).to_bytes(4, "big")) + codec.tlv(3, b"\x02\x08") + codec.tlv(10, b"\x00")
            return Reply(bytes([len(fields)]) + fields + b"\x90\x00", status=0x9000)
        if self.selected == "openpgp":
            assert (ins, p1, p2) == (0xca, 0, 0x4f)
            manufacturer = b"\x00\x06" if self.device.idVendor == 0x1050 and self.fault != "OpenPGP-manufacturer-stuck" else b"\xff\xfe"
            return Reply(AIDS["openpgp"] + b"\x03\x04" + manufacturer + b"\x00\x00\x00\x17\x00\x00\x90\x00", status=0x9000)
        if self.selected == "vendor":
            assert ins == 0x1f
            self.pending = True
            return Reply(b"\x90\x00", status=0x9000)
        if self.selected == "fido":
            assert ins == 0x10
            return Reply(self.cbor(data).data + b"\x90\x00", status=0x9000)
        if ins == 0x1c:
            self.writes.append(("rescue", data))
        return self.phy.transfer(wire, 0, lambda *args: None)

    def descriptors(self):
        result = []
        for index, role in enumerate(self.device.roles):
            if role == "card":
                continue
            result.append({"vendor_id": self.device.idVendor, "product_id": self.device.idProduct, "serial_number": "offline-key",
                "interface_number": index, "usage_page": 0xf1d0 if role == "hid" else 1, "usage": 1 if role == "hid" else 6,
                "product_string": self.device.strings[2], "manufacturer_string": self.device.strings[1], "path_hex": bytes([self.address, index]).hex(), "profile": "rsk"})
        return result


class Hid:
    layer, active = "offline_USB_identity_HID", False

    def __init__(self, model, descriptor):
        self.model, self.descriptor = model, descriptor

    def initialize(self, trace, timeout):
        trace.emit("session_opened", session_id="hid", backend="offline_USB_transition")

    def close(self):
        pass

    def transfer(self, command, wire, deadline, observe):
        if command == 0x42:
            body = codec.tlv(2, (17).to_bytes(4, "big"))
            result = Reply(bytes([len(body)]) + body)
        elif command == 3:
            ins = apdu_parts(wire)[0]
            if ins == 0x1f:
                self.model.pending = True
            result = Reply(b"\x90\x00", status=0x9000)
        else:
            result = self.model.cbor(wire)
        observe("tx", wire)
        observe("rx", result.data)
        return result


@pytest.mark.parametrize("fault,sparse,needle", [(None, False, None), (None, True, None), ("mask-ignored", False, "predeclared identity and interface topology"),
    ("identity-loses-key", False, "CTAP success"), ("replays-old-continuity-proof", False, "InvalidSignature"),
    ("ATR-stuck-RS-Key", False, "CCID ATR follows"), ("OpenPGP-manufacturer-stuck", False, "manufacturer follows effective VID"),
    ("restore-corrupts-PHY", False, "complete original PHY fields"),
    ("initial-HID-neighbor", False, None)])
def test_actual_native_USB_identity_masks_rebind_and_restore_with_private_key_continuity(tmp_path, monkeypatch, fault, sparse, needle):
    model = Model(fault, sparse)
    monkeypatch.setattr(usb_identity, "MASKS", (0, 1, 4, 5, 8, 9, 12, 13, 255))
    monkeypatch.setattr(usb_identity, "hid_inventory", model.descriptors)
    monkeypatch.setattr(usb_identity, "Hid", lambda descriptor, clock: Hid(model, descriptor))
    monkeypatch.setattr(usb.util, "get_string", lambda device, index: device.strings[index])
    monkeypatch.setattr(usb.util, "claim_interface", lambda *args: None)
    monkeypatch.setattr(usb.util, "release_interface", lambda *args: None)
    monkeypatch.setattr(usb.util, "dispose_resources", lambda *args: None)
    def find(**kwargs):
        return [model.device] if (kwargs["idVendor"], kwargs["idProduct"]) == (model.device.idVendor, model.device.idProduct) else []
    monkeypatch.setattr(usb.core, "find", find)
    trace = Trace(tmp_path / "USB-identity", {})
    descriptor = {**usb_identity.read_device(model.device), "interface_number": 2, "profile": "rsk"}
    card = usb_ccid.UsbCard(descriptor, trace.now, backend=model.device, operator=True)
    card.initialize(trace, 15)
    initial_hid = model.descriptors()[1]
    if fault == "initial-HID-neighbor":
        initial_hid = {**initial_hid, "product_id": 65535}
    session = Session(trace, card=card, hid=Hid(model, initial_hid), profile="rsk", options=Options(exercise=True, touch=True,
        operator=True, pin="fixture-PIN", allow_effects=("config_change", "reboot")))
    session.values["same_instance_confirmed"] = True
    oracle.execute(session, ["usb-identity"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if fault == "initial-HID-neighbor":
        assert not model.writes and not failures
        assert all(row["applicability"] == "blocked_by_precondition" and "share the observed USB identity" in row["reason"] for row in trace.cases)
        return
    if needle:
        assert any(needle in reason for _, reason in failures), failures[:20]
        if fault == "identity-loses-key":
            assert len(model.writes) == 1, "no restoration write may reach an unproved rebound key"
        elif fault == "replays-old-continuity-proof":
            assert failures[0][0].endswith(".00") and len(model.writes) == 2, "replayed first-case proof must fail before any next-case mutation"
        elif fault in ("ATR-stuck-RS-Key", "OpenPGP-manufacturer-stuck"):
            assert model.phy.fields == model.initial, "a proved key must still restore after public identity assertions fail"
        elif fault == "restore-corrupts-PHY":
            assert failures[0][0].endswith(".00") and len(model.writes) == 2
            assert session.broken and all(row["verdict"] == "inconclusive" for row in trace.cases[1:])
    else:
        assert trace.cases and all(row["verdict"] == "pass" for row in trace.cases), failures[:20]
        assert model.phy.fields == ({**model.initial, 0: model.defaults[0], 11: b"\x1f"} if sparse else model.initial)
        assert model.silent_queries >= 2 * len(trace.cases)


@pytest.mark.parametrize("mask", range(256))
def test_every_mask_preserves_a_real_manageable_interface_and_does_not_invent_WCID_or_LWIP(mask):
    expected = mask if mask & 5 else 31
    assert usb_identity.surfaces(mask) == tuple(name for bit, name in ((8, "keyboard"), (4, "hid"), (1, "card")) if expected & bit)
    assert set(usb_identity.surfaces(mask)) & {"card", "hid"}


def test_USB_transition_never_selects_a_neighbor_with_an_almost_matching_identity():
    identity = usb_identity.Identity(0x1209, 0xf1d2, "owner", "RS-Key", "RS-Key", 4)
    wanted = {"vendor_id": identity.vid, "product_id": identity.pid, "serial_number": identity.serial, "interface_number": 0, "usage_page": 0xf1d0}
    for key, changed in (("serial_number", "neighbor"), ("interface_number", 1), ("vendor_id", 0x534c)):
        with pytest.raises(TransferError, match="absent or ambiguous"):
            usb_identity.unique_hid([{**wanted, key: changed}], identity, 0, 0xf1d0)
    with pytest.raises(TransferError, match="absent or ambiguous"):
        usb_identity.unique_hid([wanted, wanted], identity, 0, 0xf1d0)


def test_wallet_USB_transition_target_is_rejected_before_enumerating(monkeypatch):
    monkeypatch.setattr(usb.core, "find", lambda **kwargs: pytest.fail("wallet VID must not be enumerated"))
    with pytest.raises(TransferError, match="wallet VID"):
        usb_identity.read_candidates((usb_identity.Identity(0x534c, 1, "wallet", "Trezor", "SatoshiLabs", 4),))
