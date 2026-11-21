# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Native CCID framing/control runs against fake USB endpoints, never hardware."""
import pytest
import usb.core
import usb.util

import oracle
from oracle_lib import usb_ccid
from oracle_lib.trace import Outcome, TransferError, recover

DESCRIPTOR = {"id": "ccid-test", "location": "3:7:1:2", "vendor_id": 0x1209, "product_id": 0xf1d2,
    "bus": 3, "address": 7, "ports": [2], "configuration": 1, "interface_number": 2,
    "profile": "rsk", "serial_number": "offline-key"}


def response(kind, sequence, body, status=0, slot=0):
    return bytes([kind]) + len(body).to_bytes(4, "little") + bytes([slot, sequence, status, 0, 0]) + body


class Endpoint:
    bmAttributes, wMaxPacketSize = 2, 64

    def __init__(self, device, address):
        self.device, self.bEndpointAddress = device, address

    def write(self, wire, timeout):
        self.device.writes.append((bytes(wire), timeout))
        sequence = wire[6]
        if self.device.extension and wire[0] == 0x6f:
            self.device.queue += [response(0x80, sequence, b"", 0x80)]
        kind = 0x80 if wire[0] in (0x62, 0x6f) else 0x81
        body = b"\x3b\x00" if wire[0] == 0x62 else b"abc\x90\x00" if wire[0] == 0x6f else b""
        sequence = (sequence + 1) & 255 if self.device.wrong_sequence else sequence
        packet = response(kind, sequence, body)
        self.device.queue += [packet[:5], packet[5:9], packet[9:]]
        return len(wire) - 1 if self.device.short_write else len(wire)

    def read(self, size, timeout):
        assert size == 64 and timeout > 0
        if self.device.read_error is not None:
            raise self.device.read_error
        return self.device.queue.pop(0)


class Configuration:
    bConfigurationValue = 1

    def __init__(self, device):
        self.interface = Interface(device)

    def __getitem__(self, key):
        assert key == (2, 0)
        return self.interface

    def __iter__(self):
        return iter([self.interface])


class Interface:
    bInterfaceClass, bInterfaceNumber, bAlternateSetting = 0x0b, 2, 0

    def __init__(self, device):
        self.endpoints = [Endpoint(device, 0x81), Endpoint(device, 0x02)]

    def __iter__(self):
        return iter(self.endpoints)


class Device:
    idVendor, idProduct, bus, address, port_numbers = 0x1209, 0xf1d2, 3, 7, (2,)
    iManufacturer, iProduct, iSerialNumber = 1, 2, 3
    active_driver, wrong_sequence, short_write, extension, read_error = False, False, False, False, None

    def __init__(self):
        self.queue, self.writes, self.controls = [], [], []
        self.strings = {1: "RS-Key", 2: "RS-Key offline", 3: "offline-key"}
        self.configuration = Configuration(self)

    def __iter__(self):
        return iter([self.configuration])

    def get_active_configuration(self):
        return self.configuration

    def is_kernel_driver_active(self, interface):
        assert interface == 2
        return self.active_driver

    def ctrl_transfer(self, *args, **kwargs):
        self.controls.append((args, kwargs))
        raise usb.core.USBError("unsupported class request", error_code=-9, errno=32)


def install(monkeypatch, device):
    calls = []
    monkeypatch.setattr(usb.util, "get_string", lambda value, index: value.strings[index])
    monkeypatch.setattr(usb.util, "claim_interface", lambda value, interface: calls.append(("claim", value, interface)))
    monkeypatch.setattr(usb.util, "release_interface", lambda value, interface: calls.append(("release", value, interface)))
    monkeypatch.setattr(usb.util, "dispose_resources", lambda value: calls.append(("dispose", value)))
    monkeypatch.setattr(usb.core, "find", lambda **kwargs: [device])
    return calls


def test_native_USB_bus_reset_is_an_explicit_selected_device_API_not_a_reconnect(monkeypatch):
    device = Device()
    calls = install(monkeypatch, device)
    resets, events = [], []
    device.reset = lambda: resets.append("selected-device-reset")
    card = usb_ccid.UsbCard(DESCRIPTOR, lambda: 0, backend=device)
    reply = card.usb_reset(1_000_000_000, lambda direction, data, **fields: events.append(fields))
    assert reply.protocol == "success" and resets == ["selected-device-reset"]
    assert [event["api"] for event in events] == ["libusb.reset_device.invoked", "libusb.reset_device.returned"]
    assert card.device is None and not card.claimed
    assert any(call[0] == "dispose" for call in calls)
    assert not device.writes and not device.controls


def test_native_USB_reset_expired_deadline_never_reaches_the_selected_device(monkeypatch):
    device = Device()
    install(monkeypatch, device)
    resets = []
    device.reset = lambda: resets.append(True)
    card = usb_ccid.UsbCard(DESCRIPTOR, lambda: 2, backend=device)
    with pytest.raises(TransferError) as error:
        card.usb_reset(1, lambda *args, **kwargs: None)
    assert error.value.outcome == Outcome.DEADLINE and not resets
    card.close()


def test_native_packet_accumulation_time_extensions_control_stall_and_recovery(monkeypatch):
    device = Device()
    device.extension = True
    calls = install(monkeypatch, device)
    card = usb_ccid.UsbCard(DESCRIPTOR, lambda: 0)
    events, controls = [], []
    def observe(direction, data, **fields):
        events.append((direction, data, fields))
    def extension(frame):
        controls.append(card.usb_control(0x21, 1, frame[6] << 8, 2, b"", 1000000000, observe))
    card.on_extension = extension
    reply = card.transfer(b"\x00\xfd\x00\x00", 1000000000, observe)
    assert (reply.protocol, reply.status, reply.data) == ("success", 0x9000, b"abc\x90\x00")
    assert len(controls) == 1 and (controls[0].protocol, controls[0].status) == ("transport_error", "USB_STALL")
    assert device.controls[0][0] == (0x21, 1, 0, 2, b"")
    assert any(fields.get("api") == "libusb.control" for _, _, fields in events)
    card.on_extension = None
    assert card.transfer(b"\x00\xfd\x00\x00", 1000000000, observe).data == reply.data
    card.close()
    assert [call[0] for call in calls] == ["claim", "release", "dispose"]


@pytest.mark.parametrize("fault,needle", [("driver", "OS driver owns"), ("serial", "serial changed"),
    ("family", "wallet profile"), ("backend", "exact selected interface")])
def test_native_claim_requires_exact_nonwallet_unclaimed_interface(monkeypatch, fault, needle):
    device = Device()
    calls = install(monkeypatch, device)
    descriptor = dict(DESCRIPTOR)
    if fault == "driver":
        device.active_driver = True
    elif fault == "serial":
        device.strings[3] = "other-device"
    elif fault == "family":
        descriptor["profile"] = "trezor"
    else:
        device.address = 8
    with pytest.raises(TransferError, match=needle):
        usb_ccid.UsbCard(descriptor, lambda: 0, backend=device)
    assert not any(call[0] == "claim" for call in calls) and not device.writes and not device.controls


@pytest.mark.parametrize("code,backend,outcome", [(19, -4, Outcome.DISCONNECTED), (60, -7, Outcome.DEADLINE),
    (13, -3, Outcome.HOST_REJECTED), (16, -6, Outcome.HOST_REJECTED), (5, -1, Outcome.RUNNER_ERROR)])
def test_native_USB_failures_keep_the_actual_cause(code, backend, outcome):
    result = usb_ccid.usb_error(usb.core.USBError("injected USB failure", error_code=backend, errno=code))
    assert result.outcome == outcome and result.code == code


@pytest.mark.parametrize("fault", ["sequence", "short-write", "disconnected"])
def test_native_bulk_integrity_faults_fail_without_fabricating_APDU_success(monkeypatch, fault):
    device = Device()
    install(monkeypatch, device)
    if fault == "sequence":
        device.wrong_sequence = True
    elif fault == "short-write":
        device.short_write = True
    else:
        device.read_error = usb.core.USBError("removed", error_code=-4, errno=19)
    card = usb_ccid.UsbCard(DESCRIPTOR, lambda: 0)
    with pytest.raises(TransferError) as caught:
        card.transfer(b"\x00\xfd\x00\x00", 1000000000, lambda *args, **kwargs: None)
    if fault == "disconnected":
        assert caught.value.outcome == Outcome.DISCONNECTED
    elif fault == "sequence":
        assert caught.value.protocol == "malformed_response"
    else:
        assert "short native" in str(caught.value)
    card.close()


def test_native_inventory_selector_and_capture_wiring_are_offline(monkeypatch, tmp_path):
    device = Device()
    install(monkeypatch, device)
    found = usb_ccid.inventory()
    descriptor = found["interfaces"][0]
    assert descriptor["profile"] == "rsk" and not found["errors"]
    assert usb_ccid.select(found["interfaces"], descriptor["id"]) == descriptor
    with pytest.raises(ValueError, match="matched 2"):
        usb_ccid.select([descriptor, descriptor], descriptor["serial_number"])
    def forbidden_inventory():
        pytest.fail("native-only capture must not enumerate HID or PC/SC")
    monkeypatch.setattr(oracle, "inventory", forbidden_inventory)
    def execute(session, suites):
        with session.case("native-usb-wiring", ("T10",)):
            session.check("native card APDU recorder is used", session.card_value(session.apdu(b"\x00\xfd\x00\x00")), b"abc")
    monkeypatch.setattr(oracle, "execute", execute)
    target = tmp_path / "native-usb"
    assert oracle.main(["capture", "--out", str(target), "--ccid-usb", descriptor["id"], "--profile", "rsk", "--suite", "select"]) == 0
    assert any(row["observation_layer"] == "usb_ccid" for row in recover(target)["exchanges"])


def test_wallet_raw_USB_option_is_refused_before_inventory(monkeypatch, tmp_path):
    monkeypatch.setattr(usb_ccid, "inventory", lambda: pytest.fail("wallet raw USB must fail before discovery"))
    assert oracle.main(["capture", "--out", str(tmp_path / "wallet"), "--ccid-usb", "anything", "--profile", "trezor"]) == 2
