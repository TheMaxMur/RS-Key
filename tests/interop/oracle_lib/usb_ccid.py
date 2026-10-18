# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Explicit native CCID bulk/control access; never detach an OS reader driver."""
import hashlib
import math
import sys

from .trace import Outcome, Reply, TransferError
from .transport import device_kind

CCID_CLASS, BULK_TYPE = 0x0b, 2
HEADER_SIZE, MAX_RESPONSE_SIZE = 10, 1024 * 1024
ABORT_REQUEST, CLASS_INTERFACE_OUT = 1, 0x21


def inventory():
    import usb.core
    import usb.util
    interfaces, errors = [], []
    for device in usb.core.find(find_all=True):
        if device.idVendor == 0x534c:
            continue
        try:
            for configuration in device:
                for interface in configuration:
                    if interface.bInterfaceClass != CCID_CLASS or interface.bAlternateSetting:
                        continue
                    info = {"vendor_id": device.idVendor, "product_id": device.idProduct,
                        "bus": device.bus, "address": device.address, "ports": list(device.port_numbers or ()),
                        "configuration": configuration.bConfigurationValue, "interface_number": interface.bInterfaceNumber,
                        "manufacturer_string": usb.util.get_string(device, device.iManufacturer) if device.iManufacturer else None,
                        "product_string": usb.util.get_string(device, device.iProduct) if device.iProduct else None,
                        "serial_number": usb.util.get_string(device, device.iSerialNumber) if device.iSerialNumber else None}
                    info["profile"] = device_kind(info)
                    if info["profile"] == "trezor":
                        continue
                    location = f"{device.bus}:{device.address}:{configuration.bConfigurationValue}:{interface.bInterfaceNumber}"
                    info["id"] = "ccid-" + hashlib.sha256(location.encode()).hexdigest()[:16]
                    info["location"] = location
                    interfaces.append(info)
        except (usb.core.USBError, OSError) as error:
            errors.append({"bus": device.bus, "address": device.address, "error": str(error)})
    return {"interfaces": interfaces, "errors": errors}


def select(interfaces, selector):
    matches = [item for item in interfaces if selector in (item["id"], item["location"], item.get("serial_number"))]
    if len(matches) != 1:
        raise ValueError(f"CCID USB selector matched {len(matches)} interfaces; use the exact id from list --ccid-usb")
    return matches[0]


def timeout_ms(deadline, clock):
    remaining = deadline - clock()
    if remaining <= 0:
        raise TransferError("USB CCID deadline elapsed", Outcome.DEADLINE)
    return max(1, math.ceil(remaining / 1000000))


def usb_error(error):
    code = getattr(error, "errno", None)
    backend_code = getattr(error, "backend_error_code", None)
    outcome = Outcome.DEADLINE if code in (60, 110) or backend_code == -7 else Outcome.DISCONNECTED if code in (6, 19) or backend_code == -4 else Outcome.HOST_REJECTED if code in (1, 13, 16) or backend_code in (-3, -6) else Outcome.RUNNER_ERROR
    return TransferError(f"USB CCID: {error}", outcome, code=code)


class UsbCard:
    layer, whole_messages, emulated = "usb_ccid", False, False

    def __init__(self, descriptor, clock, backend=None, operator=False):
        import usb.core
        import usb.util
        if descriptor.get("profile") == "trezor" or descriptor["vendor_id"] == 0x534c:
            raise TransferError("wallet profile excludes raw CCID USB", Outcome.HOST_REJECTED)
        self.descriptor, self.clock, self.sequence = dict(descriptor), clock, 0
        self.operator = operator
        self.on_extension, self.atr, self.buffer = None, b"", bytearray()
        self.recovering = False
        self.device, self.claimed = None, False
        self.util = usb.util
        try:
            if backend is None:
                matches = [device for device in usb.core.find(find_all=True, idVendor=descriptor["vendor_id"], idProduct=descriptor["product_id"])
                    if device.bus == descriptor["bus"] and device.address == descriptor["address"]]
                if len(matches) != 1:
                    raise TransferError("exact selected CCID USB device is absent or ambiguous", Outcome.HOST_REJECTED)
                backend = matches[0]
            if (backend.idVendor, backend.idProduct, backend.bus, backend.address) != (descriptor["vendor_id"], descriptor["product_id"], descriptor["bus"], descriptor["address"]):
                raise TransferError("CCID USB backend does not match the exact selected interface", Outcome.HOST_REJECTED)
            self.device = backend
            configuration = backend.get_active_configuration()
            if configuration.bConfigurationValue != descriptor["configuration"]:
                raise TransferError("selected CCID configuration is not active; no configuration reset was attempted", Outcome.HOST_REJECTED)
            interface = configuration[(descriptor["interface_number"], 0)]
            if interface.bInterfaceClass != CCID_CLASS:
                raise TransferError("selected interface is not CCID", Outcome.HOST_REJECTED)
            if descriptor.get("serial_number") and (not backend.iSerialNumber or self.util.get_string(backend, backend.iSerialNumber) != descriptor["serial_number"]):
                raise TransferError("selected CCID USB serial changed before interface claim", Outcome.HOST_REJECTED)
            endpoints = [endpoint for endpoint in interface if endpoint.bmAttributes & 3 == BULK_TYPE]
            incoming = [endpoint for endpoint in endpoints if endpoint.bEndpointAddress & 128]
            outgoing = [endpoint for endpoint in endpoints if not endpoint.bEndpointAddress & 128]
            if len(incoming) != 1 or len(outgoing) != 1:
                raise TransferError("CCID interface has no unique bulk endpoint pair", Outcome.HOST_REJECTED)
            try:
                active = backend.is_kernel_driver_active(descriptor["interface_number"])
            except NotImplementedError:
                active = False
            if active:
                raise TransferError("OS driver owns this CCID interface; release that reader explicitly before raw capture", Outcome.HOST_REJECTED)
            self.util.claim_interface(backend, descriptor["interface_number"])
            self.claimed = True
            self.incoming, self.outgoing = incoming[0], outgoing[0]
        except usb.core.USBError as error:
            self.close()
            raise usb_error(error) from error
        except BaseException:
            self.close()
            raise

    def _write(self, wire, deadline, observe):
        import usb.core
        try:
            count = self.outgoing.write(wire, timeout=timeout_ms(deadline, self.clock))
        except usb.core.USBError as error:
            raise usb_error(error) from error
        observe("tx", wire, api="libusb.bulk.write", endpoint=self.outgoing.bEndpointAddress)
        if count != len(wire):
            raise TransferError("short native USB CCID bulk write")

    def send_only(self, wire, deadline, observe):
        self._write(wire, deadline, observe)
        return Reply(b"", "no_response_expected")

    def _message(self, deadline, observe):
        import usb.core
        while True:
            if len(self.buffer) >= HEADER_SIZE:
                size = HEADER_SIZE + int.from_bytes(self.buffer[1:5], "little")
                if size > MAX_RESPONSE_SIZE:
                    raise TransferError("CCID response exceeds the host framing ceiling", protocol="malformed_response")
                if len(self.buffer) >= size:
                    message = bytes(self.buffer[:size])
                    del self.buffer[:size]
                    return message
            try:
                chunk = bytes(self.incoming.read(self.incoming.wMaxPacketSize, timeout=timeout_ms(deadline, self.clock)))
            except usb.core.USBError as error:
                raise usb_error(error) from error
            observe("rx", chunk, api="libusb.bulk.read", endpoint=self.incoming.bEndpointAddress)
            if not chunk:
                raise TransferError("zero-length native CCID response packet", protocol="malformed_response")
            self.buffer.extend(chunk)

    def raw(self, wire, deadline, observe):
        sequence = wire[6] if len(wire) >= HEADER_SIZE else None
        self._write(wire, deadline, observe)
        while True:
            response = self._message(deadline, observe)
            if sequence is not None and response[6] != sequence:
                if self.recovering:
                    observe("control", b"", api="ccid.recovery.discard-old-sequence", old_sequence=response[6], expected_sequence=sequence)
                    continue
                raise TransferError("native CCID response sequence mismatch", protocol="malformed_response")
            if response[7] & 0xc0 == 0x80:
                if self.on_extension is not None:
                    self.on_extension(response)
                continue
            return response

    def transfer(self, request, deadline, observe, message_type=0x6f):
        sequence, self.sequence = self.sequence, (self.sequence + 1) & 255
        wire = bytes([message_type]) + len(request).to_bytes(4, "little") + bytes([0, sequence, 0, 0, 0]) + request
        response = self.raw(wire, deadline, observe)
        expected_type = 0x80 if message_type in (0x62, 0x6f) else 0x81
        if response[0] != expected_type or response[5] != 0:
            raise TransferError("native CCID response type or slot mismatch", protocol="malformed_response")
        if response[7] & 0xc0:
            return Reply(response, "transport_error", response[8])
        data = response[HEADER_SIZE:]
        if message_type != 0x6f:
            return Reply(data)
        if len(data) < 2:
            raise TransferError("native CCID APDU response lacks its status word", protocol="malformed_response")
        status = int.from_bytes(data[-2:], "big")
        return Reply(data, "success" if status == 0x9000 else "applet_error", status)

    def usb_control(self, request_type, request, value, index, data, deadline, observe):
        import usb.core
        observe("control", data if isinstance(data, bytes) else b"", api="libusb.control", request_type=request_type, request=request, value=value, index=index, requested_length=data if isinstance(data, int) else len(data))
        try:
            result = self.device.ctrl_transfer(request_type, request, value, index, data, timeout=timeout_ms(deadline, self.clock))
        except usb.core.USBError as error:
            if getattr(error, "errno", None) == 32 or getattr(error, "backend_error_code", None) == -9:
                return Reply(b"", "transport_error", "USB_STALL")
            raise usb_error(error) from error
        response = bytes(result) if not isinstance(result, int) else b""
        observe("rx", response, api="libusb.control.result")
        return Reply(response)

    def control(self, action, deadline, observe):
        if action == "card_reset":
            self.transfer(b"", deadline, observe, 0x63)
            result = self.transfer(b"", deadline, observe, 0x62)
            self.atr = result.data
            return result
        if action in ("reconnect", "power_cycle"):
            self.reopen(self.operator)
            self.recovering = True
            try:
                result = self.transfer(b"", deadline, observe, 0x62)
                self.atr = result.data
                return result
            finally:
                self.recovering = False
        raise TransferError("unsupported native CCID connection action", Outcome.HOST_REJECTED)

    def usb_reset(self, deadline, observe):
        import usb.core
        timeout_ms(deadline, self.clock)
        if self.device is None:
            raise TransferError("selected native CCID handle is closed before USB reset", Outcome.HOST_REJECTED)
        observe("control", b"", api="libusb.reset_device.invoked", scope="selected composite USB device; no physical power cut")
        try:
            self.device.reset()
        except usb.core.USBError as error:
            raise usb_error(error) from error
        observe("control", b"", api="libusb.reset_device.returned", scope="host API completion; device reset instant and power state are not observed")
        self.close()
        return Reply(b"")

    def wait_disconnect(self, deadline, observe):
        response = self._message(deadline, observe)
        observe("control", response, api="ccid.unexpected-response-before-reboot-disconnect")
        raise TransferError("unexpected CCID response while awaiting reboot disconnect", protocol="malformed_response")

    def reopen(self, operator=False):
        old = self.descriptor
        available = inventory()["interfaces"]
        serial = old.get("serial_number")
        matches = [item for item in available if serial and item.get("serial_number") == serial and all(item.get(key) == old.get(key) for key in ("vendor_id", "product_id", "configuration", "interface_number", "profile"))]
        if len(matches) != 1:
            if serial or not operator:
                raise TransferError("CCID USB rebind is absent, ambiguous or serial-less; no neighboring-device fallback", Outcome.HOST_REJECTED)
            for item in available:
                print(f"oracle: raw CCID rebind candidate {item['id']} {item.get('product_string')}", file=sys.stderr)
            chosen = select(available, input("oracle: exact raw CCID selector for the replugged test key: ").strip())
            if any(chosen.get(key) != old.get(key) for key in ("vendor_id", "product_id", "configuration", "interface_number", "profile")):
                raise TransferError("CCID USB rebind changed the selected interface/family", Outcome.HOST_REJECTED)
        else:
            chosen = matches[0]
        sequence = self.sequence
        self.close()
        self.__init__(chosen, self.clock, operator=self.operator)
        self.sequence = sequence
        return chosen

    def drop_response(self, request, deadline, observe):
        sequence, self.sequence = self.sequence, (self.sequence + 1) & 255
        wire = b"\x6f" + len(request).to_bytes(4, "little") + bytes([0, sequence, 0, 0, 0]) + request
        self._write(wire, deadline, observe)
        self.close()
        raise TransferError("injected native USB handle close before reading the APDU response", Outcome.CANCELLED, protocol="injected_response_loss")

    def initialize(self, trace, timeout):
        reply = trace.exchange("ccid", self.layer, "ccid.usb.power-on", b"", timeout,
            lambda deadline, observe: self.transfer(b"", deadline, observe, 0x62))
        if reply.protocol != "success":
            raise TransferError("native CCID power-on failed", protocol=reply.protocol, code=reply.status)
        self.atr = reply.data

    def close(self):
        if self.device is not None:
            import usb.core
            try:
                if self.claimed:
                    self.util.release_interface(self.device, self.descriptor["interface_number"])
            except usb.core.USBError as error:
                if getattr(error, "errno", None) not in (6, 19) and getattr(error, "backend_error_code", None) != -4:
                    raise
            finally:
                self.util.dispose_resources(self.device)
                self.claimed, self.device = False, None
