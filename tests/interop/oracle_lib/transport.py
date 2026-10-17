# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Explicit instance selection, raw CTAPHID, and bounded PC/SC calls."""
import hashlib
import multiprocessing
import os
import socket
import time

from .trace import Outcome, Reply, TransferError

REPORT_LEN = 64
MAX_HID_MESSAGE = 7609
FIDO_USAGE_PAGE = 0xF1D0
HID_INIT, HID_PING, HID_MSG, HID_CBOR = 0x06, 0x01, 0x03, 0x10
HID_ERROR, HID_KEEPALIVE = 0x3F, 0x3B
BROADCAST_CID = b"\xff" * 4


def device_kind(info):
    words = " ".join(str(info.get(k) or "") for k in ("product_string", "manufacturer_string")).lower()
    if "trezor" in words or "satoshilabs" in words or info.get("vendor_id") == 0x534C:
        return "trezor"
    if "rs-key" in words or " rsk" in words:
        return "rsk"
    if info.get("vendor_id") == 0x1050:
        return "yubikey"
    return "generic"


def inventory():
    devices, otp_devices, errors = [], [], []
    try:
        import hid
        for info in hid.enumerate():
            fido_interface = info.get("usage_page") == FIDO_USAGE_PAGE
            otp_interface = info.get("usage_page") == 1 and info.get("usage") == 6 and device_kind(info) in ("rsk", "yubikey")
            if not (fido_interface or otp_interface):
                continue
            path = info["path"]
            path = path if isinstance(path, bytes) else os.fsencode(path)
            descriptor = {key: value for key, value in info.items() if key != "path"}
            (devices if fido_interface else otp_devices).append({"id": ("hid-" if fido_interface else "otp-") + hashlib.sha256(path).hexdigest()[:16],
                            "path_hex": path.hex(), "profile": device_kind(info), **descriptor})
    except (ImportError, OSError) as error:
        errors.append({"backend": "hidapi", "error": str(error)})
    readers_found = []
    try:
        from smartcard.System import readers
        readers_found = [str(reader) for reader in readers()]
    except Exception as error:
        errors.append({"backend": "pcsc", "error": f"{type(error).__name__}: {error}"})
    return {"hid": devices, "otp_hid": otp_devices, "readers": readers_found, "errors": errors}


def select_hid(devices, selector):
    matches = [device for device in devices if selector in (device["id"], device["path_hex"], device.get("serial_number"))]
    if len(matches) != 1:
        raise ValueError(f"HID selector matched {len(matches)} interfaces; use the exact id from list")
    return matches[0]


def _remaining(deadline, clock):
    left = deadline - clock()
    if left <= 0:
        raise TransferError("request deadline elapsed", Outcome.DEADLINE)
    return left / 1e9


class Hid:
    layer = "hid_report"

    def __init__(self, descriptor, clock, backend=None):
        self.clock = clock
        self.descriptor = descriptor
        self.cid = BROADCAST_CID
        self.capabilities = 0
        self.active = False
        if backend is None:
            import hid
            backend = hid.device()
            backend.open_path(bytes.fromhex(descriptor["path_hex"]))
        self.backend = backend

    def close(self):
        self.backend.close()

    def cancel(self, deadline, observe):
        _remaining(deadline, self.clock)
        frame = (self.cid + b"\x91\x00\x00").ljust(REPORT_LEN, b"\x00")
        written = self.backend.write(b"\x00" + frame)
        observe("tx", frame, report_id=0)
        if written is not None and written != REPORT_LEN + 1:
            raise TransferError("short HID CANCEL write", Outcome.DISCONNECTED)
        self.active = False
        return Reply(b"", "no_response_expected", timing={"tx_complete_ns": self.clock()})

    def transfer(self, command, data, deadline, observe):
        if not 0 <= command < 128 or len(data) > MAX_HID_MESSAGE:
            raise TransferError("request exceeds CTAPHID framing bounds", Outcome.HOST_REJECTED)
        size = len(data)
        frames = [self.cid + bytes([command | 0x80]) + size.to_bytes(2, "big") + data[:57]]
        frames.extend(self.cid + bytes([index]) + data[offset:offset + 59]
                      for index, offset in enumerate(range(57, size, 59)))
        return self.transfer_reports(command, [frame.ljust(REPORT_LEN, b"\x00") for frame in frames], deadline, observe)

    def transfer_reports(self, command, frames, deadline, observe):
        if not frames or any(len(frame) != REPORT_LEN for frame in frames):
            raise TransferError("raw CTAPHID requests require complete reports", Outcome.HOST_REJECTED)
        self.active = True
        for frame in frames:
            _remaining(deadline, self.clock)
            written = self.backend.write(b"\x00" + frame)
            tx_complete = self.clock()
            observe("tx", frame, tx_complete, report_id=0)
            if written is not None and written != REPORT_LEN + 1:
                raise TransferError("short HID write", Outcome.DISCONNECTED)
        first_rx = None
        last_rx = None

        def receive():
            nonlocal first_rx, last_rx
            while True:
                milliseconds = max(1, min(100, int(_remaining(deadline, self.clock) * 1000)))
                try:
                    frame = bytes(self.backend.read(REPORT_LEN, milliseconds))
                except OSError as error:
                    raise TransferError(str(error), Outcome.DISCONNECTED) from error
                if not frame:
                    continue
                timestamp = self.clock()
                observe("rx", frame, timestamp, cid=frame[:4].hex())
                if len(frame) != REPORT_LEN:
                    raise TransferError("short HID response report", protocol="malformed_response")
                if frame[:4] != self.cid:
                    continue
                if first_rx is None:
                    first_rx = timestamp
                last_rx = timestamp
                return frame

        while True:
            frame = receive()
            if frame[4] != HID_KEEPALIVE | 0x80:
                break
            if int.from_bytes(frame[5:7], "big") != 1:
                raise TransferError("invalid keepalive length", protocol="malformed_response")
        response_command = frame[4] & 0x7F
        if not frame[4] & 0x80 or response_command not in (command, HID_ERROR):
            raise TransferError("unexpected HID response command", protocol="malformed_response")
        total = int.from_bytes(frame[5:7], "big")
        if total > MAX_HID_MESSAGE:
            raise TransferError("oversized HID response", protocol="malformed_response")
        first_final = last_rx
        response = bytearray(frame[7:7 + min(total, 57)])
        sequence = 0
        while len(response) < total:
            frame = receive()
            if frame[4] != sequence:
                raise TransferError("invalid HID continuation sequence", protocol="malformed_response")
            response.extend(frame[5:5 + min(59, total - len(response))])
            sequence += 1
        timing = {"tx_complete_ns": tx_complete, "first_rx_ns": first_rx,
                  "first_final_rx_ns": first_final, "final_rx_ns": last_rx}
        data = bytes(response)
        self.active = False
        if response_command == HID_ERROR:
            if len(data) != 1:
                raise TransferError("invalid HID error length", protocol="malformed_response")
            return Reply(data, "transport_error", data[0], timing)
        if command == HID_CBOR:
            if not data:
                raise TransferError("missing CTAP status", protocol="malformed_response")
            return Reply(data, "success" if data[0] == 0 else "applet_error", data[0], timing)
        if command == HID_MSG:
            if len(data) < 2:
                raise TransferError("missing APDU status", protocol="malformed_response")
            status = int.from_bytes(data[-2:], "big")
            return Reply(data, "success" if status == 0x9000 else "applet_error", status, timing)
        return Reply(data, timing=timing)

    def initialize(self, trace, timeout):
        nonce = os.urandom(8)
        reply = trace.exchange("hid", self.layer, "ctaphid.init", nonce, timeout,
                               lambda deadline, observe: self.transfer(HID_INIT, nonce, deadline, observe))
        if reply.protocol != "success" or len(reply.data) != 17 or reply.data[:8] != nonce:
            raise TransferError("INIT nonce or response mismatch", protocol="malformed_response")
        self.cid, self.capabilities = reply.data[8:12], reply.data[16]
        if self.cid in (b"\x00" * 4, BROADCAST_CID):
            raise TransferError("invalid allocated CID", protocol="malformed_response")
        trace.emit("session_opened", session_id="hid", cid=self.cid.hex(), capabilities=self.capabilities)


class TcpReports:
    def __init__(self, address):
        host, port = address.rsplit(":", 1)
        self.socket = socket.create_connection((host, int(port)), timeout=5)
        self.pending = bytearray()

    def write(self, data):
        self.socket.sendall(data[1:])
        return len(data)

    def read(self, length, milliseconds):
        self.socket.settimeout(milliseconds / 1000)
        try:
            while len(self.pending) < length:
                chunk = self.socket.recv(length - len(self.pending))
                if not chunk:
                    raise OSError("emulator report socket closed")
                self.pending.extend(chunk)
        except socket.timeout:
            return b""
        result = bytes(self.pending[:length])
        del self.pending[:length]
        return result

    def close(self):
        self.socket.close()


def _pcsc_worker(pipe, reader_name):
    connection = None
    try:
        from smartcard.System import readers
        matches = [reader for reader in readers() if str(reader) == reader_name]
        if len(matches) != 1:
            raise ValueError("reader name is absent or ambiguous")
        connection = matches[0].createConnection()
        connection.connect()
        pipe.send(("ready", bytes(connection.getATR())))
        while True:
            request = pipe.recv()
            if request is None:
                break
            started = time.monotonic_ns()
            pipe.send(("started", started))
            try:
                data, sw1, sw2 = connection.transmit(list(request))
                ended = time.monotonic_ns()
                pipe.send(("reply", bytes(data) + bytes([sw1, sw2]), started, ended))
            except Exception as error:
                pipe.send(("error", type(error).__name__, str(error)))
                break
    except (EOFError, BrokenPipeError):
        pass
    except Exception as error:
        try:
            pipe.send(("error", type(error).__name__, str(error)))
        except (OSError, EOFError):
            pass
    finally:
        if connection:
            connection.disconnect()
        pipe.close()


class Pcsc:
    layer = "pcsc_apdu"

    def __init__(self, reader, clock, origin, timeout=10, worker=None):
        self.clock, self.origin = clock, origin
        self.broken = False
        context = multiprocessing.get_context("spawn")
        self.pipe, child = context.Pipe()
        self.process = context.Process(target=worker or _pcsc_worker, args=(child, reader), daemon=True)
        self.process.start()
        child.close()
        if not self.pipe.poll(timeout):
            self.close()
            raise TransferError(f"{self.layer} connection deadline elapsed", Outcome.DEADLINE)
        response = self.pipe.recv()
        if response[0] != "ready":
            self.close()
            raise TransferError(f"{self.layer} connection failed: {response[1:]}", Outcome.HOST_REJECTED)
        self.atr = response[1]

    def transfer(self, request, deadline, observe):
        if self.broken:
            raise TransferError("PC/SC session is no longer usable", Outcome.HOST_REJECTED)
        self.pipe.send(request)
        started = None
        while True:
            remaining = max(0, (deadline - self.clock()) / 1e9)
            if not remaining or not self.pipe.poll(remaining):
                self.broken = True
                self.process.terminate()
                self.process.join(timeout=1)
                raise TransferError("PC/SC transmit deadline elapsed; mutation outcome unknown", Outcome.DEADLINE)
            try:
                response = self.pipe.recv()
            except EOFError as error:
                self.broken = True
                raise TransferError("PC/SC worker exited", Outcome.DISCONNECTED) from error
            if response[0] == "started":
                started = response[1] - self.origin
                observe("tx", request, started, evidence="pcsc_api_invoked")
                continue
            if response[0] == "error":
                self.broken = True
                raise TransferError(f"PC/SC {response[1]}: {response[2]}", Outcome.DISCONNECTED)
            if response[0] != "reply" or started is None:
                raise TransferError("invalid PC/SC worker response")
            data, start, end = response[1:]
            observe("rx", data, end - self.origin, evidence="pcsc_api_returned")
            status = int.from_bytes(data[-2:], "big")
            return Reply(data, "success" if status == 0x9000 else "applet_error", status, {
                "backend_call_start_ns": start - self.origin,
                "backend_call_end_ns": end - self.origin, "backend_api_duration_ns": end - start,
                "final_rx_ns": end - self.origin,
            })

    def close(self):
        if self.process.is_alive():
            try:
                self.pipe.send(None)
            except (OSError, EOFError):
                pass
            self.process.join(timeout=1)
            if self.process.is_alive():
                self.process.terminate()
                self.process.join(timeout=1)
        self.pipe.close()


class EmuCard:
    layer = "ccid_message"

    def __init__(self, address, clock):
        host, port = address.rsplit(":", 1)
        self.socket = socket.create_connection((host, int(port)), timeout=5)
        self.clock, self.sequence = clock, 0

    def _exact(self, size, deadline):
        result = bytearray()
        while len(result) < size:
            self.socket.settimeout(_remaining(deadline, self.clock))
            chunk = self.socket.recv(size - len(result))
            if not chunk:
                raise TransferError("emulator card socket closed", Outcome.DISCONNECTED)
            result.extend(chunk)
        return bytes(result)

    def transfer(self, request, deadline, observe, message_type=0x6F):
        sequence = self.sequence
        self.sequence = (sequence + 1) & 255
        message = bytes([message_type]) + len(request).to_bytes(4, "little") + bytes([0, sequence, 0, 0, 0]) + request
        self.socket.sendall(b"\x00" + len(message).to_bytes(4, "big") + message)
        observe("tx", message)
        while True:
            try:
                size = int.from_bytes(self._exact(4, deadline), "big")
                if not 10 <= size <= 1024 * 1024:
                    raise TransferError("invalid emulator CCID frame length", protocol="malformed_response")
                response = self._exact(size, deadline)
            except socket.timeout as error:
                raise TransferError("emulator card deadline", Outcome.DEADLINE) from error
            observe("rx", response)
            if response[6] != sequence or int.from_bytes(response[1:5], "little") != len(response) - 10:
                raise TransferError("CCID response sequence or length mismatch", protocol="malformed_response")
            if response[7] & 0xC0 == 0x80:
                continue
            if response[7] & 0xC0:
                return Reply(response, "transport_error", response[8])
            data = response[10:]
            if message_type != 0x6F:
                return Reply(data)
            if len(data) < 2:
                raise TransferError("missing emulator APDU status", protocol="malformed_response")
            status = int.from_bytes(data[-2:], "big")
            return Reply(data, "success" if status == 0x9000 else "applet_error", status)

    def initialize(self, trace, timeout):
        reply = trace.exchange("ccid", self.layer, "ccid.power_on", b"", timeout,
                               lambda deadline, observe: self.transfer(b"", deadline, observe, 0x62))
        self.atr = reply.data

    def close(self):
        self.socket.close()
