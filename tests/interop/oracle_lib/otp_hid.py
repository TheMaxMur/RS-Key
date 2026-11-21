# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""OTP feature reports run in an isolated worker to bound blocking HID APIs."""
import time
import sys
import errno

from .trace import Outcome, Reply, TransferError
from .transport import Pcsc
from .native_otp import IO_NOT_PERMITTED, IO_NOT_PRIVILEGED


def _otp_worker(pipe, path_hex):
    backend = None
    try:
        import hid
        from yubikit.core import TimeoutError as DeviceTimeout
        from yubikit.core.otp import CommandRejectedError, OtpConnection, OtpProtocol, check_crc
        if sys.platform == "darwin":
            from .native_otp import MacFeature
            backend = MacFeature(bytes.fromhex(path_hex))
        else:
            backend = hid.device()
            backend.open_path(bytes.fromhex(path_hex))

        class FeatureConnection(OtpConnection):
            def receive(self):
                api = getattr(backend, "read_api", "get_feature_report")
                pipe.send(("io", "control", b"", time.monotonic_ns(), {"api": api, "report_id": 0, "requested_length": 8 if sys.platform == "darwin" else 9}))
                raw = bytes(backend.get_feature_report(0, 9))
                pipe.send(("io", "rx", raw, time.monotonic_ns(), {"api": api, "report_id": 0}))
                if len(raw) == 9 and raw[0] == 0:
                    return raw[1:]
                return raw

            def send(self, data):
                raw = b"\x00" + data if getattr(backend, "report_id_prefix", True) else data
                pipe.send(("io", "tx", raw, time.monotonic_ns(), {"api": getattr(backend, "write_api", "send_feature_report"), "report_id": 0}))
                written = backend.send_feature_report(raw)
                if written is not None and written != len(raw):
                    raise OSError("short OTP feature report write")

            def close(self):
                pass

        connection = FeatureConnection()
        pipe.send(("ready", b""))
        protocol = None
        while True:
            request = pipe.recv()
            if request is None:
                break
            if isinstance(request, dict) and "raw_feature" in request:
                started = time.monotonic_ns()
                report = request["raw_feature"]
                if report is None:
                    response = connection.receive()
                else:
                    connection.send(report)
                    response = b""
                pipe.send(("raw_reply", response, report is None, started, time.monotonic_ns()))
                continue
            slot, data, expected_len = request
            started = time.monotonic_ns()
            try:
                protocol = protocol or OtpProtocol(connection)
                if slot == -1:
                    response = protocol.read_status()
                else:
                    response = protocol.send_and_receive(slot, data)
                    if expected_len:
                        if not check_crc(response[:expected_len + 2]):
                            raise ValueError("OTP response CRC mismatch")
                        response = response[:expected_len]
                pipe.send(("reply", response, None, started, time.monotonic_ns()))
            except (CommandRejectedError, DeviceTimeout) as error:
                pipe.send(("reply", b"", type(error).__name__, started, time.monotonic_ns()))
    except (EOFError, BrokenPipeError):
        pass
    except Exception as error:
        try:
            code = getattr(error, "errno", None)
            outcome = Outcome.HOST_REJECTED if code in (errno.EACCES, errno.EPERM, IO_NOT_PERMITTED, IO_NOT_PRIVILEGED) else Outcome.DISCONNECTED
            pipe.send(("error", type(error).__name__, str(error), code, outcome.value))
        except (OSError, EOFError):
            pass
    finally:
        if backend:
            backend.close()
        pipe.close()


class OtpFeature(Pcsc):
    layer = "otp_hid_feature"

    def __init__(self, descriptor, clock, origin, timeout=10):
        self.descriptor = descriptor
        super().__init__(descriptor["path_hex"], clock, origin, timeout, _otp_worker)

    def reopen(self, operator=False):
        from .binding import rebind
        descriptor = rebind(self.descriptor, "otp_hid", operator)
        self.close()
        self.__init__(descriptor, self.clock, self.origin)
        return descriptor

    def transfer(self, slot, data, expected_len, deadline, observe):
        if self.broken:
            raise TransferError("OTP worker is no longer usable", Outcome.HOST_REJECTED)
        if slot != -1 and (not 0 <= slot <= 255 or len(data) > 64):
            raise TransferError("OTP command exceeds feature framing bounds", Outcome.HOST_REJECTED)
        self.pipe.send((slot, data, expected_len))
        return self._receive_reply(deadline, observe)

    def raw_feature(self, report, deadline, observe):
        if self.broken or report is not None and (not isinstance(report, bytes) or len(report) != 8):
            raise TransferError("raw OTP feature operation requires one 8-byte report or GET", Outcome.HOST_REJECTED)
        self.pipe.send({"raw_feature": report})
        return self._receive_reply(deadline, observe)

    def _receive_reply(self, deadline, observe):
        last_rx = None
        while True:
            remaining = max(0, (deadline - self.clock()) / 1e9)
            if not remaining or not self.pipe.poll(remaining):
                self.broken = True
                self.process.terminate()
                self.process.join(timeout=1)
                raise TransferError("OTP feature deadline elapsed; mutation outcome unknown", Outcome.DEADLINE)
            try:
                response = self.pipe.recv()
            except EOFError as error:
                self.broken = True
                raise TransferError("OTP feature worker exited", Outcome.DISCONNECTED) from error
            if response[0] == "io":
                _, direction, raw, timestamp, fields = response
                observe(direction, raw, timestamp - self.origin, **fields)
                if direction == "rx":
                    last_rx = timestamp - self.origin
            elif response[0] == "reply":
                _, value, status, start, end = response
                return Reply(value, "success" if status is None else "applet_error", status, {
                    "backend_call_start_ns": start - self.origin, "backend_call_end_ns": end - self.origin,
                    "backend_api_duration_ns": end - start, "final_rx_ns": last_rx})
            elif response[0] == "raw_reply":
                _, value, reading, start, end = response
                return Reply(value, "success" if reading else "no_response_expected", timing={
                    "backend_call_start_ns": start - self.origin, "backend_call_end_ns": end - self.origin,
                    "backend_api_duration_ns": end - start, "final_rx_ns": last_rx})
            elif response[0] == "error":
                self.broken = True
                raise TransferError(f"OTP {response[1]}: {response[2]}", Outcome(response[4]), code=response[3])
            else:
                raise TransferError("invalid OTP worker response")
