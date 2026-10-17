# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Nonexclusive macOS feature access bound to an exact HID registry entry."""
import ctypes

FEATURE_REPORT_BYTES = 8
HID_REPORT_TYPE_FEATURE = 2
IO_NOT_PERMITTED = 0xE00002E2
IO_NOT_PRIVILEGED = 0xE00002C1


class MacFeature:
    report_id_prefix = False
    read_api = "IOHIDDeviceGetReport"
    write_api = "IOHIDDeviceSetReport"

    def __init__(self, path):
        prefix = b"DevSrvsID:"
        if not path.startswith(prefix) or not path[len(prefix):].isdigit():
            raise ValueError("unsupported macOS HID path; exact registry ID required")
        entry_id = int(path[len(prefix):])
        if not 0 < entry_id < 2**64:
            raise ValueError("OTP registry entry ID is outside uint64")
        self.handle = None
        self.io = ctypes.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
        self.cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        pointer, uint, index = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_long
        signatures = {
            "IORegistryEntryIDMatching": (pointer, [ctypes.c_uint64]),
            "IOServiceGetMatchingService": (uint, [uint, pointer]),
            "IOHIDDeviceCreate": (pointer, [pointer, uint]),
            "IOObjectRelease": (ctypes.c_int, [uint]),
            "IOHIDDeviceOpen": (ctypes.c_int, [pointer, uint]),
            "IOHIDDeviceClose": (ctypes.c_int, [pointer, uint]),
            "IOHIDDeviceGetReport": (ctypes.c_int, [pointer, ctypes.c_int, index, pointer, ctypes.POINTER(index)]),
            "IOHIDDeviceSetReport": (ctypes.c_int, [pointer, ctypes.c_int, index, pointer, index]),
        }
        for name, (result, arguments) in signatures.items():
            function = getattr(self.io, name)
            function.restype, function.argtypes = result, arguments
        self.cf.CFRelease.restype, self.cf.CFRelease.argtypes = None, [pointer]
        match = self.io.IORegistryEntryIDMatching(entry_id)
        if not match:
            raise OSError("cannot match the selected OTP registry entry")
        entry = self.io.IOServiceGetMatchingService(0, match)
        if not entry:
            raise OSError("selected OTP registry entry disappeared")
        try:
            self.handle = self.io.IOHIDDeviceCreate(None, entry)
        finally:
            self.io.IOObjectRelease(entry)
        if not self.handle:
            raise OSError("cannot create selected OTP HID handle")
        status = self.io.IOHIDDeviceOpen(self.handle, 0)
        if status:
            self.close()
            raise OSError(status & 0xFFFFFFFF, "nonexclusive OTP HID open refused")

    def get_feature_report(self, report_id, length):
        buffer = ctypes.create_string_buffer(FEATURE_REPORT_BYTES)
        actual = ctypes.c_long(FEATURE_REPORT_BYTES)
        status = self.io.IOHIDDeviceGetReport(self.handle, HID_REPORT_TYPE_FEATURE, report_id, buffer, ctypes.byref(actual))
        if status:
            raise OSError(status & 0xFFFFFFFF, "OTP HID feature read refused")
        if not 0 <= actual.value <= FEATURE_REPORT_BYTES:
            raise OSError("OTP HID returned an invalid report length")
        return buffer.raw[:actual.value]

    def send_feature_report(self, data):
        if len(data) != FEATURE_REPORT_BYTES:
            raise ValueError("OTP feature payload must be eight bytes")
        buffer = ctypes.create_string_buffer(data)
        status = self.io.IOHIDDeviceSetReport(self.handle, HID_REPORT_TYPE_FEATURE, 0, buffer, len(data))
        if status:
            raise OSError(status & 0xFFFFFFFF, "OTP HID feature write refused")
        return len(data)

    def close(self):
        if self.handle:
            self.io.IOHIDDeviceClose(self.handle, 0)
            self.cf.CFRelease(self.handle)
            self.handle = None
