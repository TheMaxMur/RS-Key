#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Drive the display firmware's physical inputs and inspect its captured pixels.

Only owned image processes and loopback sockets are used. PIN labels come from
ST7789 GRAM; neither the firmware's keypad layout nor its PIN buffer is read.
"""

import argparse
import contextlib
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
import hashlib
import hmac
import json
from pathlib import Path
import re
import shutil
import socket
import threading
import time

from PIL import Image

import image_assurance as a
from ctaphid import Protocol2, decode, write

WIDTH, HEIGHT = 240, 320
HOST_WATCHDOG = 600
BG = 0x0862
FG = 0xEF9E
KEY_BG = 0x10C3


def rgb565(r, g, b):
    return (r >> 3) << 11 | (g >> 2) << 5 | (b >> 3)


def blend(fg, bg, alpha):
    def channel(shift, mask):
        return (((fg >> shift) & mask) * alpha + ((bg >> shift) & mask) * (15 - alpha) + 7) // 15
    return channel(11, 31) << 11 | channel(5, 63) << 5 | channel(0, 31)


class Font:
    """Read the public font asset, independently of the firmware's runtime state."""

    def __init__(self, role):
        source = (a.ROOT / "third_party/ibm-plex/font_data.rs").read_text()
        data = re.search(rf"const {role}_DATA:.*?= &\[(.*?)\];", source, re.S)[1]
        self.data = bytes(int(x, 16) for x in re.findall(r"0x([0-9A-F]+)", data))
        glyphs = re.search(rf"const {role}_GLYPHS:.*?= &\[(.*?)\];", source, re.S)[1]
        self.glyphs = [dict((k, int(v)) for k, v in re.findall(r"(\w+): (-?\d+)", glyph))
                       for glyph in re.findall(r"Glyph \{(.*?)\}", glyphs, re.S)]
        metrics = re.search(rf"const {role}: Font = Font \{{(.*?)\}};", source, re.S)[1]
        self.ascent = int(re.search(r"ascent: (\d+)", metrics)[1])
        self.descent = int(re.search(r"descent: (\d+)", metrics)[1])

    @lru_cache(maxsize=128)
    def raster(self, text):
        pixels, pen, right = {}, 0, 0
        for char in text:
            glyph = self.glyphs[ord(char) - 32]
            for y in range(glyph["height"]):
                for x in range(glyph["width"]):
                    i = y * glyph["width"] + x
                    packed = self.data[glyph["offset"] + i // 2]
                    alpha = (packed >> 4) if i % 2 == 0 else packed & 15
                    pixels[pen + glyph["left"] + x, glyph["top"] + y] = alpha
            right = max(right, pen + glyph["left"] + glyph["width"])
            pen += glyph["advance"]
        return max(pen, right), pixels

    def at(self, frame, text, center, fg=FG, bg=BG):
        width, pixels = self.raster(text)
        x0 = center[0] - width // 2
        baseline = center[1] + (self.ascent - self.descent) // 2
        return all(frame[(baseline + y) * WIDTH + x0 + x] == blend(fg, bg, alpha)
                   for (x, y), alpha in pixels.items())

    def find(self, frame, text, region=(0, 0, WIDTH, HEIGHT), fg=FG, bg=BG):
        width, pixels = self.raster(text)
        active = [(x, y, blend(fg, bg, alpha)) for (x, y), alpha in pixels.items() if alpha]
        if not active:
            raise ValueError("empty text template")
        anchor = max(active, key=lambda pixel: pixel[2])
        first_y, last_y = min(y for _, y in pixels), max(y for _, y in pixels)
        for baseline in range(region[1] - first_y, region[3] - last_y):
            for left in range(region[0], region[2] - width + 1):
                ax, ay, color = anchor
                if frame[(baseline + ay) * WIDTH + left + ax] != color:
                    continue
                if all(frame[(baseline + y) * WIDTH + left + x] == color for x, y, color in active):
                    return left, baseline
        return None


STRONG = Font("STRONG")
HEADING = Font("HEADING")
BODY = Font("BODY")
BODY_STRONG = Font("BODY_STRONG")
MUTED = rgb565(154, 163, 173)
DANGER = rgb565(255, 112, 116)
SURFACE = rgb565(19, 23, 29)
ACCENT = rgb565(77, 155, 255)


def keypad(frame):
    result = {}
    for row, col in [(r, c) for r in range(3) for c in range(3)] + [(3, 1)]:
        center = (49 + 71 * col, 108 + 55 * row)
        digits = [str(n) for n in range(10) if STRONG.at(frame, str(n), center, bg=KEY_BG)]
        if len(digits) != 1 or digits[0] in result:
            return None
        result[digits[0]] = center
    return result if len(result) == 10 else None


class Panel:
    def __init__(self, dev, directory, taps_port):
        self.dev, self.directory = dev, directory
        self.taps = socket.create_connection(("127.0.0.1", taps_port), timeout=30) if taps_port else None
        self.replies = self.taps.makefile("rb") if self.taps else None
        self.frames = []

    def close(self):
        if self.taps:
            self.replies.close()
            self.taps.close()

    def frame(self):
        raw = bytes.fromhex(self.dev.inspect("panel-read"))
        assert len(raw) == WIDTH * HEIGHT * 2, "incomplete panel capture"
        return [int.from_bytes(raw[i:i + 2], "big") for i in range(0, len(raw), 2)]

    def save(self, label, frame):
        raw = b"".join(pixel.to_bytes(2, "big") for pixel in frame)
        (self.directory / f"{label}.rgb565").write_bytes(raw)
        rgb = bytes(channel for p in frame for channel in
                    (((p >> 11) & 31) * 255 // 31, ((p >> 5) & 63) * 255 // 63, (p & 31) * 255 // 31))
        Image.frombytes("RGB", (WIDTH, HEIGHT), rgb).save(self.directory / f"{label}.png")
        self.frames.append({"label": label, "sha256": hashlib.sha256(raw).hexdigest(),
                            "panel": a.fields(self.dev.inspect("panel")),
                            "status": a.fields(self.dev.inspect("status"))})

    def wait(self, label, predicate, future=None):
        deadline = time.monotonic() + HOST_WATCHDOG
        while time.monotonic() < deadline:
            state = a.fields(self.dev.inspect("status"))
            assert state["dead"] == "false", f"image faulted awaiting {label}"
            frame = self.frame()
            if predicate(frame):
                self.save(label, frame)
                return frame
            if future and future.done():
                future.result()  # Preserve the actual transport failure.
                raise AssertionError(f"host command completed before {label}")
            time.sleep(0.2)
        self.save(f"{label}-watchdog", frame)
        if future:
            cancel(self.dev)
        raise AssertionError(f"host watchdog awaiting {label}")

    def text(self, label, text, font=HEADING, future=None, **kwargs):
        return self.wait(label, lambda frame: font.find(frame, text, **kwargs), future)

    def tap(self, x, y, hold=0, gap=80):
        assert self.taps, "this scenario has no scripted finger"
        self.taps.sendall(f"{x},{y},{hold},{gap}\n".encode())
        assert self.replies.readline() == b"ok\n", "tap source refused a contact"

    def armed(self, future):
        before = int(a.fields(self.dev.inspect("panel"))["touch_reports"])
        deadline = time.monotonic() + HOST_WATCHDOG
        while int(a.fields(self.dev.inspect("panel"))["touch_reports"]) < before + 2:
            if future.done():
                future.result()
                raise AssertionError("ceremony completed before its touch polling loop")
            assert time.monotonic() < deadline, "firmware never polled the displayed touch prompt"
            time.sleep(0.1)

    def elapsed(self, ns, future=None):
        start = int(a.fields(self.dev.inspect("status"))["emulated_ns"])
        deadline = time.monotonic() + HOST_WATCHDOG
        while int(a.fields(self.dev.inspect("status"))["emulated_ns"]) - start < ns:
            if future:
                assert not future.done(), "ceremony accepted an insufficient hold"
            assert time.monotonic() < deadline, "image stopped advancing"
            time.sleep(0.1)

    def pin(self, label, pin, future=None):
        frame = self.wait(f"{label}-keypad", keypad, future)
        layout = keypad(frame)
        for digit in pin:
            self.tap(*layout[digit])
        self.tap(191, 273)
        return layout

    def caption(self, label, text, rejected=False, future=None):
        return self.text(label, text, BODY, future, region=(0, 290, WIDTH, HEIGHT),
                         fg=DANGER if rejected else MUTED)

    def menu(self, label, text):
        return self.text(label, text, BODY, bg=SURFACE)

    def wake_button(self):
        self.dev.inspect("panel-wake down")
        self.elapsed(100_000_000)
        self.dev.inspect("panel-wake up")


class HidProgress:
    def __init__(self, hid):
        self.hid = hid
        self.upneeded = threading.Event()
        self.keepalives = []

    def read(self, *args, **kwargs):
        report = self.hid.read(*args, **kwargs)
        if len(report) >= 8 and report[4] == 0xBB:
            self.keepalives.append(report[7])
            if report[7] == 2:
                self.upneeded.set()
        return report

    def __getattr__(self, name):
        return getattr(self.hid, name)


def confirm(frame):
    return (STRONG.find(frame, "Save", (90, 245, 230, 305), bg=rgb565(47, 125, 240))
            or BODY.find(frame, "Hold to approve", (90, 245, 230, 305), bg=rgb565(47, 125, 240)))


def cancel(dev, cid=None):
    write(dev.hid, (dev.cid if cid is None else cid) + b"\x91\x00\x00")


def residue(dev, pin):
    def check():
        result = a.fields(dev.inspect(f"scan {pin.hex()}"))
        assert int(result["count"]) == 0, f"PIN residue: {result['addresses']}"
        return result
    clean = check()
    address = a.image_operations.CONTROL_ADDRESS
    previous = dev.inspect(f"read {address} {len(pin)}")
    dev.inspect(f"plant {address} {pin.hex()}")
    try:
        try:
            check()
        except AssertionError as error:
            assert str(error) == f"PIN residue: {address}", error
        else:
            raise AssertionError("planted PIN did not fail the same residue check")
    finally:
        dev.inspect(f"plant {address} {previous}")
    assert check() == clean
    return {"clean": clean, "planted_at": address, "planted_rejected_and_restored": True}


@contextlib.contextmanager
def worker():
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        yield pool
    finally:
        # The owning Device closes sockets and reaps its child even on an oracle error.
        pool.shutdown(wait=False, cancel_futures=True)


def hold_prompt(frame):
    return BODY.find(frame, "Hold to approve", (90, 245, 230, 305), bg=rgb565(47, 125, 240))


def ceremonies(dev, panel, report, cases=None):
    progress = HidProgress(dev.hid)
    dev.hid = progress
    with worker() as pool:
        cases = cases or ("deny", "cancel", "short-hold", "approve")
        registrations = [kind for kind in cases if kind != "short-hold"]
        if "short-hold" in cases and "approve" not in registrations:
            registrations.append("approve")
        for kind in registrations:
            before = a.fields(dev.inspect("status"))
            expected = 0x27 if kind == "deny" else 0x2D if kind == "cancel" else 0
            def operation():
                if expected:
                    return dev.ctap(1, {1: a.CDH, 2: {"id": a.RP}, 3: {"id": b"user", "name": "image"},
                                       4: [{"alg": -7, "type": "public-key"}], 7: {"rk": True}}, expected)
                return a.create_credential(dev)
            progress.upneeded.clear()
            future = pool.submit(dev.measured, kind, operation, report)
            assert progress.upneeded.wait(HOST_WATCHDOG), "no USB UPNEEDED keepalive"
            panel.wait(f"{kind}-prompt", confirm, future)
            if kind == "deny":
                panel.tap(50, 272)
            elif kind == "cancel":
                panel.armed(future)
                cancel(dev)
            else:
                panel.tap(170, 272)
            result = future.result(timeout=HOST_WATCHDOG)
            if expected:
                # Non-secure can answer CANCEL before the Secure worker returns.
                # Drain that worker before checking for a late credential write.
                dev.ctap(4)
                after = a.fields(dev.inspect("status"))
                assert after["programmed_bytes"] == before["programmed_bytes"], f"{kind}: refused registration wrote flash"
            print(f"PASS {kind}", flush=True)
        if registrations[-1] != "approve":
            return
        cred, public = result
        for label in (["short-hold", "get-assertion"] if "short-hold" in cases else ["get-assertion"]):
            progress.upneeded.clear()
            future = pool.submit(dev.measured, label, lambda: a.assertion(dev, cred, public), report)
            assert progress.upneeded.wait(HOST_WATCHDOG), "no assertion UPNEEDED keepalive"
            panel.wait(f"{label}-prompt", hold_prompt, future)
            if label == "short-hold":
                panel.armed(future)
                panel.tap(170, 272, 400)
                panel.elapsed(900_000_000, future)
                panel.save("short-hold-still-pending", panel.frame())
            panel.tap(170, 272, 1200)
            future.result(timeout=HOST_WATCHDOG)
            print(f"PASS {label} signature", flush=True)
    report["keepalives"] = progress.keepalives


def stale_touch(dev, panel, report):
    progress = HidProgress(dev.hid)
    dev.hid = progress
    with worker() as pool:
        future = pool.submit(a.create_credential, dev)
        assert progress.upneeded.wait(HOST_WATCHDOG)
        panel.wait("stale-registration", confirm, future)
        panel.tap(170, 272)
        cred, public = future.result(timeout=HOST_WATCHDOG)
        request = {1: a.RP, 2: a.CDH, 3: [{"id": cred, "type": "public-key"}]}
        progress.upneeded.clear()
        future = pool.submit(dev.measured, "stale-cancel", lambda: dev.ctap(2, request, 0x2D), report)
        assert progress.upneeded.wait(HOST_WATCHDOG)
        panel.wait("stale-first-prompt", hold_prompt, future)
        panel.armed(future)
        panel.tap(170, 272, 3000)
        panel.elapsed(400_000_000, future)
        cancel(dev)
        future.result(timeout=HOST_WATCHDOG)
        progress.upneeded.clear()
        future = pool.submit(dev.measured, "stale-next-command", lambda: a.assertion(dev, cred, public), report)
        assert progress.upneeded.wait(HOST_WATCHDOG)
        panel.wait("stale-next-prompt", hold_prompt, future)
        panel.elapsed(3_200_000_000, future)
        panel.save("stale-finger-did-not-approve", panel.frame())
        panel.tap(170, 272, 1200)
        future.result(timeout=HOST_WATCHDOG)
    report["keepalives"] = progress.keepalives
    print("PASS stale held finger / fresh gesture / independent signature", flush=True)


def timeout(dev, panel, report):
    panel.text("timeout-onboarding", "Set a PIN?")
    panel.tap(120, 272)
    panel.elapsed(300_000_000)
    panel.tap(210, 302)
    panel.text("timeout-settings", "Settings", fg=ACCENT)
    panel.tap(120, 80)
    panel.text("timeout-display", "Display", fg=ACCENT)
    panel.tap(120, 152)
    panel.text("timeout-setting", "Touch timeout", fg=ACCENT)
    for _ in range(4):
        panel.tap(60, 190)
    panel.text("timeout-ten-seconds", "10 s")
    panel.tap(26, 40)
    panel.text("timeout-display-return", "Display", fg=ACCENT)
    panel.tap(26, 40)
    panel.text("timeout-settings-return", "Settings", fg=ACCENT)
    panel.tap(30, 302)
    panel.elapsed(300_000_000)
    request = {1: a.CDH, 2: {"id": a.RP}, 3: {"id": b"user", "name": "image"},
               4: [{"alg": -7, "type": "public-key"}], 7: {"rk": True}}
    with worker() as pool:
        future = pool.submit(dev.measured, "timeout", lambda: dev.ctap(1, request, 0x27), report)
        panel.wait("timeout-prompt", confirm, future)
        future.result(timeout=HOST_WATCHDOG)
        elapsed = report["timeout_ctap"][0]["elapsed_ns"]
        assert 9_900_000_000 <= elapsed <= 11_000_000_000, f"timeout at {elapsed} image ns"
        future = pool.submit(dev.measured, "timeout-next-registration", lambda: a.create_credential(dev), report)
        panel.wait("timeout-next-prompt", confirm, future)
        panel.tap(170, 272)
        future.result(timeout=HOST_WATCHDOG)
    print("PASS image-clock timeout / next fresh registration", flush=True)


def physical(dev, panel, report):
    other = a.emu.EmuHid()
    other.open_path()
    try:
        other_cid = a.ctaphid_init(other)
        with worker() as pool:
            future = pool.submit(a.create_credential, dev)
            panel.wait("physical-registration", confirm, future)
            panel.armed(future)
            dev.inspect("panel-touch 170 272 50")
            cred, public = future.result(timeout=HOST_WATCHDOG)
            future = pool.submit(dev.measured, "physical-sign-in", lambda: a.assertion(dev, cred, public), report)
            panel.wait("physical-sign-in", hold_prompt, future)
            panel.armed(future)
            write(other, other_cid + b"\x91\0\0")
            panel.elapsed(200_000_000, future)
            dev.inspect("panel-touch 170 272 2000")
            panel.elapsed(450_000_000, future)
            dev.inspect("panel-touch 200 200 2000")
            panel.elapsed(100_000_000, future)
            dev.inspect("panel-touch 170 272 2000")
            panel.elapsed(450_000_000, future)
            dev.inspect("panel-release")
            panel.elapsed(200_000_000, future)
            panel.save("physical-slide-and-lift-did-not-approve", panel.frame())
            dev.inspect("panel-touch 170 272 1200")
            future.result(timeout=HOST_WATCHDOG)
    finally:
        other.close()
    print("PASS foreign-channel cancel / slide / lift / fresh hold / signature", flush=True)


def device_pin(dev, panel, report):
    pin = "81726395"

    def provision():
        panel.text("onboarding", "Set a PIN?")
        panel.tap(120, 272)
        panel.elapsed(300_000_000)
        panel.tap(210, 302)
        panel.text("settings", "Settings", fg=ACCENT)
        panel.tap(120, 116)
        panel.menu("security", "Set device PIN")
        panel.tap(120, 188)
        panel.elapsed(300_000_000)
        panel.tap(120, 80)
        panel.caption("device-choose", "Choose a PIN")
        panel.pin("device-cancel", pin[:3])
        panel.tap(28, 23)
        panel.menu("device-cancelled", "Set device PIN")
        panel.tap(120, 80)
        panel.caption("device-choose-again", "Choose a PIN")
        layout = panel.pin("device-new", pin)
        panel.caption("device-confirm", "Re-enter to confirm")
        panel.pin("device-mismatch", "91726395")
        panel.caption("device-mismatch-refused", "PINs don't match", rejected=True)
        panel.pin("device-new-retry", pin)
        panel.caption("device-confirm-retry", "Re-enter to confirm")
        panel.pin("device-confirm-good", pin)
        panel.menu("device-set", "Change device PIN")
        assert layout != {str(n): (49 + 71 * ((n - 1) % 3), 108 + 55 * ((n - 1) // 3))
                          for n in range(1, 10)} | {"0": (120, 273)}, "PIN scrambling was not enabled"
        return layout

    layout = dev.measured("device-pin-provision", provision, report)

    def refuse_unlock():
        panel.tap(26, 40)
        panel.text("settings-return", "Settings", fg=ACCENT)
        panel.tap(30, 302)
        panel.elapsed(300_000_000)
        panel.wake_button()
        panel.elapsed(300_000_000)
        assert a.fields(dev.inspect("panel"))["backlight"] == "0", "wake button did not blank panel"
        panel.wake_button()
        panel.text("device-locked", "Locked")
        panel.tap(120, 200)
        panel.pin("device-unlock-wrong", "91726395")
        panel.caption("device-wrong-refused", "Wrong PIN, 7 left", rejected=True)
        panel.tap(28, 23)
        panel.text("device-unlock-cancelled", "Locked")

    dev.measured("device-pin-refuse-unlock", refuse_unlock, report)
    dev.power_cycle()

    def unlock():
        panel.text("device-locked-after-reboot", "Locked")
        panel.tap(120, 200)
        panel.caption("device-retries-persisted", "7 tries remaining")
        panel.pin("device-unlock-correct", pin)
        panel.elapsed(500_000_000)
        panel.tap(210, 302)
        panel.text("device-unlocked-settings", "Settings", fg=ACCENT)

    dev.measured("device-pin-unlock-after-reboot", unlock, report)
    report["device_pin"] = {"scrambled_layout": layout, "wrong_retry_persisted": 7,
                            "residue": residue(dev, pin.encode())}
    print("PASS device PIN mismatch/cancel/wrong/reboot/correct", flush=True)


def scramble(panel):
    panel.text("onboarding", "Set a PIN?")
    panel.tap(120, 272)
    panel.elapsed(300_000_000)
    panel.tap(210, 302)
    panel.text("settings", "Settings", fg=ACCENT)
    panel.tap(120, 116)
    panel.menu("security", "Set device PIN")
    panel.tap(120, 188)
    panel.elapsed(300_000_000)
    panel.tap(26, 40)
    panel.text("settings-return", "Settings", fg=ACCENT)
    panel.tap(30, 302)
    panel.elapsed(300_000_000)


def fido_pin(dev, panel, report):
    pin = b"82639517"
    ka = dev.ctap(6, {1: 2, 2: 2})[1]
    proto = Protocol2(ka[-2], ka[-3])
    encrypted = proto.encrypt(pin.ljust(64, b"\0"))
    dev.ctap(6, {1: 2, 2: 3, 3: proto.cose(), 4: proto.authenticate(encrypted), 5: encrypted})
    scramble(panel)
    progress = HidProgress(dev.hid)
    dev.hid = progress
    with worker() as pool:
        for kind, expected, retries in [("wrong", 0x3F, 7), ("decline", 0x27, 7),
                                        ("cancel", 0x2D, 7), ("correct", 0, 8)]:
            ka = dev.ctap(6, {1: 2, 2: 2})[1]
            proto = Protocol2(ka[-2], ka[-3])
            progress.upneeded.clear()
            label = f"fido-pin-{kind}"
            future = pool.submit(dev.measured, label,
                lambda: dev.ctap(6, {1: 2, 2: 6, 3: proto.cose(), 9: 3, 10: a.RP}, expected), report)
            assert progress.upneeded.wait(HOST_WATCHDOG), "no built-in UV keepalive"
            panel.wait(f"{label}-consent", confirm, future)
            panel.tap(170, 272, 1200)
            panel.wait(f"{label}-pad", keypad, future)
            if kind == "decline":
                panel.tap(28, 23)
            elif kind == "cancel":
                panel.armed(future)
                cancel(dev)
            else:
                panel.pin(label, (b"92639517" if kind == "wrong" else pin).decode(), future)
            result = future.result(timeout=HOST_WATCHDOG)
            assert dev.ctap(6, {1: 2, 2: 7})[5] == retries, f"{label}: wrong retry count"
            report[f"{label}-retries"] = retries
            print(f"PASS {label}", flush=True)
        token = proto.decrypt(result[2])
        assert len(token) == 32, "wrong built-in UV token length"
        auth = hmac.new(token, a.CDH, hashlib.sha256).digest()
        future = pool.submit(dev.measured, "fido-pin-token-used", lambda: dev.ctap(1,
            {1: a.CDH, 2: {"id": a.RP}, 3: {"id": b"uv-user", "name": "image-uv"},
             4: [{"alg": -7, "type": "public-key"}], 7: {"rk": True}, 8: auth, 9: 2}), report)
        panel.wait("fido-token-makecredential", confirm, future)
        panel.tap(170, 272, 1200)
        answer = future.result(timeout=HOST_WATCHDOG)
        assert answer[2][32] & 5 == 5, "built-in UV token did not set UP+UV"
    report["fido_keepalives"] = progress.keepalives
    report["fido_pin_residue"] = residue(dev, pin)
    print("PASS built-in UV token used by makeCredential", flush=True)


def secure(dev, p2, report):
    payload = bytes.fromhex("000082000000000200000000000000") + bytes([0, 0x20, 0, p2])
    dev.card.seq = (dev.card.seq + 1) & 255
    seq = dev.card.seq
    header = bytes([0x69]) + len(payload).to_bytes(4, "little") + bytes([0, seq, 0, 0, 0])
    dev.inspect("transport-begin")
    dev.card.sock.sendall(bytes([a.emu.OP_CCID]) + (len(header) + len(payload)).to_bytes(4, "big") + header + payload)
    report["request"] = (header + payload).hex()
    report["extensions"] = []
    while True:
        reply = a.emu._recv_frame(dev.card.sock)
        assert len(reply) >= 10 and reply[0] == 0x80 and reply[6] == seq, "invalid secure CCID reply"
        length = int.from_bytes(reply[1:5], "little")
        assert len(reply) == 10 + length, "CCID length mismatch"
        if reply[7] & 0xC0 == 0x80:
            report["extensions"].append(reply.hex())
            continue
        report["reply"] = reply.hex()
        report["transport"] = {key: int(value) for key, value in a.fields(dev.inspect("transport-end")).items()}
        assert report["transport"]["max_gap_ns"] <= a.USB_MAX_GAP_NS, "CCID starved USB on the image clock"
        assert report["extensions"], "CCID PIN entry sent no time extensions"
        return reply[7] & 0xC0, reply[8], reply[10:]


def ccid_pin(dev, panel, report):
    def retries(applet):
        if applet == "openpgp":
            return dev.apdu(bytes.fromhex("00ca00c400"))[-3]
        return dev.apdu(bytes.fromhex("00f7008000"))[-1]
    scramble(panel)
    with worker() as pool:
        for applet, aid, p2 in [("openpgp", a.OPENPGP, 0x81),
                               ("piv", bytes.fromhex("a000000308000010000100"), 0x80)]:
            dev.select(aid)
            for kind in ("wrong", "decline", "correct"):
                label = f"{applet}-pin-{kind}"
                row = report.setdefault(label, {})
                row["retry_before"] = retries(applet)
                future = pool.submit(dev.measured, label + "-stack", lambda: secure(dev, p2, row), report)
                panel.wait(f"{label}-consent", confirm, future)
                panel.tap(170, 272, 1200)
                panel.wait(f"{label}-pad", keypad, future)
                if kind == "decline":
                    panel.tap(28, 23)
                else:
                    panel.pin(label, "923456" if kind == "wrong" else "123456", future)
                status, error, body = future.result(timeout=HOST_WATCHDOG)
                if kind == "decline":
                    assert (status, error, body) == (0x40, 0xEF, b""), "CCID PIN decline was not final"
                else:
                    assert (status, error) == (0, 0), "CCID secure transport failed"
                    expected = (b"\x69\x82" if applet == "openpgp" else b"\x63\xc2") if kind == "wrong" else b"\x90\0"
                    assert body == expected, f"CCID PIN verdict {body.hex()}, expected {expected.hex()}"
                row["retry_after"] = retries(applet)
                assert row["retry_after"] == (row["retry_before"] - 1 if kind == "wrong" else
                                              row["retry_before"] if kind == "decline" else 3), "CCID retry count mismatch"
                print(f"PASS {label}", flush=True)
    report["ccid_pin_residue"] = residue(dev, b"123456")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emulator", required=True, type=Path)
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--only", choices=["ceremonies", "stale", "physical", "timeout", "pin", "fido-pin", "ccid-pin"], default="ceremonies")
    parser.add_argument("--case", choices=["deny", "cancel", "short-hold", "approve"])
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=False)
    artifacts = args.work / "artifacts"
    artifacts.mkdir()
    binary, image = artifacts / "rsk-emu", artifacts / "display.elf"
    shutil.copy2(args.emulator, binary)
    shutil.copy2(args.image, image)
    report = {"inputs": {str(path.name): hashlib.sha256(path.read_bytes()).hexdigest()
                         for path in (binary, image, Path(__file__), Path(a.__file__),
                                      a.ROOT / "third_party/ibm-plex/font_data.rs")}}
    for source in (Path(__file__), Path(a.__file__), Path(a.image_operations.__file__),
                   a.ROOT / "tests/ctaphid.py", a.ROOT / "tests/emu.py"):
        shutil.copy2(source, artifacts / source.name)
    taps_port = None if args.only == "physical" else a.port()
    try:
        with a.device(binary, image, args.work / "flash", args.work, "image",
                      display=True, taps_port=taps_port) as dev:
            panel = Panel(dev, args.work, taps_port)
            report["frames"] = panel.frames
            try:
                report["launch"] = dev.process.args
                if args.only == "ceremonies":
                    ceremonies(dev, panel, report, [args.case] if args.case else None)
                else:
                    {"stale": stale_touch, "physical": physical, "timeout": timeout, "pin": device_pin,
                     "fido-pin": fido_pin, "ccid-pin": ccid_pin}[args.only](dev, panel, report)
            finally:
                panel.close()
        report["passed"] = True
    finally:
        (args.work / "report.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
