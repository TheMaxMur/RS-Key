# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Run the same diagnostic protocol over image TCP reports or a selected USB key."""

from dataclasses import asdict
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import struct
import subprocess
import sys
import tempfile
import time
import zlib

import tz_hardware as hw


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class Link:
    def __init__(self, device):
        self.device = device
        nonce = os.urandom(8)
        self.send(b'\xff' * 4 + bytes([0x86, 0, 8]) + nonce)
        response = bytes(device.read(64, 2000))
        assert len(response) >= 23 and response[4] == 0x86 and response[7:15] == nonce, 'diagnostic HID INIT failed'
        self.cid = response[15:19]

    def send(self, data):
        assert len(data) <= 64
        self.device.write(b'\0' + data.ljust(64, b'\0'))

    def command(self, action, argument=0):
        payload = b'hw' + struct.pack('<II', action, argument)
        self.send(self.cid + bytes([0xfe, 0, len(payload)]) + payload)
        response = bytes(self.device.read(64, 2000))
        assert response[:7] == self.cid + bytes([0xfe, 0, 4]), f'diagnostic reply differs: {response.hex()}'
        return int.from_bytes(response[7:11], 'little')

    def close(self):
        self.device.close()


class Model:
    physical = False

    def __init__(self, emulator, directory, work):
        sys.path.insert(0, str(hw.ROOT / 'tools/emu'))
        import image_assurance as lab
        self.lab = lab
        self.device = lab.Device(emulator.resolve(), directory / 'combined.elf', work / 'store.bin', work, 'diagnostic')
        self.expected_crc = zlib.crc32(lab.scratch_code(directory / 'combined.elf')[1])

    def open(self):
        device = self.lab.emu.EmuHid()
        device.open_path()
        try:
            return Link(device)
        except BaseException:
            device.close()
            raise

    def clock(self):
        return int(self.lab.fields(self.device.inspect('status'))['power_ups'])

    def wait_reset(self, before, denied):
        deadline = time.monotonic() + 240
        while self.clock() == before:
            assert time.monotonic() < deadline, 'image never completed the diagnostic watchdog reset'
            time.sleep(0.1)
        return dict(power_ups_before=before, power_ups_after=self.clock())

    def card(self):
        card = self.lab.emu.EmuCard()
        card.connect()
        return card

    def close_card(self, card):
        card.disconnect()

    def close(self):
        self.device.close()


def enumerate_usb_devices():
    tree = plistlib.loads(subprocess.check_output(['/usr/sbin/ioreg', '-p', 'IOUSB', '-l', '-a']))
    devices = []
    def visit(node):
        if isinstance(node, list):
            for child in node:
                visit(child)
        elif isinstance(node, dict):
            if 'idVendor' in node:
                devices.append(node)
            visit(node.get('IORegistryEntryChildren', []))
    visit(tree)
    return devices


def bootrom_serials():
    return [device.get('USB Serial Number') for device in enumerate_usb_devices()
            if device.get('idVendor') == 0x2e8a and device.get('idProduct') in (3, 15)]


class Physical:
    physical = True

    def __init__(self, serial, directory):
        assert serial, 'physical key serial is required'
        self.serial = serial
        os.environ['RSK_TEST_SERIAL'] = serial
        with tempfile.TemporaryDirectory(prefix='rskey-scratch-crc-') as folder:
            output = Path(folder) / 'scratch.bin'
            subprocess.run(['arm-none-eabi-objcopy', '-O', 'binary', '--only-section=.rsk_scratch_exec',
                            str(directory / 'combined.elf'), str(output)], check=True)
            data = output.read_bytes()
            assert len(data) == hw.SCRATCH_END - hw.SCRATCH_START
            self.expected_crc = zlib.crc32(data)

    def present(self):
        matches = [device for device in enumerate_usb_devices() if device.get('USB Serial Number') == self.serial]
        assert len(matches) <= 1, 'ambiguous physical USB serial'
        return bool(matches)

    def open(self):
        import hid
        devices = [item for item in hid.enumerate() if item.get('serial_number') == self.serial
                   and item.get('usage_page') == 0xf1d0]
        if not devices:
            raise OSError('selected physical FIDO interface is not enumerated')
        assert len(devices) == 1, 'ambiguous physical FIDO interface'
        device = hid.device()
        device.open_path(devices[0]['path'])
        try:
            return Link(device)
        except BaseException:
            device.close()
            raise

    def clock(self):
        assert self.present(), 'selected USB key disappeared before arming'
        return time.monotonic()

    def wait_reset(self, before, denied):
        deadline = before + hw.WATCHDOG_MS / 1000 + 15
        while self.present():
            assert time.monotonic() < deadline, 'physical key never detached for the diagnostic reset'
            time.sleep(0.02)
        detached_after = time.monotonic() - before
        fatal_detach = not denied or detached_after < hw.WATCHDOG_MS / 1000 - 1
        deadline = time.monotonic() + 60
        while not self.present():
            assert time.monotonic() < deadline, 'physical key did not re-enumerate after the watchdog'
            time.sleep(0.05)
        return dict(detached_after_seconds=detached_after, reenumerated_after_seconds=time.monotonic() - before,
                    fatal_detach_observed=fatal_detach)

    def card(self):
        from _device import find_reader
        from smartcard.Exceptions import CardConnectionException
        from smartcard.scard import SCARD_LEAVE_CARD, SCARD_SHARE_EXCLUSIVE
        deadline = time.monotonic() + 30
        while True:
            reader = find_reader(require_marker=True)
            if reader is not None:
                connection = reader.createConnection()
                try:
                    connection.connect(mode=SCARD_SHARE_EXCLUSIVE, disposition=SCARD_LEAVE_CARD)
                    return connection
                except CardConnectionException:
                    if time.monotonic() >= deadline:
                        raise
            assert time.monotonic() < deadline, 'selected physical CCID reader is missing'
            time.sleep(0.1)

    def close_card(self, card):
        from smartcard.Exceptions import CardConnectionException
        try:
            card.disconnect()
        except CardConnectionException:
            pass  # The observed USB removal invalidates this pre-fault PC/SC handle.

    def close(self):
        pass


def reconnect(backend, build_id):
    deadline = time.monotonic() + 90
    while True:
        link = None
        try:
            link = backend.open()
            assert link.command(hw.GET, 8) == build_id, 'different diagnostic image is running'
            return link
        except (AssertionError, OSError, TimeoutError):
            if link is not None:
                link.close()
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


def metadata(link, backend):
    values = {name: link.command(hw.GET, index) for name, index in
              [('scratch_crc', 4), ('launch', 5), ('load_crc', 6), ('ns_entry', 7), ('boot_authority', 11)]}
    values['ns_registers'] = [link.command(hw.GET, index) for index in range(34, 38)]
    assert values['scratch_crc'] == values['load_crc'] == backend.expected_crc, (
        f'complete scratch code/padding does not match the exact ELF: {values}, expected CRC {backend.expected_crc:#x}')
    assert values['launch'] == hw.LAUNCH_FLAGS, f'Secure launch readback differs: {values}'
    # Clearing the shared FPU registers before BXNS sets the unbanked FPCA bit.
    # The pinned image model does not implement that automatic CONTROL update.
    control = hw.CONTROL_FPCA if backend.physical else 0
    assert values['ns_registers'] == [control, 0, 0, 0], f'NS entry registers differ: {values}'
    assert values['ns_entry'] == hw.ENTRY_FLAGS ^ bool(control), f'NS banked entry state differs: {values}'
    assert values['boot_authority'] == 0, 'PIV authority present before the first ICC power-on'
    return values


def checked_manifest(directory):
    import hashlib
    manifest = json.loads((directory / 'manifest.json').read_text())
    for name, expected in manifest['sha256'].items():
        assert hashlib.sha256((directory / name).read_bytes()).hexdigest() == expected, f'changed fixture artifact: {name}'
    return manifest


def fresh_authorization(backend, link=None):
    card = backend.card()
    try:
        piv_module = module('hardware_piv', hw.ROOT / 'tests/80_piv.py')
        piv = piv_module.Piv(card)
        assert piv.raw(0x20, 0, 0x80)[1] != 0x9000, 'PIN authority survived before SELECT'
        piv.select()
        status = piv.raw(0x20, 0, 0x80)[1]
        assert status & 0xfff0 == 0x63c0 and status & 15, 'PIN authority survived SELECT'
        generation = piv_module.tlv(0xac, piv_module.tlv(0x80, b'\x07'))
        assert piv.raw(0x47, 0, 0x9c, generation)[1] == 0x6982, 'management authority survived reset'
        piv.verify_pin()
        piv.auth_mgm()
        assert piv.raw(0x20, 0, 0x80)[1] == 0x9000, 'fresh PIN authorization did not succeed'
        if link is not None:
            assert link.command(hw.GET, 12) & 3 == 3, 'fresh management authorization was not observed'
        return dict(PIN_refused_before_SELECT=True, PIN_and_management_refused_after_SELECT=True,
                    fresh_authorization=True)
    finally:
        backend.close_card(card)


def bootsel(backend, directory, work, volume, bootrom_serial):
    manifest = checked_manifest(directory)
    assert bootrom_serial and not bootrom_serials(), 'BOOTSEL handover requires no preexisting BootROM device'
    assert not volume.exists(), 'BOOTSEL volume already exists before the selected key reboots'
    link = reconnect(backend, manifest['build_id'])
    try:
        initial = metadata(link, backend)
    finally:
        link.close()
    card = backend.card()
    from smartcard.Exceptions import CardConnectionException
    try:
        aid = bytes.fromhex('f000000001')
        _, sw1, sw2 = card.transmit([0, 0xa4, 4, 0, len(aid)] + list(aid))
        assert (sw1, sw2) == (0x90, 0), 'vendor SELECT refused'
        try:
            _, sw1, sw2 = card.transmit([0, 0x1f, 1, 0, 0])
            assert (sw1, sw2) == (0x90, 0), 'BOOTSEL reboot refused'
        except CardConnectionException:
            pass  # BootROM enumeration and the subsequent reads must confirm the reboot.
    finally:
        backend.close_card(card)
    deadline = time.monotonic() + 60
    while not (volume / 'INFO_UF2.TXT').is_file():
        assert time.monotonic() < deadline, 'BOOTSEL volume did not mount'
        time.sleep(0.1)
    assert not backend.present(), 'old firmware is still attached'
    assert bootrom_serials() == [bootrom_serial], 'BOOTSEL serial does not match the selected key'
    selector = ['--ser', bootrom_serial]
    info = subprocess.check_output(['picotool', 'info', '-a', *selector], text=True)
    (work / 'picotool-info.txt').write_text(info)
    def save(start, end, name):
        output = work / name
        subprocess.run(['picotool', 'save', '-r', hex(start), hex(end), str(output), '-t', 'bin', *selector], check=True)
        data = output.read_bytes()
        assert len(data) == end - start, 'BootROM read length differs'
        return data
    before = save(hw.SCRATCH_START, hw.SCRATCH_END, 'bootsel-scratch.bin')
    pattern = bytes((index * 7 + 0x5a) & 255 for index in range(256))
    source = work / 'readback-pattern.bin'
    source.write_bytes(pattern)
    subprocess.run(['picotool', 'load', str(source), '-t', 'bin', '-o', '0x20010000', *selector], check=True)
    assert save(0x20010000, 0x20010100, 'readback.bin') == pattern, 'BootROM did not serve actual SRAM bytes'
    block = (directory / 'combined.uf2').read_bytes()[:512]
    fields = struct.unpack('<8I', block[:32])
    assert fields[:5] == (0x0a324655, 0x9e5d5157, 0x2000, 0x10000000, 256)
    assert fields[5] == 0 and fields[6] > 1 and fields[7] == 0xe48bff59
    assert struct.unpack('<I', block[-4:])[0] == 0x0ab16f30
    # Keep the original total count: a partial transfer must remain in BootROM.
    with (volume / 'TZPROBE.UF2').open('wb') as output:
        output.write(block)
        output.flush()
        os.fsync(output.fileno())
    time.sleep(1)
    bitmap = save(0x20081c00, hw.SCRATCH_END, 'erase-bitmap.bin')
    assert bitmap == b'\x01' + b'\0' * 1023, 'ROM erase bitmap does not describe the single firmware sector'
    assert not backend.present(), 'partial UF2 transfer resumed the old firmware'
    result = dict(initial=initial, old_firmware_absent=True, scratch_before_crc=zlib.crc32(before),
                  BootROM_SRAM_readback=True, partial_UF2_blocks=1, erase_bitmap_sector=0,
                  complete_reload_required=True)
    (work / 'report.json').write_text(json.dumps(result, indent=2) + '\n')
    print('PASS: terminal BOOTSEL handover and ROM erase bitmap; reload the complete diagnostic image.', flush=True)
    return result


def run(backend, directory, work, selected=(), matrix=None):
    manifest = checked_manifest(directory)
    build_id = manifest['build_id']
    rows = []
    report = dict(backend='physical USB' if backend.physical else 'ARM ELF model', build_id=build_id,
                  manifest=str(directory / 'manifest.json'), matrix=matrix, cases=rows, status='running')
    link = None
    try:
        (work / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        link = reconnect(backend, build_id)
        report['initial'] = metadata(link, backend)
        cases = hw.cases(link.command(hw.GET, 30), matrix)
        if selected:
            assert set(selected) <= {case.name for case in cases}, 'unknown case selection'
            cases = [case for case in cases if case.name in selected]
        for case_id, case in enumerate(cases, 1):
            print('case:', case.name, flush=True)
            report['active_case'] = case.name
            for attempt in range(1, hw.PENDING_PACKET_ATTEMPTS + 1):
                card = None
                try:
                    if backend.physical and not case.authorized:
                        # Complete PC/SC's initial reader probes before queuing the raw CCID marker.
                        ready = backend.card()
                        backend.close_card(ready)
                    if case.authorized:
                        card = backend.card()
                        piv = module('hardware_piv', hw.ROOT / 'tests/80_piv.py').Piv(card)
                        piv.select()
                        piv.verify_pin()
                        piv.auth_mgm()
                        assert link.command(hw.GET, 12) & 3 == 3, 'PIN and management authority were not observed before the fault'
                    assert link.command(hw.SET_TARGET, case.address) == 0
                    before = backend.clock()
                    argument = case_id << 8 | case.mode | (hw.AUTH_REQUIRED if case.authorized else 0)
                    assert link.command(hw.ARM, argument) == 0, 'diagnostic arm was refused'
                    link.close()
                    link = None
                    observations = backend.wait_reset(before, case.denied)
                    link = reconnect(backend, build_id)
                    words = [link.command(hw.GET, index) for index in range(4)]
                    row = dict(case=asdict(case), case_id=case_id, attempt=attempt, words=words,
                               physical=backend.physical, observations=observations)
                    suffix = '' if attempt == 1 else f'-attempt-{attempt}'
                    (work / f'{case_id:03}-{case.name}{suffix}.json').write_text(json.dumps(row, indent=2) + '\n')
                    rows.append(row)
                    if backend.physical and hw.pending_packet_missing(words, case_id, case):
                        row['status'] = 'inconclusive'
                        row['after_boot'] = metadata(link, backend)
                        (work / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
                        print('INCONCLUSIVE: pending CCID marker unavailable before the probe', case.name, flush=True)
                        assert attempt < hw.PENDING_PACKET_ATTEMPTS, 'pending packet unavailable after the bounded retries'
                        continue
                    row['witness'] = hw.verify(words, case_id, case, backend.physical)
                    if backend.physical and case.denied:
                        assert observations['fatal_detach_observed'], 'fatal USB detach was not observed before watchdog expiry'
                    row['after_boot'] = metadata(link, backend)
                    if card is not None:
                        backend.close_card(card)
                        card = None
                        row['authorization'] = fresh_authorization(backend, link)
                    row['status'] = 'passed'
                    (work / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
                    print('PASS:', case.name, row['witness'], flush=True)
                    break
                finally:
                    if card is not None:
                        backend.close_card(card)
        print('PASS: hardware diagnostic protocol and all selected witnesses.', flush=True)
        report['status'] = 'passed'
        return report
    except BaseException as error:
        report['status'] = 'failed'
        report['error'] = repr(error)
        raise
    finally:
        (work / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        if link is not None:
            link.close()
