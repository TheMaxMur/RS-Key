# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Disposable TrustZone board fixtures and their reset-surviving witness format."""

from dataclasses import dataclass
from enum import IntEnum
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).with_suffix('')
GET, SET_TARGET, ARM, PREPARE, COMPLETE, ENTRY = range(0x48570000, 0x48570006)
MAGIC, MAGIC_MASK = 0xD0000000, 0xF0000000
ARMED, PROBING, FAULT, FENCED, COMPLETED, FAILED = range(1, 7)
PACKET, GATES, DETACHED, BUFFERS, PAYLOAD, CORE1, WRITE, COPY_MATCH = (1 << bit for bit in range(8))
WATCHDOG_MS = 4000
PENDING_PACKET_ATTEMPTS = 3
WATCHDOG_DOMAINS = 0x01FFFFF3
BULK_ENDPOINT = 0x83
WRITE_VALUE = 0x7F
READ_VALUE = 0x5A17C0DE
MARKER = b'\xa5' * 8
EXECUTED = 0x2350C0DE
AUTH_REQUIRED = 1 << 16
LAUNCH_FLAGS, ENTRY_FLAGS = 0x7FF, 7
CONTROL_FPCA = 1 << 2
SCRATCH_START, SCRATCH_END = 0x20080100, 0x20082000


class Mode(IntEnum):
    NsRead = 1
    NsWrite = 2
    S0Write = 3
    S1Write = 4
    FlashS0Write = 5
    FlashS1Write = 6
    ExecS0 = 7
    ExecS1 = 8
    FlashExecS0 = 9
    FlashExecS1 = 10
    Locks = 11
    S0Read = 12
    S1Read = 13


CORE1_MODES = {Mode.S1Write, Mode.FlashS1Write, Mode.ExecS1, Mode.FlashExecS1, Mode.S1Read}
WRITE_MODES = {Mode.NsWrite, Mode.S0Write, Mode.S1Write, Mode.FlashS0Write, Mode.FlashS1Write}
FLASH_MODES = {Mode.FlashS0Write, Mode.FlashS1Write, Mode.FlashExecS0, Mode.FlashExecS1}
EXEC_MODES = {Mode.ExecS0, Mode.ExecS1, Mode.FlashExecS0, Mode.FlashExecS1}


@dataclass(frozen=True)
class Case:
    name: str
    mode: Mode
    address: int
    denied: bool = False
    cfsr: int = 0
    sfsr: int = 0
    authorized: bool = False


def decode(words):
    if len(words) != 4 or any(type(word) is not int or not 0 <= word < 2**32 for word in words):
        raise ValueError('witness requires four u32 words')
    header, cause, address, reason = words
    if header & MAGIC_MASK != MAGIC:
        raise ValueError('missing diagnostic witness')
    return dict(case=(header >> 20) & 255, stage=(header >> 8) & 15,
                flags=header & 255, sfsr=(header >> 12) & 255,
                cfsr=cause, address=address, reset_reason=reason)


def verify(words, case_id, case, physical=True):
    record = decode(words)
    assert record['case'] == case_id, 'stale or different probe witness'
    if physical:
        assert record['reset_reason'] & 1, 'witness was not recovered after a watchdog timeout'
    flags = PACKET | COPY_MATCH
    if case.mode in CORE1_MODES:
        flags |= CORE1
    if case.mode in WRITE_MODES:
        flags |= WRITE
    if case.denied:
        assert record['stage'] == FENCED, f"protected access did not reach fatal cleanup: {record}"
        flags |= GATES | DETACHED | BUFFERS | PAYLOAD
        assert record['cfsr'] == case.cfsr and record['sfsr'] == case.sfsr, 'wrong access fault cause'
    else:
        assert record['stage'] == COMPLETED, f"allowed control did not complete: {record}"
        if case.mode == Mode.NsRead:
            assert record['cfsr'] == READ_VALUE, 'allowed load did not read its data control'
        if case.mode in WRITE_MODES:
            assert record['cfsr'] == WRITE_VALUE, 'allowed store did not change its data control'
        if case.mode in EXEC_MODES:
            assert record['cfsr'] == EXECUTED, 'scratch execution returned the wrong result'
        if case.mode == Mode.Locks:
            assert record['cfsr'] == 0, 'a locked DMA or ACCESSCTRL setting was writable'
    assert record['flags'] == flags, f"incomplete packet/fence/copy/core witness: {record}"
    assert record['address'] == case.address, 'fault or control address differs from the selected target'
    return record


def pending_packet_missing(words, case_id, case):
    record = decode(words)
    flags = COPY_MATCH | (WRITE if case.mode in WRITE_MODES else 0)
    return (record['case'] == case_id and record['stage'] == FAILED
            and record['flags'] == flags and record['cfsr'] == record['sfsr'] == 0
            and record['address'] == case.address and record['reset_reason'] & 1 != 0)


def cases(allowed, matrix=None):
    result = [Case('ns-ram-read', Mode.NsRead, allowed), Case('ns-ram-write', Mode.NsWrite, allowed),
              Case('usbctrl-read', Mode.NsRead, 0x50110000, True, 0x8200),
              Case('usbctrl-write', Mode.NsWrite, 0x50110000, True, 0x8200, authorized=True),
              Case('secure-flash-read', Mode.NsRead, 0x10000100, True, 0, 0x48),
              Case('dma-accessctrl-locks', Mode.Locks, 0)]
    for mode in (Mode.S0Write, Mode.S1Write):
        result.append(Case(mode.name + '-data', mode, 0x20080000))
    for mode in sorted(EXEC_MODES):
        result.append(Case(mode.name, mode, SCRATCH_START))
    for mode in (Mode.S0Write, Mode.S1Write, Mode.FlashS0Write, Mode.FlashS1Write):
        for name, address in [('first', SCRATCH_START), ('last', SCRATCH_END - 4)]:
            result.append(Case(mode.name + '-scratch-' + name, mode, address, True, 0x82))
    if matrix is not None:
        spec = importlib.util.spec_from_file_location('isolation_resources', ROOT / 'tests/97_trustzone_isolation.py')
        resources = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(resources)
        mode = {'read': Mode.NsRead, 'write': Mode.NsWrite}[matrix]
        existing = {(case.mode, case.address) for case in result}
        for secure, entries in [(False, resources.RESOURCES), (True, resources.MEMORY_RESOURCES)]:
            for name, address in entries:
                # Never submit stores to OTP, including its atomic and data aliases.
                if mode == Mode.NsWrite and 0x40120000 <= address < 0x40140000:
                    continue
                if (mode, address) not in existing:
                    result.append(Case('matrix-' + matrix + '-' + name, mode, address,
                                       True, 0 if secure else 0x8200, 0x48 if secure else 0))
    assert len(result) <= 255, 'diagnostic case IDs exceed the retained witness field'
    return result


def constants(build_id):
    names = ('GET SET_TARGET ARM PREPARE COMPLETE ENTRY MAGIC ARMED PROBING FAULT FENCED COMPLETED FAILED '
             'PACKET GATES DETACHED BUFFERS PAYLOAD CORE1 WRITE COPY_MATCH WATCHDOG_MS WATCHDOG_DOMAINS BULK_ENDPOINT '
             'WRITE_VALUE READ_VALUE EXECUTED AUTH_REQUIRED').split()
    header = '// SPDX-License-Identifier: AGPL-3.0-only\n// Copyright (C) 2026 RS-Key contributors\n'
    body = '#[allow(dead_code, reason = "shared disposable fixture ABI")]\nmod hardware_constants {\n'
    body += ''.join(f'pub const {name}: u32 = {globals()[name]:#x};\n' for name in names)
    body += f'pub const BUILD_ID: u32 = {build_id:#x};\n'
    body += f'pub const MARKER: [u8; {len(MARKER)}] = {list(MARKER)};\n'
    body += '#[derive(Clone, Copy, PartialEq, Eq)]\npub enum Mode {\n'
    body += ''.join(f'{mode.name} = {mode.value},\n' for mode in Mode) + '}\nimpl Mode {\n'
    body += 'pub fn decode(value: u32) -> Option<Self> { match value {\n'
    body += ''.join(f'{mode.value} => Some(Self::{mode.name}),\n' for mode in Mode) + '_ => None, } }\n'
    for name, modes in [('core1', CORE1_MODES), ('write', WRITE_MODES), ('flash', FLASH_MODES), ('execute', EXEC_MODES)]:
        body += f'pub fn {name}(self) -> bool {{ matches!(self, ' + ' | '.join(f'Self::{mode.name}' for mode in sorted(modes)) + ') }\n'
    return header + body + '}\n}\nuse hardware_constants::*;\n'


def replace(path, needle, replacement):
    text = path.read_text()
    assert text.count(needle) == 1, (str(path), needle, text.count(needle))
    path.write_text(text.replace(needle, replacement))


def instrument(tree, build_id, control):
    secure = tree / 'firmware/src/trustzone'
    ns = tree / 'firmware/trustzone/nonsecure/src'
    shutil.copyfile(FIXTURES / 'secure.rs', secure / 'hardware_probe.rs')
    shutil.copyfile(FIXTURES / 'nonsecure.rs', ns / 'probe.rs')
    for directory in (secure, ns):
        (directory / 'hardware_constants.rs').write_text(constants(build_id))
    replace(secure / 'mod.rs', 'pub mod fault;', 'pub mod fault;\npub mod hardware_probe;')
    replace(secure / 'mod.rs', 'pub fn start() {', 'pub fn start() {\n    hardware_probe::boot();')
    replace(secure / 'mod.rs', '    initialize_scratch_code();', '    initialize_scratch_code();\n    hardware_probe::initialized();')
    replace(secure / 'mod.rs', '        rsk_tz_enter_ns(entry & !1);', '        hardware_probe::launch();\n        rsk_tz_enter_ns(entry & !1);')
    replace(tree / 'firmware/src/main.rs', '    core1::spawn(p.CORE1);',
            '    trustzone::hardware_probe::init(p.WATCHDOG);\n    spawner.spawn(trustzone::hardware_probe::monitor().unwrap());\n    core1::spawn(p.CORE1);')
    replace(tree / 'firmware/src/worker.rs', '    match action {\n        abi::ABANDON =>',
            '    if (0x4857_0000..=0x4857_0005).contains(&action) {\n        return crate::trustzone::hardware_probe::control(action, ticket);\n    }\n    match action {\n        abi::ABANDON =>')
    replace(tree / 'crates/rsk-piv/src/lib.rs', "impl<'a> PivApplet<'a> {",
            "impl<'a> PivApplet<'a> {\n    pub fn hardware_probe_authority(&self) -> u32 { u32::from(self.sess.has_pin) | (u32::from(self.sess.has_mgm) << 1) | (u32::from(self.sess.pin_fresh) << 2) | (u32::from(self.sess.has_challenge) << 3) }\n")
    replace(tree / 'crates/rsk-device/src/ccid.rs', "    CcidApplets<'a, S, R, VP>\n{",
            "    CcidApplets<'a, S, R, VP>\n{\n    pub fn hardware_probe_authority(&self) -> u32 { self.piv.hardware_probe_authority() }\n")
    replace(tree / 'firmware/src/worker.rs', "impl<'a> Worker<'a> {",
            "impl<'a> Worker<'a> {\n    pub(crate) fn hardware_probe_authority(&self) -> u32 { self.ccid.hardware_probe_authority() }\n")
    replace(tree / 'firmware/src/worker.rs', '            self.ccid.scrub_with(crate::sweep::wipe_bytes);',
            '            self.ccid.scrub_with(crate::sweep::wipe_bytes);\n            crate::trustzone::hardware_probe::observe_authority(self.ccid.hardware_probe_authority());')
    replace(tree / 'firmware/src/main.rs', '    if seal_restart {',
            '    trustzone::hardware_probe::authority(worker.hardware_probe_authority());\n    if seal_restart {')
    replace(secure / 'fault.rs', '    fence();\n    rsk_tz_fault_stop()',
            '    super::hardware_probe::entered();\n    fence();\n    super::hardware_probe::fenced();\n    super::hardware_probe::wait()')
    replace(tree / 'firmware/src/core1.rs', '    loop {\n        service_xip_pause();',
            '    loop {\n        crate::trustzone::hardware_probe::core1_poll();\n        service_xip_pause();')
    replace(ns / 'diagnostics.rs', '    let value = match data {',
            '    if data.starts_with(b"hw") { return super::probe::reply(data, out); }\n    let value = match data {')
    replace(ns / 'main.rs', 'fn main() -> ! {', 'fn main() -> ! {\n    probe::entry();')
    replace(tree / 'firmware/trustzone/build.rs', '__rsk_scratch_payload_end = .;',
            'KEEP(*(.rsk_hw_scratch)) __rsk_scratch_payload_end = .;')
    if control == 'no-fence':
        replace(secure / 'fault.rs', '    fence();', '')
    elif control == 'no-probe':
        replace(ns / 'probe.rs', 'ARMED.store(argument, Ordering::Release)', 'ARMED.store(0, Ordering::Release)')
    elif control == 'writable-scratch':
        replace(secure / 'mpu.rs', 'Permission::Code => READ_ONLY,', 'Permission::Code => 0,')
    elif control == 'nonexecutable-scratch':
        replace(secure / 'mpu.rs', 'let [before, code, after, scratch] = ram_code().regions().map(ram_region);',
                'let [before, code, after, mut scratch] = ram_code().regions().map(ram_region);\n    scratch.2 |= EXECUTE_NEVER;')
    elif control == 'broken-copy':
        replace(secure / 'hardware_probe.rs', 'pub fn initialized() {',
                'pub fn initialized() {\n    // SAFETY: the disposable control corrupts one initialized padding byte before the MPU is enabled.\n    unsafe { let end = core::ptr::addr_of!(__rsk_scratch_exec_end).cast_mut(); let p = end.sub(1); p.write_volatile(p.read_volatile() ^ 1); }')
    elif control == 'unlocked-dma':
        replace(secure / 'security_policy.rs', 'value.set_lock(true);', 'value.set_lock(false);')
        replace(secure / 'security_policy.rs', 'assert!(security.s() && security.p() && security.lock());', 'assert!(security.s() && security.p());')
    elif control == 'misrouted-irq':
        replace(secure / 'mod.rs', '            rp_pac::Interrupt::SWI_IRQ_4,', '            rp_pac::Interrupt::SWI_IRQ_4,\n            rp_pac::Interrupt::SWI_IRQ_5,')
    elif control == 'no-flash-window':
        replace(secure / 'hardware_probe.rs', 'crate::trustzone::mpu::with_flash_code(|| {\n            observe_flash_window();\n            operation()\n        })',
                'operation()')
    elif control == 'wrong-core':
        replace(secure / 'hardware_probe.rs', 'if mode.core1() {\n                if mode.flash()',
                'if false {\n                if mode.flash()')
    else:
        assert control == 'normal', control


def instruction(image, symbol, expected):
    listing = subprocess.check_output(['arm-none-eabi-nm', '-n', str(image)], text=True)
    address = int(next(line.split()[0] for line in listing.splitlines() if line.endswith(' ' + symbol)), 16)
    code = subprocess.check_output(['arm-none-eabi-objdump', '-d', f'--start-address={address}',
                                    f'--stop-address={address + 4}', str(image)], text=True)
    assert re.search(rf'\s{expected}\s', code), f'{symbol} is not {expected}: {code}'


def build(work, control='normal'):
    work = work.resolve()
    work.mkdir(parents=True)
    build_id = secrets.randbelow(2**32 - 2) + 1
    with tempfile.TemporaryDirectory(prefix='rskey-tz-hardware-') as folder:
        tree = Path(folder) / 'source'
        subprocess.run(['git', 'clone', '--local', '--no-hardlinks', str(ROOT), str(tree)], check=True)
        source_commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=tree, text=True).strip()
        names = subprocess.check_output(['git', 'diff', '--name-only', 'HEAD', '-z'], cwd=ROOT).decode().split('\0')
        for name in filter(None, names):
            source, target = ROOT / name, tree / name
            if source.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
            elif target.exists():
                target.unlink()
        instrument(tree, build_id, control)
        env = {key: value for key, value in os.environ.items() if not key.startswith('RSK_TZ_') and key != 'CARGO_TARGET_DIR'}
        env.update(RSK_TZ_OUT=str(work / 'build'), RSK_TZ_GATEWAY_PROBES='1',
                   RSK_TZ_PROBE_ADDRESS='0', RSK_TZ_PROBE_ACCESS='read', CARGO_BUILD_JOBS='2')
        subprocess.run(['bash', 'scripts/build.sh', '--features', 'no-touch'], cwd=tree, env=env, check=True)
        for name, source in [('combined.elf', work / 'build/combined.elf'), ('combined.uf2', work / 'build/combined.uf2'),
                             ('nonsecure.elf', work / 'build/nonsecure/thumbv8m.main-none-eabihf/release/firmware-ns')]:
            shutil.copyfile(source, work / name)
        for image, prefix in [(work / 'combined.elf', 'RSK_HW_S'), (work / 'nonsecure.elf', 'RSK_HW_NS')]:
            for operation, mnemonic in [('READ', 'ldr'), ('WRITE', 'str')]:
                instruction(image, prefix + '_' + operation, mnemonic)
        (work / 'fixture.patch').write_bytes(subprocess.check_output(['git', 'diff', 'HEAD'], cwd=tree))
        for name in ('hardware_probe.rs', 'hardware_constants.rs'):
            shutil.copyfile(tree / 'firmware/src/trustzone' / name, work / name)
        shutil.copyfile(tree / 'firmware/trustzone/nonsecure/src/probe.rs', work / 'nonsecure_probe.rs')
    manifest = dict(build_id=build_id, control=control,
                    source_commit=source_commit,
                    sha256={name: hashlib.sha256((work / name).read_bytes()).hexdigest()
                            for name in ('combined.elf', 'combined.uf2', 'nonsecure.elf', 'fixture.patch', 'hardware_probe.rs', 'hardware_constants.rs', 'nonsecure_probe.rs')})
    (work / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest
