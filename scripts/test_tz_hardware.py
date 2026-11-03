# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Exercise the board runner's verdict entry point with incomplete witnesses."""

from dataclasses import asdict
import importlib.util
import hashlib
import json
from pathlib import Path
import subprocess
import struct
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('tz_hardware', ROOT / 'tests/tz_hardware.py')
hardware = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hardware)


def invoke(tmp_path, words, case=None, physical=True):
    if case is None:
        case = hardware.Case('usbctrl-read', hardware.Mode.NsRead, 0x50110000, True, 0x8200)
    path = tmp_path / 'record.json'
    path.write_text(json.dumps(dict(words=words, case_id=23, case=asdict(case), physical=physical)))
    return subprocess.run([sys.executable, str(ROOT / 'tests/108_trustzone_hardware.py'),
                           'verify-record', str(path)], capture_output=True, text=True)


def witness(stage=hardware.FENCED, flags=None, cause=0x8200, address=0x50110000, sfsr=0):
    if flags is None:
        flags = hardware.PACKET | hardware.GATES | hardware.DETACHED | hardware.BUFFERS | hardware.PAYLOAD | hardware.COPY_MATCH
    return [hardware.MAGIC | 23 << 20 | sfsr << 12 | stage << 8 | flags, cause, address, 1]


def test_complete_peripheral_and_sau_denials_pass_the_cli(tmp_path):
    assert invoke(tmp_path, witness()).returncode == 0
    case = hardware.Case('secure-flash', hardware.Mode.NsRead, 0x10000100, True, 0, 0x48)
    assert invoke(tmp_path, witness(cause=0, address=case.address, sfsr=0x48), case).returncode == 0


@pytest.mark.parametrize('bit', [hardware.PACKET, hardware.GATES, hardware.DETACHED,
    hardware.BUFFERS, hardware.PAYLOAD, hardware.COPY_MATCH])
def test_missing_observation_fails_through_the_cli(tmp_path, bit):
    words = witness()
    words[0] ^= bit
    result = invoke(tmp_path, words)
    assert result.returncode != 0 and 'incomplete packet/fence/copy/core witness' in result.stderr


@pytest.mark.parametrize('stage', [hardware.ARMED, hardware.PROBING, hardware.FAULT,
    hardware.COMPLETED, hardware.FAILED])
def test_missing_probe_or_fault_cleanup_cannot_pass(tmp_path, stage):
    result = invoke(tmp_path, witness(stage=stage))
    assert result.returncode != 0 and 'protected access did not reach fatal cleanup' in result.stderr


@pytest.mark.parametrize('word,value,message', [(0, 0, 'missing diagnostic witness'),
    (1, 0x82, 'wrong access fault cause'), (2, 0x50110004, 'address differs'),
    (3, 0, 'not recovered after a watchdog timeout')])
def test_wrong_witness_is_refused(tmp_path, word, value, message):
    words = witness()
    words[word] = value
    result = invoke(tmp_path, words)
    assert result.returncode != 0 and message in result.stderr


def test_previous_case_and_wrong_access_mode_are_refused(tmp_path):
    words = witness()
    words[0] ^= 1 << 20
    assert 'stale or different' in invoke(tmp_path, words).stderr
    words = witness(flags=witness()[0] & 255 | hardware.WRITE)
    assert 'incomplete packet' in invoke(tmp_path, words).stderr


def test_allowed_store_checks_the_effect_and_not_only_a_completion_marker(tmp_path):
    case = hardware.Case('ram-store', hardware.Mode.NsWrite, 0x20070020)
    flags = hardware.PACKET | hardware.COPY_MATCH | hardware.WRITE
    words = witness(hardware.COMPLETED, flags, hardware.WRITE_VALUE, case.address)
    assert invoke(tmp_path, words, case).returncode == 0
    words[1] = 0
    result = invoke(tmp_path, words, case)
    assert result.returncode != 0 and 'allowed store did not change' in result.stderr


def test_allowed_load_checks_the_data_in_addition_to_the_completion_marker(tmp_path):
    case = hardware.Case('ram-load', hardware.Mode.NsRead, 0x20070020)
    words = witness(hardware.COMPLETED, hardware.PACKET | hardware.COPY_MATCH,
                    hardware.READ_VALUE, case.address)
    assert invoke(tmp_path, words, case).returncode == 0
    words[1] = 0
    result = invoke(tmp_path, words, case)
    assert result.returncode != 0 and 'allowed load did not read' in result.stderr


def test_execution_control_checks_result_and_core(tmp_path):
    case = hardware.Case('core1-execution', hardware.Mode.ExecS1, hardware.SCRATCH_START)
    flags = hardware.PACKET | hardware.COPY_MATCH | hardware.CORE1
    words = witness(hardware.COMPLETED, flags, hardware.EXECUTED, case.address)
    assert invoke(tmp_path, words, case).returncode == 0
    words[1] ^= 1
    assert 'wrong result' in invoke(tmp_path, words, case).stderr
    words[1] = hardware.EXECUTED
    words[0] ^= hardware.CORE1
    assert 'incomplete packet' in invoke(tmp_path, words, case).stderr


def test_model_reason_exception_is_explicit_and_keeps_the_other_guards(tmp_path):
    words = witness()
    words[3] = 0
    assert invoke(tmp_path, words, physical=False).returncode == 0
    words[0] ^= hardware.PAYLOAD
    assert invoke(tmp_path, words, physical=False).returncode != 0


@pytest.mark.parametrize('control', ['normal', 'no-fence', 'no-probe', 'writable-scratch',
    'nonexecutable-scratch', 'broken-copy', 'unlocked-dma', 'misrouted-irq', 'no-flash-window', 'wrong-core'])
def test_fixture_keeps_the_existing_failure_latch_before_its_control_selector(tmp_path, control):
    paths = ('firmware/src/trustzone/mod.rs', 'firmware/src/main.rs', 'firmware/src/worker.rs',
             'firmware/src/trustzone/fault.rs', 'firmware/src/core1.rs',
             'firmware/trustzone/nonsecure/src/diagnostics.rs', 'firmware/trustzone/nonsecure/src/main.rs',
             'firmware/trustzone/build.rs', 'crates/rsk-device/src/ccid.rs', 'crates/rsk-piv/src/lib.rs',
             'firmware/src/trustzone/mpu.rs', 'firmware/src/trustzone/security_policy.rs')
    for name in paths:
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((ROOT / name).read_text())
    hardware.instrument(tmp_path, 1234, control)
    body = (tmp_path / 'firmware/src/worker.rs').read_text().split('fn rsk_tz_control_impl', 1)[1]
    assert body.index('fault::failed()') < body.index('hardware_probe::control(')
    probe = (tmp_path / 'firmware/trustzone/nonsecure/src/probe.rs').read_text()
    if control != 'no-probe':
        assert probe == (hardware.FIXTURES / 'nonsecure.rs').read_text()


def test_resource_matrices_have_unique_ids_and_do_not_write_otp():
    for matrix in ('read', 'write'):
        cases = hardware.cases(0x20070020, matrix)
        assert 166 <= len(cases) <= 255
        assert len({case.name for case in cases}) == len(cases)
        operations = [(case.mode, case.address) for case in cases]
        assert len(set(operations)) == len(operations)
        if matrix == 'write':
            assert not any(case.mode == hardware.Mode.NsWrite and
                           0x40120000 <= case.address < 0x40140000 for case in cases)
        else:
            assert any(case.address == 0x40130000 for case in cases)


@pytest.mark.parametrize('statuses,message', [
    ([0x9000], 'before SELECT'),
    ([0x6d00, 0x9000], 'survived SELECT'),
    ([0x6d00, 0x63c3, 0x9000], 'management authority'),
    ([0x6d00, 0x63c3, 0x6982, 0x63c3], 'fresh PIN'),
])
def test_recovery_refuses_surviving_or_unusable_authority(monkeypatch, statuses, message):
    monkeypatch.syspath_prepend(str(ROOT / 'tests'))
    import tz_hardware_run as runner
    replies = iter(statuses)
    closed = []
    piv = SimpleNamespace(raw=lambda *args: (b'', next(replies)), select=lambda: None,
                          verify_pin=lambda: None, auth_mgm=lambda: None)
    monkeypatch.setattr(runner, 'module', lambda *args: SimpleNamespace(Piv=lambda card: piv,
                        tlv=lambda tag, data: data))
    backend = SimpleNamespace(card=lambda: 'selected card', close_card=closed.append)
    with pytest.raises(AssertionError, match=message):
        runner.fresh_authorization(backend)
    assert closed == ['selected card']


def test_physical_card_close_uses_the_pyscard_decorator_api(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / 'tests'))
    import tz_hardware_run as runner
    closed = []
    card = SimpleNamespace(disconnect=lambda: closed.append(True))
    runner.Physical.close_card(None, card)
    assert closed == [True]


def test_changed_image_is_refused_before_a_hardware_run(monkeypatch, tmp_path):
    monkeypatch.syspath_prepend(str(ROOT / 'tests'))
    import tz_hardware_run as runner
    image = tmp_path / 'combined.uf2'
    image.write_bytes(b'original')
    (tmp_path / 'manifest.json').write_text(json.dumps(dict(build_id=1,
        sha256={'combined.uf2': hashlib.sha256(image.read_bytes()).hexdigest()})))
    image.write_bytes(b'changed')
    with pytest.raises(AssertionError, match='changed fixture artifact'):
        runner.run(None, tmp_path, tmp_path)


@pytest.mark.parametrize('physical', [False, True])
def test_entry_observations_distinguish_shared_fpca_from_banked_masks(monkeypatch, physical):
    monkeypatch.syspath_prepend(str(ROOT / 'tests'))
    import tz_hardware_run as runner
    control = hardware.CONTROL_FPCA if physical else 0
    values = {4: 123, 5: hardware.LAUNCH_FLAGS, 6: 123,
              7: hardware.ENTRY_FLAGS ^ bool(control), 11: 0, 34: control, 35: 0, 36: 0, 37: 0}
    link = SimpleNamespace(command=lambda action, index: values[index])
    backend = SimpleNamespace(physical=physical, expected_crc=123)
    assert runner.metadata(link, backend)['ns_registers'] == [control, 0, 0, 0]
    for register in range(34, 38):
        values[register] ^= 1
        with pytest.raises(AssertionError, match='NS entry registers differ'):
            runner.metadata(link, backend)
        values[register] ^= 1


def test_late_usb_detach_retains_the_fault_words_before_failing_the_run(monkeypatch, tmp_path):
    monkeypatch.syspath_prepend(str(ROOT / 'tests'))
    import tz_hardware_run as runner
    monkeypatch.setattr(runner, 'checked_manifest', lambda path: {'build_id': 1})
    words = witness()
    words[0] ^= (23 ^ 1) << 20
    def command(action, argument=0):
        if action == hardware.GET:
            return 0x20070020 if argument == 30 else words[argument]
        return 0
    link = SimpleNamespace(command=command, close=lambda: None)
    monkeypatch.setattr(runner, 'reconnect', lambda *args: link)
    monkeypatch.setattr(runner, 'metadata', lambda *args: {})
    backend = SimpleNamespace(physical=True, clock=lambda: 0,
                              card=lambda: None, close_card=lambda card: None,
                              wait_reset=lambda *args: {'fatal_detach_observed': False})
    with pytest.raises(AssertionError, match='fatal USB detach was not observed'):
        runner.run(backend, tmp_path, tmp_path, ['usbctrl-read'])
    report = json.loads((tmp_path / 'report.json').read_text())
    assert report['status'] == 'failed' and report['cases'][0]['words'] == words


@pytest.mark.parametrize('outcome', ['recover', 'cleanup_failure', 'exhausted'])
def test_only_an_unexecuted_probe_with_a_missing_packet_is_retried(monkeypatch, tmp_path, outcome):
    monkeypatch.syspath_prepend(str(ROOT / 'tests'))
    import tz_hardware_run as runner
    monkeypatch.setattr(runner, 'checked_manifest', lambda path: {'build_id': 1})
    good = witness()
    missing = witness(hardware.FAILED, hardware.COPY_MATCH, 0)
    broken_cleanup = witness(flags=hardware.COPY_MATCH)
    for words in (good, missing, broken_cleanup):
        words[0] ^= (23 ^ 1) << 20
    calls = []
    active = good
    def command(action, argument=0):
        nonlocal active
        if action == hardware.GET:
            return 0x20070020 if argument == 30 else active[argument]
        if action == hardware.ARM:
            calls.append(argument)
            active = (broken_cleanup if outcome == 'cleanup_failure'
                      else missing if outcome == 'exhausted' or len(calls) == 1 else good)
        return 0
    link = SimpleNamespace(command=command, close=lambda: None)
    monkeypatch.setattr(runner, 'reconnect', lambda *args: link)
    monkeypatch.setattr(runner, 'metadata', lambda *args: {})
    backend = SimpleNamespace(physical=True, clock=lambda: 0, card=lambda: None,
        close_card=lambda card: None, wait_reset=lambda *args: {'fatal_detach_observed': True})
    if outcome == 'recover':
        report = runner.run(backend, tmp_path, tmp_path, ['usbctrl-read'])
        assert len(calls) == 2 and report['status'] == 'passed'
        assert [row['status'] for row in report['cases']] == ['inconclusive', 'passed']
        assert len(list(tmp_path.glob('*usbctrl-read*.json'))) == 2
    else:
        message = 'incomplete packet' if outcome == 'cleanup_failure' else 'bounded retries'
        with pytest.raises(AssertionError, match=message):
            runner.run(backend, tmp_path, tmp_path, ['usbctrl-read'])
        assert len(calls) == (1 if outcome == 'cleanup_failure' else hardware.PENDING_PACKET_ATTEMPTS)
        assert json.loads((tmp_path / 'report.json').read_text())['status'] == 'failed'


@pytest.mark.parametrize('valid_bitmap,actual_serial', [(True, 'selected'), (False, 'selected'), (True, 'other')])
def test_bootsel_probe_keeps_the_transfer_incomplete_and_checks_the_rom_bitmap(monkeypatch, tmp_path, valid_bitmap, actual_serial):
    monkeypatch.syspath_prepend(str(ROOT / 'tests'))
    import tz_hardware_run as runner
    image, work, volume = (tmp_path / name for name in ('image', 'work', 'volume'))
    for directory in (image, work):
        directory.mkdir()
    block = struct.pack('<8I', 0x0a324655, 0x9e5d5157, 0x2000, 0x10000000, 256, 0, 123, 0xe48bff59)
    block += b'\0' * 476 + struct.pack('<I', 0x0ab16f30)
    (image / 'combined.uf2').write_bytes(block)
    monkeypatch.setattr(runner, 'checked_manifest', lambda path: {'build_id': 1})
    monkeypatch.setattr(runner, 'reconnect', lambda *args: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(runner, 'metadata', lambda *args: {'scratch_crc': 123})
    monkeypatch.setattr(runner.time, 'sleep', lambda duration: None)
    monkeypatch.setattr(runner.subprocess, 'check_output', lambda *args, **kwargs: 'selected RP2350')
    serials = iter([[], [actual_serial]])
    monkeypatch.setattr(runner, 'bootrom_serials', lambda: next(serials))
    commands = []
    def command(args, **kwargs):
        commands.append(args)
        if args[1] == 'save':
            start, end = (int(value, 16) for value in args[3:5])
            data = bytes(end - start)
            if start == 0x20010000:
                data = (work / 'readback-pattern.bin').read_bytes()
            if start == 0x20081c00 and valid_bitmap:
                data = b'\x01' + bytes(1023)
            Path(args[5]).write_bytes(data)
    monkeypatch.setattr(runner.subprocess, 'run', command)
    def transmit(apdu):
        if apdu[1] == 0x1f:
            volume.mkdir()
            (volume / 'INFO_UF2.TXT').write_text('RP2350')
        return [], 0x90, 0
    card = SimpleNamespace(transmit=transmit)
    backend = SimpleNamespace(card=lambda: card, close_card=lambda card: None, present=lambda: False)
    if actual_serial != 'selected':
        with pytest.raises(AssertionError, match='BOOTSEL serial'):
            runner.bootsel(backend, image, work, volume, 'selected')
        assert not commands and not (volume / 'TZPROBE.UF2').exists()
        return
    if valid_bitmap:
        result = runner.bootsel(backend, image, work, volume, 'selected')
        assert result['complete_reload_required']
    else:
        with pytest.raises(AssertionError, match='ROM erase bitmap'):
            runner.bootsel(backend, image, work, volume, 'selected')
    assert (volume / 'TZPROBE.UF2').read_bytes() == block
    assert struct.unpack_from('<I', block, 24)[0] == 123
    loads = [args for args in commands if args[1] == 'load']
    assert len(loads) == 1 and loads[0][-3:] == ['0x20010000', '--ser', 'selected']
    assert all(args[-2:] == ['--ser', 'selected'] for args in commands)
