#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Build and exercise disposable TrustZone hardware diagnostic images."""

import argparse
import json
from pathlib import Path
import tz_hardware as hardware


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    build = commands.add_parser('build')
    build.add_argument('--work', type=Path, required=True)
    build.add_argument('--control', choices=('normal', 'no-fence', 'no-probe', 'writable-scratch',
        'nonexecutable-scratch', 'broken-copy', 'unlocked-dma', 'misrouted-irq', 'no-flash-window', 'wrong-core'), default='normal')
    verify = commands.add_parser('verify-record')
    verify.add_argument('record', type=Path)
    model = commands.add_parser('model')
    model.add_argument('--image-dir', type=Path, required=True)
    model.add_argument('--emulator', type=Path, required=True)
    model.add_argument('--work', type=Path, required=True)
    model.add_argument('--case', action='append', default=[])
    model.add_argument('--matrix', choices=('read', 'write'))
    physical = commands.add_parser('physical')
    physical.add_argument('--image-dir', type=Path, required=True)
    physical.add_argument('--serial', required=True)
    physical.add_argument('--work', type=Path, required=True)
    physical.add_argument('--case', action='append', default=[])
    physical.add_argument('--matrix', choices=('read', 'write'))
    bootsel = commands.add_parser('bootsel', help='probe BootROM ownership; leaves an incomplete firmware transfer')
    bootsel.add_argument('--image-dir', type=Path, required=True)
    bootsel.add_argument('--serial', required=True)
    bootsel.add_argument('--work', type=Path, required=True)
    bootsel.add_argument('--volume', type=Path, required=True)
    bootsel.add_argument('--bootrom-serial', required=True)
    args = parser.parse_args()
    if args.command == 'build':
        hardware.build(args.work, args.control)
    elif args.command == 'verify-record':
        document = json.loads(args.record.read_text())
        case = hardware.Case(**dict(document['case'], mode=hardware.Mode(document['case']['mode'])))
        hardware.verify(document['words'], document['case_id'], case, document.get('physical', True))
    elif args.command == 'model':
        import tz_hardware_run as runner
        args.work.mkdir(parents=True)
        backend = runner.Model(args.emulator, args.image_dir.resolve(), args.work.resolve())
        try:
            runner.run(backend, args.image_dir.resolve(), args.work.resolve(), args.case, args.matrix)
        finally:
            backend.close()
    elif args.command == 'physical':
        import tz_hardware_run as runner
        args.work.mkdir(parents=True)
        backend = runner.Physical(args.serial, args.image_dir.resolve())
        runner.run(backend, args.image_dir.resolve(), args.work.resolve(), args.case, args.matrix)
    elif args.command == 'bootsel':
        import tz_hardware_run as runner
        args.work.mkdir(parents=True)
        backend = runner.Physical(args.serial, args.image_dir.resolve())
        runner.bootsel(backend, args.image_dir.resolve(), args.work.resolve(), args.volume.resolve(), args.bootrom_serial)


if __name__ == '__main__':
    main()
