#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Generate, replay and reduce PIV histories on a private emulator process."""

import argparse
from dataclasses import asdict
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
from piv_history import Failure, decode, generate, manifest, minimize
from piv_history_run import Refusal, execute

spec = importlib.util.spec_from_file_location("history_emu", ROOT / "tests/emu.py")
emu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(emu)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


class Backend:
    def __init__(self, args, directory, seed):
        self.args, self.directory, self.seed = args, directory, seed
        self.process = None
        self.log = None
        self.boot = 0
        self.port = None

    def inspect(self, command):
        with socket.create_connection(("127.0.0.1", self.port + 2), timeout=120) as link:
            link.sendall((command + "\n").encode())
            return link.makefile("rb").readline(32768).decode().strip()

    def start(self):
        self.port = self.args.port
        if self.port > 65532:
            raise ValueError("history exhausted its local TCP port range")
        # Image inspection closes from the server side, leaving TIME_WAIT behind.
        # Every boot, including the next seed, needs its own listener ports.
        self.args.port += 3
        for port in range(self.port, self.port + (3 if self.args.image else 2)):
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", port))
        command = [str(self.args.emulator), "--store", str(self.directory / "flash.store"),
                   "--fido-port", str(self.port), "--ccid-port", str(self.port + 1)]
        if self.args.image:
            command += ["--image", str(self.args.image), "--inspect-port", str(self.port + 2),
                        "--seed", f"{self.seed:016x}"]
        log_path = self.directory / f"boot-{self.boot}.log"
        self.log = log_path.open("w")
        self.process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                                        stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + (600 if self.args.image else 120)
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"emulator exited: {log_path}")
            if self.args.image:
                try:
                    state = self.inspect("status")
                    if "dead=true" in state:
                        raise RuntimeError(state)
                    if "ready=true" in state:
                        break
                except ConnectionRefusedError:
                    pass
            elif "device ready" in log_path.read_text():
                break
            time.sleep(0.05)
        else:
            raise TimeoutError(f"emulator readiness: {log_path}")
        os.environ["RSK_EMU_CCID"] = f"127.0.0.1:{self.port + 1}"
        connection = emu.EmuCard()
        connection.connect()
        return connection

    def stop(self):
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
            self.process = None
        if self.log is not None:
            self.log.close()
            self.log = None

    def reboot(self, connection):
        connection.disconnect()
        self.stop()
        self.boot += 1
        return self.start()


def run_case(args, directory, seed, operations, identity):
    directory.mkdir(parents=True, exist_ok=False)
    document = manifest(seed, operations, identity)
    write_json(directory / "history.json", document)
    backend = Backend(args, directory, seed)
    connection = None
    failure = None
    with (directory / "events.jsonl").open("w") as events:
        def progress(row):
            events.write(json.dumps(row) + "\n")
            events.flush()
        try:
            connection = backend.start()
            connection = execute(connection, seed, operations, backend.reboot, progress=progress)
            write_json(directory / "result.json", {"result": "PASS", "operations": len(operations)})
        except Refusal as error:
            failure = error.failure
            document["failure"] = asdict(failure)
            write_json(directory / "history.json", document)
            write_json(directory / "result.json", {"result": "REFUSAL", **asdict(failure)})
        except Exception as error:
            write_json(directory / "result.json", {"result": "HARNESS_OR_ORACLE_FAILURE",
                                                   "type": type(error).__name__, "message": str(error)})
            raise
        finally:
            if connection is not None and connection.sock is not None:
                connection.sock.close()
            backend.stop()
    return failure


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--seeds", type=int, default=8)
    parser.add_argument("--steps", type=int, default=128)
    parser.add_argument("--rsa", action="store_true")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--replay", type=Path)
    parser.add_argument("--reduce", action="store_true", help="reduce a --replay RESET refusal")
    parser.add_argument("--emulator", type=Path,
                        default=ROOT / "tools/emu/target/aarch64-apple-darwin/release/rsk-emu")
    parser.add_argument("--image", type=Path)
    parser.add_argument("--port", type=int, default=20029)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65532 or not 1 <= args.seeds <= 10000:
        parser.error("invalid port or seed count")
    if args.reduce and not args.replay:
        parser.error("--reduce requires --replay")
    args.emulator = args.emulator.resolve(strict=True)
    if args.image:
        args.image = args.image.resolve(strict=True)
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    identity = {"git_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                "backend": "ARM-image" if args.image else "applet-model",
                "emulator_sha256": digest(args.emulator),
                "lock_sha256": digest(ROOT / "tools/emu/Cargo.lock"),
                "image_sha256": digest(args.image) if args.image else None,
                "runner_sha256": hashlib.sha256(b"".join(path.read_bytes() for path in
                    (Path(__file__), ROOT / "tests/piv_history.py", ROOT / "tests/piv_history_run.py",
                     ROOT / "tests/102_piv_factory_reset.py", ROOT / "tests/80_piv.py",
                     ROOT / "tests/emu.py"))).hexdigest()}
    if args.replay:
        source = json.loads(args.replay.read_text())
        seed, operations = decode(source)
        for key in ("backend", "emulator_sha256", "lock_sha256", "image_sha256", "runner_sha256"):
            if source["identity"][key] != identity[key]:
                parser.error(f"replay identity differs: {key}")
        failure = run_case(args, args.output / "original", seed, operations, identity)
        print(json.dumps({"seed": seed, "failure": asdict(failure) if failure else None}), flush=True)
        if args.reduce:
            wanted = source.get("failure")
            if wanted is None or failure != Failure(wanted["phase"], wanted["instruction"], wanted["status"], tuple(wanted["cause"])):
                raise RuntimeError("original target refusal did not recur; reduction refused")
            attempt = 0
            def candidate(items):
                nonlocal attempt
                attempt += 1
                return run_case(args, args.output / f"candidate-{attempt}", seed, items, identity)
            reduced = minimize(operations, failure, candidate)
            document = manifest(seed, reduced, identity)
            document["failure"] = asdict(failure)
            write_json(args.output / "minimal.json", document)
            print(json.dumps({"minimal_operations": len(reduced), "attempts": attempt}), flush=True)
        return int(failure is not None)
    for index in range(args.seeds):
        seed = args.seed + index
        operations = generate(seed, args.steps, args.rsa)
        failure = run_case(args, args.output / f"seed-{seed}", seed, operations, identity)
        print(json.dumps({"seed": seed, "operations": len(operations),
                          "failure": asdict(failure) if failure else None}), flush=True)
        if failure is not None:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
