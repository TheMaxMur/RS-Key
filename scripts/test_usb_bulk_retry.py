# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Exercise the Secure retry tail and cleanup order in the existing host gate."""

import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def replace_once(source, old, new):
    assert source.count(old) == 1, old
    return source.replace(old, new)


def test_secure_bulk_retry_preserves_observers_and_cleanup(tmp_path):
    source = (ROOT / "firmware/src/trustzone/usb.rs").read_text()
    start = source.index("pub fn operate(")
    end = source.index('\n#[unsafe(no_mangle)]', start)
    operate = source[start:end]
    prefix = operate[:operate.index("        let action =")]
    admission = operate[operate.index("        if argument !="):
                        operate.index("        if matches!(action, abi::CTRL_SETUP")]
    tail = operate[operate.index("        if operation & !(0xffff | abi::FLAG)"):]
    packet = source[source.index("struct Packet64("):source.index("\nstruct Controller")]
    assert packet.count("fn zeroize(") == 1
    opening = packet.index("{", packet.index("fn zeroize("))
    depth, end = 1, opening + 1
    while depth:
        depth += (packet[end] == "{") - (packet[end] == "}")
        end += 1
    packet = packet[:end - 1] + "\n        observed_wipe(&self.0);\n    " + packet[end - 1:]
    gateway = source[source.index('pub unsafe extern "C" fn rsk_tz_usb_impl('):]
    gateway = replace_once(gateway, 'pub unsafe extern "C" fn rsk_tz_usb_impl(',
                           'pub fn rsk_tz_usb_impl(')
    gateway = replace_once(gateway, "buffer: *mut u8,", "buffer: &mut [u8],")
    gateway = replace_once(gateway,
        "let source = unsafe { core::slice::from_raw_parts(buffer.cast_const(), length) };",
        "let Some(source) = buffer.get(..length) else { return INVALID; };")
    gateway = replace_once(gateway,
        "let target = unsafe { core::slice::from_raw_parts_mut(buffer, count) };",
        "let Some(target) = buffer.get_mut(..count) else { return INVALID; };")
    gateway = replace_once(gateway,
        "super::rsk_tz_readable_impl(buffer.cast_const(), supplied_length)",
        "super::rsk_tz_readable_impl(buffer, supplied_length)")
    assert re.search(r"\bunsafe\b", gateway) is None
    generated = tmp_path / "secure.rs"
    generated.write_text("use super::*;\n" + packet + prefix + admission + tail + gateway)
    endpoints = (ROOT / "firmware/src/trustzone/usb/endpoints.rs").read_text()
    start = endpoints.index("pub(super) fn retry_eligible(")
    end = endpoints.index("\npub(super) fn operate(", start)
    bounds = [line for line in (ROOT / "firmware/src/usb_fence.rs").read_text().splitlines()
              if line.startswith("pub const ENDPOINTS:")]
    assert len(bounds) == 1, bounds
    generated_endpoints = tmp_path / "endpoints.rs"
    generated_endpoints.write_text(bounds[0] + "\n" + endpoints[start:end])

    metadata = subprocess.run(["rustc", "-vV"], capture_output=True, text=True, check=True)
    host = next(line.removeprefix("host: ") for line in metadata.stdout.splitlines()
                if line.startswith("host: "))
    built = subprocess.run(
        ["cargo", "build", "--locked", "--target", host, "-p", "rsk-usb", "-p", "rsk-secret",
         "--message-format=json"], cwd=ROOT,
        env={**os.environ, "CARGO_BUILD_JOBS": "2"}, capture_output=True, text=True, timeout=180,
    )
    assert built.returncode == 0, built.stdout + built.stderr
    names = {"rsk_secret", "zeroize", "embassy_usb_driver"}
    artifacts = {}
    for line in built.stdout.splitlines():
        message = json.loads(line)
        if message.get("reason") != "compiler-artifact":
            continue
        name = message["target"]["name"]
        if name in names:
            paths = [path for path in message["filenames"] if path.endswith(".rlib")]
            assert len(paths) == 1, message
            artifacts[name] = Path(paths[0])
    assert artifacts.keys() == names, artifacts
    dependencies = {path.parent for path in artifacts.values()}
    dependencies.update(path / "deps" for path in tuple(dependencies)
                        if (path / "deps").is_dir())
    binary = tmp_path / "bulk-retry-tests"
    command = ["rustc", "--edition=2024", "--test", "--target", host]
    for path in sorted(dependencies):
        command += ["-L", f"dependency={path}"]
    for name, path in sorted(artifacts.items()):
        command += ["--extern", f"{name}={path}"]
    command += [str(ROOT / "firmware/trustzone/bulk-retry-tests.rs"), "-o", str(binary)]
    compiled = subprocess.run(
        command, env={**os.environ, "RSK_BULK_RETRY_SOURCE": str(generated),
                      "RSK_BULK_RETRY_ENDPOINT_SOURCE": str(generated_endpoints)},
        capture_output=True, text=True, timeout=120,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    tested = subprocess.run(
        [str(binary), "integration::", "--nocapture"], capture_output=True, text=True, timeout=120,
    )
    assert tested.returncode == 0, tested.stdout + tested.stderr
    for name in (
        "quiet_pending_has_eight_additional_polls_full_cleanup_and_no_selfwake",
        "success_commits_once_and_errors_stop_without_another_poll",
        "deadline_and_wrap_bound_real_loop_admission",
        "each_repeat_keeps_pre_and_post_observers",
        "late_reset_in_first_post_repeat_pre_or_repeat_post_refuses_captured_epoch",
        "setup_and_resume_progress_break_pending_and_notify_once_after_cleanup",
        "fault_after_repeat_observer_prevents_a_new_hal_poll",
        "endpoint_retry_eligibility_keeps_bulk_bounds_and_blocked_states",
    ):
        assert f"integration::{name} ... ok" in tested.stdout, tested.stdout
