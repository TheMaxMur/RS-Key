# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Exercise the actual NS USB packet futures in the existing host gate."""

import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
NS = ROOT / "firmware/trustzone/nonsecure"


def item(source, signature):
    start = source.index(signature)
    opening = source.index("{", start)
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def test_ns_usb_packet_callers_clear_every_exit(tmp_path):
    source = (NS / "src/usb.rs").read_text()
    generated = ["use crate::{abi, INVALID, PENDING, EndpointAddress, EndpointError, EndpointInfo};",
                 "use crate::tests::transfer;",
                 "fn call(operation: u32, argument: u32) -> u32 { transfer(operation, argument, &mut []) }"]
    generated.append("#[derive(Clone, Copy)] " + item(source, "pub enum Transport"))
    start = source.index("static TX_EPOCHS:")
    generated.append(source[start:source.index("pub fn allocate_for", start)])
    for signature in (
        "pub(crate) fn epoch(",
        "fn endpoint(", "fn result(", "pub fn bind_response_epoch(", "fn tx_epoch(",
    ):
        generated.append(item(source, signature))
    generated += [
        "pub struct Endpoint { pub info: EndpointInfo, pub transport: Transport }",
        "pub struct ControlPipe; struct Pending(u32);",
        item(source, "impl Drop for Pending"),
        item(source, "async fn control("),
        "impl Endpoint { pub " + item(source, "async fn write(&mut self, data:") + " }",
        "impl ControlPipe { pub " + item(source, "async fn data_in(&mut self, data:") + " }",
    ]
    usb = tmp_path / "usb.rs"
    usb.write_text("\n".join(generated))
    reply = (NS / "src/reply.rs").read_text().split("#[cfg(test)]", 1)[0]
    assert reply.count("        Self(bytes)") == 1
    reply = reply.replace("        Self(bytes)", "        crate::tests::constructed(bytes);\n        Self(bytes)")
    guard = tmp_path / "reply.rs"
    guard.write_text(reply)
    metadata = subprocess.run(["rustc", "-vV"], capture_output=True, text=True, check=True)
    host = next(line.removeprefix("host: ") for line in metadata.stdout.splitlines()
                if line.startswith("host: "))
    binary = tmp_path / "ns-usb-packet-tests"
    compiled = subprocess.run(
        ["rustc", "--edition=2024", "--test", "--target", host,
         str(NS / "usb-packet-tests.rs"), "-o", str(binary)],
        env={**os.environ, "RSK_NS_USB_SOURCE": str(usb), "RSK_NS_REPLY_SOURCE": str(guard)},
        capture_output=True, text=True, timeout=120,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    tested = subprocess.run(
        [str(binary), "--test-threads=1"], capture_output=True, text=True, timeout=120,
    )
    assert tested.returncode == 0, tested.stdout + tested.stderr
    for name in (
        "endpoint_results_keep_snapshot_and_full_wipe",
        "oversized_packets_wipe_without_sg",
        "endpoint_cancellation_and_reset_keep_full_wipe_and_bound_epoch",
        "endpoint_disabled_in_same_epoch_retries",
        "control_results_and_cancellation_abandon_before_wipe",
        "control_before_ticket_cancellation_and_errors",
        "control_queue_and_poll_retries_keep_epoch_and_ticket",
        "unpolled_futures_have_no_packet_or_sg",
    ):
        assert f"tests::{name} ... ok" in tested.stdout, tested.stdout
