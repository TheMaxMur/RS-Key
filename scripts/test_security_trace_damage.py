# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

import pytest

from test_security_trace import Row, security_trace

pytestmark = pytest.mark.assurance

PROBES = r"""

StoredRecordDecoder ==
    \A width \in {-1, 0, 1, 34, 35, 36, 255, 256, 4078}:
        Beta([BoundaryRaw(0) EXCEPT !.pinRecordLen = width]).pinSet = (width # -1)

StoredUvDecoder ==
    /\ Beta([BoundaryRaw(0) EXCEPT !.alwaysUvRecordLen = -1]).alwaysUv = AlwaysUvShipped
    /\ ~Beta([BoundaryRaw(0) EXCEPT !.alwaysUvRecordLen = 1, !.alwaysUvRaw = 0]).alwaysUv
    /\ \A flag \in {1, 2, 255}:
        Beta([BoundaryRaw(0) EXCEPT !.alwaysUvRecordLen = 1, !.alwaysUvRaw = flag]).alwaysUv
    /\ \A width \in {0, 2, 255, 256, 4078}:
        Beta([BoundaryRaw(0) EXCEPT !.alwaysUvRecordLen = width, !.alwaysUvRaw = 0]).alwaysUv
"""

PIN_PREDICATE = "raw.pinRecordLen # -1"
UV_PREDICATE = """IF raw.alwaysUvRecordLen = -1 THEN AlwaysUvShipped
                         ELSE raw.alwaysUvRecordLen # 1 \\/ raw.alwaysUvRaw # 0"""


@pytest.mark.parametrize("patch,invariant", [
    (None, None),
    ((PIN_PREDICATE, "raw.pinRecordLen = 35"), "StoredRecordDecoder"),
    ((UV_PREDICATE, "raw.alwaysUvRecordLen = 1 /\\ raw.alwaysUvRaw = 1"), "StoredUvDecoder"),
], ids=["baseline", "old-pin-width", "old-uv-fallback"])
def test_the_trace_row_checks_the_runtime_stored_record_decoder(tmp_path, patch, invariant):
    row = Row(tmp_path)
    model = row.root / "formal/TraceSecurity.tla"
    source = model.read_text()
    if patch is not None:
        old, new = patch
        assert source.count(old) == 1
        source = source.replace(old, new)
    footer = source.rindex("\n===")
    model.write_text(source[:footer] + PROBES + source[footer:])
    cfg = row.root / "formal/TraceSecurity.cfg"
    cfg.write_text(cfg.read_text() + "\nINVARIANT StoredRecordDecoder\nINVARIANT StoredUvDecoder\n")
    done = row.run()
    output = done.stdout + done.stderr
    if invariant is None:
        assert done.returncode == 0, output[-2500:]
        commands = security_trace.ratchet(security_trace.COMMANDS_RATCHET)
        assert f"GREEN commands={commands}" in output
    else:
        assert done.returncode == 1, output[-2500:]
        assert (f"Invariant {invariant} is violated" in output
                or f"The invariant of {invariant} is equal to FALSE" in output), output[-2500:]
