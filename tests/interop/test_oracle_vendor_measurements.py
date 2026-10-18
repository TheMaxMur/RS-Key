# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Measurement responses expose independent build/length/timer/control defects."""
import pytest

import oracle
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts


class Card:
    layer = "offline_measurement_card"

    def __init__(self, enabled, defect):
        self.enabled, self.defect, self.paused = enabled, defect, False
        self.counter = 17

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, data = apdu_parts(wire)
        status, output = 0x9000, b""
        if ins == 0xa4:
            pass
        elif ins == 2:
            output = self.counter.to_bytes(4, "big")
        elif not self.enabled:
            status = 0x9000 if self.defect == "shipping-exposes-measurement" else 0x6d00
        elif ins == 0x12:
            output = bytes(32)
        elif ins == 0x13:
            if not data or len(data) % 32 or len(data) > 256:
                status = 0x6700
            elif p1 not in (0, 1):
                status = 0x6a86
            else:
                output = (400).to_bytes(4, "little")
        elif ins == 0x14:
            if p1 > 3:
                status = 0x6a86
            else:
                n = max(0, 32 - p2) if self.defect != "warmup-underflows" else (32 - p2) & 0xffffffff
                output = b"".join(value.to_bytes(4, "little") for value in (n, 100, 10 if n else 100, 20 if n else 100, 3 if n else 0))
                if p1 == 3:
                    output += (1 if self.defect == "wrong-OTP-divisor" else 100).to_bytes(4, "little")
        elif ins == 0x15:
            if p1 == 0:
                if not 8 <= len(data) <= 64:
                    status = 0x6700
                else:
                    output = b"".join(value.to_bytes(4, "little") for value in (0, 10, 1024))
            elif p1 in (1, 2):
                self.paused = p1 == 1
            else:
                status = 0x6a86
        else:
            raise AssertionError("unprofiled measurement instruction")
        if self.defect == "measurement-changes-counter" and ins in (0x12, 0x13, 0x14, 0x15):
            self.counter += 1
        output += status.to_bytes(2, "big")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if status == 0x9000 else "applet_error", status)


@pytest.mark.parametrize("enabled,defect,needle", [(False, None, None), (True, None, None),
    (False, "shipping-exposes-measurement", "measurement build gate"), (True, "warmup-underflows", "warmup removes samples"),
    (True, "wrong-OTP-divisor", "supplies its own divisor"), (True, "measurement-changes-counter", "persistent vendor counter")])
def test_measurement_selectors_shipping_gate_boundaries_and_timer_shapes(tmp_path, enabled, defect, needle):
    trace = Trace(tmp_path / "measurements", {})
    card = Card(enabled, defect)
    session = Session(trace, card=card, profile="rsk", options=Options(exercise=True,
        features=("bench", "keygen-bench", "core1-stats") if enabled else (), allow_effects=("config_change",)))
    oracle.execute(session, ["vendor-measurements"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures[:30]
    else:
        assert trace.cases and not failures, failures[:30]
        assert all(row["verdict"] == "pass" or row["applicability"] == "excluded_by_profile" for row in trace.cases)
        assert not card.paused and card.counter == 17
