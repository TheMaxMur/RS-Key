# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Run the production build entry point with a recording cross toolchain."""
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def build(tmp_path):
    script = tmp_path / "firmware/trustzone/build.sh"
    script.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / "firmware/trustzone/build.sh", script)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    tool = bin_dir / "cargo"
    tool.write_text('''#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ["BUILD_LOG"], "a") as log:
    log.write(json.dumps({"args": args, "product": os.environ.get("USB_PRODUCT"),
                         "target": os.environ.get("CARGO_TARGET_DIR")}) + "\\n")
out = pathlib.Path(os.environ["CARGO_TARGET_DIR"])
package = args[args.index("-p") + 1]
binary = out / "thumbv8m.main-none-eabihf/release" / package
binary.parent.mkdir(parents=True, exist_ok=True)
binary.write_bytes(b"ELF")
if package == "firmware":
    pathlib.Path(os.environ["RSK_TZ_IMPLIB"]).write_bytes(b"ABI")
    pathlib.Path(os.environ["RSK_TZ_NS_MEMORY"]).write_text("MEMORY")
''')
    tool.chmod(0o755)
    for name in ("arm-none-eabi-objcopy", "picotool"):
        tool = bin_dir / name
        tool.write_text('''#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
import pathlib, sys
pathlib.Path(sys.argv[-1]).write_bytes(b"IMAGE")
''')
        tool.chmod(0o755)
    pt = tmp_path / "scripts/pt.sh"
    pt.parent.mkdir()
    pt.write_text('#!/usr/bin/env bash\n# SPDX-License-Identifier: AGPL-3.0-only\n'
                  '# Copyright (C) 2026 RS-Key contributors\ncp "$1" "$2"\n')
    log = tmp_path / "build.jsonl"

    def run(*args, **knobs):
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("RSK_TZ_") and k != "FEATURES"}
        env.update(PATH=f"{bin_dir}:{env['PATH']}", BUILD_LOG=str(log), **knobs)
        result = subprocess.run(["bash", str(script), *args], env=env,
                                text=True, capture_output=True, check=False)
        calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        return result, calls

    return run


def features(call):
    args = call["args"]
    return set(args[args.index("--features") + 1].replace(",", " ").split())


def test_features_and_env_reach_both_secure_links(build):
    product = "RS-Key $(false); literal product"
    result, calls = build("--features", "strict-config,advertise-pqc", "-F", "fips-profile",
                          FEATURES="no-touch", USB_PRODUCT=product)
    assert result.returncode == 0, result.stderr
    assert len(calls) == 3
    expected = {"rsk-device/trustzone", "strict-config", "advertise-pqc", "fips-profile", "no-touch"}
    assert features(calls[0]) == features(calls[2]) == expected
    assert all(call["product"] == product for call in calls)
    assert "strict-config" in features(calls[1])


def test_default_is_touch_enabled_with_no_test_probes(build):
    result, calls = build()
    assert result.returncode == 0, result.stderr
    assert features(calls[0]) == features(calls[2]) == {"rsk-device/trustzone"}
    assert "--features" not in calls[1]["args"]


@pytest.mark.parametrize("selected", ["strict-config\tadvertise-pqc", "no-touch\nstrict-config"])
def test_cargo_whitespace_feature_lists_keep_ns_policy(build, selected):
    result, calls = build(FEATURES=selected)
    assert result.returncode == 0, result.stderr
    assert "strict-config" in features(calls[1])


def test_existing_test_env_is_supported_and_probes_compose(build):
    result, calls = build(RSK_TZ_NO_TOUCH="1", RSK_TZ_DISPLAY="1",
                          RSK_TZ_GATEWAY_PROBES="1", RSK_TZ_PROBE_ADDRESS="0x50110000")
    assert result.returncode == 0, result.stderr
    assert features(calls[0]) == features(calls[2]) == {"rsk-device/trustzone", "no-touch", "display"}
    assert features(calls[1]) == {"test-gateway-probes", "test-hostile-access"}


@pytest.mark.parametrize("args", [("--features",), ("--features=",), ("--target", "wrong"), ("--all-features",)])
def test_invalid_arguments_fail_before_compilation(build, args):
    result, calls = build(*args)
    assert result.returncode != 0
    assert calls == []
