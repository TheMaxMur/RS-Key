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
                         "target": os.environ.get("CARGO_TARGET_DIR"),
                         "stage": os.environ.get("RSK_TZ_STAGE"),
                         "ns_image": os.environ.get("RSK_TZ_NS_IMAGE")}) + "\\n")
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
    expected = {"strict-config", "advertise-pqc", "fips-profile", "no-touch"}
    assert features(calls[0]) == features(calls[2]) == expected
    assert all(call["product"] == product for call in calls)
    assert "strict-config" in features(calls[1])


def test_default_is_touch_enabled_with_no_test_probes(build):
    result, calls = build()
    assert result.returncode == 0, result.stderr
    assert features(calls[0]) == features(calls[2]) == set()
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
    assert features(calls[0]) == features(calls[2]) == {"no-touch", "display"}
    assert features(calls[1]) == {"test-gateway-probes", "test-hostile-access"}


@pytest.mark.parametrize("args", [("--features",), ("--features=",), ("--target", "wrong"), ("--all-features",)])
def test_invalid_arguments_fail_before_compilation(build, args):
    result, calls = build(*args)
    assert result.returncode != 0
    assert calls == []


@pytest.mark.parametrize("args,knobs", [
    ((), {}),
    (("--no-default-features",), {"RSK_TRUSTZONE_PROTOTYPE": "0"}),
    (("--features=",), {}),
])
def test_no_feature_or_old_env_can_select_a_monolithic_build(build, args, knobs):
    result, calls = build(*args, **knobs)
    if "--features=" in args:
        assert result.returncode != 0 and not calls
        return
    assert result.returncode == 0, result.stderr
    assert [call["args"][call["args"].index("-p") + 1] for call in calls] == [
        "firmware", "firmware-ns", "firmware",
    ]
    assert calls[0]["stage"] == "import" and calls[0]["ns_image"] is None
    assert calls[2]["stage"] == "final" and calls[2]["ns_image"].endswith("nonsecure.bin")


@pytest.fixture(scope="module")
def firmware_build_script(tmp_path_factory):
    out = tmp_path_factory.mktemp("firmware-build-script") / "build"
    subprocess.run(["rustc", "--edition=2024", str(ROOT / "firmware/build.rs"), "-o", str(out)],
                   check=True, capture_output=True, text=True)
    return out


@pytest.mark.parametrize("knobs,expected", [
    ({}, "RS-Key requires Secure + Non-secure firmware"),
    ({"RSK_TRUSTZONE_PROTOTYPE": "0"}, "RS-Key requires Secure + Non-secure firmware"),
    ({"RSK_TRUSTZONE_PROTOTYPE": "1"}, "RS-Key requires Secure + Non-secure firmware"),
    ({"RSK_TZ_STAGE": "legacy"}, "RS-Key requires Secure + Non-secure firmware"),
    ({"RSK_TZ_STAGE": "final"}, "final TrustZone stage requires RSK_TZ_NS_IMAGE"),
    ({"RSK_TZ_STAGE": "import", "RSK_TZ_NS_IMAGE": "stale.bin"},
     "import-library stage must not embed a Non-secure image"),
])
def test_firmware_build_entry_refuses_missing_or_invalid_composition(firmware_build_script, knobs, expected):
    env = {k: v for k, v in os.environ.items() if not k.startswith("RSK_TZ_")}
    env.update(knobs)
    result = subprocess.run([str(firmware_build_script)], env=env, cwd=ROOT / "firmware",
                            capture_output=True, text=True, check=False)
    assert result.returncode != 0
    assert expected in result.stderr


@pytest.mark.parametrize("size", [0, 7, 65537])
def test_final_build_rejects_incomplete_or_oversized_ns(firmware_build_script, tmp_path, size):
    image = tmp_path / "ns.bin"
    image.write_bytes(bytes(size))
    env = dict(os.environ, RSK_TZ_STAGE="final", RSK_TZ_NS_IMAGE=str(image))
    result = subprocess.run([str(firmware_build_script)], env=env, cwd=ROOT / "firmware",
                            capture_output=True, text=True, check=False)
    assert result.returncode != 0 and "invalid Non-secure image size" in result.stderr
