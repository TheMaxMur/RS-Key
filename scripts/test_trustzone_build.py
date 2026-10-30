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
    script = tmp_path / "scripts/build.sh"
    script.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / "scripts/build.sh", script)
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
                         "ns_image": os.environ.get("RSK_TZ_NS_IMAGE"),
                         "env": {key: os.environ.get(key) for key in (
                             "RSK_BUILD_TEST_VALUE", "CARGO_NET_OFFLINE", "RUSTFLAGS",
                             "CARGO_ENCODED_RUSTFLAGS")}}) + "\\n")
if args[0] == "tree":
    selected = args[args.index("--features") + 1]
    print(os.environ.get("BUILD_OTP_FEATURES", "default,strict-config" if "strict-config" in selected else "default"))
    sys.exit(int(os.environ.get("BUILD_TREE_EXIT", "0")))
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
    pt.parent.mkdir(exist_ok=True)
    pt.write_text('#!/usr/bin/env bash\n# SPDX-License-Identifier: AGPL-3.0-only\n'
                  '# Copyright (C) 2026 RS-Key contributors\ncp "$1" "$2"\n')
    log = tmp_path / "build.jsonl"

    def run(*args, **knobs):
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("RSK_TZ_") and k not in ("FEATURES", "CARGO_TARGET_DIR", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS")}
        env.update(PATH=f"{bin_dir}:{env['PATH']}", BUILD_LOG=str(log), **knobs)
        result = subprocess.run(["bash", str(script), *args], env=env,
                                cwd=tmp_path, text=True, capture_output=True, check=False)
        calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        return result, [call for call in calls if call["args"][0] == "build"]

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


@pytest.mark.parametrize("alias", ["firmware", "rsk-otp", "rsk-device", "rsk-display"])
def test_dependency_feature_aliases_keep_ns_transport_policy(build, alias):
    result, calls = build("--features", f"{alias}/strict-config")
    assert result.returncode == 0, result.stderr
    assert features(calls[0]) == features(calls[2]) == {f"{alias}/strict-config"}
    assert features(calls[1]) == {"strict-config"}


@pytest.mark.parametrize("enabled", [False, True])
def test_optional_dependency_policy_uses_cargos_resolved_features(build, enabled):
    selected = "rsk-display?/strict-config" + (",display" if enabled else "")
    resolved = "default,strict-config" if enabled else "default"
    result, calls = build("-F", selected, BUILD_OTP_FEATURES=resolved)
    assert result.returncode == 0, result.stderr
    assert ("--features" in calls[1]["args"]) == enabled
    if enabled:
        assert features(calls[1]) == {"strict-config"}


def test_feature_resolution_shares_configs_target_and_defaults(build, tmp_path):
    result, calls = build("--config=net.retry=3", "--offline", "--frozen",
                          "--no-default-features", "-Fstrict-config")
    assert result.returncode == 0, result.stderr
    all_calls = [json.loads(line) for line in (tmp_path / "build.jsonl").read_text().splitlines()]
    query, = [call for call in all_calls if call["args"][0] == "tree"]
    args = query["args"]
    assert features(query) == features(calls[0])
    assert args[args.index("--config") + 1] == "net.retry=3"
    assert args[args.index("--target") + 1] == "thumbv8m.main-none-eabihf"
    assert args[args.index("--invert") + 1] == "rsk-otp"
    assert args[args.index("--edges") + 1] == "normal,build"
    assert all(flag in args for flag in ("--offline", "--frozen", "--locked", "--no-default-features"))


def test_failed_feature_resolution_stops_before_nonsecure_link(build):
    result, calls = build(BUILD_TREE_EXIT="1")
    assert result.returncode != 0
    assert len(calls) == 1


def test_existing_test_env_is_supported_and_probes_compose(build):
    result, calls = build(RSK_TZ_NO_TOUCH="1", RSK_TZ_DISPLAY="1",
                          RSK_TZ_GATEWAY_PROBES="1", RSK_TZ_PROBE_ADDRESS="0x50110000")
    assert result.returncode == 0, result.stderr
    assert features(calls[0]) == features(calls[2]) == {"no-touch", "display"}
    assert features(calls[1]) == {"test-gateway-probes", "test-hostile-access"}


def test_cargo_options_and_arbitrary_environment_reach_all_stages(build):
    config = 'env.BUILD_LABEL = "literal $(false); label"'
    knobs = {"RSK_BUILD_TEST_VALUE": "a b; $(false)\nnext", "CARGO_NET_OFFLINE": "true",
             "RUSTFLAGS": "--cfg custom_build", "CARGO_ENCODED_RUSTFLAGS": "--cfg\x1fcustom_build"}
    options = ["--config", config, "--config=net.retry=3", "--jobs", "2", "--offline",
               "--frozen", "-vv", "--color=never"]
    result, calls = build(*options, **knobs)
    assert result.returncode == 0, result.stderr
    assert len(calls) == 3
    for call in calls:
        assert all(call["env"].get(k) == v for k, v in knobs.items())
        assert call["args"][call["args"].index("--target") + 1] == "thumbv8m.main-none-eabihf"
        assert all(option in call["args"] for option in options if not option.startswith("--config="))
        assert "net.retry=3" in call["args"]
        assert call["args"][call["args"].index("--target-dir") + 1] == call["target"]


@pytest.mark.parametrize("source", ["cli", "cargo_env", "out_env"])
def test_relative_output_paths_are_absolute_and_keep_worlds_separate(build, source):
    args, knobs = (), {}
    if source == "cli":
        args = ("--target-dir", "build files")
        knobs = {"CARGO_TARGET_DIR": "ignored cargo", "RSK_TZ_OUT": "ignored out"}
    elif source == "cargo_env":
        knobs = {"CARGO_TARGET_DIR": "build files"}
    else:
        knobs = {"RSK_TZ_OUT": "build files", "CARGO_TARGET_DIR": "ignored cargo"}
    result, calls = build(*args, **knobs)
    assert result.returncode == 0, result.stderr
    assert len(calls) == 3
    secure = Path(calls[0]["target"])
    assert secure.is_absolute() and secure.name == "secure"
    assert secure == Path(calls[2]["target"])
    assert Path(calls[1]["target"]) == secure.parent / "nonsecure"
    assert "build files" in secure.parts
    assert (secure.parent / "combined.elf").exists()
    assert (secure.parent / "combined.uf2").exists()
    assert Path(calls[2]["ns_image"]).is_absolute()


def test_attached_features_and_defaults_are_forwarded(build):
    result, calls = build("-Fstrict-config", "--features=strong-pin", "--no-default-features")
    assert result.returncode == 0, result.stderr
    assert features(calls[0]) == features(calls[2]) == {"strict-config", "strong-pin"}
    assert features(calls[1]) == {"strict-config"}
    assert all("--no-default-features" in call["args"] for call in calls)


def test_help_does_not_start_a_build(build):
    result, calls = build("--help")
    assert result.returncode == 0 and not calls
    assert "--features" in result.stdout and "CARGO_TARGET_DIR" in result.stdout


def test_config_file_paths_follow_the_caller_and_stage_vars_are_owned(build, tmp_path):
    config = tmp_path / "config files/local.toml"
    config.parent.mkdir()
    config.write_text("[net]\noffline = true\n")
    result, calls = build("--config", "config files/local.toml", RSK_TZ_STAGE="bogus",
                          RSK_TZ_NS_IMAGE="stale.bin", CARGO_BUILD_TARGET="wrong")
    assert result.returncode == 0, result.stderr
    assert all(str(config) in call["args"] for call in calls)
    assert calls[0]["ns_image"] is None and calls[1]["ns_image"] is None
    assert [call["stage"] for call in calls] == ["import", None, "final"]


@pytest.mark.parametrize("args", [
    ("--features",), ("--features=",), ("--target", "wrong"), ("--all-features",),
    ("--target-dir",), ("--target-dir=",), ("--config",), ("--config=",),
    ("--jobs",), ("--profile", "dev"), ("-p", "firmware"), ("--workspace",),
    ("--manifest-path", "Cargo.toml"), ("--bin", "firmware"), ("--unknown",),
])
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
