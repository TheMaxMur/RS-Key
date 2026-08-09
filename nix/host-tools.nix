# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
#
# Host-side tooling for the dev shell: the Python interpreter behind the `rsk`
# CLI + the device tests, and the `rsk` / `rsk-tui` launchers. Returns the three
# things the dev shell drops on PATH; the two PyPI shims are internal.
{ pkgs }:
let
  # ML-DSA (FIPS 204) reference implementation in pure Python — not in nixpkgs;
  # used by the PQC device test to verify signatures.
  dilithiumPy = pkgs.python3Packages.buildPythonPackage rec {
    pname = "dilithium_py";
    version = "1.4.0";
    pyproject = true;
    src = pkgs.fetchPypi {
      inherit pname version;
      sha256 = "0ai54hjqniwcyqw4kibxnd3by0vqc78nm45gl1i2009lmz35bm5n";
    };
    build-system = [ pkgs.python3Packages.hatchling ];
    # the 'pkcs' extra (ecdsa) is not needed; no runtime deps
    doCheck = false;
  };

  # Tiny prompt-with-timeout helper the vendored third-party test suite imports — not
  # in nixpkgs.
  inputimeoutPy = pkgs.python3Packages.buildPythonPackage rec {
    pname = "inputimeout";
    version = "1.0.4";
    format = "wheel";
    src = pkgs.fetchPypi {
      inherit pname version;
      format = "wheel";
      python = "py3";
      dist = "py3";
      sha256 = "0hss8wij922igihjdliiv052hinw7qmdbj7giqk2bz1wflkkvqpl";
    };
    doCheck = false;
  };

  # The host-side Python for the `rsk` CLI (tools/rsk) + the device tests.
  rskPython = pkgs.python3.withPackages (ps: [
    ps.hidapi # FIDO CTAPHID transport
    ps.pyusb # raw USB: the descriptor/interface-order suites (02, 77)
    ps.cryptography # P-256 ECDH / AES-CBC / HMAC (clientPIN + MSE backup)
    ps.pyscard # PC/SC for the CCID applets
    ps.mnemonic # BIP-39 seed rendering
    ps.shamir-mnemonic # SLIP-39 Shamir shares
    ps.fido2 # `rsk fido` set-pin / list-passkeys
    ps.pytest # third_party/ conformance suites
    inputimeoutPy # prompt helper used by the vendored FIDO suite
    dilithiumPy # ML-DSA-44 verification (PQC device test)
    # ykman as an importable module (keyboard-OTP test drives its OtpConnection)
    (ps.toPythonModule pkgs.yubikey-manager)
  ]);

  # `rsk` as a first-class dev-shell command: finds the repo root, puts tools/
  # on PYTHONPATH, and runs the package. Works from any subdir and under
  # `nix develop -c rsk ...`.
  rskBin = pkgs.writeShellScriptBin "rsk" ''
    root="$(${pkgs.git}/bin/git rev-parse --show-toplevel 2>/dev/null || echo "$PWD")"
    export PYTHONPATH="$root/tools''${PYTHONPATH:+:$PYTHONPATH}"
    exec ${rskPython}/bin/python -m rsk "$@"
  '';

  # `rsk-tui` — the Rust ratatui dashboard (tools/tui, its own workspace).
  # cargo-runs it for the host target (overriding the repo's thumbv8m default);
  # first run compiles, then it is instant. Reads device state natively.
  rskTui = pkgs.writeShellScriptBin "rsk-tui" ''
    root="$(${pkgs.git}/bin/git rev-parse --show-toplevel 2>/dev/null || echo "$PWD")"
    host="$(rustc -vV | sed -n 's/host: //p')"
    exec cargo run --release --quiet --target "$host" \
      --manifest-path "$root/tools/tui/Cargo.toml" -- "$@"
  '';
in
{
  inherit rskPython rskBin rskTui;
}
