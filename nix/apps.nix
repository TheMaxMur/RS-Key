# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
#
# `nix run` apps + their packages, so the host tooling runs without entering the
# dev shell:
#   nix run .#rsk -- status        # the Python device CLI
#   nix run .#rsk-tui              # the ratatui dashboard (prebuilt host binary)
#   nix run .#flash -- [UF2]       # build + sign + flash, one command (secure boot)
#
# Hand it pkgs, the flake `self` (source for the CLI + TUI), the host toolchain,
# the `rskPython` interpreter (host-tools.nix), and the default firmware package
# (the reproducible unsigned image the flasher seals).
{
  pkgs,
  self,
  toolchain,
  rskPython,
  firmwarePackage,
}:
let
  inherit (pkgs) lib;

  # The Python `rsk` CLI as a standalone app: the interpreter already carries
  # every dep (host-tools.nix); point PYTHONPATH at the in-store `tools/` tree so
  # `import rsk` resolves without a checkout, and run the package.
  rskApp = pkgs.writeShellApplication {
    name = "rsk";
    runtimeInputs = [ rskPython ];
    text = ''
      export PYTHONPATH="${self}/tools''${PYTHONPATH:+:$PYTHONPATH}"
      exec python -m rsk "$@"
    '';
  };

  # The ratatui dashboard, built as a prebuilt host binary (no compile-on-run).
  # Reuse the pinned fenix toolchain (its host rust-std builds host binaries);
  # tools/tui is its own detached workspace with its own Cargo.lock (crates.io
  # only — no git deps, so no outputHashes). System deps mirror the dev shell:
  # pcsclite + libudev on Linux; the apple SDK frameworks come from the darwin
  # stdenv (the dev-shell tui build needs no explicit framework inputs either).
  rustPlatform = pkgs.makeRustPlatform {
    cargo = toolchain;
    rustc = toolchain;
  };
  rskTuiPkg = rustPlatform.buildRustPackage {
    pname = "rsk-tui";
    version = "0.1.0";
    src = self;
    sourceRoot = "source/tools/tui";
    cargoLock.lockFile = ../tools/tui/Cargo.lock;
    nativeBuildInputs = [ pkgs.pkg-config ];
    buildInputs = lib.optionals pkgs.stdenv.isLinux [
      pkgs.pcsclite
      pkgs.udev 
    ];
    meta = {
      description = "RS-Key device dashboard — a self-contained ratatui cockpit";
      license = lib.licenses.agpl3Only;
      mainProgram = "rsk-tui";
    };
  };

  # One-command flasher wrapping the secure-boot ritual (docs/production.md,
  # docs/build.md). With no argument it seals the reproducible default firmware
  # (`nix build .#firmware`, the RS-Key identity); pass a path to seal a flavor
  # you built yourself. The signing key never lives in the store — it is read
  # from the host at run time. The device must already run secure boot with the
  # matching boot key provisioned; with anti-rollback fused the seal version must
  # be >= the board floor (--rollback, default 1). This signs + flashes a real
  # device — it is deliberately not run by CI or the gate.
  flashApp = pkgs.writeShellApplication {
    name = "rsk-flash";
    runtimeInputs = [
      pkgs.picotool
      pkgs.gnupg # gpgconf, to free the CCID reader before the reboot
      pkgs.coreutils
      rskApp # `rsk reboot bootsel`
    ];
    text = ''
      keys_dir="''${RS_KEY_SECRETS:-$HOME/.rs-key-secrets}"
      key="$keys_dir/secure_boot_key.pem"
      otp="$keys_dir/otp_secureboot.json"
      rollback="''${RSK_ROLLBACK:-1}"
      assume_yes=0
      uf2=""

      usage() {
        cat <<'EOF'
      rsk-flash — build, sign and flash an RS-Key firmware image (secure boot).

      Usage: nix run .#flash -- [options] [UNSIGNED.uf2]

      With no UF2 the reproducible default firmware is sealed and flashed.

      Options:
        -y, --yes      skip the confirmation prompt
        -h, --help     show this help

      Environment:
        RS_KEY_SECRETS  signing-key directory (default: ~/.rs-key-secrets)
        RSK_ROLLBACK    anti-rollback version stamped into the seal (default: 1)

      Steps: picotool seal --sign (--rollback N) -> rsk reboot bootsel ->
      picotool load -> picotool reboot. Irreversible-ish; read docs/production.md.
      EOF
      }

      while [ $# -gt 0 ]; do
        case "$1" in
          -y | --yes) assume_yes=1; shift ;;
          -h | --help) usage; exit 0 ;;
          --) shift; break ;;
          -*) echo "rsk-flash: unknown option: $1" >&2; usage >&2; exit 2 ;;
          *) uf2="$1"; shift ;;
        esac
      done
      [ $# -gt 0 ] && [ -z "$uf2" ] && uf2="$1"

      # Default unsigned image: the reproducible nix-built firmware.
      [ -z "$uf2" ] && uf2="${firmwarePackage}/firmware.uf2"

      [ -f "$uf2" ] || { echo "rsk-flash: unsigned image not found: $uf2" >&2; exit 1; }
      [ -f "$key" ] || { echo "rsk-flash: signing key not found: $key (set RS_KEY_SECRETS)" >&2; exit 1; }
      [ -f "$otp" ] || { echo "rsk-flash: OTP seal json not found: $otp (set RS_KEY_SECRETS)" >&2; exit 1; }

      workdir="$(mktemp -d)"
      trap 'rm -rf "$workdir"' EXIT
      signed="$workdir/firmware-signed.uf2"

      echo "==> sealing (signing) the image"
      echo "    image:    $uf2"
      echo "    key:      $key"
      echo "    otp json: $otp"
      echo "    rollback: $rollback"
      picotool seal --sign --hash "$uf2" "$signed" "$key" "$otp" \
        --major 1 --minor 0 --rollback "$rollback"

      if [ "$assume_yes" -ne 1 ]; then
        printf '==> flash this signed image to the connected RS-Key? [y/N] '
        read -r reply
        case "$reply" in
          [yY]*) ;;
          *) echo "aborted."; exit 0 ;;
        esac
      fi

      echo "==> rebooting the device into BOOTSEL"
      gpgconf --kill all >/dev/null 2>&1 || true # free the CCID reader (scdaemon)
      rsk reboot bootsel || true                 # device drops off the bus; reply is ignored

      echo "==> waiting for BOOTSEL"
      ok=0
      for _ in $(seq 1 30); do
        if picotool info >/dev/null 2>&1; then ok=1; break; fi
        sleep 1
      done
      if [ "$ok" -ne 1 ]; then
        echo "rsk-flash: device did not appear in BOOTSEL — hold BOOTSEL, replug, then re-run" >&2
        exit 1
      fi

      echo "==> loading the signed image"
      picotool load "$signed"
      picotool reboot || true
      echo "==> done. Confirm the new bcdDevice (ioreg / lsusb) and 'rsk secure-boot status'."
    '';
  };
in
{
  packages = {
    rsk = rskApp;
    rsk-tui = rskTuiPkg;
    rsk-flash = flashApp;
  };

  apps = {
    rsk = {
      type = "app";
      program = "${rskApp}/bin/rsk";
    };
    rsk-tui = {
      type = "app";
      program = "${lib.getExe rskTuiPkg}";
    };
    flash = {
      type = "app";
      program = "${flashApp}/bin/rsk-flash";
    };
  };
}
