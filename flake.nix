# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

{
  description = "RS-Key (RSK) — an open security-key firmware for the RP2350: FIDO2, OpenPGP, PIV, OATH, OTP";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # SDL2 ONLY, and deliberately not the main pin. `tools/emu --display` opens its
    # window through the Rust `sdl2` crate, whose event enum is SDL2's; unstable now
    # ships `sdl2-compat` (SDL3 behind an SDL2 API) as `SDL2`, which emits SDL3-era
    # window events (0x207) the crate aborts on. 24.11 is the last branch carrying
    # real SDL2, and nothing else is taken from it — the toolchain, every tool and
    # every build stay on the main pin.
    nixpkgs-sdl2.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  # The per-system pieces live in nix/: firmware.nix (the `nix build` packages +
  # the mkFirmware builder), host-tools.nix (the Python + rsk/rsk-tui commands),
  # devshells.nix (the dev + fuzz shells), checks.nix (`nix flake check`), and
  # ccid.nix (the host-side CCID driver package + overlay). This file just wires
  # the shared context (pkgs, the cross target, the toolchains) into them.
  outputs =
    {
      self,
      nixpkgs,
      nixpkgs-sdl2,
      flake-utils,
      fenix,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        sdl2 = (import nixpkgs-sdl2 { inherit system; }).SDL2;
        fx = fenix.packages.${system};

        # RP2350 = dual Cortex-M33 -> thumbv8m.main-none-eabihf (hardware float).
        # (RP2350 also has RISC-V Hazard3 cores; we target the ARM cores, which embassy-rp supports.)
        target = "thumbv8m.main-none-eabihf";

        toolchain = fx.combine [
          fx.stable.toolchain
          fx.targets.${target}.stable.rust-std
        ];

        # cargo-fuzz needs nightly (libfuzzer + -Zsanitizer); host target only.
        fuzzToolchain = fx.complete.toolchain;

        hostTools = import ./nix/host-tools.nix { inherit pkgs; };
        firmware = import ./nix/firmware.nix { inherit pkgs target toolchain; };
        apps' = import ./nix/apps.nix {
          inherit pkgs self toolchain;
          inherit (hostTools) rskPython;
          firmwarePackage = firmware.packages.firmware;
        };
      in
      {
        packages =
          firmware.packages
          // apps'.packages
          // {
            ccid-rs-key = import ./nix/ccid.nix { inherit pkgs; };
          };
        inherit (firmware) lib;
        apps = apps'.apps;

        devShells = import ./nix/devshells.nix (
          {
            inherit
              pkgs
              sdl2
              target
              toolchain
              fuzzToolchain
              ;
          }
          // hostTools
        );

        # `nix fmt` formats the flake's Nix; `nix flake check` runs nix/checks.nix.
        # Plain nixfmt only takes file args, so wrap it to recurse the tree when
        # `nix fmt` is called with none.
        formatter = pkgs.writeShellApplication {
          name = "fmt";
          runtimeInputs = [ pkgs.nixfmt ];
          text = ''
            targets=("$@")
            if [ "''${#targets[@]}" -eq 0 ]; then targets=("."); fi
            find "''${targets[@]}" -name '*.nix' -not -path '*/.git/*' -print0 \
              | xargs -0 -r nixfmt
          '';
        };

        checks = import ./nix/checks.nix {
          inherit pkgs toolchain;
          inherit (firmware) firmwareSrc cargoDeps;
        };
      }
    )
    // {
      # System-independent, so it sits outside eachDefaultSystem. Applying it
      # (`nixpkgs.overlays = [ rs-key.overlays.ccid-rs-key ]`) is the whole fix on
      # NixOS: the pcscd module's plugin list is `[ pkgs.ccid ]`, so replacing that
      # attribute is enough. Overriding `prev.ccid`, not `final.ccid` — the latter
      # is the attribute being defined here. Without the overlay, point
      # services.pcscd.plugins at packages.<system>.ccid-rs-key with lib.mkForce:
      # the module assigns its own `[ pkgs.ccid ]`, and two ccid bundles collide in
      # the plugin buildEnv it maps them through (docs/linux.md).
      overlays.ccid-rs-key = _final: prev: {
        ccid = import ./nix/ccid.nix { pkgs = prev; };
      };
    };
}
