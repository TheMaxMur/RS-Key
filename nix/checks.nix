# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
#
# `nix flake check` extras: keep the flake's own Nix formatted, and run the
# host-side cargo unit tests — the deterministic, sandbox-safe slice of
# scripts/check.sh — against the vendored deps. Run one alone with
# `nix build .#checks.<system>.<name>`.
{
  pkgs,
  toolchain,
  firmwareSrc,
  cargoDeps,
}:
let
  hostTarget = pkgs.stdenv.hostPlatform.rust.rustcTarget;
in
{
  # The check half of `nix fmt` — fails if any tracked .nix drifts from nixfmt.
  nixfmt = pkgs.runCommand "rsk-nixfmt-check" { nativeBuildInputs = [ pkgs.nixfmt ]; } ''
    nixfmt --check ${firmwareSrc}/flake.nix ${firmwareSrc}/nix/*.nix
    touch $out
  '';

  # Host cargo unit tests over the vendored deps — offline and pure. Matches
  # check.sh's profile (default `test`, not --release) so it stays quick, and
  # its selection: the whole workspace less `firmware` and `rsk-wipe`, the only
  # two members outside crates/ and the only two that are thumbv8m-only. This
  # was a hand-written crate list, complete the day it was written and never
  # amended once — 12 of 24 by the time anyone checked, under a comment
  # promising all of them. The on-device tests/ scripts need real hardware and
  # stay out of the sandbox.
  cargo-test = pkgs.stdenv.mkDerivation {
    name = "rsk-cargo-test";
    src = firmwareSrc;
    inherit cargoDeps;
    nativeBuildInputs = [
      pkgs.rustPlatform.cargoSetupHook
      toolchain
      pkgs.gcc-arm-embedded # rsk-rsa's build.rs (cc) even on the host build
    ];
    buildPhase = ''
      runHook preBuild
      cargo test --offline --frozen --target ${hostTarget} \
        --workspace --exclude firmware --exclude rsk-wipe
      runHook postBuild
    '';
    installPhase = "touch $out";
    doCheck = false;
  };
}
