# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
#
# The dev shells: `default` (toolchain + picotool + security tooling + the host
# `rsk`/`rsk-tui` commands) and `fuzz` (nightly for cargo-fuzz).
{
  pkgs,
  target,
  toolchain,
  fuzzToolchain,
  rskPython,
  rskBin,
  rskTui,
}:
{
  default = pkgs.mkShell {
    packages = [
      toolchain
      pkgs.flip-link # stack-overflow-safe linker for embedded
      pkgs.probe-rs-tools # flash/debug over SWD (optional; needs a probe)
      pkgs.picotool # ELF -> UF2 + BOOTSEL flashing, no probe needed
      pkgs.pkg-config
      pkgs.gcc-arm-embedded
      # arm-none-eabi-gcc — builds rsk-rsa-asm's C+ARM-asm
      # fast RSA modexp. `cc` auto-detects it.

      pkgs.yubikey-manager # ykman CLI (device management, guides)
      pkgs.libgcrypt # the vendored OpenPGP card suite loads it via ctypes

      # Security tooling (see scripts/check.sh).
      pkgs.gitleaks # secret detection (pre-commit hook over staged diff)
      pkgs.cargo-audit # SCA: RustSec advisory scan of Cargo.lock
      pkgs.cargo-deny # SCA: advisories + licenses + source/ban policy
      pkgs.cargo-cyclonedx # CycloneDX SBOM generation (release provenance)
      pkgs.cargo-vet # supply-chain: provenance-of-review (audited dependency set)
      pkgs.cargo-llvm-cov # host-crate line-coverage floor for the daily deep-checks

      # Documentation site (see scripts/docs.sh): the GitHub Pages source is the
      # docs/ tree rendered by mdBook; mdbook-mermaid renders the diagrams; lychee
      # is the offline broken-link checker.
      pkgs.mdbook
      pkgs.mdbook-mermaid
      pkgs.lychee

      # Host-side tooling: the `rsk` CLI (tools/rsk) + the `rsk-tui` dashboard
      # (tools/tui) + the CTAPHID/FIDO device tests (tests/). See host-tools.nix
      # for the Python deps.
      rskPython
      rskBin
      rskTui
    ];

    # tools/tui links the host PC/SC and HID stacks. On Linux the pcsc-sys and
    # hidapi build scripts resolve libpcsclite/libudev via pkg-config (the gate
    # clippies the TUI, so CI needs them); darwin uses the system frameworks.
    buildInputs = pkgs.lib.optionals pkgs.stdenv.isLinux [
      pkgs.pcsclite
      pkgs.systemd # libudev, for the hidapi crate's hidraw backend
    ];

    shellHook = ''
      # the Gnuk-derived OpenPGP card suite (third_party/) dlopens libgcrypt
      export DYLD_FALLBACK_LIBRARY_PATH="${pkgs.lib.getLib pkgs.libgcrypt}/lib''${DYLD_FALLBACK_LIBRARY_PATH:+:$DYLD_FALLBACK_LIBRARY_PATH}"
      # The dev-shell `rsk-tui` is a bare `cargo run` (no nix RPATH), so its
      # DT_NEEDED libudev/libpcsclite must be on the loader path at run time —
      # pkg-config only satisfies them at build time.
      export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath ([ pkgs.libgcrypt ] ++ pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.systemd pkgs.pcsclite ])}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

      # Install repo git hooks (idempotent; symlinked so edits take effect).
      if [ -d .git ] && [ -f scripts/hooks/pre-commit ]; then
        ln -sf ../../scripts/hooks/pre-commit .git/hooks/pre-commit
      fi

      echo "rs-key devshell"
      echo "  rustc:    $(rustc --version 2>/dev/null)"
      echo "  target:   ${target}"
      echo "  picotool: $(picotool version 2>/dev/null | head -1 || echo 'n/a')"
      echo
      echo "Build:  cargo build --release -p firmware   # pick the target crate"
      echo "  (or:  nix build .#firmware                 # hermetic → result/firmware.uf2)"
      echo "PT:     scripts/pt.sh target/${target}/release/firmware fw-pt.elf   # fence the KV store"
      echo "UF2:    picotool uf2 convert fw-pt.elf -t elf firmware.uf2"
      echo "Flash:  hold BOOTSEL, plug in the RP2350, drag firmware.uf2 to the RP2350 drive"
      echo "Check:  ./scripts/check.sh        # fmt + clippy + test + audit + deny + gitleaks"
      echo "Fuzz:   nix develop .#fuzz -c cargo fuzz run <target>"
      echo "CLI:    rsk status | rsk backup … | rsk secure-boot … | rsk otp … (rsk --help)"
      echo "TUI:    rsk-tui                    # live device dashboard"
      echo "Docs:   ./scripts/docs.sh serve    # preview the docs site (build|check)"
    '';
  };

  # Nightly shell for cargo-fuzz (`cargo fuzz run apdu`) and Miri
  # (`cargo miri test`, fuzz/tests/miri.rs). The nightly-complete toolchain
  # carries both; MIRIFLAGS is the policy the Miri suite expects.
  fuzz = pkgs.mkShell {
    packages = [
      fuzzToolchain
      pkgs.cargo-fuzz
    ];
    # `-Zmiri-many-seeds` (bare) re-runs the whole suite once per seed over a
    # large default range; under the interpreter, with ML-KEM/ML-DSA/EC/RSA in
    # the mix, one pass is ~1 h. The test RNGs are deterministically seeded and
    # the code is single-threaded, so the seed varies only Miri's address
    # nondeterminism, where samples have steep diminishing returns. 16 seeds
    # (~4 h) began timing out as the crypto suite grew; 8 (~2 h) samples that
    # nondeterminism just as well and leaves headroom under the job budget.
    MIRIFLAGS = "-Zmiri-many-seeds=0..8 -Zdeduplicate-diagnostics -Zmiri-strict-provenance";
    # libFuzzer's runtime is C++: on Linux the fuzz binaries need
    # libstdc++.so.6 at run time, and a nix-linked binary's loader does not
    # search the host's /usr/lib (broke the deep-checks CI job, every target
    # exit 127). Lazy `optionalString` keeps darwin from evaluating the gcc
    # lib path at all — dyld finds the system libc++ there anyway.
    LD_LIBRARY_PATH = pkgs.lib.optionalString pkgs.stdenv.isLinux (
      pkgs.lib.makeLibraryPath [ pkgs.stdenv.cc.cc.lib ]
    );
    shellHook = ''
      echo "rs-key fuzz devshell (nightly)"
      echo "  rustc: $(rustc --version 2>/dev/null)"
      echo "List:   cargo fuzz list"
      echo "Run:    cargo fuzz run <target> -- -max_total_time=30"
      echo "Cov:    ./scripts/fuzz-coverage.sh [target]   # per-target coverage → fuzz/coverage/"
      echo "Miri:   cargo miri test --manifest-path fuzz/Cargo.toml"
    '';
  };
}
