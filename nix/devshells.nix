# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
#
# The dev shells: `default` (toolchain + picotool + security tooling + the host
# `rsk`/`rsk-tui` commands) and `fuzz` (nightly for cargo-fuzz).
{
  pkgs,
  sdl2,
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
      # Mutation testing (scripts/mutants-all.sh, weekly + `--in-diff` by hand).
      # Coverage says a line ran; this says a test would notice if it changed —
      # which is the property the `require_pin_inputs` gap was invisible to.
      pkgs.cargo-mutants

      # TLA+ model checking (formal/, scripts run by the weekly `formal` row).
      # The model, its 44 mutants and `floors.txt` were ratchets nobody pulled
      # automatically: no workflow ran TLC, and `run-tlc.sh` reached a jar by a
      # hardcoded /nix/store path that only this machine had. Pinning the tool
      # here is what lets CI run it at all.
      #
      # The whole package rather than just its 2.2 MB jar, because the jar alone
      # still needs a JVM and the script was taking `java` from the host PATH —
      # a prover whose runtime differs per contributor. `jre8` below is the JDK
      # tlaplus already wraps (same store path), so it costs nothing extra; the
      # 208 MB closure is that JDK, not the tool.
      pkgs.tlaplus
      pkgs.jre8

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

      # The emulator's `--display` window (tools/emu): SDL2 is what
      # embedded-graphics-simulator opens the panel in, so the trusted-display
      # flow can be driven with a mouse instead of a soldered CST328.
      sdl2
    ];

    # tools/tui links the host PC/SC and HID stacks. On Linux the pcsc-sys and
    # hidapi build scripts resolve libpcsclite/libudev via pkg-config (the gate
    # clippies the TUI, so CI needs them); darwin uses the system frameworks.
    buildInputs = [
      sdl2
    ]
    ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
      pkgs.pcsclite
      pkgs.systemd # libudev, for the hidapi crate's hidraw backend
    ];

    shellHook = ''
      # flip-link (the embedded linker in .cargo/config.toml) shells out to
      # `rust-lld`, which lives inside the rustc sysroot and is not on PATH.
      export PATH="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin:$PATH"
      # rustc does not read buildInputs, so name SDL2's lib dir for the linker —
      # without it `tools/emu --display` fails with `ld: library 'SDL2' not found`.
      export LIBRARY_PATH="${pkgs.lib.getLib sdl2}/lib''${LIBRARY_PATH:+:$LIBRARY_PATH}"
      # the Gnuk-derived OpenPGP card suite (third_party/) dlopens libgcrypt
      export DYLD_FALLBACK_LIBRARY_PATH="${pkgs.lib.getLib pkgs.libgcrypt}/lib''${DYLD_FALLBACK_LIBRARY_PATH:+:$DYLD_FALLBACK_LIBRARY_PATH}"
      # The dev-shell `rsk-tui` and `rsk-emu` are bare `cargo run`s (no nix
      # RPATH), so their DT_NEEDED libudev/libpcsclite/libSDL2 must be on the
      # loader path at run time — `LIBRARY_PATH` above only satisfies the linker.
      #
      # SDL2 belongs here even though nothing in CI opens a window: `tools/emu`
      # links `embedded-graphics-simulator` unconditionally, so EVERY run of the
      # emulator needs the library present. Whether it is depends on the host —
      # a NixOS box gave the binary an RPATH into the store and hid this, while a
      # GitHub runner did not and every emulator suite died on
      # `libSDL2-2.0.so.0: cannot open shared object file`.
      export LD_LIBRARY_PATH="${
        pkgs.lib.makeLibraryPath (
          [
            pkgs.libgcrypt
            sdl2
          ]
          ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
            pkgs.systemd
            pkgs.pcsclite
            # check.sh's fuzz-liveness row executes the libFuzzer binaries, whose
            # runtime is C++, and this shell — not `.#fuzz`, which already names
            # it — is where that row runs. Without it every target dies on
            # `libstdc++.so.6: cannot open shared object file` and the row reports
            # 53 dead harnesses, which is a loader path, not a preamble.
            pkgs.stdenv.cc.cc.lib
          ]
        )
      }''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

      # formal/run-tlc.sh needs the jar path AND its own -Xmx per configuration
      # (floors.txt carries 12g/24g rows), so it invokes `java -cp` directly —
      # the package's own `tlc` wrapper passes its arguments to TLC, not to the
      # JVM, and cannot carry a heap setting.
      export TLA2TOOLS_JAR="${pkgs.tlaplus}/share/java/tla2tools.jar"

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
