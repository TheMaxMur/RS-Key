# Reproducing the evidence

This page is for someone who did not write the code and is checking what the
project claims: a reviewer with a clean checkout, no board, and no reason to
take anybody's word for a number.

Everything below the hardware fence is reproducible from source alone. The
hardware half is not, is destructive, and is the maintainer's — it is fenced off
at the end of this page and no instructions for it are given here.

## The one command

```sh
git clone https://github.com/TheMaxMur/RS-Key && cd RS-Key
nix develop -c ./scripts/reproduce.sh quick     # start here
```

`scripts/reproduce.sh` runs the evidence-producing commands in tiers, prints the
command and the exit code of each, and ends on a verdict line. It also prints,
every time and whether or not the run passed, the classes of evidence it did
**not** attempt. That block is the point of the script: a wrapper that quietly
omits what it cannot do is worse than the list of commands it replaced.

```sh
nix develop -c ./scripts/reproduce.sh --list        # the phases and what each reproduces
nix develop -c ./scripts/reproduce.sh --refusals    # what this checkout cannot produce, by name
nix develop -c ./scripts/reproduce.sh quick merge   # minutes, then both gate layers
nix develop -c ./scripts/reproduce.sh model         # the TLA+ tiers, hours
nix develop -c ./scripts/reproduce.sh deep          # the weekly rows, most of a day
```

Tiers exist so the cheap half can be run first. `quick` is a couple of minutes
and re-derives the generated assurance pages from the tree; `merge` is what
every pull request runs; `model` is the model checker, which is hours and wants
the machine to itself; `deep` is the weekly matrix. Any phase can also be named
on its own, and phases can be combined — a repeated phase runs once.

One run at a time. Two gate runs collide on the build tree and two TLC runs
collide on the model checker's per-configuration logs, so a second copy refuses
to start rather than interleaving with the first.

## What a clean checkout does not have

Three preconditions are real, and the script says so rather than failing
obscurely two minutes in:

- **A built firmware image.** Three gate rows disassemble the image the tree
  builds — the constant-time audit, the segment and allocator map, and the
  registered-owner binding — and their mutation tables inject a machine-code
  defect into it. With no image they fail rather than skip, on purpose: a table
  that stops running is indistinguishable from one that passes. Inside
  `scripts/check.sh` the image is built by an earlier row, so the `gate` phase
  is self-contained; run one of those gates on its own and build the firmware
  first. Note which image you are auditing — the gate builds several flavours in
  sequence and the last one wins, which is why those rows sit where they do in
  the file rather than at the end.
- **Kani.** The proof runner is rustup-based and deliberately outside the pinned
  dev shell, so CI installs it out of band and so must you. The `proofs` phases
  refuse by name, with the install command, when it is absent.
- **Network, once.** The dev shell, the crate registry and the advisory database
  are fetched on first use. After that a run is offline apart from the
  supply-chain rows.

## What cannot be reproduced from software

`--refusals` prints this list at every run; it is repeated here so the page and
the script cannot come apart on which half is which. Nothing on it is a
shortcoming of the script — each is evidence about something a checkout is not.

- **On-device suites.** The numbered scripts under `tests/` drive real USB and
  real flash. Most of them run against the software emulator instead, and the
  `emu` phase is exactly that; the rest need a board.
- **The USB-stack suites.** They run the emulator's USB/IP mode inside a Linux
  guest with `vhci_hcd` and KVM. A macOS checkout has neither.
- **Two-key interop.** The RS-Key/YubiKey differential cells need both keys
  attached. The allow-list that separates an expected divergence from a fidelity
  gap is held by the gate; the cells themselves are not run.
- **Fuzz-corpus coverage.** The coverage report measures the corpus the weekly
  job accumulates across runs, which is a CI cache and not a property of any
  checkout.
- **CodeQL.** Advisory, runs on GitHub's infrastructure, no local entry point.
- **Release provenance.** Signing, attestation and the published-artifact half of
  the release manifest need a tag and the maintainer's signing identity. The
  gate checks the recipe; only a release exercises it.
- **Board measurement.** Latency, SRAM residue, side-channel and secure-boot
  measurements are taken off silicon.

## Where the numbers come from

No count on this page, because a count typed here is a second copy of a truth
that lives somewhere else and rots on its own schedule. What each tier covers
and what the last recorded run of it produced is derived and published in
[Testing](testing.md) and [the formal model](formal.md); the model checker's own
matrix is kept per run in `formal/runs.toml`, and the assurance pages under
[Security](assurance-vector.md) are regenerated by the `quick` phase and diffed
against what is committed.

## Keeping the script honest

`scripts/reproduce.sh --self-test` holds the phase table against the tree: every
gate row, every shell runner under `scripts/` and `formal/`, and every job of
the three workflows that produce evidence must be claimed by a phase or excluded
with a reason, in both directions. A new evidence runner, a new weekly job, or a
gate row that starts needing something a checkout has not got lands unclaimed
and fails the self-test, which is the only thing that stops this page and that
script from slowly describing a tree that no longer exists. Its mutation table
is `scripts/test_reproduce.py`.

---

## Maintainer-only: the hardware half

**Do not attempt any of the following, and do not ask an agent to.** They are
irreversible, key-dependent, or both, and they belong to the maintainer alone:

- flashing an image to a board,
- secure-boot signing and sealing an image,
- writing OTP fuses, including the anti-rollback epoch,
- any destructive hardware-in-the-loop run: factory resets on a provisioned
  key, the SRAM-residue scan, and anything that leaves the board in BOOTSEL.

Each already has a page written for the person who owns the keys —
[Production setup](production.md), [Signing keys](signing-keys.md),
[OTP fuses](otp-fuses.md) and [Anti-rollback](anti-rollback.md) — and the
procedures live there, not here. A reviewer who wants the hardware evidence
should ask the maintainer to run it and publish the log, not run it themselves:
a wrong fuse is not recoverable, and a test board that has been sealed to
somebody else's key cannot be reflashed back.

`scripts/reproduce.sh` has no hardware phase and never will. It refuses the
whole class up front, names this page, and never flashes, signs, or writes a
fuse.
