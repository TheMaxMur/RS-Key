# third_party — vendored upstream test suites

Two external conformance suites, vendored so the firmware can be validated
without checking out the upstream repos. They are **not** part of RS-Key's
own test suite (`tests/`, `cargo test`) — they are the upstream ecosystems'
own tests, kept runnable against this implementation.

Both directories carry their own licenses, distinct from the repository's own
AGPL-3.0-only. Note the split between each file's **per-file header** (the
operative license for that file) and the **bundled `LICENSE`** (the upstream
repo's top-level license file):

| Directory | Origin | License (per-file headers) | Bundled `LICENSE` |
|---|---|---|---|
| `pico-fido-tests/` | [polhenarejos/pico-fido](https://github.com/polhenarejos/pico-fido) `tests/` | **GPL-3.0-only** (headers read "GNU General Public License … version 3") | AGPL-3.0 (pico-fido's repo LICENSE) |
| `openpgp-card-tests/` | [polhenarejos/pico-openpgp](https://github.com/polhenarejos/pico-openpgp) `tests/`, derived from [Gnuk](https://www.fsij.org/gnuk/) (NIIBE Yutaka / g10 Code GmbH) | **GPL-3.0-or-later** (Gnuk headers: "either version 3 … or any later version") | AGPL-3.0 |

Vendored from upstream at:

| Directory | Upstream commit | Dated |
|---|---|---|
| `pico-fido-tests/` | `b1bacec29db76f6944f9db9ffb595934a89c5a41` | 2026-08-02 |
| `openpgp-card-tests/` | `1472b26574b2e74d371fe052c7e5f5e30cd2a997` | 2026-07-27 |

Only the pytest part is taken — the docker scripts, build wrappers and C sources
that sit beside them upstream are not vendored. Record the commit when you
refresh, or the next refresh has nothing to diff against.

These suites are **run-only** (pytest/pyscard) — they are never compiled or
linked into the firmware, and every upstream header is preserved verbatim, so
the GPL/AGPL split above does not interact with RS-Key's own AGPL-3.0-only
build.

Local modifications are minimal and marked in-place. **No assertion is ever
edited** — a disagreement about behaviour goes in `tests/third_party.py`'s
divergence list, where it stays visible and a strict xfail catches it being
fixed. What is repaired here is the other case: a test that raises in its own
Python before a byte reaches the device measures nothing, so listing it would
only record that it is broken.

| File | Change |
|---|---|
| `pico-fido-tests/conftest.py` | filters the relying-party's allowed algorithms to those the installed python-fido2 can actually verify (the firmware can lead with ML-DSA-44, which older fido2 libraries parse but cannot check) |
| `pico-fido-tests/pico-fido/test_021_authenticate.py` | `test_option_up` / `test_option_uv` called `doGA(options=…)`; that helper is the WebAuthn-level one and takes no such argument, so both raised `TypeError`. They call `GA()` — the raw CTAP2 helper their neighbours use — with the credential named. Unreachable upstream, whose own getInfo omits `"up"` |

## Running them

The supported way is `tests/third_party.py`, which runs them **against RS-Key**
rather than against the device they were written for:

```sh
python tests/third_party.py fido       # the pico-fido suite
python tests/third_party.py openpgp    # the OpenPGP card suite
```

It touches nothing in these directories at run time — the run is steered from
outside by a pytest plugin (the in-place repairs above are the separate, listed
exception). Four things it supplies that the suites cannot ask for themselves:

- **the power cycle.** RS-Key takes `authenticatorReset` only inside the CTAP 2.1
  §6.6 power-up window, which an operator reopens by unplugging. pico-fido has no
  such window and resets in fixtures, so on a board a human is the missing piece
  and against `tools/emu` one message on the card socket is. Without it, 61 of the
  suite's tests error in setup.
- **the divergence list.** Everything RS-Key deliberately does not do for these
  suites is named in `DIVERGENCES` with its reason, as `xfail(strict=True)` — so a
  divergence that gets fixed *fails* the run instead of quietly staying listed.
- **the inapplicable list.** Whole modules exercising a *vendor extension* RS-Key
  does not implement — Gnuk's admin-less mode, and clearing PW3 to the empty
  string — are removed at collection rather than xfailed, because an xfailed test
  still runs: those modules expect PW3 verification to fail, which on a card
  without admin-less mode is three wrong admin PINs, and the blocked counter takes
  every later module with it. This is upstream's own `skip_gnuk_only_tests`
  fixture, reinstated from outside after upstream deleted it.
- **the ordering.** `040_pcsc_extra` selects the PIV and Management applets and
  restores the OpenPGP selection on its last line — a line an xfailed test never
  reaches. It runs last, so a listed divergence cannot leave the next section
  talking to the wrong applet.

The two suites need different amounts of machine. `openpgp` reaches the card
through pyscard alone, so the emulator's card socket stands in for the reader —
no PC/SC, no USB, no root, and it runs wherever the emulator does. `fido` is
driven by python-fido2's own HID transport, which wants a real device: point it
at `tools/emu --usbip` attached to a Linux host, or at a board.

Running pytest directly still works, and is what the commands below do.

## Running them by hand

Flash the **no-touch test build** first (the suites cannot press the
button); if your board enforces secure boot, sign it
([docs/production.md](../docs/production.md)).

```sh
# FIDO suite (pytest + python-fido2):
nix develop -c python -m pytest third_party/pico-fido-tests/pico-fido -v

# OpenPGP card suite (pytest + pyscard) — DESTRUCTIVE: resets the card,
# exercises factory PINs/KDF setup. Run section by section:
nix develop -c python -m pytest third_party/openpgp-card-tests/020_kdffull -v
```

Read a suite's conftest before running it: parts are destructive
(authenticator resets, card terminate/activate cycles) and assume factory
default PINs.
