<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Upstream parser seeds

| File | Source revision | Selection |
|---|---|---|
| `google.tar.gz` | [google/CTAP2-test-tool-corpus](https://github.com/google/CTAP2-test-tool-corpus/tree/f63171c44ad307b93e5a57c282279a97067171d2) | All four input directories and LICENSE; 24,946 inputs |
| `canokey.tar.gz` | [canokeys/canokey-core](https://github.com/canokeys/canokey-core/tree/e558d5cc6169acca1508238f7b584b8e00f8786d/fuzzing) | `fuzzing/applet*/data` and LICENSE; 1,166 raw APDUs |
| `opensk.json` | [google/OpenSK](https://github.com/google/OpenSK/blob/e161e95944871ccf719945738a272e718076c1df/libraries/opensk/fuzz/ctap2_commands_parameters_corpus.json) | The unchanged 30-entry JSON corpus |

Downloaded 2026-10-03. Upstream files are Apache-2.0: each archive preserves its
LICENSE, and the OpenSK license is the adjacent LICENSE. The archive containers
were rewritten with the repository prefix removed, mode 0644, zero timestamps
and uid/gid 0, then gzip-compressed with mtime 0. Input bytes are unchanged.
`scripts/external_corpus.py` checks the local file hashes before reading seeds.

Google's CBOR files contain command parameters, so the adapter prepends the
corresponding CTAP command byte. Its raw HID inputs go unchanged to `ctaphid`.
OpenSK's generic CBOR values are replayed under all three command bytes; its
command-specific maps retain their command. This yields 66 FIDO inputs.

Every CanoKey APDU goes unchanged to `apdu`. FIDO APDUs also go to `fido_u2f`.
PIV, OATH and OpenPGP APDUs shorter than the applet harness's 0xFF escape are
length-prefixed for their existing replay targets. Longer APDUs stay in the
parser corpus: synthesizing an extended-Lc request would change their bytes.
CanoKey's proprietary admin applet has no RS-Key equivalent.

The existing `fuzz targets alive` row replays these seeds through the compiled
targets with `-runs=0`; their bounds and setup assertions remain the oracles.
The fuzz and fuzz-coverage runners also install them in `fuzz/corpus/` before
mutation or coverage collection. These are robustness inputs, without expected
CTAP status codes or APDU status words; protocol conformance is covered by the
separate suites.

Gate wiring was falsified on 2026-10-03 through the actual `fuzz targets alive`
invocation: a temporary assertion in `fido_cbor` rejected OpenSK's
`01 19 03 e8`. The empty-input checks passed; corpus replay failed at that
assertion with libFuzzer exit 77 and propagated failure. The assertion was
removed before the green run.

```sh
nix develop -c python scripts/external_corpus.py
```
