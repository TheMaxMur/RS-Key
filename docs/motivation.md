# Motivation

## The short version

Commercial security keys are excellent, and closed. The firmware is a black
box. The capacity limits are product-segmentation choices. When a key dies or a
vendor discontinues a line, your enrolled identity dies with it. RS-Key exists
to see how far an open, auditable, memory-safe implementation can get on a $5
board.

The honest long version is a story about how one open-source project first
amazed me, then demonstrated, very concretely, what trust in a security project
actually rests on.

## The story

In the spring of 2025 I came across
[pico-fido](https://github.com/polhenarejos/pico-fido), a firmware that turns
a Raspberry Pi Pico into a FIDO2 key. A five-dollar board passed for a
YubiKey. The ecosystem tooling (browsers, `ssh-keygen -t ed25519-sk`, `ykman`)
worked with it like with the real thing. Next to it lived pico-openpgp.
Together they looked like a small miracle: a complete security key you assemble
yourself and can read down to the last byte.

I was hooked and got involved right away. WebAuthn was broken in Firefox on
Linux. Chromium worked, Firefox silently refused. I dug in with
`RUST_LOG=authenticator=debug` and traced it down: Firefox's strict CTAP2
parser was rejecting the device's responses over garbage zero bytes trailing
the CBOR payload
([pico-fido#129](https://github.com/polhenarejos/pico-fido/issues/129)). The
fix was accepted and everything worked. For the next year the key was simply
part of my daily life.

## The turn

On October 26, 2025, this commit landed:
["Update license models and add ENTERPRISE.md"](https://github.com/polhenarejos/pico-fido/commit/8b086188758ad3f60e912acd969b80d6801cfab3).

Point by point, without emotion:

- The project split into a "Community Edition" and a proprietary "Enterprise
  Edition", priced on request.
- The list of paid enterprise options includes **post-quantum cryptography
  support**. Protection from a quantum adversary became a premium feature.
- The combined firmware, [pico-fido2](https://github.com/polhenarejos/pico-fido2)
  (FIDO + OpenPGP), moved into a repository consisting of **three markdown
  files**. There is no source code. Releases v7.0 and v7.2 exist, with
  **zero** attached files. The README, meanwhile, lists "Open source" among
  the features, and its build instructions begin with
  `git clone https://github.com/youruser/pico-fido2`, an address with nothing
  behind it to clone.
- There is exactly one way to get the firmware: through the companion app,
  under a [per-device license](https://www.picokeys.com/picokeyapp/): €29.49
  for a single key, €49.49 for "Primary + Backup". A firmware license for a
  five-dollar board, priced in the range of an entry-level commercial key
  (which at least ships with a secure element and audits behind it).

I am not arguing the maintainer has no right to earn money. He does; it is
his code and his time. A security key is a special case. The only thing
separating a DIY key from a no-name dongle off AliExpress is that you can read
the firmware down to the last byte. A binary-only security-key firmware is a
"trust me" from a single person: no source, no audit, no guarantees, exactly
the thing this project had been an escape from. That day I understood the
project was over for me, and that I would have to write the replacement
myself.

## The principle

The irony is that Raspberry Pi themselves champion the opposite approach for
the RP2350:
[security through transparency](https://www.raspberrypi.com/news/security-through-transparency-rp2350-hacking-challenge-results-are-in/).
Open hacking challenges against their own chip, public write-ups of the
attacks that succeeded, and a
[second round](https://www.raspberrypi.com/news/rp2350-a4-rp2354-and-a-new-hacking-challenge/)
on fixed silicon. [TROPIC01](https://tropicsquare.com/tropic01) does the same
at the secure-element level: an open, auditable architecture instead of an
NDA. That is the right side of this story, and RS-Key intends to stay on it.

## What RS-Key does differently

- **AGPL-3.0-only, irreversibly.** RS-Key is a derivative work of the
  AGPL-licensed pico-keys (see
  [NOTICE](https://github.com/TheMaxMur/RS-Key/blob/main/NOTICE)), so the
  "relicense it proprietary" trick is legally impossible here, for anyone, me
  included.
  There is no CLA; contributors keep their copyright. This is not a promise of
  good behaviour. It is how the licensing is built.
- **Post-quantum in the open tree.** ML-DSA-44, ML-DSA-65 and ML-DSA-87
  credentials work today, for free, with the source in front of you.
- **The "enterprise" features live in the public tree.** Attestation, secure
  boot, backup, audit: the things usually kept behind a paywall land in the
  open repository.
- **Transparency as artifacts, not as a slogan.** Every external-facing parser
  has a fuzz target, every `unsafe` is documented and justified, and the threat
  model was written down before anyone is asked to trust the key with something
  real.
- **Accessibility.** A Trezor or a Nitrokey is hard and expensive to get in
  Russia. An RP2350 board is 500 rubles and a friend with a 3D printer.

And yes, this is still a love letter to writing real systems software in
Rust on a ten-dollar board. Only now it comes with a moral: the openness of a
security project is tested not by years of honest work, but by a single
commit. RS-Key is built so that the relicensing in that commit cannot happen
here.
