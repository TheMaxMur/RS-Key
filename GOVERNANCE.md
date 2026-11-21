# Governance

Who decides what in RS-Key, and how. [CONTRIBUTING.md](CONTRIBUTING.md) is the
mechanics of landing a change; this file is who gets to say yes, and on what
grounds. If the two disagree, CONTRIBUTING.md wins on process and this file wins
on authority.

RS-Key is a single-maintainer project and this document describes that honestly
rather than pretending to a committee. Nothing here is aspirational: every role
below is one someone actually performs today.

## Roles

**Maintainer** — currently one person,
[@TheMaxMur](https://github.com/TheMaxMur), who holds admin on the repository,
the release signing keys and the boards. The job:

- review and merge pull requests, or say why not;
- triage issues and vulnerability reports, and answer them (SECURITY.md states
  the expectation: an acknowledgment within a few days, best effort, one person);
- cut releases — tag, sign, publish, and decide whether a release advances the
  anti-rollback epoch;
- own the things a contributor must not do on their own: flashing, secure-boot
  signing, OTP fuse writes, pushing and tagging, bumping the embassy/toolchain
  pins, and any change that weakens the gate, the at-rest seals or a
  threat-model assumption ([AGENTS.md](AGENTS.md) → "Maintainer-only");
- keep the gate honest — `scripts/check.sh` and `scripts/check-assurance.sh`
  are the bar the maintainer is also held to, not an obstacle applied to other
  people's patches.

**Contributor** — anyone who opens an issue or a pull request. No paperwork, no
CLA; the AGPL-3.0-only header on each file is the whole agreement
([CONTRIBUTING.md](CONTRIBUTING.md) → "License"). A contributor owns their diff:
they can explain it in review, and the gate is green before they ask for one.
This holds whether or not an AI agent helped write it.

**Reporter** — anyone who reports a vulnerability privately under
[SECURITY.md](SECURITY.md). A reporter is not expected to supply a fix, and gets
credit in the advisory unless they ask not to be named.

There is no separate reviewer or committer role. Review is something
contributors and the maintainer both do; merge rights sit with the maintainer.

## How decisions get made

Most of them aren't judgment calls. **The gate decides what is correct**:
`nix develop -c ./scripts/check.sh` and `./scripts/check-assurance.sh` are the
same scripts locally and in CI, and a change that fails either does not land
regardless of who wrote it or how good the idea is. Tests, proofs, mutation
tables and measurements settle questions of fact, and the standing rule is that
a claim without a way to check it is not an argument.

What the gate cannot decide, the maintainer does, in the open:

- **Scope** — whether a feature belongs in an authenticator at all. A new
  dependency joins the device's trust base, so "does this belong here?" is asked
  before "does this work?".
- **Trade-offs** the code cannot resolve: spec conformance against
  interoperability with real hosts, flash budget against functionality, a
  behaviour that matches a YubiKey against a behaviour that matches the
  standard.
- **Refusals.** Declining a proposal is a normal outcome and gets a reason in
  the issue or PR, not silence.

Disagreement is settled by evidence first — a measurement, a spec citation, a
failing test — and by the maintainer second. There is no vote, and no appeal
beyond the fact that the project is AGPL-3.0-only: anyone who thinks a decision
is wrong may fork it, and that is a feature of the licence rather than a
threat.

Decisions leave a trace on purpose. A behaviour change lands as a commit whose
subject says what it is, with a `CHANGELOG.md` entry when it is user-visible; a
decision about *why* something is the way it is belongs in the docs it
constrains ([docs/threat-model.md](docs/threat-model.md),
[docs/limitations.md](docs/limitations.md)) rather than in a chat log.

## Becoming a maintainer

The path is a track record, not an application: sustained, reviewed
contributions, and judgment that has been visible in issues and reviews — a
reviewer who catches problems in other people's patches is worth more here than
a large first PR. The maintainer proposes and grants it; a second maintainer
would gain merge rights first, release signing later, and this file would be
updated in the same change.

Offers of help are welcome before that bar: review, board testing on hardware
this project does not own, host-platform coverage, documentation.

## Continuity

**No board's root of trust depends on this project outliving anyone.** The
secure-boot signing key is generated and held by whoever hardens the board, not
by the project ([docs/signing-keys.md](docs/signing-keys.md)); the MKEK and DEVK
are generated on-device and deliberately forgotten; release artifacts are signed
keyless, through the repository's own workflow identity, so there is no
long-lived project key in anyone's custody to lose or to leak. Whatever happens
to the people here, a device keeps working and its owner keeps the ability to
build and flash their own firmware — that is a property of the licence and the
design, not of anyone's good health.

What is genuinely single-homed is narrower: the ability to *act as this
project*. Merging changes, triaging issues, receiving private vulnerability
reports, publishing a release, and the Pages deployment that follows from the
repository.

**The live mechanism.** A second person holds write access to the repository.
They can merge pull requests, triage and close issues, and tag and publish a
release — which is the whole of what continuing this project requires — from day
one, with no legal process, no password handover and nothing to unseal first.
That is what makes continuity a standing property rather than a plan: the rights
are in place before anyone needs them.

**Write, and deliberately not admin.** An administrator can change settings,
grant access to others and remove the maintainer; write access is enough to
continue the project and not enough to take it over, and that asymmetry is the
point of choosing it. What write does not reach — repository settings, granting
access, and the private security advisories — stays with the maintainer and
passes with the estate. The cost is real and is stated rather than hidden: a
vulnerability reported privately while the maintainer is unreachable waits for
the account to change hands, and a reporter who needs an answer sooner than that
should open a public issue saying only that they are waiting.

The second person is named in the maintainer's will rather than here, because
publishing the name makes them a target and tells a reader nothing they can act
on.

**The legal half.** Ownership of the account, and the right to transfer the
repository and its name, pass through the maintainer's estate; the recovery
credentials live with those documents. They are kept apart from the second
person's access on purpose — one half keeps the project moving, the other settles
who owns it, and neither half alone is enough to quietly take it over.

**The honest limit.** This restores the ability to *act*, not the accumulated
context: the bus factor for knowledge stays at one, and no amount of repository
permissions changes that. The written threat model, the formal models, the
assurance case and a merge gate that encodes the bar are the mitigation — they
exist so a successor can tell what the project promised and check whether a
change still keeps that promise, instead of reconstructing it from commit
archaeology.

## Changing this document

By pull request, like everything else. A change to how authority works here is
a change the maintainer has to agree to, which makes it the one file where
"the maintainer decides" is also the amendment procedure.
