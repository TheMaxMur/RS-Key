#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Hold the models' deliberate narrowings against `assurance/model_exceptions.toml`.

A TLA+ module earns its verdict by being about the whole surface it names. Where
it is not, it says so with a clause: one applet named in a guard the other two do
not get, a set literal that leaves out a reference the tree really has, a `CASE`
that answers for two of five and sends the rest to `OTHER`. Each of those is a
DECISION — a fact about the product stated as a hole in the model — and every one
of them is a place a defect can live where no mutant will ever find it.

Stage 6 asks that each such exception be a registry row with its own mutant, and
that an exception in a model with no row redden the gate. Before this row there
was no registry and no gate: `git grep -i exempt scripts/` found only tier
exclusions, and deleting `\\/ a = Oath` from `RSKeyAppletSeams` — the clause that
let OATH re-lock on a re-SELECT while PIV and OpenPGP could not — changed the
input of nothing.

WHICH EXCEPTIONS EXIST IS DERIVED HERE, never stored. That is the whole
difference between this and a fourth hand-kept roster, and this tree has already
deleted one guard that grew 800 lines defending nine copies of a list. Three
shapes are derived, each over the module's own DOMAIN VOCABULARY — the names it
defines as strings and the members of the enumerations it can see, its own and
its `EXTENDS`ed ones — rather than from a dictionary in this file. A gate that
knows the word "Oath" is complete over exactly the applets someone remembered to
type into it:

* `clause` — a comparison of a narrowed subject against a domain literal.
  Narrowed three ways, and the second and third are holes this guard's own table
  found in it: the subject is BOUND (a parameter or a `\\A`/`\\E`/`|->` binder) and
  the comparison is an operand of `\\/` or `/\\`; or the subject is bound and the
  comparison IS a function constructor's body, where there is no connective to be
  an operand of; or the subject is a state VARIABLE the definition compares
  against two different literals, which is a guard enumerating part of a domain.
  The connective is what separates an exception from a dispatch:
  `IF a = Piv THEN … ELSE …` answers for every applet, `IF Bug… \\/ a = Oath THEN`
  adds one. A `CASE` is dispatch throughout and nothing inside one is collected;
* `set` — a set literal that is a proper subset of another in the same module, or
  that disagrees with a same-named literal in a sibling module while overlapping
  it. Both directions of the second, so neither module is the privileged one;
* `case` — a `CASE` over a bound subject whose named arms are a proper subset of
  an enumeration in scope, measured against EVERY such superset rather than the
  smallest. A heuristic there would move a derived field under a later edit and
  redden a row that had not changed.

What is checked, and the direction of each:

* every derived narrowing has exactly one row, and every row names one that is
  still derived. That second direction is the one Stage 6 asks for by name: the
  exception leaves the model, and the row that described it is left pointing at
  nothing;
* the derived half of a row — `shape`, `site`, `clause`, `against`, `omits` — is
  compared, not trusted. Editing `a = Oath` into `a = Pgp` is then a finding
  rather than an unrelated diff, and a set literal that quietly gains a member is
  a row to re-decide;
* `mutant` names a configuration that EXISTS and that switches a `Bug…` constant
  the row's own definition reads. A row cannot claim a mutant from another
  module, or one that mutates something else in the same one;
* or it says `owes`, and then `owed` names the configuration that would refute it
  and that configuration must NOT exist. That is the ledger held in the second
  direction: pay the debt and the row goes red until it claims what it paid;
* `carried_by`, where a row has one, resolves to an id in
  `assurance/abstractions.toml`. Two registries disposing of the same narrowing
  without knowing about each other is how the second one starts being wrong;
* the derivation is not empty. A shape that stops matching satisfies every rule
  above over nothing, which is the failure a verdict column cannot show.

Limits, so the row is not read as more than it is. It cannot say a narrowing is
JUSTIFIED — `why` and `production` are prose and no script reads them for
meaning, exactly as `assurance/deleters.toml` says of its own dispositions. It
cannot say a claimed mutant refutes the NARROWING rather than something else in
the same definition: `SeamSolo_BugSigPinNotSpent.cfg` drives the clause at
`PgpKeyOp` and mutates the spend, not the `pw1`-only half, and only the row's own
prose says so. `kind` is a hand-written label and relabelling a narrowing as a
dispatch dodges nothing here but earns no red either. And the three shapes reach
LITERALS: a narrowing written over a Boolean variable — the `McTokenlessGuard`
family in `RSKeySecurityState` — is outside all three, which is deliberate rather
than an oversight, because those are the narrowings that already carry a switch
apiece.
"""

import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODELS = pathlib.Path("formal")
LEDGER = pathlib.Path("assurance/model_exceptions.toml")
#: Read only to resolve `carried_by`. The narrowing roster there is hand-typed
#: prose bullets byte-diffed into a generated page, so it cannot key on a derived
#: exception; what it CAN do is stop the same narrowing being disposed of twice
#: in two files with two answers.
ABSTRACTIONS = pathlib.Path("assurance/abstractions.toml")

#: A definition's head: `Name ==` or `Name(a, b) ==`. TLA+ operator names are
#: capitalised throughout these modules, which is what keeps a `\\* comment` or a
#: continuation line from reading as a new definition.
DEF = re.compile(r"^([A-Z][A-Za-z0-9_]*)\s*(?:\(([^)]*)\))?\s*==")
#: `EXTENDS RSKeyTokenAbstract, TLC` — where a module's vocabulary comes from
#: when it does not define it. Read for the reason the whole file is derived:
#: scoped to the module's own text, `RSKeyTokenGate`'s narrowing of `op` against
#: an operation named in `RSKeyTokenAbstract` was invisible, and so was the fact
#: that its own `CASE` covers every one of them. Names outside `formal/` (the
#: standard modules) resolve to nothing and drop out.
EXTENDS = re.compile(r"^EXTENDS\s+(.+)$")
#: A DOMAIN LITERAL NAME: `Piv == "piv"`. The module's own vocabulary, derived so
#: that this file names no applet, no reference and no operation.
STRDEF = re.compile(r'^([A-Z][A-Za-z0-9_]*)\s*==\s*"([^"]*)"\s*$')
#: A set-literal definition's head. The body is joined across lines by
#: [`set_literals`], because `InvNames` and `Refs` both wrap.
SETDEF = re.compile(r"^([A-Z][A-Za-z0-9_]*)\s*==\s*\{")
#: Members a set literal may have for this row to read it as an enumeration:
#: bare names and strings. A comprehension (`{ f \\in Fids : Live(f) }`) is not an
#: enumeration and omits nothing by construction.
ENUMERATION = re.compile(
    r'[\s,]*(?:"[^"]*"|[A-Za-z_][A-Za-z0-9_]*)'
    r'(?:\s*,\s*(?:"[^"]*"|[A-Za-z_][A-Za-z0-9_]*))*[\s,]*'
)
#: Where a subject comes from when it is not a parameter: a quantifier or a
#: function-constructor binder. Both range over a set, which is what makes the
#: comparison against one member a narrowing rather than a definition.
BINDER = re.compile(r"(?:\\A|\\E)\s+([a-z][A-Za-z0-9_]*)|\[\s*([a-z][A-Za-z0-9_]*)\s+\\in\b")
#: A `CASE`/`[]` arm's guard, which is dispatch and not an exception — collected
#: for the `case` shape and excluded from the `clause` one.
ARM = re.compile(r'(?:CASE|\[\])\s*([a-z][A-Za-z0-9_]*)\s*=\s*"([^"]*)"')
#: The mutation switches, by this repo's own convention: every `Bug…` constant a
#: definition reads, so a claimed configuration can be held to the definition.
SWITCH = re.compile(r"\bBug[A-Za-z0-9_]*\b")
#: A configuration turning one on. `gen-configs.sh` writes every switch into
#: every configuration of its family, so only the TRUE one identifies the mutant.
CFG_ON = re.compile(r"^\s*(Bug[A-Za-z0-9_]*)\s*=\s*TRUE\s*$", re.M)

#: TLA+'s two comment forms. Both are stripped before anything else looks at the
#: text: the module headers are one long `(* … *)` block apiece and the prose in
#: them talks about the very clauses below, so a scan that reads comments finds
#: the narrowing twice and the second one has no line to cite.
LINE_COMMENT = "\\*"

#: Enough of a token stream to answer "what is this comparison an operand of".
#: Longest alternatives first, so `\\/` is one token and not a stray backslash.
TOKEN = re.compile(
    r'"[^"]*"|\\/|/\\|\\in|\\notin|\\A|\\E|->|\[\]|[A-Za-z_][A-Za-z0-9_]*|[=#()\[\]{},.\':]|\S'
)
CONNECTIVES = frozenset({"\\/", "/\\"})
#: A comparison's left-hand side: a bound name or a state variable, both spelled
#: lowercase-first throughout these modules.
IDENTIFIER = re.compile(r"[a-z][A-Za-z0-9_]*")
#: A function constructor, `[r \\in Refs |-> …]`. The one place a narrowing has no
#: connective to be an operand of, because the comparison IS the whole body.
FUNCTION = re.compile(r"\|->")

SHAPES = ("clause", "set", "case")
#: The judgement the derivation cannot make. `narrowing` is a hole in the model
#: standing for a fact about the product; `dispatch` is a per-case answer the
#: connective test read as a hole; `mutant-arm` is a defect the module carries on
#: purpose, and it is the one kind that may never say `owes`.
KINDS = ("narrowing", "dispatch", "mutant-arm")
OWES = "owes"

ROW_FIELDS = (
    "against",
    "carried_by",
    "clause",
    "id",
    "kind",
    "line",
    "module",
    "mutant",
    "omits",
    "owed",
    "production",
    "shape",
    "site",
    "why",
)
TABLES = ("exception",)
ID = re.compile(r"^MX-[A-Z0-9]+-[0-9]{3}$")

#: Under this the derivation found (almost) nothing and every rule below passed
#: over an empty roster — the shape `deleter_gate.py` floors for the same reason.
#: Measured at 13 across the twenty modules when this landed; floored well under
#: so ordinary movement in the models does not trip it and a broken scan does.
FLOOR_SITES = 6


def strip_comments(text):
    """The module with both comment forms blanked, LINE-FOR-LINE.

    Blanked rather than removed: every finding this row prints cites a line
    number in the file a reader will open, so the scan may not renumber. Block
    comments nest in TLA+ and the modules use that, so the depth is counted
    rather than matched.
    """
    out, depth = [], 0
    for line in text.splitlines():
        kept, at = [], 0
        while at < len(line):
            if line.startswith("(*", at):
                depth += 1
                kept.append("  ")
                at += 2
            elif depth and line.startswith("*)", at):
                depth -= 1
                kept.append("  ")
                at += 2
            elif depth:
                kept.append(" ")
                at += 1
            elif line.startswith(LINE_COMMENT, at):
                kept.append(" " * (len(line) - at))
                at = len(line)
            else:
                kept.append(line[at])
                at += 1
        out.append("".join(kept))
    return out


def modules(root):
    """`{name: [code lines]}` for every `formal/*.tla`, comments blanked."""
    found = {}
    for path in sorted((root / MODELS).glob("*.tla")):
        found[path.name] = strip_comments(path.read_text(encoding="utf-8"))
    return found


def definitions(lines):
    """[(name, [parameters], first line, last line)] over one module.

    A definition runs to the next one, which is what lets the clause scan ask
    which operator a comparison is inside and the switch scan ask which `Bug…`
    constants that operator reads.
    """
    spans, current = [], None
    for number, line in enumerate(lines, 1):
        head = DEF.match(line)
        if head:
            if current:
                spans.append(current)
            params = [p.strip() for p in (head.group(2) or "").split(",") if p.strip()]
            current = [head.group(1), params, number, number]
        elif current:
            current[3] = number
    if current:
        spans.append(current)
    return [tuple(span) for span in spans]


def set_literals(lines):
    """`{name: (line, members, the QUOTED ones)}` for the module's enumerations.

    The two member sets are kept apart because the string vocabulary is the
    quoted half and nothing else. Filtering by capitalisation instead — bare
    names are capitalised in these modules and string members were assumed not to
    be — silently emptied the vocabulary of `Ops`, whose eleven members are
    `"Noop"`, `"SetPin"`, `"UseAcfg"` …, and took `RSKeyTokenGate`'s only
    narrowing out of the derivation with it.
    """
    found, at = {}, 0
    while at < len(lines):
        head = SETDEF.match(lines[at])
        if head:
            body, last = lines[at], at
            while body.count("{") > body.count("}") and last + 1 < len(lines):
                last += 1
                body += " " + lines[last]
            if body.count("{") == body.count("}"):
                inner = body[body.index("{") + 1 : body.rindex("}")]
                if ENUMERATION.fullmatch(inner):
                    written = [part.strip() for part in inner.split(",") if part.strip()]
                    if written:
                        found[head.group(1)] = (
                            at + 1,
                            frozenset(p.strip('"') for p in written),
                            frozenset(p[1:-1] for p in written if p.startswith('"')),
                        )
            at = last
        at += 1
    return found


def inherited(module, code, seen=None):
    """`module` and every `formal/` module it EXTENDS, transitively.

    Order matters only for the cycle guard: TLA+ forbids one, but a scan that
    trusts that recurses for ever the day someone writes it by mistake.
    """
    seen = set() if seen is None else seen
    if module in seen or module not in code:
        return seen
    seen.add(module)
    for line in code[module]:
        found = EXTENDS.match(line.strip())
        if not found:
            continue
        for name in found.group(1).split(","):
            inherited(f"{name.strip()}.tla", code, seen)
    return seen


def vocabulary(module, code):
    """(domain literal NAMES, domain literal STRINGS) in scope for `module`.

    The names are `Piv == "piv"`; the strings are every literal that appears in
    an enumeration the module can see, its own or an EXTENDed one. Both derived,
    so this file holds no applet, reference or operation name of its own — a
    dictionary written here would keep the registry "complete" over exactly the
    words someone typed.
    """
    names, strings = set(), set()
    for source in inherited(module, code):
        names |= {m.group(1) for line in code[source] if (m := STRDEF.match(line.strip()))}
        for _line, _members, quoted in set_literals(code[source]).values():
            strings |= quoted
    return names, strings


def visible_sets(module, code):
    """`{name: (line, members)}` for every enumeration `module` can see.

    The line belongs to the module that DEFINES the set, which is why an
    inherited one is keyed apart from the local table below: a `case` row cites
    the `CASE`'s own line, and the superset it is measured against only has to be
    resolvable, not local.
    """
    found = {}
    for source in inherited(module, code):
        for name, value in set_literals(code[source]).items():
            found.setdefault(name, value)
    return found


def comparisons(lines, low, high, names, strings):
    """[(line, subject, operator, literal, is a connective operand)] in one definition.

    Every comparison of a lowercase identifier against a domain literal, with the
    one fact the shapes below dispatch on: whether it stands as an OPERAND of
    `\\/` or `/\\`. That test is taken over TOKENS rather than over the line —
    reading the line for a connective anywhere calls `IF a = Piv THEN x \\/ y` a
    narrowing, which is the direction that fills a registry with rows nobody can
    decide.
    """
    tokens = []
    for number in range(low, high + 1):
        for token in TOKEN.finditer(lines[number - 1]):
            tokens.append((token.group(0), number))
    case_at = next((i for i, (t, _) in enumerate(tokens) if t == "CASE"), None)
    found = []
    for i in range(len(tokens) - 2):
        subject, operator, literal = (tokens[i][0], tokens[i + 1][0], tokens[i + 2][0])
        if operator not in ("=", "#") or not IDENTIFIER.fullmatch(subject):
            continue
        # `tok.rp = NoRp` is a record field, not the bound `rp` of the enclosing
        # operator; without this the token walk reads three of
        # RSKeySecurityState's guards as narrowings of their own parameter.
        if i and tokens[i - 1][0] == ".":
            continue
        quoted = literal.startswith('"') and literal[1:-1] in strings
        if not (quoted or literal in names):
            continue
        # A `CASE` is dispatch throughout — its arms AND their bodies — so
        # nothing at or after it is collected here. The `case` shape asks the
        # coverage question about the same text instead.
        if case_at is not None and i >= case_at:
            continue
        before = i - 1
        while before >= 0 and tokens[before][0] == "(":
            before -= 1
        after = i + 3
        while after < len(tokens) and tokens[after][0] == ")":
            after += 1
        left = tokens[before][0] if before >= 0 else None
        right = tokens[after][0] if after < len(tokens) else None
        found.append(
            (
                tokens[i][1],
                subject,
                operator,
                literal,
                left in CONNECTIVES or right in CONNECTIVES,
            )
        )
    return found


def clause_sites(module, code):
    """Every `clause`-shaped narrowing in one module.

    A comparison of a NARROWED subject against a domain literal. Three ways for
    a subject to be narrowed, and the second and third were holes this row went
    looking for in itself after the first was written:

    * it is BOUND — an operator parameter or a `\\A`/`\\E`/`|->` binder — so it
      ranges over a set and pinning it to one member takes the rest out. Then the
      comparison must stand as a connective operand, which is what separates
      `IF Bug… \\/ a = Oath THEN` from the total dispatch `IF a = Piv THEN … ELSE`;
    * or it is a STATE VARIABLE the definition compares against two DIFFERENT
      domain literals, each as a connective operand — a guard enumerating part of
      a domain. `/\\ sel = Piv` is an action's own subject and not a narrowing;
      `/\\ (sel = Piv \\/ sel = Pgp)` is one, and with only the bound rule a
      constructed defect of exactly that shape passed at rc 0. Closing it found a
      real one: `RSKeyAppletPolicies`'s `PivKeyOp` spends for two of the three PIN
      policies and records for one;
    * or it is bound and the comparison IS a function constructor's body, where
      there is no connective to be an operand of. `[r \\in Refs |-> r = "oathCode"]`
      is the characteristic function of one member, which is the same narrowing
      the `/\\`-joined copies of it carry.
    """
    lines = code[module]
    names, strings = vocabulary(module, code)
    found = []
    for name, params, low, high in definitions(lines):
        bound = set(params)
        for number in range(low, high + 1):
            for binder in BINDER.finditer(lines[number - 1]):
                bound.add(binder.group(1) or binder.group(2))
        seen = comparisons(lines, low, high, names, strings)
        enumerated = {
            subject
            for subject in {s for _l, s, _o, _lit, conn in seen if conn}
            if len({lit for _l, s, _o, lit, conn in seen if conn and s == subject}) > 1
        }
        for number, subject, operator, literal, connective in seen:
            if subject in bound:
                if not (connective or FUNCTION.search(lines[number - 1])):
                    continue
            elif not (connective and subject in enumerated):
                continue
            found.append(
                {
                    "module": module,
                    "line": number,
                    "shape": "clause",
                    "site": name,
                    "clause": f"{subject} {operator} {literal}",
                    "against": "",
                    "omits": [],
                }
            )
    return found


def set_sites(module, lines, others):
    """Every `set`-shaped narrowing: a literal that omits what a sibling has.

    Two sources, and the second is symmetric on purpose. Inside one module, a
    proper subset of another literal — `VerifyTargets` under `Refs`. Across
    modules, a literal of the SAME NAME that overlaps and disagrees: `Refs` is
    seven references in the seam module and five in the lattice, and each of the
    two directions is a decision the other cannot state.
    """
    here = set_literals(lines)
    found = []
    for name, (line, members, _quoted) in sorted(here.items()):
        for other, (_line, against, _q) in sorted(here.items()):
            if other != name and members < against:
                found.append(
                    {
                        "module": module,
                        "line": line,
                        "shape": "set",
                        "site": name,
                        "clause": name,
                        "against": other,
                        "omits": sorted(against - members),
                    }
                )
        for sibling, sibling_lines in sorted(others.items()):
            if sibling == module:
                continue
            twin = set_literals(sibling_lines).get(name)
            if twin is None or twin[1] == members or not (twin[1] & members):
                continue
            found.append(
                {
                    "module": module,
                    "line": line,
                    "shape": "set",
                    "site": name,
                    "clause": name,
                    "against": f"{sibling}:{name}",
                    "omits": sorted(twin[1] - members),
                }
            )
    return found


def case_sites(module, code):
    """Every `case`-shaped narrowing: a `CASE` that answers for part of a set.

    Measured against every enumeration that properly contains the arms, not the
    smallest of them. The smallest is a heuristic, and a heuristic in a DERIVED
    field moves a row that nobody edited the day a new literal lands.
    """
    lines = code[module]
    sets = visible_sets(module, code)
    found = []
    for name, _params, low, high in definitions(lines):
        body = "\n".join(lines[low - 1 : high])
        if "CASE" not in body:
            continue
        arms = set(ARM.findall(body))
        if not arms:
            continue
        covered = frozenset(literal for _subject, literal in arms)
        for over, (_line, members, _quoted) in sorted(sets.items()):
            if covered < members:
                found.append(
                    {
                        "module": module,
                        "line": low,
                        "shape": "case",
                        "site": name,
                        "clause": name,
                        "against": over,
                        "omits": sorted(members - covered),
                    }
                )
    return found


def exceptions(root):
    """Every derived narrowing of every model, in a stable order."""
    code = modules(root)
    found = []
    for module, lines in code.items():
        found += clause_sites(module, code)
        found += set_sites(module, lines, code)
        found += case_sites(module, code)
    return sorted(found, key=lambda s: (s["module"], s["line"], s["clause"], s["against"]))


def switches(root, module, line):
    """The `Bug…` constants the definition holding `line` reads.

    What makes a claimed mutant falsifiable: a configuration may only be claimed
    by a row whose own definition reads the switch that configuration turns on.
    """
    lines = modules(root).get(module)
    if lines is None:
        return set()
    for _name, _params, low, high in definitions(lines):
        if low <= line <= high:
            return set(SWITCH.findall("\n".join(lines[low - 1 : high])))
    return set()


def switched_on(root, cfg):
    """The switches a configuration turns TRUE, or None when there is no such file."""
    path = root / MODELS / cfg
    if not path.is_file():
        return None
    return set(CFG_ON.findall(path.read_text(encoding="utf-8")))


def rows(root):
    with (root / LEDGER).open("rb") as handle:
        return tomllib.load(handle)


def abstraction_ids(root):
    path = root / ABSTRACTIONS
    if not path.is_file():
        return set()
    with path.open("rb") as handle:
        return {a["id"] for a in tomllib.load(handle).get("abstraction", [])}


def key(site):
    return (site["module"], site["line"], site["clause"], site["against"])


def moved(derived, row):
    """Where a row's clause is now, if it is anywhere — the deleter-gate message.

    A citation whose line has shifted and one whose clause has been deleted are
    different findings, and reporting the second for the first sends the reader
    to re-decide a narrowing that has not changed.
    """
    elsewhere = sorted(
        str(s["line"])
        for s in derived
        if s["module"] == row["module"]
        and s["clause"] == row["clause"]
        and s["against"] == row.get("against", "")
    )
    return f"; it is at :{', :'.join(elsewhere)} now" if elsewhere else ""


def audit(root):
    """Every disagreement between the registry and the models, reported once."""
    problems = []
    doc = rows(root)
    derived = exceptions(root)
    if len(derived) < FLOOR_SITES:
        problems.append(
            f"{len(derived)} narrowings derived over {MODELS}/*.tla, under the floor"
            f" of {FLOOR_SITES} — the scan found (almost) nothing, so every rule"
            " below passed over an empty roster"
        )
        return problems

    if stray := sorted(set(doc) - set(TABLES)):
        problems.append(
            f"{LEDGER} carries {stray}, which nothing reads — a table added here is"
            " held by no rule and shown to no reader"
        )
    # An entry that cannot be ADDRESSED is reported once and then left out of
    # everything below, because the rules below read the keys it is missing: the
    # first version raised out of the mutant check on a row with no `line`, and a
    # `run()` that catches the exception then blames the whole file for one row.
    entries, addressable = [], doc.get("exception", [])
    ledger = {}
    for entry in addressable:
        try:
            ledger[(entry["module"], entry["line"], entry["clause"], entry.get("against", ""))] = entry
        except KeyError as missing:
            problems.append(f"{LEDGER}: an entry has no {missing}")
        else:
            entries.append(entry)
    # A duplicate key would otherwise be SILENT: the row that lost the race is
    # still schema-checked by the loop below, so it reads as decided while the
    # narrowing it was meant to address is disposed of by the other one.
    if len(ledger) != len(entries):
        problems.append(
            f"{LEDGER}: two entries name the same module, line, clause and"
            " against, so one of them addresses nothing"
        )
    seen = set()
    for entry in entries:
        if (found := entry.get("id")) in seen:
            problems.append(f"{LEDGER}: two entries carry the id `{found}`")
        seen.add(found)

    by_key = {key(site): site for site in derived}
    for missing in sorted(by_key.keys() - ledger.keys()):
        site = by_key[missing]
        against = f" against `{site['against']}`" if site["against"] else ""
        problems.append(
            f"{site['module']}:{site['line']} narrows `{site['clause']}`{against} in"
            f" {site['site']} and {LEDGER} does not dispose of it"
        )
    for gone in sorted(ledger.keys() - by_key.keys()):
        module, line, clause, against = gone
        where = f" against `{against}`" if against else ""
        problems.append(
            f"{LEDGER} disposes of {module}:{line} `{clause}`{where}, which the model"
            f" no longer narrows{moved(derived, ledger[gone])}"
        )

    for shared in sorted(by_key.keys() & ledger.keys()):
        site, entry = by_key[shared], ledger[shared]
        where = f"{entry['module']}:{entry['line']}"
        for field in ("shape", "site", "omits"):
            recorded = entry.get(field, [] if field == "omits" else "")
            if recorded != site[field]:
                problems.append(
                    f"{where}: {field} derives as {site[field]!r} and is recorded as"
                    f" {recorded!r} — re-decide the narrowing, do not re-label it"
                )

    known = abstraction_ids(root)
    for entry in entries:
        where = f"{entry.get('module', '?')}:{entry.get('line', '?')}"
        if stray := sorted(set(entry) - set(ROW_FIELDS)):
            problems.append(f"{where}: carries {stray}, which nothing reads")
        if not ID.match(entry.get("id", "")):
            problems.append(f"{where}: id `{entry.get('id')}` is not MX-<AREA>-<NNN>")
        if entry.get("kind") not in KINDS:
            problems.append(f"{where}: kind `{entry.get('kind')}` is not one of {KINDS}")
        if entry.get("shape") not in SHAPES:
            problems.append(f"{where}: shape `{entry.get('shape')}` is not one of {SHAPES}")
        for field in ("why", "production"):
            if not entry.get(field, "").strip():
                problems.append(f"{where}: a narrowing with no {field} is not a decision")
        if (carried := entry.get("carried_by")) and carried not in known:
            problems.append(
                f"{where}: carried_by `{carried}` is not an id in {ABSTRACTIONS}"
            )
        problems += mutant_problems(root, entry, where)
    return problems


def mutant_problems(root, entry, where):
    """The debt half of a row: a mutant that refutes it, or a debt that is unpaid."""
    problems, claimed, owed = [], entry.get("mutant", ""), entry.get("owed")
    if claimed == OWES:
        if entry.get("kind") == "mutant-arm":
            problems.append(
                f"{where}: a mutant arm that owes a mutant is a clause nothing drives"
            )
        if not owed:
            problems.append(
                f"{where}: `mutant = \"{OWES}\"` with no `owed` — a debt with no"
                " creditor is a note, and nothing can notice it being paid"
            )
        elif switched_on(root, owed) is not None:
            problems.append(
                f"{where}: owes {owed}, and {MODELS}/{owed} exists — the debt is paid"
                " and the row still says it is owed; claim it as the mutant"
            )
        return problems
    if owed is not None:
        problems.append(f"{where}: claims {claimed} and still names `owed` {owed}")
    if not claimed:
        problems.append(f"{where}: no mutant and no `{OWES}` — say which it is")
        return problems
    on = switched_on(root, claimed)
    if on is None:
        problems.append(f"{where}: claims {claimed}, which is not a file in {MODELS}")
        return problems
    reads = switches(root, entry["module"], entry["line"])
    if not on & reads:
        problems.append(
            f"{where}: claims {claimed}, which switches {sorted(on) or 'nothing'} on,"
            f" and the definition holding this narrowing reads {sorted(reads) or 'no'}"
            " switch — a mutant that drives some other clause is not this row's"
        )
    return problems


def summary(root):
    derived = exceptions(root)
    doc = rows(root).get("exception", [])
    kinds = {shape: sum(1 for s in derived if s["shape"] == shape) for shape in SHAPES}
    owing = sum(1 for e in doc if e.get("mutant") == OWES)
    return (
        f"model-exception-gate: ok — {len(derived)} narrowings over "
        f"{len({s['module'] for s in derived})} of "
        f"{len(list((root / MODELS).glob('*.tla')))} models ("
        + ", ".join(f"{n} {shape}" for shape, n in kinds.items())
        + f"), each disposed of; {len(doc) - owing} carried by a mutant, {owing} owing one"
    )


def run(root):
    try:
        problems = audit(root)
    except (KeyError, OSError, TypeError, tomllib.TOMLDecodeError) as error:
        problems = [f"{LEDGER} cannot be read as a narrowing registry: {error}"]
    if problems:
        print("model-exception-gate:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(
            "\nEvery place a model deliberately narrows owes a row: what it\n"
            "excludes, which production fact it stands for, and the mutant that\n"
            "refutes it — or, honestly, that it still owes one. An exception with\n"
            f"no row is a hole no mutant can find; decide it in {LEDGER}.",
            file=sys.stderr,
        )
        return 1
    print(summary(root))
    return 0


def main():
    if sys.argv[1:]:
        print("usage: model_exception_gate.py", file=sys.stderr)
        return 2
    return run(ROOT)


if __name__ == "__main__":
    sys.exit(main())
