#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""List the production `fn` spans of a Rust file, for the stage C1 inventory.

THIS IS A MEASUREMENT, NOT A GATE. It is not wired into `scripts/check.sh` and
asserts nothing; running it reproduces the denominator of
`assurance/c1_inventory.tsv`, which is where its output and the classification
built on it live. A ratchet over this number is what §15 C1 item 4 eventually
wants, and it must NOT be built before the unit it counts is the right one —
the adversarial review of 2026-09-18 established that it is not (see the
inventory file's own header).

WHAT IT COUNTS. Every `fn` with a body, outside `#[cfg(test)]`/`#[cfg(kani)]`
items, from the first attribute or doc-comment line of the signature through
the closing brace. A file whose `mod` declaration is cfg-gated in the PARENT is
invisible here and must be excluded by the caller; this scanner reads one file
at a time and cannot see that.

WHAT MADE IT WRONG, five times in one session, because a counter that has been
wrong five ways is a counter to distrust:

  1. `;` at paren depth 0 was read as a bodiless declaration, so every
     `-> [u8; 32]` lost its function. Bracket depth is tracked now.
  2. The same `;` in the cfg scan let a `#[cfg(test)] fn` through into the
     production count.
  3. The cfg scan matched `#[cfg(test)]` literally and missed
     `#[cfg(any(test, kani, feature = "assurance-trace"))]`.
  4. Module-level gating in the parent file is invisible here (above).
  5. `#[cfg(not(kani))]` still matches the word `kani` and is dropped as if it
     were proof-only. Every such site in the tagged files today marks a
     `const … ;`, so the `;` branch fires first and the cost is zero — but the
     defect is armed, and the first `#[cfg(not(kani))] fn` would take its lines
     out of a count a ratchet reads as progress.
"""
import re
import sys


def strip_spans(src):
    """Return src with string/char/line-comment/block-comment bytes blanked."""
    out = list(src)
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == '/' and i + 1 < n and src[i + 1] == '/':
            j = src.find('\n', i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = ' '
            i = j
        elif c == '/' and i + 1 < n and src[i + 1] == '*':
            depth, j = 1, i + 2
            while j < n and depth:
                if src[j] == '/' and j + 1 < n and src[j + 1] == '*':
                    depth += 1
                    j += 2
                elif src[j] == '*' and j + 1 < n and src[j + 1] == '/':
                    depth -= 1
                    j += 2
                else:
                    j += 1
            for k in range(i, min(j, n)):
                if src[k] != '\n':
                    out[k] = ' '
            i = j
        elif c == 'r' and i + 1 < n and src[i + 1] in '#"':
            m = re.match(r'r(#*)"', src[i:])
            if m:
                term = '"' + m.group(1)
                j = src.find(term, i + m.end())
                j = n if j < 0 else j + len(term)
                for k in range(i, j):
                    if src[k] != '\n':
                        out[k] = ' '
                i = j
            else:
                i += 1
        elif c == '"':
            j = i + 1
            while j < n:
                if src[j] == '\\':
                    j += 2
                elif src[j] == '"':
                    j += 1
                    break
                else:
                    j += 1
            for k in range(i, min(j, n)):
                if src[k] != '\n':
                    out[k] = ' '
            i = j
        elif c == "'":
            m = re.match(r"'(\\.|[^\\'])'", src[i:])
            if m:
                for k in range(i, i + m.end()):
                    out[k] = ' '
                i += m.end()
            else:
                i += 1
        else:
            i += 1
    return ''.join(out)


def line_of(src, pos):
    return src.count('\n', 0, pos) + 1


def main(path):
    src = open(path).read()
    bare = strip_spans(src)
    lines = src.split('\n')

    # cfg-gated regions: a `mod x { }` or item preceded by #[cfg(test|kani)]
    gated = set()
    for m in re.finditer(r'#\[cfg(?:_attr)?\([^\]]*\)\]', bare):
        if not re.search(r'\b(test|kani|assurance-trace|assurance_trace)\b', m.group(0)):
            continue
        # `;` and `{` only terminate at bracket/paren depth 0: a `[u8; 32]` in a
        # signature is not a bodiless declaration, and reading it as one let
        # `#[cfg(test)] fn wrap_keydev_legacy(&mut [u8; N])` past this scan.
        j, semi, dp, db = -1, -1, 0, 0
        for k in range(m.end(), len(bare)):
            ch = bare[k]
            if ch == '(':
                dp += 1
            elif ch == ')':
                dp -= 1
            elif ch == '[':
                db += 1
            elif ch == ']':
                db -= 1
            elif dp == 0 and db == 0 and ch == ';':
                semi = k
                break
            elif dp == 0 and db == 0 and ch == '{':
                j = k
                break
        if semi != -1 or j == -1:
            continue
        depth, k = 1, j + 1
        while k < len(bare) and depth:
            if bare[k] == '{':
                depth += 1
            elif bare[k] == '}':
                depth -= 1
            k += 1
        for ln in range(line_of(src, m.start()), line_of(src, k) + 1):
            gated.add(ln)

    rows = []
    for m in re.finditer(r'\bfn\s+([A-Za-z_][A-Za-z0-9_]*)', bare):
        pre = bare[:m.start()]
        # a `fn` inside a type position (`fn(` pointer) has no name -> regex already excludes
        start = m.start()
        # walk back over the signature to the first line of attributes/visibility
        ls = src.rfind('\n', 0, start) + 1
        start_line = line_of(src, start)
        # include preceding attribute / doc-comment lines
        i = start_line - 1
        while i >= 1:
            t = lines[i - 1].strip()
            if t.startswith('#[') or t.startswith('#![') or t.startswith('///') or t.startswith('//!') \
               or t.startswith('pub ') and i == start_line - 1:
                i -= 1
            else:
                break
        sig_first = i + 1
        # body: find the '{' that opens it, or ';' for a trait decl
        j = m.end()
        depth_paren = depth_brack = 0
        while j < len(bare):
            ch = bare[j]
            if ch == '(':
                depth_paren += 1
            elif ch == ')':
                depth_paren -= 1
            elif ch == '[':
                depth_brack += 1
            elif ch == ']':
                depth_brack -= 1
            elif ch == ';' and depth_paren == 0 and depth_brack == 0:
                j = -1
                break
            elif ch == '{' and depth_paren == 0 and depth_brack == 0:
                break
            j += 1
        if j == -1 or j >= len(bare):
            continue  # trait/extern declaration, no body
        depth, k = 1, j + 1
        while k < len(bare) and depth:
            if bare[k] == '{':
                depth += 1
            elif bare[k] == '}':
                depth -= 1
            k += 1
        end_line = line_of(src, k - 1)
        if start_line in gated:
            continue
        rows.append((m.group(1), sig_first, end_line, end_line - sig_first + 1))

    total_fn = sum(r[3] for r in rows)
    print(f'# {path}: {len(lines)} lines total, {len(rows)} production fns, {total_fn} fn lines')
    for name, a, b, c in rows:
        print(f'{name}\t{path}:{a}\t{a}-{b}\t{c}')


if __name__ == '__main__':
    for p in sys.argv[1:]:
        main(p)
