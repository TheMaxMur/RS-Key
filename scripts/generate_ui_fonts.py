#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Generate the trusted-display IBM Plex 4-bit coverage tables."""

import argparse
import hashlib
import os
import pathlib
import subprocess
import sys

import PIL
from PIL import Image, ImageDraw, ImageFont, features


ROOT = pathlib.Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "third_party" / "ibm-plex" / "font_data.rs"
CHARS = "".join(chr(code) for code in range(0x20, 0x7F)) + "\N{EM DASH}\N{MIDDLE DOT}"
ROLES = (
    ("READY", "sans", "IBMPlexSans-SemiBold.ttf", 30),
    ("HEADING", "sans", "IBMPlexSans-SemiBold.ttf", 19),
    ("STRONG", "sans", "IBMPlexSans-SemiBold.ttf", 18),
    ("BODY", "sans", "IBMPlexSans-Regular.ttf", 13),
    ("BODY_STRONG", "sans", "IBMPlexSans-SemiBold.ttf", 13),
    ("MONO", "mono", "IBMPlexMono-Regular.ttf", 12),
    ("MONO_SMALL", "mono", "IBMPlexMono-Regular.ttf", 11),
)


def font_dir(family):
    name = "IBM_PLEX_SANS_DIR" if family == "sans" else "IBM_PLEX_MONO_DIR"
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"{name} is not set; run this script in `nix develop`")
    return pathlib.Path(value)


def pack_coverage(values):
    packed = bytearray()
    for index in range(0, len(values), 2):
        high = values[index]
        low = values[index + 1] if index + 1 < len(values) else 0
        packed.append((high << 4) | low)
    return packed


def rasterize(font, char):
    advance = max(0, round(font.getlength(char)))
    box = font.getbbox(char, anchor="ls")
    if box is None:
        return advance, 0, 0, 0, 0, bytearray()
    left, top, right, bottom = box
    width = max(0, right - left)
    height = max(0, bottom - top)
    if width == 0 or height == 0:
        return advance, left, top, 0, 0, bytearray()

    image = Image.new("L", (width, height), 0)
    draw = ImageDraw.Draw(image)
    draw.text((-left, -top), char, font=font, fill=255, anchor="ls")
    bounds = image.getbbox()
    if bounds is None:
        return advance, left, top, 0, 0, bytearray()
    x0, y0, x1, y1 = bounds
    image = image.crop(bounds)
    coverage = [(value + 8) // 17 for value in image.get_flattened_data()]
    return advance, left + x0, top + y0, x1 - x0, y1 - y0, pack_coverage(coverage)


def byte_lines(data):
    if not data:
        return ["    "]
    values = [f"0x{value:02X}" for value in data]
    return ["    " + ", ".join(values[i : i + 16]) + "," for i in range(0, len(values), 16)]


def generate_role(name, path, size):
    # Pinned, not defaulted: Pillow picks Raqm when libraqm is present and FreeType's
    # own layout when it is not, and the two disagree about two advances in READY
    # ('f' and the middle dot, 10 px against 11). A silent fallback would rewrite the
    # tables; `raster_versions` refuses the run instead.
    font = ImageFont.truetype(str(path), size=size, layout_engine=ImageFont.Layout.RAQM)
    ascent, descent = font.getmetrics()
    data = bytearray()
    glyphs = []
    for char in CHARS:
        advance, left, top, width, height, packed = rasterize(font, char)
        glyphs.append((advance, left, top, width, height, len(data)))
        data.extend(packed)

    lines = [f"const {name}_DATA: &[u8] = &[", *byte_lines(data), "];", ""]
    lines.append(f"const {name}_GLYPHS: &[Glyph; {len(glyphs)}] = &[")
    for advance, left, top, width, height, offset in glyphs:
        lines.append(
            "    Glyph { "
            f"advance: {advance}, left: {left}, top: {top}, width: {width}, "
            f"height: {height}, offset: {offset} "
            "},"
        )
    lines.extend(
        [
            "];",
            "",
            f"pub(super) const {name}: Font = Font {{",
            f"    ascent: {ascent},",
            f"    descent: {descent},",
            f"    glyphs: {name}_GLYPHS,",
            f"    data: {name}_DATA,",
            "};",
            "",
        ]
    )
    return lines


def raster_versions():
    """What actually decides the bytes, recorded so a red row names its own cause.

    The font files are hashed below, but they are only half the input: FreeType
    rasterises and Raqm lays out, and either moving changes the tables with nothing
    in the diff to say so.
    """
    if not features.check("raqm"):
        raise SystemExit(
            "libraqm is missing; Pillow would silently lay the glyphs out with "
            "FreeType instead and the tables would not match"
        )
    return (
        f"Pillow {PIL.__version__}, "
        f"FreeType {features.version('freetype2')}, "
        f"Raqm {features.version('raqm')}"
    )


def generated_text():
    paths = {}
    for _, family, filename, _ in ROLES:
        path = font_dir(family) / filename
        if not path.is_file():
            raise SystemExit(f"font is missing: {path}")
        paths[(family, filename)] = path

    digests = {
        key: hashlib.sha256(path.read_bytes()).hexdigest() for key, path in paths.items()
    }
    lines = [
        "// SPDX-License-Identifier: OFL-1.1",
        "// Copyright (C) 2017 IBM Corp.",
        "",
        "// Generated by scripts/generate_ui_fonts.py. Do not edit.",
        f"// {raster_versions()}",
    ]
    for (family, filename), digest in sorted(digests.items()):
        lines.append(f"// {family}/{filename} sha256: {digest}")
    lines.extend(["", "use super::{Font, Glyph};", ""])
    for name, family, filename, size in ROLES:
        lines.extend(generate_role(name, paths[(family, filename)], size))
    raw = "\n".join(lines)
    formatted = subprocess.run(
        ["rustfmt", "--edition", "2024"],
        input=raw,
        capture_output=True,
        check=True,
        text=True,
    )
    return formatted.stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail when the output is stale")
    args = parser.parse_args()
    generated = generated_text()
    if args.check:
        current = OUTPUT.read_text() if OUTPUT.is_file() else ""
        if current != generated:
            print(f"{OUTPUT.relative_to(ROOT)} is stale; run scripts/generate_ui_fonts.py")
            return 1
        print("IBM Plex UI font data is current")
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(generated)
    print(f"wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
