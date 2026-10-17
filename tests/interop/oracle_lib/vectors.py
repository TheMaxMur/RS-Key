# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Seeded pairwise input combinations; single-defect boundaries remain explicit."""
from itertools import combinations, product
import math
import random


def pairwise(dimensions, seed):
    names = list(dimensions)
    levels = [tuple(dimensions[name]) for name in names]
    if any(not values for values in levels):
        raise ValueError("pairwise dimensions cannot be empty")
    pairs = tuple(combinations(range(len(names)), 2))
    if math.prod(len(values) for values in levels) > 65536:
        raise ValueError("pairwise candidate product exceeds explicit generation bound")
    candidates = list(product(*(range(len(values)) for values in levels)))
    random.Random(seed).shuffle(candidates)
    def obligations(row):
        return {(left, row[left], right, row[right]) for left, right in pairs}
    if not pairs:
        return [dict(zip(names, (values[index] for values, index in zip(levels, row)))) for row in candidates]
    required = sorted(set().union(*(obligations(row) for row in candidates)))
    bits = {obligation: 1 << index for index, obligation in enumerate(required)}
    masks = [sum(bits[value] for value in obligations(row)) for row in candidates]
    remaining = (1 << len(required)) - 1
    chosen = []
    while remaining:
        index = max(range(len(candidates)), key=lambda offset: (masks[offset] & remaining).bit_count())
        row, covered = candidates[index], masks[index] & remaining
        if not covered:
            raise ValueError("pairwise generator stopped before covering its obligations")
        remaining &= ~covered
        chosen.append(dict(zip(names, (values[index] for values, index in zip(levels, row)))))
    return chosen
