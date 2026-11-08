<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Assurance vector

A property can have evidence at several layers. For example, a model can
rule out a bad state, a Rust test can exercise the matching transition,
and a board test can check the hardware event that triggers it. Each
result has its own scope.

The [generated assurance vector](https://github.com/TheMaxMur/RS-Key/blob/main/assurance/reports/assurance-vector.md)
lists that evidence by property. Use the property ID to find its model
and code references, evidence bundle, tool or platform dependencies and
remaining gaps. The [assurance matrix](assurance-matrix.md) shows how
the scope changes across build configurations. The
[formal model](formal.md) explains what the models represent.
