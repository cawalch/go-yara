# Regex Parity Fixtures

This directory contains regex-only YARA rules and matching sample inputs for
targeted comparisons with the official `yara` binary.

- `rules/`: fixtures for literals, alternation, anchors, boundaries, classes,
  and quantifiers
- `data/`: matching sample inputs

These fixtures are not part of an automated cross-implementation parity
command; use them for focused manual checks.
