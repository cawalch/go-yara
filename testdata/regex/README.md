# Regex parity suite (staged)

This directory contains a small, curated set of regex-only YARA rules and sample data intended for parity checks against the official `yara` binary. These are staged tests for the in-repo zero-dependency regex engine plan.

Structure:
- rules/: YARA rule files, each focusing on a specific feature area
- data/: Sample data files used when running targeted parity comparisons

Notes:
- These are not wired into the global parity harness yet (keep `-skip-regex` in global runs).
- Once the executor exists (Phase 4), we can add an opt-in flag to run this suite.

