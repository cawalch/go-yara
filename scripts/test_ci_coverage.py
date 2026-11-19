"""Regression checks for package accounting and coverage aggregation."""

import json
from pathlib import Path
import tempfile
import unittest

from ci_coverage import merge, partition, read_profile


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.unit, self.integration = self.root / "unit", self.root / "integration"
        self.output = self.root / "merged.out"
        packages = ["m/compiler", "m/no_statements", "m/tests/integration", "m/tests/integration/child"]
        lanes = partition(packages, "m/tests/integration")
        for lane, directory in (("unit", self.unit), ("integration", self.integration)):
            directory.mkdir()
            (directory / "packages.json").write_text(json.dumps({
                "all": packages, "integration_prefix": "m/tests/integration",
                "lane": lane, "packages": lanes[lane],
            }))
            (directory / "coverage.out").write_text("mode: atomic\n")

    def test_integration_only_and_shared_blocks_are_counted(self):
        (self.unit / "coverage.out").write_text("mode: atomic\nm/a.go:1.1,2.2 2 3\n")
        (self.integration / "coverage.out").write_text(
            "mode: atomic\nm/a.go:1.1,2.2 2 4\nm/tests/integration/b.go:1.1,2.2 5 0\n")
        merge(self.unit, self.integration, self.output)
        self.assertEqual(read_profile(self.output), {
            "m/a.go:1.1,2.2": (2, 7), "m/tests/integration/b.go:1.1,2.2": (5, 0),
        })

    def test_empty_integration_profile_and_no_statement_package(self):
        (self.unit / "coverage.out").write_text("mode: atomic\nm/a.go:1.1,2.2 2 0\n")
        merge(self.unit, self.integration, self.output)
        self.assertEqual(read_profile(self.output), {"m/a.go:1.1,2.2": (2, 0)})

    def test_missing_or_overlapping_packages_fail(self):
        path = self.integration / "packages.json"
        original = json.loads(path.read_text())
        for packages in ([], original["packages"] + ["m/compiler"]):
            with self.subTest(packages=packages):
                path.write_text(json.dumps({**original, "packages": packages}))
                with self.assertRaises(ValueError):
                    merge(self.unit, self.integration, self.output)

    def test_inconsistent_block_shapes_fail(self):
        (self.unit / "coverage.out").write_text("mode: atomic\nm/a.go:1.1,2.2 2 1\n")
        (self.integration / "coverage.out").write_text("mode: atomic\nm/a.go:1.1,2.2 3 1\n")
        with self.assertRaises(ValueError):
            merge(self.unit, self.integration, self.output)

    def test_missing_invalid_or_duplicate_profile_fails(self):
        path = self.unit / "coverage.out"
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            merge(self.unit, self.integration, self.output)
        for content in ("", "mode: set\n", "mode: atomic\na:1.1,2.2 1 -1\n",
                        "mode: atomic\na:1.1,2.2 1 0\na:1.1,2.2 1 1\n"):
            with self.subTest(content=content):
                path.write_text(content)
                with self.assertRaises(ValueError):
                    merge(self.unit, self.integration, self.output)


if __name__ == "__main__":
    unittest.main()
