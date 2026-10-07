"""In-process unit tests for version ordering (SPEC §5.5)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from auditor import versions  # noqa: E402


def gt(ecosystem, candidate, baseline):
    return versions.is_greater(ecosystem, candidate, baseline)


class Pep440Test(unittest.TestCase):
    def test_simple_ordering(self):
        self.assertTrue(gt("PyPI", "2.20.0", "2.19.0"))
        self.assertFalse(gt("PyPI", "2.19.0", "2.20.0"))
        self.assertFalse(gt("PyPI", "2.19.0", "2.19.0"))

    def test_trailing_zero_equivalence(self):
        self.assertFalse(gt("PyPI", "1.0", "1.0.0"))
        self.assertFalse(gt("PyPI", "1.0.0", "1.0"))

    def test_prerelease_sorts_before_release(self):
        self.assertTrue(gt("PyPI", "1.0.0", "1.0.0b1"))
        self.assertFalse(gt("PyPI", "1.0.0b1", "1.0.0"))

    def test_epoch(self):
        self.assertTrue(gt("PyPI", "1!1.0.0", "2.0.0"))

    def test_post_release(self):
        self.assertTrue(gt("PyPI", "1.0.0.post1", "1.0.0"))

    def test_invalid_versions(self):
        self.assertIsNone(versions.pep440_key("not a version"))
        self.assertIsNone(versions.pep440_key(None))
        self.assertFalse(gt("PyPI", "bogus", "1.0.0"))


class SemverTest(unittest.TestCase):
    def test_simple_ordering(self):
        self.assertTrue(gt("npm", "4.17.12", "4.17.11"))
        self.assertFalse(gt("npm", "4.17.11", "4.17.11"))

    def test_prerelease_sorts_before_release(self):
        self.assertTrue(gt("npm", "1.2.3", "1.2.3-beta.1"))
        self.assertFalse(gt("npm", "1.2.3-beta.1", "1.2.3"))

    def test_numeric_prerelease_identifiers(self):
        self.assertTrue(gt("npm", "1.0.0-alpha.2", "1.0.0-alpha.1"))
        # More pre-release fields win when the preceding ones are equal.
        self.assertTrue(gt("npm", "1.0.0-alpha.1", "1.0.0-alpha"))
        self.assertFalse(gt("npm", "1.0.0-alpha", "1.0.0-alpha.1"))

    def test_invalid_versions(self):
        self.assertIsNone(versions.semver_key("1.2"))
        self.assertIsNone(versions.semver_key("latest"))
        self.assertFalse(gt("npm", "latest", "1.0.0"))

    def test_unknown_ecosystem(self):
        self.assertIsNone(versions.parse_version("Maven", "1.0.0"))
        self.assertFalse(gt("Maven", "2.0.0", "1.0.0"))


if __name__ == "__main__":
    unittest.main()
