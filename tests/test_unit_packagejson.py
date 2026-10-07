"""In-process unit tests for the ``package.json`` parser (SPEC §5.2)."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from auditor import packagejson  # noqa: E402
from auditor.errors import UsageError  # noqa: E402
from auditor.models import RANGE_RESOLVED_TO_MIN, UNRESOLVABLE_RANGE  # noqa: E402

PATH = "package.json"


def parse(raw):
    return packagejson.parse_text(json.dumps(raw), PATH)


class PackageJsonParserTest(unittest.TestCase):
    def test_exact_version(self):
        dependencies, warnings = parse({"dependencies": {"lodash": "4.17.11"}})
        self.assertEqual(dependencies[0].version, "4.17.11")
        self.assertFalse(dependencies[0].dev)
        self.assertEqual(warnings, [])

    def test_caret_resolved_to_minimum(self):
        dependencies, warnings = parse({"dependencies": {"lodash": "^4.17.11"}})
        self.assertEqual(dependencies[0].version, "4.17.11")
        self.assertEqual([w.code for w in warnings], [RANGE_RESOLVED_TO_MIN])

    def test_tilde_resolved_to_minimum(self):
        dependencies, _ = parse({"dependencies": {"lodash": "~4.17.11"}})
        self.assertEqual(dependencies[0].version, "4.17.11")

    def test_prerelease_minimum(self):
        dependencies, warnings = parse({"dependencies": {"x": "^1.2.3-beta.1"}})
        self.assertEqual(dependencies[0].version, "1.2.3-beta.1")
        self.assertEqual([w.code for w in warnings], [RANGE_RESOLVED_TO_MIN])

    def test_unresolvable_ranges(self):
        raw = {
            "dependencies": {
                "a": "*",
                "b": "latest",
                "c": ">=1.2.3",
                "d": "1.2",
                "e": "1",
                "f": "",
                "g": "git+https://example.com/x.git",
                "h": "file:../x",
                "i": "npm:other@1.0.0",
                "j": "^1 || ^2",
            }
        }
        dependencies, warnings = parse(raw)
        self.assertEqual(len(dependencies), 10)
        for dependency in dependencies:
            self.assertIsNone(dependency.version)
        self.assertEqual([w.code for w in warnings], [UNRESOLVABLE_RANGE] * 10)

    def test_non_string_version_is_unresolvable(self):
        dependencies, warnings = parse({"dependencies": {"a": 123}})
        self.assertIsNone(dependencies[0].version)
        self.assertEqual([w.code for w in warnings], [UNRESOLVABLE_RANGE])

    def test_dev_dependencies_are_flagged(self):
        dependencies, _ = parse({"devDependencies": {"lodash": "4.17.11"}})
        self.assertTrue(dependencies[0].dev)

    def test_dependencies_come_before_dev_and_alphabetically(self):
        raw = {
            "dependencies": {"zeta": "1.0.0", "alpha": "1.0.0"},
            "devDependencies": {"beta": "1.0.0", "aaa": "1.0.0"},
        }
        dependencies, _ = parse(raw)
        self.assertEqual([d.name for d in dependencies], ["alpha", "zeta", "aaa", "beta"])

    def test_peer_and_optional_dependencies_are_ignored(self):
        raw = {
            "peerDependencies": {"react": "^18.0.0"},
            "optionalDependencies": {"fsevents": "^2.0.0"},
        }
        dependencies, warnings = parse(raw)
        self.assertEqual(dependencies, [])
        self.assertEqual(warnings, [])

    def test_empty_object(self):
        dependencies, warnings = parse({})
        self.assertEqual(dependencies, [])
        self.assertEqual(warnings, [])

    def test_npm_name_is_lowercased(self):
        dependencies, _ = parse({"dependencies": {"@Scope/Pkg": "1.0.0"}})
        self.assertEqual(dependencies[0].name, "@scope/pkg")

    def test_source_line_is_none(self):
        dependencies, _ = parse({"dependencies": {"a": "1.0.0"}})
        self.assertIsNone(dependencies[0].line)

    def test_invalid_json_raises(self):
        with self.assertRaises(UsageError):
            packagejson.parse_text("{ not json }", PATH)

    def test_non_object_raises(self):
        with self.assertRaises(UsageError):
            packagejson.parse_text("[]", PATH)

    def test_dependencies_not_an_object_raises(self):
        with self.assertRaises(UsageError):
            packagejson.parse_text('{"dependencies": []}', PATH)

    def test_dev_dependencies_not_an_object_raises(self):
        with self.assertRaises(UsageError):
            packagejson.parse_text('{"devDependencies": "x"}', PATH)


if __name__ == "__main__":
    unittest.main()
