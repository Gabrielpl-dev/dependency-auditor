"""In-process unit tests for report assembly and rendering (SPEC §6)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from auditor import naming, report  # noqa: E402
from auditor.models import Dependency, InputFile, Warning  # noqa: E402


def dependency(name="requests", version="2.19.0", ecosystem="PyPI", **kwargs):
    return Dependency(
        ecosystem=ecosystem, name=name, version=version, file="requirements.txt", line=1, **kwargs
    )


class NamingTest(unittest.TestCase):
    def test_pypi(self):
        self.assertEqual(naming.normalize_pypi("Foo_Bar.Baz"), "foo-bar-baz")
        self.assertEqual(naming.normalize_pypi("UPPER"), "upper")

    def test_npm(self):
        self.assertEqual(naming.normalize_npm("@Scope/Pkg"), "@scope/pkg")

    def test_normalize_dispatch(self):
        self.assertEqual(naming.normalize("PyPI", "A_B"), "a-b")
        self.assertEqual(naming.normalize("npm", "A_B"), "a_b")
        with self.assertRaises(ValueError):
            naming.normalize("Maven", "a")


class FixedVersionTest(unittest.TestCase):
    def test_picks_smallest_greater_fixed(self):
        vulnerability = {
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "2.25.0"},
                                {"fixed": "2.10.0"},
                                {"fixed": "2.20.0"},
                            ],
                        }
                    ]
                }
            ]
        }
        self.assertEqual(report._fixed_version(vulnerability, "PyPI", "2.19.0"), "2.20.0")

    def test_no_fixed_event(self):
        vulnerability = {"affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}
        self.assertIsNone(report._fixed_version(vulnerability, "PyPI", "2.19.0"))

    def test_non_ecosystem_ranges_are_ignored(self):
        vulnerability = {
            "affected": [
                {
                    "ranges": [
                        {"type": "GIT", "events": [{"fixed": "abcdef"}]},
                        {"type": "SEMVER", "events": [{"fixed": "2.20.0"}]},
                    ]
                }
            ]
        }
        self.assertIsNone(report._fixed_version(vulnerability, "PyPI", "2.19.0"))

    def test_malformed_entries_are_skipped(self):
        vulnerability = {
            "affected": [None, "nope", {"ranges": [None, "bad", {"type": "ECOSYSTEM", "events": [None, "x", {"fixed": 5}]}]}]
        }
        self.assertIsNone(report._fixed_version(vulnerability, "PyPI", "2.19.0"))

    def test_no_affected(self):
        self.assertIsNone(report._fixed_version({}, "PyPI", "2.19.0"))


class BuildPackageTest(unittest.TestCase):
    def test_non_audited_package(self):
        package = report.build_package(dependency(version=None), [{"id": "X"}])
        self.assertFalse(package["audited"])
        self.assertEqual(package["vulnerabilities"], [])
        self.assertIsNone(package["max_severity"])

    def test_max_severity_is_the_highest(self):
        raw = [
            {"id": "A", "database_specific": {"severity": "LOW"}},
            {"id": "B", "database_specific": {"severity": "CRITICAL"}},
            {"id": "C", "database_specific": {"severity": "MEDIUM"}},
        ]
        package = report.build_package(dependency(), raw)
        self.assertEqual(package["max_severity"], "critical")
        self.assertEqual([v["id"] for v in package["vulnerabilities"]], ["A", "B", "C"])

    def test_non_dict_vulnerabilities_are_skipped(self):
        package = report.build_package(dependency(), [None, "x"])
        self.assertEqual(package["vulnerabilities"], [])

    def test_missing_id_and_summary_are_normalised(self):
        package = report.build_package(dependency(), [{"aliases": ["Z", "A", 1], "summary": 5}])
        vulnerability = package["vulnerabilities"][0]
        self.assertEqual(vulnerability["id"], "")
        self.assertEqual(vulnerability["aliases"], ["A", "Z"])
        self.assertIsNone(vulnerability["summary"])

    def test_package_shape(self):
        package = report.build_package(dependency(extras=["security"], dev=True), [])
        self.assertEqual(
            sorted(package),
            [
                "audited",
                "dev",
                "ecosystem",
                "extras",
                "max_severity",
                "name",
                "source",
                "version",
                "vulnerabilities",
            ],
        )
        self.assertEqual(package["extras"], ["security"])
        self.assertTrue(package["dev"])


class SummaryAndRenderTest(unittest.TestCase):
    def build(self, fail_on="high", exit_code=1):
        packages = [
            report.build_package(
                dependency(), [{"id": "A", "database_specific": {"severity": "HIGH"}}]
            ),
            report.build_package(dependency(name="flask", version="1.0.0"), []),
        ]
        warnings = [
            Warning("NOT_PINNED", "requirements.txt", "msg", line=5, package="x"),
            Warning("UNRESOLVABLE_RANGE", "package.json", "msg", line=None, package="y"),
        ]
        inputs = [
            InputFile("package.json", "npm", 1),
            InputFile("requirements.txt", "PyPI", 2),
        ]
        return report.build_report(fail_on, inputs, packages, warnings, exit_code)

    def test_summary_counts(self):
        document = self.build()
        summary = document["summary"]
        self.assertEqual(summary["packages_total"], 3)
        self.assertEqual(summary["packages_audited"], 2)
        self.assertEqual(summary["packages_vulnerable"], 1)
        self.assertEqual(summary["vulnerabilities_total"], 1)
        self.assertEqual(summary["counts"], {"critical": 0, "high": 1, "medium": 0, "low": 0, "unknown": 0})

    def test_inputs_are_sorted_by_path(self):
        document = self.build()
        self.assertEqual([item["path"] for item in document["inputs"]], ["package.json", "requirements.txt"])

    def test_warnings_are_sorted_and_lineless_last(self):
        document = self.build()
        self.assertEqual([w["file"] for w in document["warnings"]], ["package.json", "requirements.txt"])

    def test_exit_code_computation(self):
        high = report.build_package(
            dependency(), [{"id": "A", "database_specific": {"severity": "HIGH"}}]
        )
        unknown = report.build_package(
            dependency(), [{"id": "B", "database_specific": {"severity": "WEIRD"}}]
        )
        self.assertEqual(report.compute_exit_code("high", [high]), 1)
        self.assertEqual(report.compute_exit_code("critical", [high]), 0)
        self.assertEqual(report.compute_exit_code("low", [unknown]), 0)

    def test_render_json_is_a_single_document(self):
        text = report.render_json(self.build())
        self.assertTrue(text.endswith("\n"))
        import json

        self.assertEqual(json.loads(text)["schema_version"], "1.0")

    def test_render_human_and_quiet(self):
        document = self.build()
        human = report.render_human(document, color=False)
        self.assertIn("Result: FAIL (exit 1)", human)
        self.assertIn("warnings:", human)

        import io

        buffer = io.StringIO()
        report.write_report(document, as_json=False, quiet=True, stdout=buffer)
        self.assertEqual(buffer.getvalue(), "Result: FAIL (exit 1)\n")

        buffer = io.StringIO()
        report.write_report(document, as_json=True, quiet=True, stdout=buffer)
        self.assertTrue(buffer.getvalue().lstrip().startswith("{"))

    def test_color_is_only_added_when_requested(self):
        document = self.build()
        self.assertNotIn("\033[", report.render_human(document, color=False))
        self.assertIn("\033[", report.render_human(document, color=True))

    def test_non_audited_packages_render_as_skip(self):
        packages = [report.build_package(dependency(version=None), [])]
        inputs = [InputFile("requirements.txt", "PyPI", 1)]
        document = report.build_report("high", inputs, packages, [], 0)
        self.assertIn("SKIP", report.render_human(document, color=False))


if __name__ == "__main__":
    unittest.main()
