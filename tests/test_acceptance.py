"""Black-box acceptance tests for the v0.1 contract.

Every test drives ``./app`` as a subprocess in fixture mode (SPEC §4.2), so the
suite is fully offline. Test names carry the specification identifiers they
verify (AC-n and §7 edge cases).
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from helpers import APP, ROOT, fixture, run, run_json, warnings_by_code  # noqa: E402

DEAD_PROXY = {
    "http_proxy": "http://127.0.0.1:9",
    "https_proxy": "http://127.0.0.1:9",
    "HTTP_PROXY": "http://127.0.0.1:9",
    "HTTPS_PROXY": "http://127.0.0.1:9",
    "no_proxy": "",
    "NO_PROXY": "",
}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="auditor-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def make(self, name, content, directory=None):
        path = os.path.join(directory or self.tmp, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
        return path

    def make_bytes(self, name, content):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as handle:
            handle.write(content)
        return path

    def package_by_name(self, document, name):
        for package in document["packages"]:
            if package["name"] == name:
                return package
        self.fail("package %r not found" % name)


class AcceptanceCriteria(Base):
    def test_ac1_no_vulnerabilities(self):
        manifest = self.make("requirements.txt", "flask==1.0.0\n")
        proc, document = run_json([manifest], fixture("empty.json"))
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(document["summary"]["packages_total"], 1)
        self.assertEqual(document["summary"]["vulnerabilities_total"], 0)
        self.assertEqual(document["summary"]["exit_code"], 0)

    def test_ac2_vulnerability_above_threshold(self):
        manifest = self.make("requirements.txt", "requests==2.19.0\n")
        proc, document = run_json(["--fail-on", "high", manifest], fixture("severity-high.json"))
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(document["packages"][0]["max_severity"], "high")
        self.assertEqual(document["summary"]["counts"]["high"], 1)

    def test_ac3_vulnerability_below_threshold(self):
        manifest = self.make("requirements.txt", "requests==2.19.0\n")
        proc, document = run_json(
            ["--fail-on", "critical", manifest], fixture("severity-high.json")
        )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(document["summary"]["exit_code"], 0)
        self.assertEqual(document["packages"][0]["max_severity"], "high")
        self.assertEqual(len(document["packages"][0]["vulnerabilities"]), 1)

    def test_ac4_severity_from_cvss_v3(self):
        manifest = self.make("requirements.txt", "requests==2.19.0\n")
        _, document = run_json([manifest], fixture("basic.json"))
        vulnerability = document["packages"][0]["vulnerabilities"][0]
        self.assertEqual(vulnerability["cvss_score"], 9.8)
        self.assertEqual(vulnerability["severity"], "critical")

    def test_ac5_fallback_to_database_specific(self):
        manifest = self.make("requirements.txt", "requests==2.19.0\n")
        _, document = run_json([manifest], fixture("severity-moderate.json"))
        vulnerability = document["packages"][0]["vulnerabilities"][0]
        self.assertEqual(vulnerability["severity"], "medium")
        self.assertIsNone(vulnerability["cvss_score"])

    def test_ac6_unknown_never_fails(self):
        manifest = self.make("requirements.txt", "requests==2.19.0\n")
        proc, document = run_json(
            ["--fail-on", "low", manifest], fixture("severity-unknown.json")
        )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(document["packages"][0]["vulnerabilities"][0]["severity"], "unknown")
        self.assertEqual(document["summary"]["counts"]["unknown"], 1)

    def test_ac7_minimum_fixed_version(self):
        manifest = self.make("requirements.txt", "requests==2.19.0\n")
        _, document = run_json([manifest], fixture("fixed-multiple.json"))
        vulnerability = document["packages"][0]["vulnerabilities"][0]
        self.assertEqual(vulnerability["fixed_version"], "2.20.0")

    def test_ac8_null_fixed_version(self):
        manifest = self.make("requirements.txt", "requests==2.19.0\n")
        _, document = run_json([manifest], fixture("fixed-none.json"))
        self.assertIsNone(document["packages"][0]["vulnerabilities"][0]["fixed_version"])

    def test_ac9_absent_fixture_key_is_not_an_error(self):
        manifest = self.make("requirements.txt", "flask==1.0.0\n")
        proc, document = run_json([manifest], fixture("empty.json"))
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(document["packages"][0]["vulnerabilities"], [])
        self.assertEqual(document["warnings"], [])

    def test_ac10_no_network_in_fixture_mode(self):
        manifest = self.make("requirements.txt", "requests==2.19.0\n")
        proc, document = run_json([manifest], fixture("basic.json"), extra_env=DEAD_PROXY)
        self.assertIn(proc.returncode, (0, 1))
        self.assertIsInstance(document, dict)

    def test_ac11_invalid_fixture(self):
        manifest = self.make("requirements.txt", "requests==2.19.0\n")
        proc = run([manifest], os.path.join(self.tmp, "missing.json"))
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, "")
        self.assertNotEqual(proc.stderr, "")

    def test_ac11_invalid_fixture_json_mode(self):
        manifest = self.make("requirements.txt", "requests==2.19.0\n")
        proc = run(["--json", manifest], fixture("invalid.json"))
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, "")
        self.assertNotEqual(proc.stderr, "")

    def test_ac12_json_stdout_is_pure(self):
        manifest = self.make("requirements.txt", "requests==2.19.0\n")
        proc = run(["--json", manifest], fixture("basic.json"))
        _, end = json.JSONDecoder().raw_decode(proc.stdout)
        self.assertEqual(proc.stdout[end:].strip(), "")
        json.loads(proc.stdout)

    def test_ac13_extras_are_parsed(self):
        manifest = self.make("requirements.txt", "requests[security,socks]==2.19.0\n")
        _, document = run_json([manifest], fixture("empty.json"))
        package = document["packages"][0]
        self.assertEqual(package["extras"], ["security", "socks"])
        self.assertTrue(package["audited"])
        self.assertEqual(package["name"], "requests")

    def test_ac14_line_without_version(self):
        manifest = self.make("requirements.txt", "requests\n")
        _, document = run_json([manifest], fixture("empty.json"))
        self.assertIn("NOT_PINNED", warnings_by_code(document))
        package = document["packages"][0]
        self.assertIsNone(package["version"])
        self.assertFalse(package["audited"])
        self.assertEqual(package["vulnerabilities"], [])

    def test_ac15_npm_caret_resolved_to_minimum(self):
        manifest = self.make("package.json", '{"dependencies": {"lodash": "^4.17.11"}}')
        _, document = run_json([manifest], fixture("range-resolved.json"))
        package = document["packages"][0]
        self.assertEqual(package["version"], "4.17.11")
        self.assertTrue(package["audited"])
        self.assertIn("RANGE_RESOLVED_TO_MIN", warnings_by_code(document))

    def test_ac16_npm_dev_dependencies(self):
        manifest = self.make("package.json", '{"devDependencies": {"lodash": "4.17.11"}}')
        _, document = run_json([manifest], fixture("range-resolved.json"))
        package = document["packages"][0]
        self.assertTrue(package["dev"])
        self.assertTrue(package["audited"])

    def test_ac17_directory_with_both_manifests(self):
        self.make("requirements.txt", "flask==1.0.0\n")
        self.make("package.json", '{"dependencies": {"lodash": "4.17.11"}}')
        _, document = run_json([self.tmp], fixture("range-resolved.json"))
        ecosystems = sorted(item["ecosystem"] for item in document["inputs"])
        self.assertEqual(ecosystems, ["PyPI", "npm"])
        self.assertEqual(document["summary"]["packages_total"], 2)

    def test_ac18_directory_without_manifests(self):
        proc = run([self.tmp], fixture("empty.json"))
        self.assertEqual(proc.returncode, 2)

    def test_ac19_help_and_version(self):
        help_proc = run(["--help"], fixture("empty.json"))
        self.assertEqual(help_proc.returncode, 0)
        self.assertNotEqual(help_proc.stdout, "")
        version_proc = run(["--version"], fixture("empty.json"))
        self.assertEqual(version_proc.returncode, 0)
        self.assertIn("0.1.0", version_proc.stdout)

    def test_ac20_determinism_and_ordering(self):
        first = self.make("requirements.txt", "flask==1.0.0\nrequests==2.19.0\n")
        run_a = run(["--json", first], fixture("basic.json"))
        run_b = run(["--json", first], fixture("basic.json"))
        self.assertEqual(run_a.stdout, run_b.stdout)

        reversed_path = self.make("reversed/requirements.txt", "requests==2.19.0\nflask==1.0.0\n")
        _, document = run_json([reversed_path], fixture("basic.json"))
        original = json.loads(run_a.stdout)

        def pairs(doc):
            return [(p["name"], p["version"]) for p in doc["packages"]]

        self.assertEqual(pairs(document), pairs(original))

        for doc in (document, original):
            for package in doc["packages"]:
                package["source"]["line"] = None
                package["source"]["file"] = "requirements.txt"
            for item in doc["inputs"]:
                item["path"] = "requirements.txt"
        self.assertEqual(document, original)


class EdgeCases(Base):
    def test_edge_1_directory_with_only_package_json(self):
        self.make("package.json", '{"dependencies": {"lodash": "4.17.11"}}')
        proc, document = run_json([self.tmp], fixture("empty.json"))
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(len(document["inputs"]), 1)

    def test_edge_3_empty_requirements(self):
        manifest = self.make("requirements.txt", "")
        proc, document = run_json([manifest], fixture("empty.json"))
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(document["packages"], [])
        self.assertEqual(document["warnings"], [])
        self.assertEqual(document["inputs"][0]["packages_total"], 0)

    def test_edge_4_package_json_without_dependencies(self):
        manifest = self.make("package.json", '{"name": "x"}')
        proc, document = run_json([manifest], fixture("empty.json"))
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(document["packages"], [])

    def test_edge_5_empty_package_json_object(self):
        manifest = self.make("package.json", "{}")
        proc, document = run_json([manifest], fixture("empty.json"))
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(document["packages"], [])

    def test_edge_6_invalid_package_json(self):
        manifest = self.make("package.json", "{ nope }")
        proc = run(["--json", manifest], fixture("empty.json"))
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, "")

    def test_edge_7_dependencies_as_array(self):
        manifest = self.make("package.json", '{"dependencies": []}')
        proc = run([manifest], fixture("empty.json"))
        self.assertEqual(proc.returncode, 2)

    def test_edge_8_crlf_requirements(self):
        manifest = self.make("requirements.txt", "requests==2.19.0\r\nflask==1.0.0\r\n")
        _, document = run_json([manifest], fixture("empty.json"))
        names = [package["name"] for package in document["packages"]]
        self.assertEqual(names, ["flask", "requests"])
        self.assertEqual(document["packages"][1]["source"]["line"], 1)

    def test_edge_9_bom_requirements(self):
        manifest = self.make_bytes("requirements.txt", b"\xef\xbb\xbfrequests==2.19.0\n")
        _, document = run_json([manifest], fixture("empty.json"))
        self.assertEqual(document["packages"][0]["name"], "requests")

    def test_edge_10_line_continuation(self):
        manifest = self.make("requirements.txt", "requests==2.19.0 \\\n    --hash=sha256:abc\n")
        _, document = run_json([manifest], fixture("empty.json"))
        self.assertEqual(document["packages"][0]["name"], "requests")
        self.assertEqual(document["packages"][0]["version"], "2.19.0")

    def test_edge_12_environment_marker(self):
        manifest = self.make(
            "requirements.txt", 'requests==2.19.0 ; python_version >= "3.7"\n'
        )
        _, document = run_json([manifest], fixture("empty.json"))
        self.assertEqual(document["packages"][0]["version"], "2.19.0")

    def test_edge_13_hash_directive(self):
        manifest = self.make(
            "requirements.txt", "requests==2.19.0 --hash=sha256:deadbeef\n"
        )
        _, document = run_json([manifest], fixture("empty.json"))
        self.assertEqual(document["packages"][0]["version"], "2.19.0")

    def test_edge_14_option_line_ignored(self):
        manifest = self.make("requirements.txt", "-r base.txt\nflask==1.0.0\n")
        _, document = run_json([manifest], fixture("empty.json"))
        self.assertIn("OPTION_LINE_IGNORED", warnings_by_code(document))
        self.assertEqual([p["name"] for p in document["packages"]], ["flask"])

    def test_edge_15_same_package_two_versions(self):
        manifest = self.make("requirements.txt", "a==1.0\na==2.0\n")
        _, document = run_json([manifest], fixture("empty.json"))
        self.assertEqual(
            [(p["name"], p["version"]) for p in document["packages"]],
            [("a", "1.0"), ("a", "2.0")],
        )
        self.assertNotIn("DUPLICATE_REQUIREMENT", warnings_by_code(document))

    def test_edge_15b_duplicate_requirement(self):
        manifest = self.make("requirements.txt", "a==1.0\na==1.0\n")
        _, document = run_json([manifest], fixture("empty.json"))
        self.assertEqual(len(document["packages"]), 1)
        self.assertIn("DUPLICATE_REQUIREMENT", warnings_by_code(document))

    def test_edge_16_same_package_two_ecosystems(self):
        self.make("requirements.txt", "lodash==1.0.0\n")
        self.make("package.json", '{"dependencies": {"lodash": "4.17.11"}}')
        _, document = run_json([self.tmp], fixture("empty.json"))
        ecosystems = sorted(package["ecosystem"] for package in document["packages"])
        self.assertEqual(ecosystems, ["PyPI", "npm"])

    def test_edge_17_fixture_empty_array(self):
        manifest = self.make("requirements.txt", "requests==2.19.0\n")
        _, document = run_json([manifest], fixture("empty-array.json"))
        self.assertEqual(document["packages"][0]["vulnerabilities"], [])
        self.assertIsNone(document["packages"][0]["max_severity"])

    def test_edge_19_fixture_invalid_json(self):
        manifest = self.make("requirements.txt", "requests==2.19.0\n")
        proc = run([manifest], fixture("invalid.json"))
        self.assertEqual(proc.returncode, 2)

    def test_edge_19b_fixture_bad_value_type(self):
        manifest = self.make("requirements.txt", "requests==2.19.0\n")
        proc = run([manifest], fixture("bad-value.json"))
        self.assertEqual(proc.returncode, 2)

    def test_edge_21_empty_fixture_env_is_online(self):
        manifest = self.make("requirements.txt", "requests==2.19.0\n")
        proc = run([manifest], "", extra_env=DEAD_PROXY)
        # Empty means "not set": online mode, which fails to reach the network.
        self.assertEqual(proc.returncode, 3)

    def test_edge_22_no_severity_information(self):
        manifest = self.make("requirements.txt", "requests==2.19.0\n")
        _, document = run_json([manifest], fixture("severity-unknown.json"))
        vulnerability = document["packages"][0]["vulnerabilities"][0]
        self.assertEqual(vulnerability["severity"], "unknown")
        self.assertIsNone(vulnerability["cvss_score"])

    def test_edge_23_cvss_v2_only(self):
        manifest = self.make("requirements.txt", "requests==2.19.0\n")
        _, document = run_json([manifest], fixture("cvss-v2.json"))
        vulnerability = document["packages"][0]["vulnerabilities"][0]
        self.assertEqual(vulnerability["severity"], "unknown")
        self.assertIsNone(vulnerability["cvss_score"])

    def test_edge_27_tilde_resolved_to_minimum(self):
        manifest = self.make("package.json", '{"dependencies": {"lodash": "~4.17.11"}}')
        _, document = run_json([manifest], fixture("range-resolved.json"))
        self.assertEqual(document["packages"][0]["version"], "4.17.11")
        self.assertIn("RANGE_RESOLVED_TO_MIN", warnings_by_code(document))

    def test_edge_28_npm_exact_no_warning(self):
        manifest = self.make("package.json", '{"dependencies": {"lodash": "4.17.11"}}')
        _, document = run_json([manifest], fixture("range-resolved.json"))
        self.assertEqual(document["packages"][0]["version"], "4.17.11")
        self.assertEqual([w["code"] for w in document["warnings"]], [])

    def test_edge_29_unresolvable_ranges(self):
        manifest = self.make(
            "package.json",
            json.dumps(
                {
                    "dependencies": {
                        "a": "*",
                        "b": "latest",
                        "c": "git+https://example.com/x.git",
                        "d": "file:../x",
                        "e": "workspace:*",
                        "f": ">=1.2.3",
                        "g": "1.2",
                        "h": "",
                    }
                }
            ),
        )
        _, document = run_json([manifest], fixture("empty.json"))
        for package in document["packages"]:
            self.assertIsNone(package["version"])
            self.assertFalse(package["audited"])
        self.assertEqual(
            [w["code"] for w in document["warnings"]],
            ["UNRESOLVABLE_RANGE"] * 8,
        )

    def test_edge_30_npm_prerelease_caret(self):
        manifest = self.make("package.json", '{"dependencies": {"x": "^1.2.3-beta.1"}}')
        _, document = run_json([manifest], fixture("empty.json"))
        self.assertEqual(document["packages"][0]["version"], "1.2.3-beta.1")

    def test_edge_31_fail_on_critical_with_high(self):
        manifest = self.make("requirements.txt", "requests==2.19.0\n")
        proc = run(["--fail-on", "critical", manifest], fixture("severity-high.json"))
        self.assertEqual(proc.returncode, 0)

    def test_edge_32_fail_on_low_with_low(self):
        manifest = self.make("requirements.txt", "requests==2.19.0\n")
        proc = run(["--fail-on", "low", manifest], fixture("severity-low.json"))
        self.assertEqual(proc.returncode, 1)

    def test_edge_33_fail_on_medium_with_unknown(self):
        manifest = self.make("requirements.txt", "requests==2.19.0\n")
        proc = run(["--fail-on", "medium", manifest], fixture("severity-unknown.json"))
        self.assertEqual(proc.returncode, 0)

    def test_edge_34_invalid_fail_on(self):
        manifest = self.make("requirements.txt", "requests==2.19.0\n")
        proc = run(["--fail-on", "bogus", manifest], fixture("empty.json"))
        self.assertEqual(proc.returncode, 2)

    def test_edge_35_json_wins_over_quiet(self):
        manifest = self.make("requirements.txt", "requests==2.19.0\n")
        proc = run(["--json", "--quiet", manifest], fixture("basic.json"))
        json.loads(proc.stdout)
        self.assertEqual(proc.returncode, 1)

    def test_edge_36_pypi_name_normalisation(self):
        manifest = self.make("requirements.txt", "Foo_Bar==1.0.0\n")
        _, document = run_json([manifest], fixture("empty.json"))
        self.assertEqual(document["packages"][0]["name"], "foo-bar")

    def test_edge_37_npm_scoped_name_normalisation(self):
        manifest = self.make("package.json", '{"dependencies": {"@scope/Pkg": "1.0.0"}}')
        _, document = run_json([manifest], fixture("empty.json"))
        self.assertEqual(document["packages"][0]["name"], "@scope/pkg")

    def test_edge_38_nonexistent_path(self):
        proc = run([os.path.join(self.tmp, "nope.txt")], fixture("empty.json"))
        self.assertEqual(proc.returncode, 2)

    def test_edge_39_unknown_basename(self):
        manifest = self.make("deps.txt", "requests==2.19.0\n")
        proc = run([manifest], fixture("empty.json"))
        self.assertEqual(proc.returncode, 2)

    def test_edge_40_json_parseable_on_exit_1(self):
        manifest = self.make("requirements.txt", "requests==2.19.0\n")
        proc = run(["--json", manifest], fixture("basic.json"))
        self.assertEqual(proc.returncode, 1)
        json.loads(proc.stdout)

    def test_no_positional_or_two_positionals(self):
        manifest = self.make("requirements.txt", "requests==2.19.0\n")
        self.assertEqual(run([], fixture("empty.json")).returncode, 2)
        other = self.make("package.json", "{}")
        self.assertEqual(run([manifest, other], fixture("empty.json")).returncode, 2)

    def test_unknown_flag(self):
        manifest = self.make("requirements.txt", "requests==2.19.0\n")
        self.assertEqual(run(["--nope", manifest], fixture("empty.json")).returncode, 2)

    def test_quiet_only_prints_result(self):
        manifest = self.make("requirements.txt", "requests==2.19.0\n")
        proc = run(["--quiet", manifest], fixture("basic.json"))
        self.assertEqual(proc.stdout.strip(), "Result: FAIL (exit 1)")

    def test_executable_bit_set(self):
        self.assertTrue(os.access(APP, os.X_OK))
        env = dict(os.environ)
        env["AUDITOR_OSV_FIXTURE"] = fixture("empty.json")
        proc = subprocess.run(
            [APP, "--version"], cwd=ROOT, env=env, capture_output=True, text=True
        )
        self.assertEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
