"""Regression coverage for the two confirmed review findings."""

import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from auditor import cli, osv, report
from auditor.errors import NetworkError
from auditor.models import Dependency
from test_unit_osv import _FakeResponse


def affected(name, ecosystem, fixed):
    return {
        "package": {"name": name, "ecosystem": ecosystem},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": fixed}]}],
    }


class ReviewRegressions(unittest.TestCase):
    def test_online_summary_is_hydrated_before_cli_threshold(self):
        summary = {"id": "GHSA-test", "modified": "2026-01-01T00:00:00Z"}
        full = {
            "id": "GHSA-test",
            "database_specific": {"severity": "HIGH"},
            "affected": [affected("requests", "PyPI", "2.30.0")],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "requirements.txt")
            with open(path, "w") as handle:
                handle.write("requests==2.19.0\n")
            output = io.StringIO()
            with mock.patch.dict(os.environ, {osv.FIXTURE_ENV: ""}), mock.patch.object(
                osv.urllib.request, "urlopen",
                side_effect=[_FakeResponse({"results": [{"vulns": [summary]}]}), _FakeResponse(full)],
            ) as urlopen, mock.patch.object(sys, "stdout", output):
                exit_code = cli.main([path, "--json", "--fail-on", "high"])
            self.assertEqual(exit_code, 1)
            vulnerability = json.loads(output.getvalue())["packages"][0]["vulnerabilities"][0]
            self.assertEqual(vulnerability["severity"], "high")
            self.assertEqual(vulnerability["fixed_version"], "2.30.0")
            request = urlopen.call_args_list[1].args[0]
            self.assertEqual(request.full_url, "https://api.osv.dev/v1/vulns/GHSA-test")
            self.assertEqual(request.get_method(), "GET")

    def test_fix_belongs_to_audited_package_and_ecosystem(self):
        vulnerability = {"id": "X", "affected": [
            affected("other-package", "PyPI", "2.20.0"),
            affected("requests", "npm", "2.21.0"),
            affected("requests", "PyPI", "2.30.0"),
        ]}
        dep = Dependency(ecosystem="PyPI", name="requests", version="2.19.0", file="requirements.txt", line=1)
        package = report.build_package(dep, [vulnerability])
        self.assertEqual(package["vulnerabilities"][0]["fixed_version"], "2.30.0")

    def test_detail_failure_is_a_network_error(self):
        summary = {"id": "X", "modified": "2026-01-01T00:00:00Z"}
        with mock.patch.object(osv.urllib.request, "urlopen", side_effect=[
            _FakeResponse({"results": [{"vulns": [summary]}]}),
            osv.urllib.error.URLError("detail unavailable"),
        ]):
            with self.assertRaises(NetworkError):
                osv.OnlineSource().query([("PyPI", "requests", "2.19.0")])

    def test_fix_normalizes_package_names(self):
        dep = Dependency(ecosystem="PyPI", name="foo-bar", version="1.0.0", file="requirements.txt", line=1)
        package = report.build_package(dep, [{"id": "X", "affected": [affected("Foo_Bar", "PyPI", "2.0.0")]}])
        self.assertEqual(package["vulnerabilities"][0]["fixed_version"], "2.0.0")

    def test_no_matching_package_has_no_fix(self):
        dep = Dependency(ecosystem="PyPI", name="requests", version="2.19.0", file="requirements.txt", line=1)
        for entry in [affected("other", "PyPI", "3.0.0"), affected("requests", "npm", "3.0.0"), {"ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "3.0.0"}]}]}]:
            with self.subTest(entry=entry):
                package = report.build_package(dep, [{"id": "X", "affected": [entry]}])
                self.assertIsNone(package["vulnerabilities"][0]["fixed_version"])

    def test_shared_id_is_fetched_once_per_batch(self):
        triples = [("PyPI", "a", "1.0.0"), ("PyPI", "b", "1.0.0")]
        summary = {"id": "X"}
        full = {"id": "X", "database_specific": {"severity": "HIGH"}}
        with mock.patch.object(osv.urllib.request, "urlopen", side_effect=[
            _FakeResponse({"results": [{"vulns": [summary]}, {"vulns": [summary]}]}),
            _FakeResponse(full),
        ]) as urlopen:
            result = osv.OnlineSource().query(triples)
        self.assertEqual(result, {triple: [full] for triple in triples})
        self.assertEqual(urlopen.call_count, 2)

    def test_invalid_details_raise_network_error(self):
        for payload in [[], {"id": "wrong"}, {}, b"invalid json"]:
            with self.subTest(payload=payload), mock.patch.object(osv.urllib.request, "urlopen", side_effect=[
                _FakeResponse({"results": [{"vulns": [{"id": "X"}]}]}),
                _FakeResponse(payload),
            ]):
                with self.assertRaises(NetworkError):
                    osv.OnlineSource().query([("PyPI", "requests", "2.19.0")])
