"""In-process unit tests for the OSV sources (SPEC §4).

The online source is exercised with a stubbed ``urlopen``; nothing leaves the
process, so the suite stays deterministic and offline.
"""

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from auditor import osv  # noqa: E402
from auditor.errors import NetworkError, UsageError  # noqa: E402

TRIPLE = ("PyPI", "requests", "2.19.0")


class _FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.status = status

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FixtureSourceTest(unittest.TestCase):
    def write(self, content):
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        self.addCleanup(os.unlink, handle.name)
        handle.write(content)
        handle.close()
        return handle.name

    def test_returns_vulnerabilities_for_present_keys(self):
        path = self.write(json.dumps({"PyPI:requests@2.19.0": [{"id": "X"}]}))
        source = osv.FixtureSource(path)
        self.assertEqual(source.query([TRIPLE]), {TRIPLE: [{"id": "X"}]})

    def test_absent_key_is_an_empty_list(self):
        path = self.write("{}")
        source = osv.FixtureSource(path)
        self.assertEqual(source.query([TRIPLE]), {TRIPLE: []})

    def test_extra_keys_are_ignored(self):
        path = self.write(json.dumps({"unrelated": [{"id": "X"}]}))
        source = osv.FixtureSource(path)
        self.assertEqual(source.query([TRIPLE]), {TRIPLE: []})

    def test_non_array_value_raises(self):
        path = self.write(json.dumps({"PyPI:requests@2.19.0": {"id": "X"}}))
        source = osv.FixtureSource(path)
        with self.assertRaises(UsageError):
            source.query([TRIPLE])

    def test_invalid_json_raises(self):
        path = self.write("{ nope }")
        with self.assertRaises(UsageError):
            osv.FixtureSource(path)

    def test_non_object_raises(self):
        path = self.write("[]")
        with self.assertRaises(UsageError):
            osv.FixtureSource(path)

    def test_missing_file_raises(self):
        with self.assertRaises(UsageError):
            osv.FixtureSource("/definitely/not/here.json")


class FixtureEnvTest(unittest.TestCase):
    def test_unset_or_empty_means_online(self):
        self.assertIsNone(osv.fixture_path_from_env({}))
        self.assertIsNone(osv.fixture_path_from_env({osv.FIXTURE_ENV: ""}))
        self.assertEqual(
            osv.fixture_path_from_env({osv.FIXTURE_ENV: "/tmp/x.json"}), "/tmp/x.json"
        )

    def test_build_source_selects_fixture(self):
        path = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        self.addCleanup(os.unlink, path.name)
        path.write("{}")
        path.close()
        self.assertIsInstance(
            osv.build_source({osv.FIXTURE_ENV: path.name}), osv.FixtureSource
        )
        self.assertIsInstance(osv.build_source({}), osv.OnlineSource)


class OnlineSourceTest(unittest.TestCase):
    def query(self, payload, triples=None):
        def fake_urlopen(request, timeout=None):
            if request.get_method() == "GET":
                return _FakeResponse({"id": request.full_url.rsplit("/", 1)[-1]})
            return _FakeResponse(payload)

        with mock.patch.object(osv.urllib.request, "urlopen", side_effect=fake_urlopen):
            return osv.OnlineSource().query(triples or [TRIPLE])

    def test_successful_batch(self):
        result = self.query({"results": [{"vulns": [{"id": "X"}]}]})
        self.assertEqual(result, {TRIPLE: [{"id": "X"}]})

    def test_missing_vulns_means_empty(self):
        self.assertEqual(self.query({"results": [{}]}), {TRIPLE: []})
        self.assertEqual(self.query({"results": [{"vulns": None}]}), {TRIPLE: []})

    def test_queries_are_deduplicated_and_sorted(self):
        triples = [("npm", "b", "1.0.0"), ("PyPI", "a", "1.0.0"), ("npm", "b", "1.0.0")]
        captured = {}

        def fake_urlopen(request, timeout=None):
            captured["body"] = json.loads(request.data.decode())
            return _FakeResponse({"results": [{}, {}]})

        with mock.patch.object(osv.urllib.request, "urlopen", side_effect=fake_urlopen):
            result = osv.OnlineSource().query(triples)
        self.assertEqual(len(captured["body"]["queries"]), 2)
        self.assertEqual(
            [q["package"]["ecosystem"] for q in captured["body"]["queries"]], ["PyPI", "npm"]
        )
        self.assertEqual(len(result), 2)

    def test_no_queries_does_not_touch_the_network(self):
        with mock.patch.object(osv.urllib.request, "urlopen") as urlopen:
            self.assertEqual(osv.OnlineSource().query([]), {})
        urlopen.assert_not_called()

    def test_result_count_mismatch_raises(self):
        with self.assertRaises(NetworkError):
            self.query({"results": []})

    def test_missing_results_field_raises(self):
        with self.assertRaises(NetworkError):
            self.query({})

    def test_invalid_json_raises(self):
        with self.assertRaises(NetworkError):
            self.query(b"not json")

    def test_http_error_raises(self):
        error = osv.urllib.error.HTTPError("u", 500, "boom", {}, None)
        with mock.patch.object(osv.urllib.request, "urlopen", side_effect=error):
            with self.assertRaises(NetworkError):
                osv.OnlineSource().query([TRIPLE])

    def test_connection_error_raises(self):
        error = osv.urllib.error.URLError("no dns")
        with mock.patch.object(osv.urllib.request, "urlopen", side_effect=error):
            with self.assertRaises(NetworkError):
                osv.OnlineSource().query([TRIPLE])

    def test_non_2xx_status_raises(self):
        with mock.patch.object(
            osv.urllib.request, "urlopen", return_value=_FakeResponse({"results": [{}]}, 302)
        ):
            with self.assertRaises(NetworkError):
                osv.OnlineSource().query([TRIPLE])

    def test_non_object_result_raises(self):
        with self.assertRaises(NetworkError):
            self.query({"results": ["nope"]})

    def test_invalid_vulns_field_raises(self):
        with self.assertRaises(NetworkError):
            self.query({"results": [{"vulns": "nope"}]})


if __name__ == "__main__":
    unittest.main()
