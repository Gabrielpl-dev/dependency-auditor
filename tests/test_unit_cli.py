"""In-process unit tests for the CLI plumbing (SPEC §3)."""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "tests"))

from auditor import cli, files  # noqa: E402
from auditor.errors import UsageError  # noqa: E402
from helpers import fixture  # noqa: E402


class DetectEcosystemTest(unittest.TestCase):
    def test_requirements_variants(self):
        self.assertEqual(cli.detect_ecosystem("requirements.txt"), "PyPI")
        self.assertEqual(cli.detect_ecosystem("req/requirements-dev.txt"), "PyPI")

    def test_package_json(self):
        self.assertEqual(cli.detect_ecosystem("./package.json"), "npm")

    def test_unknown(self):
        for name in ("deps.txt", "package.json.bak", "Requirements.txt"):
            with self.assertRaises(UsageError):
                cli.detect_ecosystem(name)


class ResolveInputsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="auditor-cli-")
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)

    def write(self, name, content="x"):
        path = os.path.join(self.tmp, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    def test_file_passthrough(self):
        path = self.write("requirements.txt")
        self.assertEqual(cli.resolve_input_files(path), [path])

    def test_directory_picks_existing_manifests(self):
        self.write("requirements.txt")
        self.write("other.txt")
        resolved = cli.resolve_input_files(self.tmp)
        self.assertEqual([os.path.basename(p) for p in resolved], ["requirements.txt"])

    def test_empty_directory_raises(self):
        with self.assertRaises(UsageError):
            cli.resolve_input_files(self.tmp)

    def test_missing_path_raises(self):
        with self.assertRaises(UsageError):
            cli.resolve_input_files(os.path.join(self.tmp, "gone"))


class MainTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="auditor-cli-")
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)
        self.manifest = os.path.join(self.tmp, "requirements.txt")
        with open(self.manifest, "w", encoding="utf-8") as handle:
            handle.write("requests==2.19.0\n")

    def run_main(self, argv, environ):
        stdout, stderr = io.StringIO(), io.StringIO()
        saved = dict(os.environ)
        os.environ.clear()
        os.environ.update(environ)
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = cli.main(argv)
        finally:
            os.environ.clear()
            os.environ.update(saved)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_fixture_run_exit_one(self):
        code, stdout, _ = self.run_main(
            ["--json", self.manifest],
            {"AUDITOR_OSV_FIXTURE": fixture("basic.json")},
        )
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(stdout)["summary"]["exit_code"], 1)

    def test_usage_error_exit_two(self):
        code, stdout, stderr = self.run_main(
            [os.path.join(self.tmp, "missing.txt")],
            {"AUDITOR_OSV_FIXTURE": fixture("empty.json")},
        )
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertNotEqual(stderr, "")

    def test_network_error_exit_three(self):
        code, stdout, stderr = self.run_main(
            [self.manifest], {"AUDITOR_OSV_FIXTURE": "", "https_proxy": "http://127.0.0.1:9"}
        )
        self.assertEqual(code, 3)
        self.assertEqual(stdout, "")
        self.assertNotEqual(stderr, "")

    def test_unexpected_error_exit_four(self):
        with mock.patch("auditor.cli.run", side_effect=RuntimeError("boom")):
            code, _, stderr = self.run_main([self.manifest], {})
        self.assertEqual(code, 4)
        self.assertIn("boom", stderr)


class FilesTest(unittest.TestCase):
    def test_missing_file_raises_usage_error(self):
        with self.assertRaises(UsageError):
            files.read_text("/definitely/not/here")

    def test_non_utf8_raises_usage_error(self):
        handle = tempfile.NamedTemporaryFile(delete=False)
        self.addCleanup(os.unlink, handle.name)
        handle.write(b"\xff\xfe\x00")
        handle.close()
        with self.assertRaises(UsageError):
            files.read_text(handle.name)

    def test_crlf_normalisation(self):
        handle = tempfile.NamedTemporaryFile("w", delete=False, newline="")
        self.addCleanup(os.unlink, handle.name)
        handle.write("a\r\nb\r\n")
        handle.close()
        self.assertEqual(files.read_text(handle.name), "a\nb\n")


if __name__ == "__main__":
    unittest.main()
