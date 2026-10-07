"""Shared black-box helpers for the acceptance tests.

Tests never import the project code: they execute ``./app`` as a subprocess,
always in fixture mode, so nothing ever touches the network.
"""

import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "app")
FIXTURES = os.path.join(ROOT, "tests", "fixtures")
SRC = os.path.join(ROOT, "src")


def fixture(name):
    """Absolute path of a named fixture under ``tests/fixtures``."""
    return os.path.join(FIXTURES, name)


def run(args, fixture_path, cwd=None, extra_env=None):
    """Run ``./app`` with ``AUDITOR_OSV_FIXTURE`` set and capture its streams."""
    env = dict(os.environ)
    env.pop("AUDITOR_OSV_FIXTURE", None)
    env["AUDITOR_OSV_FIXTURE"] = fixture_path
    # Make sure no ambient proxy setting could ever be needed: fixture mode
    # must not perform I/O at all.
    if extra_env:
        env.update(extra_env)
    command = [sys.executable, APP] + list(args)
    return subprocess.run(
        command,
        cwd=cwd or ROOT,
        env=env,
        capture_output=True,
        text=True,
    )


def run_json(args, fixture_path, cwd=None, extra_env=None):
    """Run the tool with ``--json`` and parse the stdout document."""
    proc = run(list(args) + ["--json"], fixture_path, cwd=cwd, extra_env=extra_env)
    document = json.loads(proc.stdout)
    return proc, document


def write(path, content):
    """Write ``content`` to ``path``, creating parent directories."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    return path


def warnings_by_code(document):
    return [warning["code"] for warning in document["warnings"]]
