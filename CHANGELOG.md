# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-06

### Added

- Offline-first CLI (`./app`) that audits pinned Python and npm dependencies
  against OSV.dev for known vulnerabilities.
- Parsing of `requirements.txt` (PyPI) and `package.json` (npm), including
  extras, environment markers, line continuations, inline hashes and comments.
- Batch querying of `https://api.osv.dev/v1/querybatch`, with deterministic
  ordering and deduplication of queries.
- Deterministic offline mode through the `AUDITOR_OSV_FIXTURE` environment
  variable, which never performs network I/O.
- Severity derivation from CVSS v3 base scores, falling back to
  `database_specific.severity` and then `unknown`.
- Suggested minimum fixed version derived from OSV `ECOSYSTEM` ranges.
- Human-readable report and a versioned JSON report (`schema_version: "1.0"`).
- Configurable failure policy via `--fail-on` and stable exit codes
  (`0`, `1`, `2`, `3`, `4`).
- Public test suite (stdlib `unittest`) that runs entirely offline, plus an
  80% line-coverage gate for the parsers and the severity derivation.
- GitHub Actions CI with `lint` and `test` jobs on a Python version matrix.
- Example manifests and an offline fixture under `examples/`.
