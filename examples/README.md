# Examples

Small, self-contained inputs you can run offline. The fixture in this directory
(`osv-fixture.json`) mimics the OSV.dev response for exactly these packages, so
no network access is required.

| File | What it is |
|---|---|
| `requirements.txt` | Pinned PyPI dependencies (`flask==1.0.0`, `requests[security]==2.19.0`). |
| `package.json` | npm `dependencies` and `devDependencies` (`lodash`, `minimist`). |
| `osv-fixture.json` | Offline replacement for the OSV.dev `querybatch` response (§4.3). |

## A run that fails (exit 1)

`requests 2.19.0` has a `critical` vulnerability, which is at or above the
default `--fail-on high` threshold:

```console
$ AUDITOR_OSV_FIXTURE=examples/osv-fixture.json ./app examples
dependency-auditor 0.1.0
fail-on: high

examples/package.json (npm)
  FAIL  lodash 4.17.11
        GHSA-jf85-cpcp-j695  high (7.5)  fixed in 4.17.12
        CVE-2019-10744: Prototype pollution in lodash
  FAIL  minimist 1.2.0  (dev)
        GHSA-vh95-rmgr-6w4m  medium (-)  fixed in 1.2.3
        CVE-2020-7598: Prototype pollution in minimist

examples/requirements.txt (PyPI)
  OK    flask 1.0.0
  FAIL  requests 2.19.0
        GHSA-9hjg-9r4m-mvj7  critical (9.8)  fixed in 2.20.0
        CVE-2018-18074: Requests session fixation / credential leak on redirect

warnings:
  examples/package.json RANGE_RESOLVED_TO_MIN  range de "minimist" resolvido para o mínimo 1.2.0

Summary: 4 packages (4 audited), 3 vulnerable, 3 vulnerabilities
         critical 1 | high 1 | medium 1 | low 0 | unknown 0
Result: FAIL (exit 1)
```

## A run that passes (exit 0)

The `--fail-on` threshold decides what "passes". Point the tool at a manifest
whose packages are all absent from the fixture — an absent key is never an error
(§7.18):

```console
$ mkdir -p /tmp/safe && printf 'flask==1.0.0\n' > /tmp/safe/requirements.txt
$ AUDITOR_OSV_FIXTURE=examples/osv-fixture.json ./app /tmp/safe/requirements.txt
dependency-auditor 0.1.0
fail-on: high

/tmp/safe/requirements.txt (PyPI)
  OK    flask 1.0.0

Summary: 1 packages (1 audited), 0 vulnerable, 0 vulnerabilities
         critical 0 | high 0 | medium 0 | low 0 | unknown 0
Result: OK (exit 0)
```

## Machine-readable output

```console
$ AUDITOR_OSV_FIXTURE=examples/osv-fixture.json ./app --json examples | jq '.summary'
{
  "packages_total": 4,
  "packages_audited": 4,
  "packages_vulnerable": 3,
  "vulnerabilities_total": 3,
  "counts": {"critical": 1, "high": 1, "medium": 1, "low": 0, "unknown": 0},
  "exit_code": 1
}
```
