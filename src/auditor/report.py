"""Report assembly and rendering (SPEC §6)."""

import json
import os
import sys

from . import SCHEMA_VERSION, TOOL_NAME, __version__
from . import severity as severity_module
from . import naming, versions

_RESET = "\033[0m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_ORDERED_SEVERITIES = ("critical", "high", "medium", "low", "unknown")


def _fixed_version(vulnerability, ecosystem, installed, name=None):
    """Smallest greater ``fixed`` event, scoped to the package when supplied."""
    candidates = []
    for affected in vulnerability.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        if name is not None:
            package = affected.get("package")
            if not isinstance(package, dict) or package.get("ecosystem") != ecosystem:
                continue
            package_name = package.get("name")
            if not isinstance(package_name, str):
                continue
            if naming.normalize(ecosystem, package_name) != naming.normalize(ecosystem, name):
                continue
        for version_range in affected.get("ranges") or []:
            if not isinstance(version_range, dict):
                continue
            if version_range.get("type") != "ECOSYSTEM":
                continue
            for event in version_range.get("events") or []:
                if not isinstance(event, dict):
                    continue
                fixed = event.get("fixed")
                if isinstance(fixed, str) and versions.is_greater(ecosystem, fixed, installed):
                    candidates.append(fixed)
    if not candidates:
        return None
    return min(candidates, key=lambda value: versions.parse_version(ecosystem, value))


def build_vulnerability(vulnerability, ecosystem, installed, name=None):
    """Turn a raw OSV vulnerability into its report representation."""
    severity, score, vector = severity_module.derive(vulnerability)
    identifier = vulnerability.get("id")
    if not isinstance(identifier, str):
        identifier = ""
    aliases = [a for a in (vulnerability.get("aliases") or []) if isinstance(a, str)]
    summary = vulnerability.get("summary")
    if not isinstance(summary, str):
        summary = None
    return {
        "id": identifier,
        "aliases": sorted(aliases),
        "summary": summary,
        "severity": severity,
        "cvss_score": score,
        "cvss_vector": vector,
        "fixed_version": _fixed_version(vulnerability, ecosystem, installed, name),
    }


def build_package(dependency, raw_vulnerabilities):
    """Turn a dependency plus its raw vulnerabilities into a report package."""
    if dependency.audited:
        vulnerabilities = [
            build_vulnerability(vuln, dependency.ecosystem, dependency.version, dependency.name)
            for vuln in raw_vulnerabilities
            if isinstance(vuln, dict)
        ]
        vulnerabilities.sort(key=lambda item: item["id"])
        max_severity = None
        best_rank = -1
        for vulnerability in vulnerabilities:
            current = severity_module.rank(vulnerability["severity"])
            if current > best_rank:
                best_rank = current
                max_severity = vulnerability["severity"]
    else:
        vulnerabilities = []
        max_severity = None

    return {
        "name": dependency.name,
        "version": dependency.version,
        "ecosystem": dependency.ecosystem,
        "dev": dependency.dev,
        "audited": dependency.audited,
        "extras": list(dependency.extras),
        "source": {"file": dependency.file, "line": dependency.line},
        "max_severity": max_severity,
        "vulnerabilities": vulnerabilities,
    }


def compute_exit_code(fail_on, packages):
    """``1`` when any vulnerability's severity reaches the threshold, else ``0``."""
    threshold = severity_module.rank(fail_on)
    for package in packages:
        for vulnerability in package["vulnerabilities"]:
            if severity_module.rank(vulnerability["severity"]) >= threshold:
                return 1
    return 0


def build_summary(inputs, packages, exit_code):
    """Compute the aggregate counters of the report."""
    counts = {name: 0 for name in _ORDERED_SEVERITIES}
    vulnerabilities_total = 0
    packages_vulnerable = 0
    for package in packages:
        if package["vulnerabilities"]:
            packages_vulnerable += 1
        for vulnerability in package["vulnerabilities"]:
            vulnerabilities_total += 1
            key = vulnerability["severity"]
            if key in counts:
                counts[key] += 1
    return {
        "packages_total": sum(item.packages_total for item in inputs),
        "packages_audited": sum(1 for package in packages if package["audited"]),
        "packages_vulnerable": packages_vulnerable,
        "vulnerabilities_total": vulnerabilities_total,
        "counts": counts,
        "exit_code": exit_code,
    }


def build_report(fail_on, inputs, packages, warnings, exit_code):
    """Assemble the full report object (dict) in the §6.3 schema."""
    ordered_inputs = sorted(inputs, key=lambda item: item.path)
    ordered_packages = sorted(
        packages, key=lambda item: (item["source"]["file"], item["ecosystem"], item["name"])
    )
    ordered_warnings = sorted(warnings, key=lambda item: item.sort_key())
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "fail_on": fail_on,
        "inputs": [
            {"path": item.path, "ecosystem": item.ecosystem, "packages_total": item.packages_total}
            for item in ordered_inputs
        ],
        "packages": ordered_packages,
        "warnings": [
            {
                "code": item.code,
                "file": item.file,
                "line": item.line,
                "package": item.package,
                "message": item.message,
            }
            for item in ordered_warnings
        ],
        "summary": build_summary(ordered_inputs, ordered_packages, exit_code),
    }


def render_json(report):
    """Serialise the report as exactly one JSON document."""
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def _colors_enabled(stream):
    if os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def _format_vulnerability(vulnerability):
    score = vulnerability["cvss_score"]
    score_text = "%.1f" % score if isinstance(score, (int, float)) else "-"
    line = "        %s  %s (%s)" % (
        vulnerability["id"],
        vulnerability["severity"],
        score_text,
    )
    if vulnerability["fixed_version"] is not None:
        line += "  fixed in %s" % vulnerability["fixed_version"]
    lines = [line]
    if vulnerability["summary"]:
        prefix = ""
        if vulnerability["aliases"]:
            prefix = "%s: " % vulnerability["aliases"][0]
        lines.append("        %s%s" % (prefix, vulnerability["summary"]))
    return lines


def render_human(report, color=False):
    """Render the canonical human report (not a machine contract)."""
    packages = report["packages"]
    summary = report["summary"]
    exit_code = summary["exit_code"]
    result = "FAIL (exit %d)" % exit_code if exit_code else "OK (exit 0)"
    result_line = "Result: %s" % result

    lines = ["%s %s" % (TOOL_NAME, __version__), "fail-on: %s" % report["fail_on"], ""]

    by_file = {}
    for package in packages:
        by_file.setdefault(package["source"]["file"], []).append(package)

    for input_file in report["inputs"]:
        lines.append("%s (%s)" % (input_file["path"], input_file["ecosystem"]))
        for package in by_file.get(input_file["path"], []):
            version = package["version"] if package["version"] is not None else "-"
            dev = "  (dev)" if package["dev"] else ""
            if not package["audited"]:
                lines.append("  SKIP  %s %s%s" % (package["name"], version, dev))
                continue
            if package["vulnerabilities"]:
                status = _red("FAIL", color)
            else:
                status = _green("OK  ", color)
            lines.append("  %s  %s %s%s" % (status, package["name"], version, dev))
            for vulnerability in package["vulnerabilities"]:
                lines.extend(_format_vulnerability(vulnerability))
        lines.append("")

    failed = [w for w in report["warnings"]]
    if failed:
        lines.append("warnings:")
        for warning in failed:
            location = warning["file"]
            if warning["line"] is not None:
                location += ":%d" % warning["line"]
            lines.append("  %s %s  %s" % (location, warning["code"], warning["message"]))
        lines.append("")

    counts = summary["counts"]
    lines.append(
        "Summary: %d packages (%d audited), %d vulnerable, %d vulnerabilities"
        % (
            summary["packages_total"],
            summary["packages_audited"],
            summary["packages_vulnerable"],
            summary["vulnerabilities_total"],
        )
    )
    lines.append(
        "         %s"
        % " | ".join("%s %d" % (name, counts[name]) for name in _ORDERED_SEVERITIES)
    )
    lines.append(result_line)
    return "\n".join(lines) + "\n"


def _wrap(code, text, color):
    return "%s%s%s" % (code, text, _RESET) if color else text


def _red(text, color):
    return _wrap(_RED, text, color)


def _green(text, color):
    return _wrap(_GREEN, text, color)


def write_report(report, as_json, quiet, stdout=None):
    """Write the report to ``stdout`` honouring ``--json`` and ``--quiet``."""
    stdout = sys.stdout if stdout is None else stdout
    if as_json:
        stdout.write(render_json(report))
        return
    if quiet:
        exit_code = report["summary"]["exit_code"]
        result = "FAIL (exit %d)" % exit_code if exit_code else "OK (exit 0)"
        stdout.write("Result: %s\n" % result)
        return
    stdout.write(render_human(report, color=_colors_enabled(stdout)))
