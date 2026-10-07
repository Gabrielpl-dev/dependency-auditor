"""Line-coverage gate for the parser and severity modules (SPEC §9.4).

Uses the standard-library ``trace`` module so the project stays dependency
free. Only the in-process unit tests are traced, because subprocess-based
acceptance tests cannot be observed by ``trace``.

Usage: python3 tests/coverage_check.py [threshold]
"""

import os
import sys
import trace
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "tests"))

TARGETS = (
    ("auditor.requirements", "requirements.txt parser"),
    ("auditor.packagejson", "package.json parser"),
    ("auditor.severity", "severity derivation"),
    ("auditor.cvss", "CVSS v3 base score"),
)

TEST_MODULES = (
    "test_unit_requirements",
    "test_unit_packagejson",
    "test_unit_severity",
)


def run_tests():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite(
        loader.loadTestsFromName(module) for module in TEST_MODULES
    )
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=1).run(suite)
    if not result.wasSuccessful():
        sys.exit("unit tests failed; cannot measure coverage")


def main(argv):
    threshold = float(argv[1]) if len(argv) > 1 else 80.0

    tracer = trace.Trace(count=1, trace=0, ignoredirs=[sys.prefix, sys.exec_prefix])
    tracer.runfunc(run_tests)
    results = tracer.results()

    covered = {}
    for (filename, lineno), count in results.counts.items():
        if count:
            covered.setdefault(os.path.abspath(filename), set()).add(lineno)

    failures = []
    print("\nLine coverage (parser and severity modules):")
    for module_name, label in TARGETS:
        module = __import__(module_name, fromlist=["__file__"])
        filename = os.path.abspath(module.__file__)
        executable = trace._find_executable_linenos(filename)
        if not executable:
            continue
        hit = covered.get(filename, set()) & set(executable)
        percentage = 100.0 * len(hit) / len(executable)
        status = "OK " if percentage >= threshold else "LOW"
        print("  %s %-42s %5.1f%% (%d/%d)" % (status, label, percentage, len(hit), len(executable)))
        if percentage < threshold:
            failures.append(label)

    if failures:
        print("\nFAILED: below %.0f%%: %s" % (threshold, ", ".join(failures)))
        return 1
    print("\nOK: every target module is at or above %.0f%%." % threshold)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
