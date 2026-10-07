"""In-process unit tests for the ``requirements.txt`` parser (SPEC §5.1)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from auditor import requirements  # noqa: E402
from auditor.models import (  # noqa: E402
    DUPLICATE_REQUIREMENT,
    INVALID_REQUIREMENT_LINE,
    NOT_EXACT_PIN,
    NOT_PINNED,
    OPTION_LINE_IGNORED,
)

PATH = "requirements.txt"


def codes(warnings):
    return [warning.code for warning in warnings]


class RequirementsParserTest(unittest.TestCase):
    def parse(self, text):
        return requirements.parse_text(text, PATH)

    def test_blank_and_comment_lines_are_ignored(self):
        dependencies, warnings = self.parse("\n   \n# a comment\n\t\n")
        self.assertEqual(dependencies, [])
        self.assertEqual(warnings, [])

    def test_inline_comment_is_removed(self):
        dependencies, _ = self.parse("requests==2.19.0  # pin for security\n")
        self.assertEqual(dependencies[0].version, "2.19.0")

    def test_inline_comment_helper_keeps_urls_intact(self):
        strip = requirements._strip_inline_comment
        self.assertEqual(strip("flask==1.0.0 # pin"), "flask==1.0.0 ")
        self.assertEqual(strip("https://example.com/x # note"), "https://example.com/x # note")
        self.assertEqual(strip("flask==1.0.0"), "flask==1.0.0")
        self.assertEqual(strip("#whole line comment"), "#whole line comment")

    def test_option_lines_are_ignored_with_warning(self):
        dependencies, warnings = self.parse("-r base.txt\n--index-url https://x\n")
        self.assertEqual(dependencies, [])
        self.assertEqual(codes(warnings), [OPTION_LINE_IGNORED, OPTION_LINE_IGNORED])

    def test_environment_markers_are_stripped(self):
        dependencies, _ = self.parse('flask==1.0.0 ; python_version < "3.8"\n')
        self.assertEqual(dependencies[0].version, "1.0.0")

    def test_hash_directives_are_stripped(self):
        dependencies, _ = self.parse("flask==1.0.0 --hash=sha256:abcdef\n")
        self.assertEqual(dependencies[0].version, "1.0.0")

    def test_extras_are_lowercased(self):
        dependencies, _ = self.parse("Requests[Security,SOCKS]==2.19.0\n")
        self.assertEqual(dependencies[0].name, "requests")
        self.assertEqual(dependencies[0].extras, ["security", "socks"])

    def test_not_pinned(self):
        dependencies, warnings = self.parse("requests\n")
        self.assertEqual(dependencies[0].version, None)
        self.assertEqual(dependencies[0].extras, [])
        self.assertEqual(codes(warnings), [NOT_PINNED])
        self.assertEqual(warnings[0].package, "requests")

    def test_not_exact_pin(self):
        for line in ("requests>=2.0\n", "requests~=2.0\n", "requests!=1.0\n", "requests==2.*\n"):
            dependencies, warnings = self.parse(line)
            self.assertEqual(dependencies[0].version, None)
            self.assertEqual(codes(warnings), [NOT_EXACT_PIN], line)

    def test_arbitrary_equality_is_not_exact(self):
        _, warnings = self.parse("requests===2.19.0\n")
        self.assertEqual(codes(warnings), [NOT_EXACT_PIN])

    def test_comma_separated_specifier_is_not_exact(self):
        _, warnings = self.parse("requests==2.19.0,!=2.20.0\n")
        self.assertEqual(codes(warnings), [NOT_EXACT_PIN])

    def test_invalid_line(self):
        dependencies, warnings = self.parse("this is not a requirement\n")
        self.assertEqual(dependencies, [])
        self.assertEqual(codes(warnings), [INVALID_REQUIREMENT_LINE])
        self.assertIsNone(warnings[0].package)

    def test_duplicate_requirement_keeps_first(self):
        dependencies, warnings = self.parse("a==1.0\na==1.0\n")
        self.assertEqual(len(dependencies), 1)
        self.assertEqual(codes(warnings), [DUPLICATE_REQUIREMENT])

    def test_line_continuation_joins_lines(self):
        dependencies, _ = self.parse("flask==1.0.0 \\\n    --hash=sha256:abc\n")
        self.assertEqual(dependencies[0].version, "1.0.0")
        self.assertEqual(dependencies[0].line, 1)

    def test_line_numbers_track_physical_lines(self):
        dependencies, warnings = self.parse("# header\n\nflask==1.0.0\nrequests\n")
        self.assertEqual(dependencies[0].line, 3)
        self.assertEqual(dependencies[1].line, 4)
        self.assertEqual(warnings[0].line, 4)

    def test_pypi_name_normalisation(self):
        dependencies, _ = self.parse("Foo_Bar.Baz==1.0\n")
        self.assertEqual(dependencies[0].name, "foo-bar-baz")


if __name__ == "__main__":
    unittest.main()
