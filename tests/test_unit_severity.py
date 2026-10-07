"""In-process unit tests for severity derivation and CVSS v3 scoring (SPEC §5.4)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from auditor import cvss, severity  # noqa: E402

CRITICAL_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
HIGH_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"


class CvssTest(unittest.TestCase):
    def test_critical_vector(self):
        self.assertEqual(cvss.base_score(CRITICAL_VECTOR), 9.8)

    def test_high_vector(self):
        self.assertEqual(cvss.base_score(HIGH_VECTOR), 7.5)

    def test_zero_impact(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
        self.assertEqual(cvss.base_score(vector), 0.0)

    def test_scope_changed(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        self.assertEqual(cvss.base_score(vector), 6.1)

    def test_invalid_vectors(self):
        self.assertIsNone(cvss.base_score("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"))
        self.assertIsNone(cvss.base_score("not-a-vector"))
        self.assertIsNone(cvss.base_score(None))
        self.assertIsNone(cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"))
        self.assertIsNone(cvss.base_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))
        self.assertIsNone(cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H"))
        self.assertIsNone(cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/A:H"))
        self.assertIsNone(cvss.base_score("CVSS:3.1/AV:N/AC:L/PRN/UI:N/S:U/C:H/I:H/A:H"))


class SeverityTest(unittest.TestCase):
    def test_bands(self):
        self.assertEqual(severity.band_from_score(0.0), "unknown")
        self.assertEqual(severity.band_from_score(3.9), "low")
        self.assertEqual(severity.band_from_score(6.9), "medium")
        self.assertEqual(severity.band_from_score(8.9), "high")
        self.assertEqual(severity.band_from_score(9.0), "critical")
        self.assertEqual(severity.band_from_score(10.0), "critical")

    def test_cvss_takes_precedence(self):
        vulnerability = {
            "severity": [{"type": "CVSS_V3", "score": CRITICAL_VECTOR}],
            "database_specific": {"severity": "LOW"},
        }
        self.assertEqual(
            severity.derive(vulnerability), ("critical", 9.8, CRITICAL_VECTOR)
        )

    def test_database_specific_fallback(self):
        for raw, expected in (
            ("LOW", "low"),
            ("medium", "medium"),
            ("MODERATE", "medium"),
            ("High", "high"),
            ("CRITICAL", "critical"),
            ("weird", "unknown"),
        ):
            self.assertEqual(
                severity.derive({"database_specific": {"severity": raw}}),
                (expected, None, None),
            )

    def test_unknown_when_nothing_available(self):
        self.assertEqual(severity.derive({}), ("unknown", None, None))
        self.assertEqual(
            severity.derive({"database_specific": {"severity": 3}}), ("unknown", None, None)
        )
        self.assertEqual(severity.derive({"database_specific": "nope"}), ("unknown", None, None))

    def test_cvss_v2_and_v4_are_ignored(self):
        vulnerability = {
            "severity": [
                {"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
                {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H"},
            ],
            "database_specific": {"severity": "HIGH"},
        }
        self.assertEqual(severity.derive(vulnerability), ("high", None, None))

    def test_unparsable_cvss_v3_falls_back(self):
        vulnerability = {
            "severity": [{"type": "CVSS_V3", "score": "garbage"}],
            "database_specific": {"severity": "MEDIUM"},
        }
        self.assertEqual(severity.derive(vulnerability), ("medium", None, None))

    def test_non_dict_severity_entries_are_skipped(self):
        vulnerability = {"severity": ["nope", {"type": "CVSS_V3", "score": HIGH_VECTOR}]}
        self.assertEqual(severity.derive(vulnerability), ("high", 7.5, HIGH_VECTOR))

    def test_ranks(self):
        self.assertEqual(severity.rank("unknown"), 0)
        self.assertEqual(severity.rank("low"), 1)
        self.assertEqual(severity.rank("critical"), 4)
        self.assertEqual(severity.rank(None), 0)


if __name__ == "__main__":
    unittest.main()
