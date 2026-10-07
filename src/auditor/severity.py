"""Severity derivation (SPEC §5.4).

Precedence per vulnerability:

1. a ``CVSS_V3`` vector, whose base score is computed and banded;
2. otherwise ``database_specific.severity``;
3. otherwise ``unknown``.

CVSS v2 / v4 vectors are treated as absent on purpose.
"""

from . import cvss

SEVERITY_UNKNOWN = "unknown"
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

# Ordering used by ``--fail-on`` and by ``max_severity``.
RANKS = {
    SEVERITY_UNKNOWN: 0,
    SEVERITY_LOW: 1,
    SEVERITY_MEDIUM: 2,
    SEVERITY_HIGH: 3,
    SEVERITY_CRITICAL: 4,
}

FAIL_ON_LEVELS = ("low", "medium", "high", "critical")

_DATABASE_SPECIFIC = {
    "low": SEVERITY_LOW,
    "medium": SEVERITY_MEDIUM,
    "moderate": SEVERITY_MEDIUM,
    "high": SEVERITY_HIGH,
    "critical": SEVERITY_CRITICAL,
}


def rank(severity):
    """Return the ``--fail-on`` rank of ``severity`` (``None`` -> 0)."""
    return RANKS.get(severity, 0)


def band_from_score(score):
    """Map a CVSS v3 base score to a reportable severity."""
    # A 0.0 score has no band of its own; it is reported as ``unknown`` so that
    # it can never trigger ``--fail-on`` (SPEC §5.4).
    if score < 0.1:
        return SEVERITY_UNKNOWN
    if score < 4.0:
        return SEVERITY_LOW
    if score < 7.0:
        return SEVERITY_MEDIUM
    if score < 9.0:
        return SEVERITY_HIGH
    return SEVERITY_CRITICAL


def _from_cvss(vulnerability):
    for entry in vulnerability.get("severity") or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") != "CVSS_V3":
            continue
        vector = entry.get("score")
        score = cvss.base_score(vector)
        if score is None:
            continue
        return band_from_score(score), score, vector
    return None


def _from_database_specific(vulnerability):
    database_specific = vulnerability.get("database_specific")
    if not isinstance(database_specific, dict):
        return None
    raw = database_specific.get("severity")
    if not isinstance(raw, str):
        return None
    return _DATABASE_SPECIFIC.get(raw.strip().lower(), SEVERITY_UNKNOWN)


def derive(vulnerability):
    """Return ``(severity, cvss_score, cvss_vector)`` for a raw OSV vulnerability."""
    from_cvss = _from_cvss(vulnerability)
    if from_cvss is not None:
        return from_cvss
    from_database = _from_database_specific(vulnerability)
    if from_database is not None:
        return from_database, None, None
    return SEVERITY_UNKNOWN, None, None
