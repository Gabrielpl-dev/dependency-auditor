"""CVSS v3.x base-score computation (SPEC §5.4).

Only the base score is needed: the tool derives a severity band from it. The
implementation follows the CVSS v3.1 specification, including its specific
round-up function. CVSS v2 and v4 vectors are out of scope and treated as
absent by the caller.
"""

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def roundup(value):
    """CVSS v3 round-up: away from zero, to one decimal place."""
    integer_input = round(value * 100000)
    if integer_input % 10000 == 0:
        return integer_input / 100000.0
    return (math.floor(integer_input / 10000) + 1) / 10.0


def parse_vector(vector):
    """Parse a CVSS v3 vector into its metric dictionary, or ``None``."""
    if not isinstance(vector, str):
        return None
    parts = vector.strip().split("/")
    if not parts or not parts[0].upper().startswith("CVSS:3"):
        return None
    metrics = {}
    for part in parts[1:]:
        if part.count(":") != 1:
            return None
        key, _, value = part.partition(":")
        key = key.upper()
        if key in metrics:
            return None
        metrics[key] = value.upper()
    if any(key not in metrics for key in _REQUIRED):
        return None
    if metrics["S"] not in ("U", "C"):
        return None
    if metrics["AV"] not in _AV or metrics["AC"] not in _AC or metrics["UI"] not in _UI:
        return None
    if metrics["C"] not in _CIA or metrics["I"] not in _CIA or metrics["A"] not in _CIA:
        return None
    scope_changed = metrics["S"] == "C"
    pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED
    if metrics["PR"] not in pr_table:
        return None
    return metrics


def base_score(vector):
    """Return the CVSS v3 base score for ``vector``, or ``None`` if invalid."""
    metrics = parse_vector(vector)
    if metrics is None:
        return None

    scope_changed = metrics["S"] == "C"
    pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED
    confidentiality = _CIA[metrics["C"]]
    integrity = _CIA[metrics["I"]]
    availability = _CIA[metrics["A"]]

    iss = 1 - (1 - confidentiality) * (1 - integrity) * (1 - availability)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    exploitability = (
        8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * pr_table[metrics["PR"]] * _UI[metrics["UI"]]
    )

    if impact <= 0:
        return 0.0
    if scope_changed:
        return roundup(min(1.08 * (impact + exploitability), 10))
    return roundup(min(impact + exploitability, 10))
