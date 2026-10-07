"""Package-name normalisation (SPEC §4.6).

PyPI names follow PEP 503: lowercase, runs of ``-``, ``_`` and ``.`` collapse
into a single ``-``. npm names are simply lowercased in full, scope included.
"""

import re

ECOSYSTEM_PYPI = "PyPI"
ECOSYSTEM_NPM = "npm"

_PEP503_SEPARATORS = re.compile(r"[-_.]+")


def normalize_pypi(name):
    """Normalise a PyPI project name per PEP 503."""
    return _PEP503_SEPARATORS.sub("-", name).lower()


def normalize_npm(name):
    """Normalise an npm package name: full lowercase, scope preserved."""
    return name.lower()


def normalize(ecosystem, name):
    """Normalise ``name`` according to ``ecosystem``."""
    if ecosystem == ECOSYSTEM_PYPI:
        return normalize_pypi(name)
    if ecosystem == ECOSYSTEM_NPM:
        return normalize_npm(name)
    raise ValueError("unknown ecosystem: %r" % (ecosystem,))
