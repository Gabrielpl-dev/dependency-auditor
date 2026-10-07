"""``package.json`` parser (SPEC §5.2)."""

import json
import re

from .errors import UsageError
from .files import read_text
from .models import (
    Dependency,
    Warning,
    RANGE_RESOLVED_TO_MIN,
    UNRESOLVABLE_RANGE,
)
from .naming import ECOSYSTEM_NPM, normalize_npm

_EXACT_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_MIN_RE = re.compile(r"^[\^~](\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$")

# Dependencies first, devDependencies second; both alphabetically (SPEC §5.2.5).
_SECTIONS = (("dependencies", False), ("devDependencies", True))


def _resolve_range(raw):
    """Return ``(version, warning_code)`` for a declared npm range."""
    if not isinstance(raw, str):
        return None, UNRESOLVABLE_RANGE
    value = raw.strip()
    if _EXACT_RE.match(value):
        return value, None
    match = _MIN_RE.match(value)
    if match:
        return match.group(1), RANGE_RESOLVED_TO_MIN
    return None, UNRESOLVABLE_RANGE


def parse_text(text, path):
    """Parse ``package.json`` content into ``(dependencies, warnings)``."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as error:
        raise UsageError("JSON inválido em %s: %s" % (path, error)) from error

    if not isinstance(data, dict):
        raise UsageError("esperado um objeto JSON no topo de %s" % (path,))

    dependencies = []
    warnings = []

    for section, dev in _SECTIONS:
        if section not in data:
            continue
        table = data[section]
        if not isinstance(table, dict):
            raise UsageError('"%s" deve ser um objeto em %s' % (section, path))
        for raw_name in sorted(table):
            name = normalize_npm(raw_name)
            version, warning_code = _resolve_range(table[raw_name])
            if warning_code is not None:
                warnings.append(
                    Warning(
                        warning_code,
                        path,
                        'range não resolvível para "%s" — não auditado' % name
                        if warning_code == UNRESOLVABLE_RANGE
                        else 'range de "%s" resolvido para o mínimo %s' % (name, version),
                        line=None,
                        package=name,
                    )
                )
            dependencies.append(
                Dependency(
                    ecosystem=ECOSYSTEM_NPM,
                    name=name,
                    version=version,
                    file=path,
                    line=None,
                    dev=dev,
                )
            )

    return dependencies, warnings


def parse(path):
    """Read and parse a ``package.json`` file from disk."""
    return parse_text(read_text(path), path)
