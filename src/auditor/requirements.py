"""``requirements.txt`` parser (SPEC §5.1)."""

import re

from .files import read_text
from .models import (
    Dependency,
    Warning,
    DUPLICATE_REQUIREMENT,
    INVALID_REQUIREMENT_LINE,
    NOT_EXACT_PIN,
    NOT_PINNED,
    OPTION_LINE_IGNORED,
)
from .naming import ECOSYSTEM_PYPI, normalize_pypi

_PACKAGE_RE = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)\s*(?P<extras>\[[^\]]*\])?\s*(?P<rest>.*)$")
_NON_EXACT_OPERATORS = (">=", "<=", "~=", "!=", ">", "<", "=")


def _logical_lines(text):
    """Yield ``(line_number, text)`` joining backslash continuations (SPEC §5.1.1)."""
    logical = []
    pending = ""
    start = None
    for index, raw in enumerate(text.split("\n"), start=1):
        if start is None:
            start = index
        trimmed = raw.rstrip()
        if trimmed.endswith("\\"):
            pending += trimmed[:-1]
            continue
        pending += raw
        logical.append((start, pending))
        pending = ""
        start = None
    if start is not None:
        logical.append((start, pending))
    return logical


def _strip_inline_comment(line):
    for index, char in enumerate(line):
        if char == "#" and index > 0 and line[index - 1].isspace():
            if "://" in line[:index]:
                return line
            return line[:index]
    return line


def _remove_marker(line):
    index = line.find(";")
    return line if index == -1 else line[:index]


def _remove_hash_options(line):
    index = line.find("--hash")
    return line if index == -1 else line[:index]


def _parse_extras(raw):
    if not raw:
        return []
    extras = []
    for part in raw[1:-1].split(","):
        item = part.strip().lower()
        if item:
            extras.append(item)
    return extras


def _classify(body):
    """Classify a cleaned requirement line.

    Returns ``(name, extras, version, warning_code)`` or ``None`` when the line
    does not match the package grammar (``INVALID_REQUIREMENT_LINE``).
    """
    match = _PACKAGE_RE.match(body)
    if not match:
        return None
    name = match.group("name")
    extras = _parse_extras(match.group("extras"))
    rest = match.group("rest").strip()

    if rest == "":
        return name, extras, None, NOT_PINNED
    if rest.startswith("==="):
        return name, extras, None, NOT_EXACT_PIN
    if rest.startswith("=="):
        candidate = rest[2:].strip()
        if candidate == "" or "*" in candidate or "," in candidate:
            return name, extras, None, NOT_EXACT_PIN
        return name, extras, candidate, None
    if rest.startswith(_NON_EXACT_OPERATORS):
        return name, extras, None, NOT_EXACT_PIN
    return None


def parse_text(text, path):
    """Parse ``requirements.txt`` content into ``(dependencies, warnings)``."""
    dependencies = []
    warnings = []
    seen = set()

    for line_number, logical in _logical_lines(text):
        body = logical.strip()
        if not body or body.startswith("#"):
            continue
        body = _strip_inline_comment(body).strip()
        if not body:
            continue
        if body.startswith("-"):
            warnings.append(
                Warning(
                    OPTION_LINE_IGNORED,
                    path,
                    'linha de opção ignorada: "%s"' % body,
                    line=line_number,
                )
            )
            continue
        body = _remove_marker(body)
        body = _remove_hash_options(body).strip()
        if not body:
            continue

        classified = _classify(body)
        if classified is None:
            warnings.append(
                Warning(
                    INVALID_REQUIREMENT_LINE,
                    path,
                    'linha de requisito inválida: "%s"' % body,
                    line=line_number,
                )
            )
            continue

        raw_name, extras, version, warning_code = classified
        name = normalize_pypi(raw_name)

        if warning_code is not None:
            if warning_code == NOT_PINNED:
                message = '"%s" sem versão fixada — não auditado' % name
            else:
                message = '"%s" sem versão exata fixada — não auditado' % name
            warnings.append(Warning(warning_code, path, message, line=line_number, package=name))

        key = (name, version)
        if key in seen:
            warnings.append(
                Warning(
                    DUPLICATE_REQUIREMENT,
                    path,
                    'requisito duplicado: "%s"' % name,
                    line=line_number,
                    package=name,
                )
            )
            continue
        seen.add(key)

        dependencies.append(
            Dependency(
                ecosystem=ECOSYSTEM_PYPI,
                name=name,
                version=version,
                file=path,
                line=line_number,
                extras=extras,
            )
        )

    return dependencies, warnings


def parse(path):
    """Read and parse a ``requirements`` file from disk."""
    return parse_text(read_text(path), path)
