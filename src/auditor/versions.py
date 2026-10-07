"""Version ordering for the supported ecosystems (SPEC §5.5).

Only ordering matters here: the tool compares an installed version against the
``fixed`` events of an OSV range and keeps the smallest applicable one. Full
PEP 440 / SemVer parsing is therefore reduced to a sortable key plus a strict
greater-than comparison.

Both parsers are deliberately tolerant: when a version cannot be understood we
return ``None`` and callers simply skip that candidate instead of guessing.
"""

import re

# PyPI ---------------------------------------------------------------- PEP 440

_PEP440_RE = re.compile(
    r"""
    ^\s*v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?P<pre>[-_.]?(?P<pre_l>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>[0-9]+)?)?
    (?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?))?
    (?P<dev>[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$
    """,
    re.VERBOSE | re.IGNORECASE,
)

_PRE_RANK = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}

# Release segments are padded so that 1.0 == 1.0.0.
_RELEASE_WIDTH = 12
# Local-version segments: numeric segments sort after alphanumeric ones, hence
# the leading marker (0 = text, 1 = number).
_TEXT_SEGMENT = 0
_NUMBER_SEGMENT = 1


def _release_tuple(release):
    parts = [int(p) for p in release.split(".")]
    parts += [0] * (_RELEASE_WIDTH - len(parts))
    return tuple(parts[:_RELEASE_WIDTH])


def _local_key(local):
    if not local:
        return (0,)
    segments = re.split(r"[-_.]", local)
    encoded = []
    for segment in segments:
        if segment.isdigit():
            encoded.append((_NUMBER_SEGMENT, int(segment), ""))
        else:
            encoded.append((_TEXT_SEGMENT, 0, segment))
    return (1, tuple(encoded))


def _pre_key(pre_l, pre_n, post_present, dev_present):
    if pre_l is None:
        # ``1.0.dev0`` sorts before ``1.0`` but after nothing else.
        if not post_present and dev_present:
            return (-1, 0, 0)
        return (1, 0, 0)
    return (0, _PRE_RANK.get(pre_l, 2) + 1, pre_n if pre_n is not None else 0)


def pep440_key(version):
    """Return a sortable key for a PEP 440 version, or ``None`` if invalid."""
    if not isinstance(version, str):
        return None
    match = _PEP440_RE.match(version)
    if not match:
        return None
    epoch = int(match.group("epoch") or 0)
    release = _release_tuple(match.group("release"))

    pre_l = match.group("pre_l")
    if pre_l is not None:
        pre_l = pre_l.lower()
    pre_n = match.group("pre_n")

    post_l = match.group("post_l")
    post_n1 = match.group("post_n1")
    post_n2 = match.group("post_n2")
    post_present = post_l is not None or post_n1 is not None
    if post_n1 is not None:
        post_number = int(post_n1)
    elif post_n2 is not None:
        post_number = int(post_n2)
    else:
        post_number = 0
    post_key = (1, post_number) if post_present else (0, 0)

    dev_l = match.group("dev_l")
    dev_n = match.group("dev_n")
    dev_present = dev_l is not None
    dev_key = (0, int(dev_n) if dev_n is not None else 0) if dev_present else (1, 0)

    return (
        epoch,
        release,
        _pre_key(pre_l, int(pre_n) if pre_n is not None else 0, post_present, dev_present),
        post_key,
        dev_key,
        _local_key(match.group("local")),
    )


# npm ------------------------------------------------------------------- SemVer

_SEMVER_RE = re.compile(
    r"^\s*(?P<major>0|[1-9][0-9]*)\.(?P<minor>0|[1-9][0-9]*)\.(?P<patch>0|[1-9][0-9]*)"
    r"(?:-(?P<pre>[0-9A-Za-z.-]+))?(?:\+(?P<build>[0-9A-Za-z.-]+))?\s*$"
)


def _semver_prerelease_key(pre):
    if pre is None:
        # A release outranks any of its pre-releases.
        return (1, ())
    encoded = []
    for identifier in pre.split("."):
        if identifier.isdigit():
            encoded.append((0, int(identifier), ""))
        else:
            encoded.append((1, 0, identifier))
    return (0, tuple(encoded))


def semver_key(version):
    """Return a sortable key for a SemVer version, or ``None`` if invalid."""
    if not isinstance(version, str):
        return None
    match = _SEMVER_RE.match(version)
    if not match:
        return None
    return (
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch")),
        _semver_prerelease_key(match.group("pre")),
    )


# Public helpers -------------------------------------------------------------

_KEY_FUNCTIONS = {"PyPI": pep440_key, "npm": semver_key}


def parse_version(ecosystem, version):
    """Return the ordering key for ``version`` in ``ecosystem`` (or ``None``)."""
    key_function = _KEY_FUNCTIONS.get(ecosystem)
    if key_function is None:
        return None
    return key_function(version)


def is_greater(ecosystem, candidate, baseline):
    """True when ``candidate`` is a valid version strictly greater than ``baseline``."""
    candidate_key = parse_version(ecosystem, candidate)
    baseline_key = parse_version(ecosystem, baseline)
    if candidate_key is None or baseline_key is None:
        return False
    return candidate_key > baseline_key
