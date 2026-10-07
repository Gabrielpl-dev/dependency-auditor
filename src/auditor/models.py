"""Plain data structures shared across parsers, sources and the report."""

from dataclasses import dataclass, field
from typing import List, Optional

# Warning codes (SPEC §6.4) — a closed enum.
NOT_PINNED = "NOT_PINNED"
NOT_EXACT_PIN = "NOT_EXACT_PIN"
INVALID_REQUIREMENT_LINE = "INVALID_REQUIREMENT_LINE"
OPTION_LINE_IGNORED = "OPTION_LINE_IGNORED"
DUPLICATE_REQUIREMENT = "DUPLICATE_REQUIREMENT"
RANGE_RESOLVED_TO_MIN = "RANGE_RESOLVED_TO_MIN"
UNRESOLVABLE_RANGE = "UNRESOLVABLE_RANGE"


@dataclass
class Warning:
    """A non-fatal diagnostic attached to a file (and possibly a line)."""

    code: str
    file: str
    message: str
    line: Optional[int] = None
    package: Optional[str] = None

    def sort_key(self):
        # Warnings without a line sort last within their file (SPEC §6.1).
        return (self.file, self.line is None, self.line or 0, self.code, self.message)


@dataclass
class Dependency:
    """A single declared dependency, before it is audited."""

    ecosystem: str
    name: str  # normalised
    version: Optional[str]
    file: str
    line: Optional[int]
    extras: List[str] = field(default_factory=list)
    dev: bool = False

    @property
    def audited(self):
        return self.version is not None

    @property
    def triple(self):
        return (self.ecosystem, self.name, self.version)


@dataclass
class InputFile:
    """One processed manifest."""

    path: str
    ecosystem: str
    packages_total: int


@dataclass
class Source:
    file: str
    line: Optional[int]


@dataclass
class Report:
    fail_on: str
    inputs: List[InputFile]
    packages: List[dict]
    warnings: List[Warning]
    summary: dict
