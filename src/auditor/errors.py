"""Error types that map 1:1 to the exit codes of the CLI contract (SPEC §3.5)."""


class AuditorError(Exception):
    """Base class for expected, user-facing failures."""

    exit_code = 4


class UsageError(AuditorError):
    """Invalid usage or invalid input (exit 2)."""

    exit_code = 2


class NetworkError(AuditorError):
    """Network / upstream failure while talking to OSV.dev (exit 3)."""

    exit_code = 3


class InternalError(AuditorError):
    """Unexpected internal failure (exit 4)."""

    exit_code = 4
