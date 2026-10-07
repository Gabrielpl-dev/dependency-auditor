"""Small file-reading helpers shared by the manifest parsers."""

import os

from .errors import UsageError


def read_text(path):
    """Read ``path`` as UTF-8 (BOM tolerated), normalising CRLF/CR to LF."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as error:
        raise UsageError("não foi possível ler %s: %s" % (path, error)) from error
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise UsageError("arquivo com codificação inválida (esperado UTF-8): %s" % (path,)) from error
    return text.replace("\r\n", "\n").replace("\r", "\n")


def readable_file(path):
    return os.path.isfile(path)
