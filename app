#!/usr/bin/env python3
"""Executable entry point for dependency-auditor.

Keeps ``src/`` importable without installation so the repository can be cloned
and run directly, with the standard library only.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from auditor.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
