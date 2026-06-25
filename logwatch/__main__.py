"""Module entry point so the package is runnable as ``python -m logwatch``.

This file deliberately contains no logic of its own: it simply forwards to
:func:`logwatch.cli.main` and propagates its integer exit code to the shell.
Keeping ``__main__`` thin means the real logic lives in importable modules
that the test-suite can exercise directly.
"""

import sys

from .cli import main

if __name__ == "__main__":
    # main() returns a process exit code (0 == clean, non-zero == problem).
    sys.exit(main())
