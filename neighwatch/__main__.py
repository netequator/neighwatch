"""Package entrypoint when invoked via `python -m neighwatch`."""

from __future__ import annotations

import sys

from neighwatch.cli import main

if __name__ == "__main__":
    sys.exit(main())
