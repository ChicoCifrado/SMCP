"""``python -m delm`` — the same CLI as the ``delm`` console script (issue #9).

Deliberately a two-liner: one parser, one entry point, so ``python -m delm
demo`` and ``delm demo`` can never drift apart.
"""

from __future__ import annotations

from smcp.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
