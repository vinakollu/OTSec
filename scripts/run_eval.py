#!/usr/bin/env python3
"""Run the full evaluation suite.

    python scripts/run_eval.py                     # all scenarios + plots
    python scripts/run_eval.py --stealth-sweep     # plus the R4 blind-band sweep
    python scripts/run_eval.py --scenario overflow --no-plots
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from otguard.eval.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
