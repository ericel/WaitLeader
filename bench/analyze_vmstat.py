#!/usr/bin/env python3
"""Parse vmstat output and report peak context-switch rate."""

from __future__ import annotations

import argparse
from pathlib import Path


def parse_peak_cs(path: Path) -> int:
    peak = 0
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        parts = line.split()
        if not parts:
            continue

        if parts[0] == "cs" and len(parts) >= 2:
            try:
                peak = max(peak, int(parts[1]))
            except ValueError:
                pass
            continue

        if len(parts) >= 12 and parts[0].isdigit():
            try:
                peak = max(peak, int(parts[11]))
            except ValueError:
                pass

    return peak


def main() -> int:
    parser = argparse.ArgumentParser(description="Report peak vmstat cs values")
    parser.add_argument("logs", nargs="+", type=Path)
    args = parser.parse_args()

    for log in args.logs:
        print(f"{log}: peak cs = {parse_peak_cs(log)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
