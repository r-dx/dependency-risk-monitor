#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from monitor.core import AdvisoryUnavailable, update_report

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        changed = update_report(args.input, args.output)
    except AdvisoryUnavailable as exc:
        print(f"advisory service unavailable; retained previous report: {exc}")
        return 0
    print("report updated" if changed else "no meaningful advisory change")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
