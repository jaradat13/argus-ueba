from __future__ import annotations

import argparse
from datetime import datetime

from .baseline import Baseline
from .ollama import fallback_summary, summarize_with_ollama
from .parsers import parse_files
from .reporting import json_report, timeline_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Argus UEBA-lite anomaly detector")
    parser.add_argument("--baseline", nargs="+", required=True, help="Historical auth/audit log files")
    parser.add_argument("--events", nargs="+", required=True, help="Current auth/audit log files to evaluate")
    parser.add_argument("--threshold", type=int, default=50, help="Minimum anomaly score to report")
    parser.add_argument("--format", choices=["timeline", "json"], default="timeline")
    parser.add_argument("--year", type=int, default=datetime.now().year, help="Year for syslog timestamps")
    parser.add_argument("--ollama-model", default="", help="Optional local Ollama model, e.g. llama3.1")
    parser.add_argument("--ollama-host", default="http://localhost:11434")
    args = parser.parse_args(argv)

    baseline_events = parse_files(args.baseline, year=args.year)
    current_events = parse_files(args.events, year=args.year)
    baseline = Baseline.from_events(baseline_events)
    findings = baseline.evaluate(current_events, threshold=args.threshold)

    summary = (
        summarize_with_ollama(findings, model=args.ollama_model, host=args.ollama_host)
        if args.ollama_model
        else fallback_summary(findings)
    )

    if args.format == "json":
        print(json_report(findings, summary=summary))
    else:
        print(timeline_report(findings, summary=summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
