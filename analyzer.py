import argparse
import sys
from typing import List, Dict
from log_analyzer.parsers import parse_line
from log_analyzer.rules import StatefulDetectors
from log_analyzer.utils import write_json, summarize_alerts
import csv
import os

def analyze_file(path: str, max_lines: int = None) -> List[Dict]:
    detectors = StatefulDetectors()
    alerts = []
    parsed = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            if max_lines and i >= max_lines:
                break
            parsed += 1
            p = parse_line(line)
            if not p:
                # Could add more parsers or skip
                continue
            new_alerts = detectors.feed(p)
            for a in new_alerts:
                # add context fields
                a["log_line_number"] = i + 1
                alerts.append(a)
    return alerts

def save_csv(alerts: List[Dict], outpath: str):
    if not alerts:
        print("No alerts to write to CSV.")
        return
    keys = sorted({k for a in alerts for k in a.keys()})
    with open(outpath, "w", newline='', encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        for a in alerts:
            # flatten values that are lists
            row = {k: (", ".join(v) if isinstance(v, list) else v) for k,v in a.items()}
            w.writerow(row)

def main():
    ap = argparse.ArgumentParser(description="Simple Log Analyzer for Security Events")
    ap.add_argument("logfile", help="Path to the log file (Apache/Nginx combined/common)")
    ap.add_argument("--out-json", default="outputs/alerts.json", help="Write alerts to JSON")
    ap.add_argument("--out-csv", default="outputs/alerts.csv", help="Write alerts to CSV")
    ap.add_argument("--max-lines", type=int, default=None, help="Max lines to process (for testing)")
    args = ap.parse_args()

    os.makedirs("outputs", exist_ok=True)
    alerts = analyze_file(args.logfile, max_lines=args.max_lines)
    print(f"Processed. Alerts found: {len(alerts)}")
    print(summarize_alerts(alerts))

    write_json(args.out_json, alerts)
    save_csv(alerts, args.out_csv)
    print(f"Wrote JSON -> {args.out_json} and CSV -> {args.out_csv}")

if __name__ == "__main__":
    main()
