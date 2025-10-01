# Log Analyzer for Security Events

**Project**: Lightweight log analyzer that detects suspicious security events in server logs (Apache/Nginx common/combined formats).  
**Author**: Your Name — (put your GitHub handle here)  
**Stack**: Python 3 (standard library). No paid tools required.

---

## Why this is valuable
- Demonstrates practical detection of common attacks (brute force, SQLi, XSS, scanning).
- Shows competency in log parsing, regex, temporal analysis, and tooling (CLI + structured outputs).
- Easy to extend to other log sources (Windows EVTX, syslog) and to ship alerts to SIEMs.

---

## Features
- Parse Apache/Nginx Common & Combined log formats.
- Rule-based detections:
  - Brute-force login detection (many 401/403 within a short window).
  - High request rate from a single IP.
  - 404 scanning detection.
  - SQLi & XSS pattern detection in request paths.
  - Suspicious user-agent detection (sqlmap, nikto, curl, wget, etc).
- Outputs:
  - `outputs/alerts.json` (structured JSON)
  - `outputs/alerts.csv` (tabular CSV)
- Modular design: add new rules in `log_analyzer/rules.py`, new parsers in `log_analyzer/parsers.py`.

---

## Quick start

1. Clone repository:
   ```bash
   git clone https://github.com/<you>/log-analyzer.git
   cd log-analyzer

2. (Optional) Create a virtualenv:
    python3 -m venv venv
    source venv/bin/activate

3.  Run the analyzer against the example log:
    python3 -m log_analyzer.analyzer examples/sample_access.log

4. Inspect outputs:
    outputs/alerts.json
    outputs/alerts.csv

## How it works (high level)

- parsers.py 
    attempts to parse each line into structured fields (ip, time, method, path, status, agent, raw).

- rules.py 
    contains stateless regex-based checks (SQLi/XSS) and stateful detectors that track request times per IP to detect spikes, many 401/403s (brute force), and lots of 404s (scanners).

- analyzer.py 
    ties everything together: iterates over the log, feeds each parsed event to detectors, and writes alerts.