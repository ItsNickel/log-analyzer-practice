import re
from datetime import datetime
from typing import Optional, Dict

# Regex for Apache/Nginx combined log format
COMBINED_LOG_RE = re.compile(
    r'(?P<ip>\S+) (?P<ident>\S+) (?P<authuser>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\S+) "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)"'
)

COMMON_LOG_RE = re.compile(
    r'(?P<ip>\S+) (?P<ident>\S+) (?P<authuser>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\S+)'
)

TIME_FORMATS = [
    "%d/%b/%Y:%H:%M:%S %z",   # e.g. 10/Oct/2000:13:55:36 -0700
    "%d/%b/%Y:%H:%M:%S"      # fallback without tz
]

def parse_apache_time(timestr: str) -> Optional[datetime]:
    for fmt in TIME_FORMATS:
        try:
            return datetime.strptime(timestr, fmt)
        except Exception:
            continue
    return None

def parse_line(line: str) -> Optional[Dict]:
    """
    Try to parse a log line in Combined or Common log format.
    Returns a dict with fields or None if parsing fails.
    """
    m = COMBINED_LOG_RE.match(line)
    if m:
        d = m.groupdict()
        parsed_time = parse_apache_time(d["time"])
        request_parts = d["request"].split()
        method = path = protocol = None
        if len(request_parts) >= 1:
            method = request_parts[0]
        if len(request_parts) >= 2:
            path = request_parts[1]
        if len(request_parts) >= 3:
            protocol = request_parts[2]
        return {
            "ip": d["ip"],
            "time": parsed_time,
            "method": method,
            "path": path,
            "protocol": protocol,
            "status": int(d["status"]),
            "size": None if d["size"] == "-" else int(d["size"]),
            "referrer": d.get("referrer"),
            "agent": d.get("agent"),
            "raw": line.strip()
        }
    m2 = COMMON_LOG_RE.match(line)
    if m2:
        d = m2.groupdict()
        parsed_time = parse_apache_time(d["time"])
        request_parts = d["request"].split()
        method = path = protocol = None
        if len(request_parts) >= 1:
            method = request_parts[0]
        if len(request_parts) >= 2:
            path = request_parts[1]
        if len(request_parts) >= 3:
            protocol = request_parts[2]
        return {
            "ip": d["ip"],
            "time": parsed_time,
            "method": method,
            "path": path,
            "protocol": protocol,
            "status": int(d["status"]),
            "size": None if d["size"] == "-" else int(d["size"]),
            "referrer": None,
            "agent": None,
            "raw": line.strip()
        }
    # not parsed
    return None
