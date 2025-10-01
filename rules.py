import re
from collections import defaultdict, deque
from datetime import timedelta
from typing import List, Dict, Any

# Configurable thresholds
BRUTE_FORCE_WINDOW = timedelta(minutes=5)
BRUTE_FORCE_THRESHOLD = 10

HIGH_RATE_WINDOW = timedelta(minutes=1)
HIGH_RATE_THRESHOLD = 100  # requests in 1 minute

ERROR_404_SCAN_THRESHOLD = 50  # many 404s in short time

# Known suspicious user agents or markers
SUSPICIOUS_AGENTS = [
    "sqlmap", "nikto", "acunetix", "fimap", "nmap", "masscan", "curl", "wget", "python-requests"
]

SQLI_PATTERNS = [
    r"(?i)union.*select", r"(?i)select.+from", r"(?i)or \d+=\d+", r"(?i)' or '1'='1", r"(--|\bAND\b.*\bOR\b)"
]
XSS_PATTERNS = [
    r"(?i)<script\b", r"(?i)javascript:", r"(?i)onerror=", r"(?i)onload=", r"(?i)<img.+src="
]

def check_sql_injection(path: str) -> bool:
    if not path:
        return False
    for p in SQLI_PATTERNS:
        if re.search(p, path):
            return True
    return False

def check_xss(path: str) -> bool:
    if not path:
        return False
    for p in XSS_PATTERNS:
        if re.search(p, path):
            return True
    return False

def check_suspicious_agent(agent: str) -> bool:
    if not agent:
        return False
    a = agent.lower()
    for s in SUSPICIOUS_AGENTS:
        if s in a:
            return True
    return False

class StatefulDetectors:
    """
    Keeps short-term state for behaviors like brute force, high request rate, scanning.
    """

    def __init__(self):
        # ip -> deque of request times
        self.ip_times = defaultdict(deque)
        # ip -> deque of (time, status)
        self.ip_status_times = defaultdict(deque)

        # ip -> deque of times with 404
        self.ip_404 = defaultdict(deque)

    def feed(self, event: Dict[str, Any]) -> List[Dict]:
        """
        Feed a parsed log event and return list of alert dicts (could be empty).
        """
        alerts = []
        ip = event.get("ip")
        t = event.get("time")
        status = event.get("status")
        path = event.get("path")
        agent = event.get("agent")
        raw = event.get("raw")

        # Keep request times
        if t:
            q = self.ip_times[ip]
            q.append(t)
            # evict old entries
            while q and (t - q[0]) > HIGH_RATE_WINDOW:
                q.popleft()
            if len(q) >= HIGH_RATE_THRESHOLD:
                alerts.append({
                    "rule": "high_request_rate",
                    "ip": ip,
                    "count": len(q),
                    "window_seconds": HIGH_RATE_WINDOW.total_seconds(),
                    "sample": raw
                })

        # Failed login / 401+403 near login endpoints
        if status in (401, 403):
            qs = self.ip_status_times[ip]
            qs.append((t, status, path, raw))
            # remove old
            while qs and (t - qs[0][0]) > BRUTE_FORCE_WINDOW:
                qs.popleft()
            # heuristic: if many 401/403 in small window -> possible brute force
            if len(qs) >= BRUTE_FORCE_THRESHOLD:
                alerts.append({
                    "rule": "brute_force_login",
                    "ip": ip,
                    "count": len(qs),
                    "window_seconds": BRUTE_FORCE_WINDOW.total_seconds(),
                    "samples": [x[3] for x in list(qs)[-5:]]
                })

        # Lots of 404s -> scanning/bot
        if status == 404:
            q404 = self.ip_404[ip]
            q404.append(t)
            while q404 and (t - q404[0]) > HIGH_RATE_WINDOW:
                q404.popleft()
            if len(q404) >= ERROR_404_SCAN_THRESHOLD:
                alerts.append({
                    "rule": "404_scanning",
                    "ip": ip,
                    "count": len(q404),
                    "sample": raw
                })

        # Static checks (stateless)
        if check_sql_injection(path or ""):
            alerts.append({
                "rule": "sqli_pattern",
                "ip": ip,
                "path": path,
                "sample": raw
            })

        if check_xss(path or ""):
            alerts.append({
                "rule": "xss_pattern",
                "ip": ip,
                "path": path,
                "sample": raw
            })

        if check_suspicious_agent(agent or ""):
            alerts.append({
                "rule": "suspicious_user_agent",
                "ip": ip,
                "agent": agent,
                "sample": raw
            })

        return alerts
