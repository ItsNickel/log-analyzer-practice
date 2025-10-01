import json
from typing import Any, List, Dict

def write_json(path: str, data: Any):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)

def summarize_alerts(alerts: List[Dict]) -> Dict[str, int]:
    counts = {}
    for a in alerts:
        r = a.get("rule")
        counts[r] = counts.get(r, 0) + 1
    return counts
