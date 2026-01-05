import json
from pathlib import Path
from typing import Dict, List

DB_PATH = Path(__file__).parent.parent / "data" / "vuln_db.json"

def load_vuln_db():
    try:
        with open(DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def match_banners_to_vulns(banners: Dict[str, str]) -> Dict[str, List[Dict]]:
    db = load_vuln_db()
    results = {}
    for port, banner in banners.items():
        findings = []
        if not banner:
            results[port] = findings
            continue
        b = banner.lower()
        for key, entries in db.items():
            if key.lower() in b:
                for e in entries:
                    item = e.copy()
                    item["reason"] = f"matched '{key}' in banner"
                    findings.append(item)
        results[port] = findings
    return results
