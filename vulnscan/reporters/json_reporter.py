import json
from pathlib import Path

def save_json_report(report: dict, outpath: str):
    p = Path(outpath)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"[reporter] JSON report saved: {p}")
