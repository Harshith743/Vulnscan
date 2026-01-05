# webapp/app.py
# Run from project root:
#   python webapp\app.py
# or
#   python -m webapp.app

import sys
import os
import time
import threading
import uuid
import json

# ensure project root is on sys.path so we can import vulnscan package
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, abort

# Import scanner pieces directly so we can update progress
from vulnscan.scanner.tcp import parse_ports, tcp_scan, grab_banner
from vulnscan.enrichers.vulnmatcher import match_banners_to_vulns
from vulnscan.reporters.json_reporter import save_json_report
from vulnscan.reporters.html_reporter import save_html_report

# Try to import nmap integration (either package or top-level modules)
try:
    from vulnscan.scanner import nmap_integration as nm_mod
except Exception:
    try:
        import modules.nmap_integration as nm_mod
    except Exception:
        nm_mod = None

app = Flask(__name__)

# -- project / reports path setup (use absolute paths so save/serve agree) --
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# In-memory progress store (scan_id -> dict)
SCAN_RESULTS = {}

def log_add(scan_id, message):
    """Append a timestamped message to the scan's log list."""
    entry = f"[{time.strftime('%H:%M:%S')}] {message}"
    SCAN_RESULTS.setdefault(scan_id, {}).setdefault("log", []).append(entry)

def background_scan(scan_id, target, ports, use_nmap):
    """Perform the scan in steps and update SCAN_RESULTS for progress polling."""
    try:
        SCAN_RESULTS[scan_id] = {"target": target, "done": False, "progress": 0, "log": []}
        log_add(scan_id, f"Starting scan for {target} ports={ports} (scan id {scan_id})")

        # Step 1 - parse ports
        port_list = parse_ports(ports)
        log_add(scan_id, f"Parsed {len(port_list)} ports")
        SCAN_RESULTS[scan_id]["progress"] = 5

        # Step 2 - TCP scan
        log_add(scan_id, "Running TCP scan...")
        open_ports = tcp_scan(target, port_list)
        SCAN_RESULTS[scan_id]["open_ports"] = open_ports
        log_add(scan_id, f"Found open ports: {open_ports}")
        SCAN_RESULTS[scan_id]["progress"] = 35

        # Step 3 - banner grabbing (per-port)
        banners = {}
        total = len(open_ports) or 1
        for idx, p in enumerate(open_ports, start=1):
            log_add(scan_id, f"Grabbing banner on port {p}...")
            b = grab_banner(target, p)
            banners[str(p)] = b
            log_add(scan_id, f"Banner for {p}: {b[:140]!r}")
            # progress within banner grabbing
            SCAN_RESULTS[scan_id]["progress"] = 35 + int((idx / total) * 25)
        SCAN_RESULTS[scan_id]["banners"] = banners

        # Step 4 - optional nmap enrichment
        if use_nmap:
            if nm_mod is None:
                log_add(scan_id, "Nmap integration not available on this host; skipping.")
            else:
                log_add(scan_id, "Running Nmap enrichment (this may take a while)...")
                try:
                    nmap_info = nm_mod.nmap_scan(target, open_ports)
                    SCAN_RESULTS[scan_id]["nmap"] = nmap_info
                    log_add(scan_id, "Nmap enrichment complete.")
                except Exception as e:
                    log_add(scan_id, f"Nmap failed: {e}")
            SCAN_RESULTS[scan_id]["progress"] = 75
        else:
            SCAN_RESULTS[scan_id]["progress"] = 60

        # Step 5 - vuln matching
        log_add(scan_id, "Matching banners to local vuln DB...")
        issues = match_banners_to_vulns(banners)
        SCAN_RESULTS[scan_id]["issues"] = issues
        SCAN_RESULTS[scan_id]["progress"] = 85

        # Step 6 - save reports (use absolute REPORTS_DIR)
        out_json = os.path.join(REPORTS_DIR, f"{scan_id}.json")
        out_html = os.path.join(REPORTS_DIR, f"{scan_id}.html")
        report = {
            "target": target,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "open_ports": open_ports,
            "banners": banners,
            "issues": issues
        }
        if "nmap" in SCAN_RESULTS[scan_id]:
            report["nmap"] = SCAN_RESULTS[scan_id]["nmap"]

        log_add(scan_id, "Saving JSON report...")
        save_json_report(report, out_json)
        SCAN_RESULTS[scan_id]["json"] = out_json
        SCAN_RESULTS[scan_id]["progress"] = 90

        log_add(scan_id, "Saving HTML report...")
        save_html_report(report, issues, out_html)
        SCAN_RESULTS[scan_id]["html"] = out_html
        SCAN_RESULTS[scan_id]["progress"] = 98

        # done
        SCAN_RESULTS[scan_id]["done"] = True
        SCAN_RESULTS[scan_id]["progress"] = 100
        log_add(scan_id, "Scan finished successfully.")
    except Exception as e:
        SCAN_RESULTS[scan_id]["error"] = str(e)
        SCAN_RESULTS[scan_id]["done"] = True
        SCAN_RESULTS[scan_id]["progress"] = SCAN_RESULTS[scan_id].get("progress", 0)
        log_add(scan_id, f"Scan failed: {e}")

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        if not target:
            return "Target required", 400
        ports = request.form.get("ports", "1-1024").strip()
        use_nmap = "use_nmap" in request.form
        scan_id = str(uuid.uuid4())[:8]
        # initialize scan state
        SCAN_RESULTS[scan_id] = {"target": target, "done": False, "progress": 0, "log": []}
        thread = threading.Thread(target=background_scan, args=(scan_id, target, ports, use_nmap), daemon=True)
        thread.start()
        return redirect(url_for("result", scan_id=scan_id))
    return render_template("index.html")

@app.route("/result/<scan_id>")
def result(scan_id):
    if scan_id not in SCAN_RESULTS:
        return "Scan ID not found.", 404
    return render_template("result.html", scan_id=scan_id)

@app.route("/status/<scan_id>")
def status(scan_id):
    """Return JSON status for polling."""
    data = SCAN_RESULTS.get(scan_id)
    if not data:
        return jsonify({"error":"not found"}), 404
    # return only keys frontend needs
    return jsonify({
        "done": bool(data.get("done")),
        "progress": int(data.get("progress", 0)),
        "log": data.get("log", [])[-20:],  # last 20 log lines
        "html": data.get("html"),
        "json": data.get("json"),
        "error": data.get("error")
    })

@app.route("/reports/<path:filename>")
def serve_report(filename):
    """Serve saved report files from REPORTS_DIR"""
    # build safe absolute path
    full = os.path.normpath(os.path.join(REPORTS_DIR, filename))
    # ensure the full path is inside REPORTS_DIR
    if not full.startswith(os.path.abspath(REPORTS_DIR)):
        return "Forbidden", 403
    if not os.path.exists(full):
        return "File not found", 404
    return send_file(full)

if __name__ == "__main__":
    app.run(debug=True)
