#!/usr/bin/env python3
"""
Mass PII / Secret Finder — local GUI (Flask) — v2

Run:
    python app.py
Then open http://127.0.0.1:7331 in your browser.

This runs entirely on your machine. Scans only fire when you click "Scan",
require you to explicitly confirm authorization, and only touch hosts
within the scope you declare — there's no telemetry, no external service
involved beyond the target(s) you specify.
"""

import io
import sqlite3
import threading
import time
import uuid

from flask import Flask, request, jsonify, render_template, send_file

from core.crawler import discover_js_files
from core.extractor import run_extraction
from core.validator import validate_findings, diff_findings
from core.report import REPORT_BUILDERS
from core.scope import ScopeGuard

app = Flask(__name__)

JOBS = {}
JOBS_LOCK = threading.Lock()

DB_PATH = "scan_history.db"


def _init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            job_id TEXT PRIMARY KEY,
            target TEXT,
            started_at REAL,
            finished_at REAL,
            findings_count INTEGER,
            critical_count INTEGER,
            high_count INTEGER,
            report_json TEXT
        )
    """)
    conn.commit()
    conn.close()


_init_db()


def _save_history(job_id, target, started_at, findings, meta):
    counts = {"CRITICAL": 0, "HIGH": 0}
    for f in findings:
        if f["severity"] in counts:
            counts[f["severity"]] += 1
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT OR REPLACE INTO scan_history VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            job_id, target, started_at, time.time(), len(findings),
            counts["CRITICAL"], counts["HIGH"],
            REPORT_BUILDERS["json"](target, findings, meta),
        ),
    )
    conn.commit()
    conn.close()


def run_scan_job(job_id, target, opts):
    job = JOBS[job_id]
    try:
        scope = ScopeGuard(
            target,
            extra_scope=opts["scope"],
            allow_subdomains=not opts["no_subdomains"],
        )

        job["status"] = "crawling"
        job["progress"] = "Discovering JS files..."
        disc = discover_js_files(
            target,
            max_files=opts["max_files"],
            timeout=opts["timeout"],
            scope=scope,
            requests_per_second=opts["rate_limit"],
            enumerate_subdomains=opts["enumerate_subdomains"],
            respect_robots=not opts["no_robots"],
        )
        job["meta"] = {
            "js_file_count": len(disc["js_files"]),
            "sourcemap_count": len(disc["sourcemaps"]),
            "sourcemaps": disc["sourcemaps"],
            "unreachable_paths": disc["errors"][:30],
            "pages_crawled": len(disc["pages_crawled"]),
            "subdomain_count": len(disc.get("subdomains_found", [])),
            "subdomains_found": disc.get("subdomains_found", []),
            "scope_excluded_sample": disc.get("scope_excluded_sample", []),
        }

        job["status"] = "extracting"
        job["progress"] = f"Scanning {len(disc['js_files'])} JS file(s) for secrets..."
        findings = run_extraction(disc["js_files"])
        findings = [f for f in findings if f["confidence"] >= opts["min_confidence"]]

        job["status"] = "validating"
        job["progress"] = f"Validating {len(findings)} finding(s)..."
        findings = validate_findings(
            findings,
            base_url=target,
            do_network_probe=opts["probe"],
            timeout=opts["timeout"],
            scope=scope,
            requests_per_second=opts["rate_limit"],
        )

        job["findings"] = findings
        job["target"] = target
        job["status"] = "done"
        job["progress"] = "Complete"

        _save_history(job_id, target, job["started_at"], findings, job["meta"])
    except Exception as e:
        job["status"] = "error"
        job["progress"] = f"Error: {e}"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.get_json(force=True)
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "target is required"}), 400
    if not data.get("confirm_authorized"):
        return jsonify({
            "error": "confirm_authorized is required — confirm you own this target or are "
                     "authorized to test it (bug bounty scope / client engagement) before scanning."
        }), 400

    job_id = uuid.uuid4().hex[:12]
    opts = {
        "max_files": int(data.get("max_files", 150)),
        "timeout": int(data.get("timeout", 10)),
        "probe": bool(data.get("probe", True)),
        "min_confidence": int(data.get("min_confidence", 0)),
        "scope": [s.strip() for s in data.get("scope", []) if s.strip()],
        "no_subdomains": bool(data.get("no_subdomains", False)),
        "enumerate_subdomains": bool(data.get("enumerate_subdomains", False)),
        "no_robots": bool(data.get("no_robots", False)),
        "rate_limit": float(data.get("rate_limit", 8.0)),
    }
    JOBS[job_id] = {
        "status": "queued",
        "progress": "Queued...",
        "findings": [],
        "meta": {},
        "target": target,
        "started_at": time.time(),
    }

    thread = threading.Thread(target=run_scan_job, args=(job_id, target, opts), daemon=True)
    thread.start()
    return jsonify({"job_id": job_id})


@app.route("/api/status/<job_id>")
def job_status(job_id):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "unknown job"}), 404
    return jsonify({
        "status": job["status"],
        "progress": job["progress"],
        "findings": job.get("findings", []),
        "meta": job.get("meta", {}),
        "target": job.get("target", ""),
    })


@app.route("/api/report/<job_id>/<fmt>")
def download_report(job_id, fmt):
    job = JOBS.get(job_id)
    if not job or job["status"] != "done":
        return jsonify({"error": "job not ready"}), 400
    builder = REPORT_BUILDERS.get(fmt)
    if not builder:
        return jsonify({"error": "unsupported format"}), 400

    content = builder(job["target"], job["findings"], job["meta"])
    mimetypes = {
        "json": "application/json", "sarif": "application/json",
        "html": "text/html", "markdown": "text/markdown", "md": "text/markdown",
        "csv": "text/csv",
    }
    ext = {"markdown": "md"}.get(fmt, fmt)
    return send_file(
        io.BytesIO(content.encode()), mimetype=mimetypes.get(fmt, "text/plain"),
        as_attachment=True, download_name=f"report-{job_id}.{ext}",
    )


@app.route("/api/history")
def history():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT job_id, target, started_at, finished_at, findings_count, critical_count, high_count "
        "FROM scan_history ORDER BY started_at DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return jsonify([
        {
            "job_id": r[0], "target": r[1], "started_at": r[2], "finished_at": r[3],
            "findings_count": r[4], "critical_count": r[5], "high_count": r[6],
        }
        for r in rows
    ])


@app.route("/api/diff", methods=["POST"])
def diff_route():
    data = request.get_json(force=True)
    job_a, job_b = JOBS.get(data.get("job_a")), JOBS.get(data.get("job_b"))
    if not job_a or not job_b:
        return jsonify({"error": "one or both job ids not found"}), 404
    d = diff_findings(job_a.get("findings", []), job_b.get("findings", []))
    return jsonify({
        "new_count": len(d["new"]), "resolved_count": len(d["resolved"]),
        "persisting_count": len(d["persisting"]), "new": d["new"],
    })


if __name__ == "__main__":
    print("\n  Mass PII / Secret Finder GUI (v2)")
    print("  -> http://127.0.0.1:7331\n")
    print("  Only scan targets you are authorized to test.\n")
    app.run(host="127.0.0.1", port=7331, debug=False)
