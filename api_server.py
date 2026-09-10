#!/usr/bin/env python3
"""
Flask API server for NetAudit.

Wraps all existing backend modules and exposes REST endpoints
for the React frontend. Does NOT modify any existing code.

Usage:
    source .venv/bin/activate
    python api_server.py
"""

import os
import sys
import json
import tempfile
import shutil
from datetime import datetime

from flask import (
    Flask, request, jsonify, send_file
)
from flask_cors import CORS

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from benchmark_audit.rule_engine import (
    evaluate_config,
    detect_vendor,
    parse_config,
)
from benchmark_audit.report_generator import generate_pdf_report

app = Flask(__name__)
CORS(app)

# Temporary upload directory
UPLOAD_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "uploads"
)
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Store results in memory for PDF download
_audit_results = {}


# --------------------------------------------------
# VENDOR DISPLAY NAMES
# --------------------------------------------------

VENDOR_DISPLAY = {
    "cisco_ios": "Cisco IOS / IOS-XE",
    "cisco_asa": "Cisco ASA",
    "juniper": "Juniper JunOS",
    "paloalto": "Palo Alto PAN-OS",
    "fortinet": "Fortinet FortiOS",
    "arista": "Arista EOS",
    "huawei": "Huawei VRP",
    "aruba": "Aruba AOS-CX",
    "unknown": "Unknown Vendor",
}


# --------------------------------------------------
# UPLOAD & DETECT VENDOR
# --------------------------------------------------

@app.route("/api/upload", methods=["POST"])
def upload_config():
    """
    Accept one or more config files.
    Returns detected vendor info for each file.
    """
    if "files" not in request.files:
        return jsonify({"error": "No files provided"}), 400

    files = request.files.getlist("files")
    if not files or files[0].filename == "":
        return jsonify({"error": "No files selected"}), 400

    results = []
    for f in files:
        # Save to upload dir
        filename = f.filename
        filepath = os.path.join(UPLOAD_DIR, filename)
        f.save(filepath)

        # Read and detect vendor
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()

        config_lines = parse_config(filepath)
        vendor = detect_vendor(config_lines)

        vendor_label = VENDOR_DISPLAY.get(vendor, vendor)

        results.append({
            "filename": filename,
            "filepath": filepath,
            "vendor": vendor,
            "vendor_display": vendor_label,
            "lines": len(config_lines),
            "size": os.path.getsize(filepath),
        })

    return jsonify({
        "status": "ok",
        "files": results,
    })


# --------------------------------------------------
# RUN BENCHMARK AUDIT
# --------------------------------------------------

@app.route("/api/audit", methods=["POST"])
def run_audit():
    """
    Run benchmark audit on uploaded files.
    Accepts JSON body with list of filenames.
    Returns full audit results.
    """
    data = request.get_json()
    if not data or "files" not in data:
        return jsonify({"error": "No files specified"}), 400

    filenames = data["files"]
    results = []

    for filename in filenames:
        filepath = os.path.join(UPLOAD_DIR, filename)
        if not os.path.isfile(filepath):
            return jsonify({
                "error": f"File not found: {filename}"
            }), 404

        try:
            result = evaluate_config(config_path=filepath)
            results.append(result)
        except Exception as e:
            return jsonify({
                "error": f"Audit failed for {filename}: {str(e)}"
            }), 500

    # Store for PDF download
    session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    _audit_results[session_id] = results

    # Build response
    response_data = []
    for r in results:
        vendor_label = VENDOR_DISPLAY.get(
            r.detected_vendor, r.detected_vendor
        )

        passed = []
        for rule in r.passed_rules:
            passed.append({
                "rule_id": rule.rule_id,
                "category": rule.category,
                "description": rule.description,
                "severity": rule.severity,
                "evidence": rule.evidence,
                "sources": rule.benchmark_sources,
            })

        failed = []
        for rule in r.failed_rules:
            failed.append({
                "rule_id": rule.rule_id,
                "category": rule.category,
                "description": rule.description,
                "severity": rule.severity,
                "evidence": rule.evidence,
                "remediation": rule.remediation,
                "sources": rule.benchmark_sources,
            })

        unknown = []
        for cmd in r.unknown_commands:
            unknown.append({
                "line_number": cmd.line_number,
                "command": cmd.command,
                "status": cmd.status,
            })

        response_data.append({
            "device_name": r.device_name,
            "config_file": r.config_file,
            "vendor": r.detected_vendor,
            "vendor_display": vendor_label,
            "total_rules": r.total_rules,
            "security_score": r.security_score,
            "max_score": r.max_score,
            "risk_level": r.risk_level,
            "passed_rules": passed,
            "failed_rules": failed,
            "unknown_commands": unknown,
            "benchmark_coverage": r.benchmark_coverage,
        })

    return jsonify({
        "status": "ok",
        "session_id": session_id,
        "devices": response_data,
        "summary": {
            "total_devices": len(results),
            "total_passed": sum(
                len(r.passed_rules) for r in results
            ),
            "total_failed": sum(
                len(r.failed_rules) for r in results
            ),
            "total_unknown": sum(
                len(r.unknown_commands) for r in results
            ),
            "total_score": sum(
                r.security_score for r in results
            ),
            "total_max_score": sum(
                r.max_score for r in results
            ),
        },
    })


# --------------------------------------------------
# DOWNLOAD PDF REPORT
# --------------------------------------------------

@app.route("/api/report/pdf/<session_id>", methods=["GET"])
def download_pdf(session_id):
    """Download the PDF report for a completed audit session."""
    if session_id not in _audit_results:
        return jsonify({"error": "Session not found"}), 404

    results = _audit_results[session_id]

    # Generate PDF to temp location
    pdf_path = generate_pdf_report(results)

    return send_file(
        pdf_path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"audit_report_{session_id}.pdf",
    )


# --------------------------------------------------
# HEALTH CHECK
# --------------------------------------------------

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "version": "2.0.0",
        "modules": {
            "benchmark_audit": True,
            "report_generator": True,
        },
    })


# --------------------------------------------------
# MAIN
# --------------------------------------------------

if __name__ == "__main__":
    print("\n  NetAudit API Server")
    print("  ===================")
    print("  http://localhost:5001")
    print("  Endpoints:")
    print("    POST /api/upload       — Upload config files")
    print("    POST /api/audit        — Run benchmark audit")
    print("    GET  /api/report/pdf   — Download PDF report")
    print("    GET  /api/health       — Health check")
    print()

    app.run(
        host="0.0.0.0",
        port=5001,
        debug=True,
    )
