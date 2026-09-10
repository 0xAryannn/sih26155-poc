#!/usr/bin/env python3
"""
CLI entry point for benchmark-based configuration auditing.

Supports multiple config files in a single run — auto-detects
the vendor for each file and generates one combined report.

Usage:
    python benchmark_audit/run_benchmark_audit.py ASA.txt
    python benchmark_audit/run_benchmark_audit.py ASA.txt configs/juniper_srx.cfg aruba_aoscx_partial.cfg
    python benchmark_audit/run_benchmark_audit.py *.cfg *.txt
    python benchmark_audit/run_benchmark_audit.py ASA.txt --json-only

Or as a module:
    python -m benchmark_audit.run_benchmark_audit ASA.txt configs/juniper_srx.cfg
"""

import sys
import os
import json
import argparse
from datetime import datetime

# Ensure the parent directory is in the path for imports
sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from benchmark_audit.rule_engine import (
    evaluate_config,
    save_report,
    BenchmarkAuditResult,
)


# --------------------------------------------------
# DISPLAY HELPERS
# --------------------------------------------------

def _color(text: str, code: str) -> str:
    """Apply ANSI color code if terminal supports it."""
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def _red(text):
    return _color(text, "91")


def _green(text):
    return _color(text, "92")


def _yellow(text):
    return _color(text, "93")


def _cyan(text):
    return _color(text, "96")


def _bold(text):
    return _color(text, "1")


def _dim(text):
    return _color(text, "2")


def _severity_color(severity: str) -> str:
    """Color-code a severity label."""
    s = severity.upper()
    if s in ("HIGH", "CRITICAL"):
        return _red(s)
    elif s in ("MEDIUM",):
        return _yellow(s)
    elif s in ("PASS",):
        return _green(s)
    else:
        return _cyan(s)


def _risk_color(risk: str) -> str:
    """Color-code a risk level."""
    if risk == "CRITICAL":
        return _red(_bold(risk))
    elif risk == "HIGH":
        return _red(risk)
    elif risk == "MEDIUM":
        return _yellow(risk)
    else:
        return _green(risk)


VENDOR_DISPLAY_NAMES = {
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
# DISPLAY: SINGLE DEVICE SECTION
# --------------------------------------------------

def _display_device_section(
    result: BenchmarkAuditResult,
    index: int,
    total: int,
) -> None:
    """Print one device's results as a section in the combined report."""

    vendor_label = VENDOR_DISPLAY_NAMES.get(
        result.detected_vendor, result.detected_vendor
    )

    print()
    print(_bold(_cyan("╔" + "═" * 58 + "╗")))
    print(_bold(_cyan(
        f"║  DEVICE {index}/{total}: "
        f"{result.device_name}"
        + " " * max(0, 38 - len(result.device_name) - len(str(index)) - len(str(total)))
        + "║"
    )))
    print(_bold(_cyan("╚" + "═" * 58 + "╝")))

    print(f"\n  Config:      {result.config_file}")
    print(f"  Vendor:      {_cyan(vendor_label)}")
    print(f"  Total Rules: {result.total_rules}")
    print(
        f"  Score:       "
        f"{result.security_score}/{result.max_score}"
    )
    print(f"  Risk Level:  {_risk_color(result.risk_level)}")

    # ---- PASSED RULES ----
    print()
    print(_bold("-" * 60))
    print(
        _green(_bold(
            f"  ✓ PASSED ({len(result.passed_rules)})"
        ))
    )
    print(_bold("-" * 60))

    for r in result.passed_rules:
        print(
            f"\n  [{_green('PASS')}] "
            f"{r.rule_id} — {r.description}"
        )
        print(
            f"    Sources:  "
            f"{', '.join(r.benchmark_sources)}"
        )
        print(f"    Evidence: {r.evidence}")

    # ---- FAILED RULES ----
    print()
    print(_bold("-" * 60))
    print(
        _red(_bold(
            f"  ✗ FAILED ({len(result.failed_rules)})"
        ))
    )
    print(_bold("-" * 60))

    for r in result.failed_rules:
        sev = _severity_color(r.severity)
        print(
            f"\n  [{_red('FAIL')}] [{sev}] "
            f"{r.rule_id} — {r.description}"
        )
        print(
            f"    Sources:     "
            f"{', '.join(r.benchmark_sources)}"
        )
        print(f"    Evidence:    {r.evidence}")
        print(f"    Remediation: {r.remediation.split(chr(10))[0]}")

    # ---- UNKNOWN COMMANDS ----
    print()
    print(_bold("-" * 60))
    print(
        _yellow(_bold(
            f"  ? UNKNOWN — NEEDS HUMAN REVIEW "
            f"({len(result.unknown_commands)})"
        ))
    )
    print(_bold("-" * 60))

    if result.unknown_commands:
        for u in result.unknown_commands:
            print(
                f"\n  [{_yellow('UNKNOWN')}] "
                f"Line {u.line_number}: {u.command}"
            )
            print(
                f"    Status: "
                f"{_yellow(u.status)}"
            )
    else:
        print(f"\n  {_green('None — all commands recognized')}")


# --------------------------------------------------
# DISPLAY: COMBINED REPORT
# --------------------------------------------------

def display_combined_report(
    results: list[BenchmarkAuditResult],
) -> None:
    """Print the full combined report for multiple devices."""

    total_passed = sum(len(r.passed_rules) for r in results)
    total_failed = sum(len(r.failed_rules) for r in results)
    total_unknown = sum(len(r.unknown_commands) for r in results)
    total_score = sum(r.security_score for r in results)
    total_max = sum(r.max_score for r in results)

    # ---- HEADER ----
    print()
    print(_bold("=" * 60))
    print(_bold("  COMBINED BENCHMARK COMPLIANCE AUDIT REPORT"))
    print(_bold("=" * 60))
    print(f"\n  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Devices:   {len(results)}")

    # Summary table
    print(f"\n  {'Device':<28} {'Vendor':<16} {'Score':>7}  {'Risk'}")
    print(f"  {'─' * 28} {'─' * 16} {'─' * 7}  {'─' * 10}")
    for r in results:
        vendor_short = VENDOR_DISPLAY_NAMES.get(
            r.detected_vendor, r.detected_vendor
        )[:16]
        score_str = f"{r.security_score}/{r.max_score}"
        print(
            f"  {r.device_name:<28} "
            f"{vendor_short:<16} "
            f"{score_str:>7}  "
            f"{_risk_color(r.risk_level)}"
        )

    # Totals
    print(f"\n  {'─' * 60}")
    print(
        f"  {_bold('TOTALS'):28} "
        f"{'':16} "
        f"{_bold(f'{total_score}/{total_max}'):>7}"
    )
    print(
        f"  Passed: {_green(str(total_passed))}  |  "
        f"Failed: {_red(str(total_failed))}  |  "
        f"Unknown: {_yellow(str(total_unknown))}"
    )

    # ---- PER-DEVICE SECTIONS ----
    for i, result in enumerate(results, start=1):
        _display_device_section(result, i, len(results))

    # ---- FOOTER ----
    print()
    print(_bold("=" * 60))
    print(_bold("  END OF COMBINED REPORT"))
    print(_bold("=" * 60))
    print()


def display_single_report(result: BenchmarkAuditResult) -> None:
    """Print a single-device report (backward compatible)."""

    print()
    print(_bold("=" * 60))
    print(_bold("  BENCHMARK COMPLIANCE AUDIT REPORT"))
    print(_bold("=" * 60))

    vendor_label = VENDOR_DISPLAY_NAMES.get(
        result.detected_vendor, result.detected_vendor
    )

    print(f"\n  Device:      {result.device_name}")
    print(f"  Config:      {result.config_file}")
    print(f"  Vendor:      {_cyan(vendor_label)}")
    print(f"  Total Rules: {result.total_rules}")
    print(
        f"  Score:       "
        f"{result.security_score}/{result.max_score}"
    )
    print(f"  Risk Level:  {_risk_color(result.risk_level)}")

    # Benchmark coverage
    print(f"\n  Benchmark Coverage:")
    for source, count in sorted(result.benchmark_coverage.items()):
        print(f"    {source}: {count} rules")

    _display_device_section(result, 1, 1)

    print()
    print(_bold("=" * 60))
    print()


# --------------------------------------------------
# SAVE COMBINED REPORT
# --------------------------------------------------

def save_combined_report(
    results: list[BenchmarkAuditResult],
    output_path: str = None,
) -> str:
    """Save a combined JSON report for all audited devices."""

    from benchmark_audit.rule_engine import DEFAULT_RESULTS_DIR
    import re as _re

    combined = {
        "report_type": "combined_benchmark_audit",
        "generated_at": datetime.now().isoformat(),
        "total_devices": len(results),
        "summary": {
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
        "devices": [r.to_dict() for r in results],
    }

    if output_path is None:
        os.makedirs(DEFAULT_RESULTS_DIR, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(
            DEFAULT_RESULTS_DIR,
            f"combined_audit_{timestamp}.json"
        )

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=4)

    return output_path


# --------------------------------------------------
# RESOLVE CONFIG PATH
# --------------------------------------------------

def _resolve_path(config_path: str) -> str:
    """Resolve a config file path, trying project root as fallback."""
    if os.path.isfile(config_path):
        return config_path

    project_root = os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
    alt_path = os.path.join(project_root, config_path)
    if os.path.isfile(alt_path):
        return alt_path

    return None


# --------------------------------------------------
# MAIN
# --------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Benchmark-based network configuration audit. "
            "Evaluates one or more config files against CIS, "
            "NIST, STIG, and ISO 27001 benchmarks. "
            "Auto-detects the vendor for each file. "
            "Generates a PDF report by default."
        ),
    )

    parser.add_argument(
        "config_files",
        nargs="+",
        help=(
            "One or more config files to audit "
            "(e.g., ASA.txt configs/juniper.cfg aruba.cfg)"
        ),
    )

    parser.add_argument(
        "--rules",
        default=None,
        help=(
            "Path to custom benchmark rules JSON. "
            "Defaults to benchmark_rules.json"
        ),
    )

    parser.add_argument(
        "--output",
        default=None,
        help="Custom output path for the report (PDF or JSON)",
    )

    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Output only JSON to stdout, no PDF or terminal report",
    )

    parser.add_argument(
        "--terminal",
        action="store_true",
        help="Show the full report in terminal instead of PDF",
    )

    args = parser.parse_args()

    # Resolve all config paths
    resolved_paths = []
    for cf in args.config_files:
        path = _resolve_path(cf)
        if path is None:
            print(f"Error: Config file not found: {cf}")
            sys.exit(1)
        resolved_paths.append(path)

    # Run audit on each config file
    results = []
    print()
    for config_path in resolved_paths:
        try:
            fname = os.path.basename(config_path)
            print(f"  Auditing: {_cyan(fname)} ...", end=" ", flush=True)
            result = evaluate_config(
                config_path=config_path,
                rules_file=args.rules,
            )
            results.append(result)

            vendor_label = VENDOR_DISPLAY_NAMES.get(
                result.detected_vendor, result.detected_vendor
            )
            print(
                f"{_green('done')} — "
                f"Vendor: {_cyan(vendor_label)}, "
                f"Score: {result.security_score}/{result.max_score}, "
                f"Risk: {_risk_color(result.risk_level)}"
            )
        except (FileNotFoundError, ValueError) as e:
            print(_red(f"ERROR: {e}"))
            sys.exit(1)

    # Output mode
    if args.json_only:
        # JSON to stdout
        if len(results) == 1:
            print(json.dumps(results[0].to_dict(), indent=4))
        else:
            combined = {
                "report_type": "combined_benchmark_audit",
                "generated_at": datetime.now().isoformat(),
                "total_devices": len(results),
                "devices": [r.to_dict() for r in results],
            }
            print(json.dumps(combined, indent=4))

    elif args.terminal:
        # Full terminal output (old behavior)
        if len(results) == 1:
            display_single_report(results[0])
        else:
            display_combined_report(results)

    else:
        # PDF report (default)
        from benchmark_audit.report_generator import (
            generate_pdf_report,
        )

        pdf_output = args.output
        pdf_path = generate_pdf_report(results, pdf_output)
        print()
        print(_bold("=" * 60))
        print(
            f"  {_green('✓')} PDF report generated: "
            f"{_bold(pdf_path)}"
        )
        print(_bold("=" * 60))
        print()

    # Also save JSON report
    if not args.json_only:
        if len(results) == 1:
            json_path = save_report(results[0])
        else:
            json_path = save_combined_report(results)
        print(f"  JSON report: {json_path}")
        print()


if __name__ == "__main__":
    main()

