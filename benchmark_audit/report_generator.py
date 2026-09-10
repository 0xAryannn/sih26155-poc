"""
PDF Report Generator for Benchmark Compliance Audit.

Generates professional PDF reports for single or multi-device
configuration audits with color-coded sections and summary tables.
"""

import os
from datetime import datetime
from fpdf import FPDF

from benchmark_audit.rule_engine import (
    BenchmarkAuditResult,
    DEFAULT_RESULTS_DIR,
)


# --------------------------------------------------
# COLOR PALETTE
# --------------------------------------------------

class Colors:
    """RGB color tuples for the PDF report."""
    # Brand / header
    HEADER_BG = (30, 41, 59)       # slate-800
    HEADER_TEXT = (255, 255, 255)   # white

    # Status colors
    PASS_BG = (220, 252, 231)      # green-100
    PASS_TEXT = (22, 101, 52)       # green-800
    FAIL_BG = (254, 226, 226)      # red-100
    FAIL_TEXT = (153, 27, 27)      # red-800
    UNKNOWN_BG = (254, 249, 195)   # yellow-100
    UNKNOWN_TEXT = (133, 100, 4)   # yellow-800

    # Severity
    SEV_HIGH = (220, 38, 38)       # red-600
    SEV_MEDIUM = (217, 119, 6)     # amber-600
    SEV_LOW = (37, 99, 235)        # blue-600
    SEV_CRITICAL = (153, 27, 27)   # red-900

    # Risk level
    RISK_CRITICAL = (153, 27, 27)
    RISK_HIGH = (220, 38, 38)
    RISK_MEDIUM = (217, 119, 6)
    RISK_LOW = (22, 163, 74)       # green-600

    # Table
    TABLE_HEADER_BG = (51, 65, 85) # slate-700
    TABLE_HEADER_TEXT = (255, 255, 255)
    TABLE_ROW_EVEN = (248, 250, 252)  # slate-50
    TABLE_ROW_ODD = (255, 255, 255)
    TABLE_BORDER = (203, 213, 225) # slate-300

    # General
    TEXT = (30, 41, 59)            # slate-800
    MUTED = (100, 116, 139)       # slate-500
    DIVIDER = (203, 213, 225)     # slate-300
    WHITE = (255, 255, 255)


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


def _risk_color(risk: str) -> tuple:
    """Get RGB color for a risk level."""
    r = risk.upper()
    if r == "CRITICAL":
        return Colors.RISK_CRITICAL
    elif r == "HIGH":
        return Colors.RISK_HIGH
    elif r == "MEDIUM":
        return Colors.RISK_MEDIUM
    return Colors.RISK_LOW


def _sev_color(severity: str) -> tuple:
    """Get RGB color for a severity level."""
    s = severity.upper()
    if s == "CRITICAL":
        return Colors.SEV_CRITICAL
    elif s == "HIGH":
        return Colors.SEV_HIGH
    elif s == "MEDIUM":
        return Colors.SEV_MEDIUM
    return Colors.SEV_LOW


# --------------------------------------------------
# PDF BUILDER
# --------------------------------------------------

class AuditPDF(FPDF):
    """Custom FPDF subclass with audit report styling."""

    def __init__(self):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.set_auto_page_break(auto=True, margin=20)
        self.set_margins(15, 15, 15)
        self._report_title = "Benchmark Compliance Audit Report"
        self._generated_at = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    @staticmethod
    def _safe(text: str) -> str:
        """Sanitize Unicode chars to ASCII for Helvetica."""
        replacements = {
            "\u2014": "-",   # em-dash
            "\u2013": "-",   # en-dash
            "\u2018": "'",   # left single quote
            "\u2019": "'",   # right single quote
            "\u201c": '"',   # left double quote
            "\u201d": '"',   # right double quote
            "\u2022": "*",   # bullet
            "\u2026": "...", # ellipsis
            "\u2713": "v",   # checkmark
            "\u2717": "x",   # cross mark
            "\u2192": "->",  # arrow
            "\u00a0": " ",   # non-breaking space
            "\u00e9": "e",   # accented e
        }
        for k, v in replacements.items():
            text = text.replace(k, v)
        # Strip any remaining non-latin1 chars
        return text.encode("latin-1", errors="replace").decode(
            "latin-1"
        )

    def cell(self, w=None, h=None, text="", *args, **kwargs):
        """Override to auto-sanitize text."""
        return super().cell(w, h, self._safe(str(text)), *args, **kwargs)

    def multi_cell(self, w, h=None, text="", *args, **kwargs):
        """Override to auto-sanitize text."""
        return super().multi_cell(w, h, self._safe(str(text)), *args, **kwargs)

    # ---- HEADER / FOOTER ----

    def header(self):
        if self.page_no() == 1:
            return  # Title page has its own header
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*Colors.MUTED)
        self.cell(0, 6, self._report_title, align="L")
        self.cell(0, 6, f"Page {self.page_no()}", align="R", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*Colors.DIVIDER)
        self.line(15, self.get_y(), 195, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(*Colors.MUTED)
        self.cell(
            0, 8,
            f"Generated {self._generated_at} | "
            f"Citadel Benchmark Audit Engine v2.0",
            align="C",
        )

    # ---- TITLE PAGE ----

    def add_title_page(self, device_count: int):
        """Add a professional title/cover page."""
        self.add_page()

        # Title block
        self.ln(50)
        self.set_fill_color(*Colors.HEADER_BG)
        self.rect(0, 40, 210, 55, "F")

        self.set_y(48)
        self.set_font("Helvetica", "B", 26)
        self.set_text_color(*Colors.HEADER_TEXT)
        self.cell(0, 12, "BENCHMARK COMPLIANCE", align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_font("Helvetica", "B", 22)
        self.cell(0, 10, "AUDIT REPORT", align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_font("Helvetica", "", 11)
        self.cell(0, 10, "CIS | NIST SP 800-53 | DISA STIG | ISO 27001", align="C", new_x="LMARGIN", new_y="NEXT")

        # Meta info
        self.set_y(105)
        self.set_text_color(*Colors.TEXT)
        self.set_font("Helvetica", "", 11)
        self.cell(0, 8, f"Generated: {self._generated_at}", align="C", new_x="LMARGIN", new_y="NEXT")
        self.cell(0, 8, f"Devices Audited: {device_count}", align="C", new_x="LMARGIN", new_y="NEXT")

    # ---- SECTION HEADERS ----

    def section_header(self, title: str, color: tuple = None):
        """Add a colored section header bar."""
        if color is None:
            color = Colors.HEADER_BG

        self._check_page_space(15)
        self.ln(4)
        self.set_fill_color(*color)
        self.set_text_color(*Colors.WHITE)
        self.set_font("Helvetica", "B", 11)
        self.cell(0, 9, f"  {title}", fill=True, new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(*Colors.TEXT)
        self.ln(2)

    def sub_header(self, title: str):
        """Add a lighter sub-section header."""
        self._check_page_space(12)
        self.ln(2)
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*Colors.TEXT)
        self.cell(0, 7, title, new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*Colors.DIVIDER)
        self.line(15, self.get_y(), 195, self.get_y())
        self.ln(2)

    # ---- DEVICE HEADER ----

    def device_header(
        self, result: BenchmarkAuditResult, index: int, total: int
    ):
        """Add a device section header with key stats."""
        self.add_page()

        vendor_label = VENDOR_DISPLAY_NAMES.get(
            result.detected_vendor, result.detected_vendor
        )

        # Device banner
        self.set_fill_color(*Colors.HEADER_BG)
        self.set_text_color(*Colors.WHITE)
        self.set_font("Helvetica", "B", 14)
        self.cell(
            0, 11,
            f"  DEVICE {index}/{total}: {result.device_name}",
            fill=True, new_x="LMARGIN", new_y="NEXT",
        )
        self.ln(3)

        # Key-value info
        self.set_text_color(*Colors.TEXT)
        self.set_font("Helvetica", "", 10)
        info = [
            ("Config File", result.config_file),
            ("Vendor", vendor_label),
            ("Total Rules", str(result.total_rules)),
            (
                "Score",
                f"{result.security_score} / {result.max_score}"
            ),
            ("Risk Level", result.risk_level),
        ]
        for label, value in info:
            self.set_font("Helvetica", "B", 10)
            self.cell(35, 7, f"{label}:", new_x="END")
            self.set_font("Helvetica", "", 10)
            if label == "Risk Level":
                self.set_text_color(*_risk_color(value))
                self.set_font("Helvetica", "B", 10)
            self.cell(0, 7, f"  {value}", new_x="LMARGIN", new_y="NEXT")
            self.set_text_color(*Colors.TEXT)
        self.ln(2)

    # ---- RULE ROWS ----

    def passed_rule(self, rule):
        """Render a single passed rule entry."""
        self._check_page_space(18)
        # Status badge
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*Colors.PASS_TEXT)
        self.set_fill_color(*Colors.PASS_BG)
        self.cell(12, 6, "PASS", fill=True, align="C", new_x="END")

        # Rule ID + description
        self.set_text_color(*Colors.TEXT)
        self.set_font("Helvetica", "B", 9)
        self.cell(2, 6, "", new_x="END")
        self.cell(18, 6, rule.rule_id, new_x="END")
        self.set_font("Helvetica", "", 9)

        desc = rule.description
        avail_w = 145
        if self.get_string_width(desc) > avail_w:
            desc = desc[:80] + "..."
        self.cell(avail_w, 6, desc, new_x="LMARGIN", new_y="NEXT")

        # Evidence (small, muted)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*Colors.MUTED)
        evidence = rule.evidence[:120] + (
            "..." if len(rule.evidence) > 120 else ""
        )
        self.cell(12, 4, "", new_x="END")
        self.multi_cell(165, 4, f"Evidence: {evidence}", new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(*Colors.TEXT)
        self.ln(1)

    def failed_rule(self, rule):
        """Render a single failed rule entry."""
        self._check_page_space(22)
        # Status badge
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*Colors.FAIL_TEXT)
        self.set_fill_color(*Colors.FAIL_BG)
        self.cell(12, 6, "FAIL", fill=True, align="C", new_x="END")

        # Severity badge
        self.cell(2, 6, "", new_x="END")
        sev_col = _sev_color(rule.severity)
        self.set_text_color(*sev_col)
        self.set_font("Helvetica", "B", 8)
        self.cell(16, 6, rule.severity, new_x="END")

        # Rule ID + description
        self.set_text_color(*Colors.TEXT)
        self.set_font("Helvetica", "B", 9)
        self.cell(18, 6, rule.rule_id, new_x="END")
        self.set_font("Helvetica", "", 9)

        desc = rule.description
        avail_w = 127
        if self.get_string_width(desc) > avail_w:
            desc = desc[:75] + "..."
        self.cell(avail_w, 6, desc, new_x="LMARGIN", new_y="NEXT")

        # Evidence + Remediation
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*Colors.MUTED)
        evidence = rule.evidence[:120] + (
            "..." if len(rule.evidence) > 120 else ""
        )
        self.cell(12, 4, "", new_x="END")
        self.multi_cell(165, 4, f"Evidence: {evidence}", new_x="LMARGIN", new_y="NEXT")

        remediation = rule.remediation.split("\n")[0][:100]
        self.cell(12, 4, "", new_x="END")
        self.set_text_color(37, 99, 235)  # blue
        self.multi_cell(165, 4, f"Remediation: {remediation}", new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(*Colors.TEXT)
        self.ln(1)

    def unknown_rule(self, unknown_cmd):
        """Render a single unknown command entry."""
        self._check_page_space(12)
        # Status badge
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*Colors.UNKNOWN_TEXT)
        self.set_fill_color(*Colors.UNKNOWN_BG)
        self.cell(16, 6, "UNKNOWN", fill=True, align="C", new_x="END")

        # Line + command
        self.cell(2, 6, "", new_x="END")
        self.set_text_color(*Colors.TEXT)
        self.set_font("Helvetica", "B", 9)
        self.cell(14, 6, f"L{unknown_cmd.line_number}", new_x="END")
        self.set_font("Helvetica", "", 9)

        cmd = unknown_cmd.command
        avail_w = 145
        if self.get_string_width(cmd) > avail_w:
            cmd = cmd[:85] + "..."
        self.cell(avail_w, 6, cmd, new_x="LMARGIN", new_y="NEXT")

        self.set_font("Helvetica", "", 7)
        self.set_text_color(*Colors.MUTED)
        self.cell(16, 4, "", new_x="END")
        self.cell(0, 4, "Needs human review", new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(*Colors.TEXT)
        self.ln(1)

    # ---- SUMMARY TABLE ----

    def summary_table(self, results: list):
        """Add the multi-device summary table."""
        self.section_header("AUDIT SUMMARY")

        # Column widths
        col_w = [55, 40, 22, 22, 22, 19]
        headers = [
            "Device", "Vendor", "Score", "Passed",
            "Failed", "Risk"
        ]

        # Header row
        self.set_font("Helvetica", "B", 9)
        self.set_fill_color(*Colors.TABLE_HEADER_BG)
        self.set_text_color(*Colors.TABLE_HEADER_TEXT)
        for i, h in enumerate(headers):
            self.cell(col_w[i], 7, f" {h}", fill=True, new_x="END")
        self.ln()

        # Data rows
        self.set_font("Helvetica", "", 9)
        for idx, r in enumerate(results):
            bg = (
                Colors.TABLE_ROW_EVEN if idx % 2 == 0
                else Colors.TABLE_ROW_ODD
            )
            self.set_fill_color(*bg)
            self.set_text_color(*Colors.TEXT)

            vendor_short = VENDOR_DISPLAY_NAMES.get(
                r.detected_vendor, r.detected_vendor
            )
            if len(vendor_short) > 18:
                vendor_short = vendor_short[:17] + "."

            name = r.device_name
            if len(name) > 28:
                name = name[:27] + "."

            cells = [
                name,
                vendor_short,
                f"{r.security_score}/{r.max_score}",
                str(len(r.passed_rules)),
                str(len(r.failed_rules)),
                r.risk_level,
            ]
            for i, val in enumerate(cells):
                if i == 5:  # Risk column
                    self.set_text_color(*_risk_color(val))
                    self.set_font("Helvetica", "B", 9)
                self.cell(
                    col_w[i], 7, f" {val}",
                    fill=True, new_x="END",
                )
                if i == 5:
                    self.set_text_color(*Colors.TEXT)
                    self.set_font("Helvetica", "", 9)
            self.ln()

        # Totals row
        total_score = sum(r.security_score for r in results)
        total_max = sum(r.max_score for r in results)
        total_passed = sum(len(r.passed_rules) for r in results)
        total_failed = sum(len(r.failed_rules) for r in results)

        self.set_font("Helvetica", "B", 9)
        self.set_fill_color(*Colors.HEADER_BG)
        self.set_text_color(*Colors.WHITE)
        totals = [
            "TOTAL", f"{len(results)} devices",
            f"{total_score}/{total_max}",
            str(total_passed), str(total_failed), "",
        ]
        for i, val in enumerate(totals):
            self.cell(col_w[i], 7, f" {val}", fill=True, new_x="END")
        self.ln()
        self.set_text_color(*Colors.TEXT)
        self.ln(3)

    # ---- HELPERS ----

    def _check_page_space(self, needed_mm: int):
        """Add a new page if not enough vertical space remains."""
        if self.get_y() + needed_mm > self.h - 25:
            self.add_page()


# --------------------------------------------------
# PUBLIC API
# --------------------------------------------------

def generate_pdf_report(
    results: list[BenchmarkAuditResult],
    output_path: str = None,
) -> str:
    """
    Generate a professional PDF audit report.

    Args:
        results: List of audit results (one per device).
        output_path: Optional custom output path. Defaults to
                     results/combined_audit_<timestamp>.pdf

    Returns:
        Absolute path to the generated PDF file.
    """
    pdf = AuditPDF()

    # Title page
    pdf.add_title_page(device_count=len(results))

    # Summary table (if multiple devices)
    if len(results) > 1:
        pdf.add_page()
        pdf.summary_table(results)

    # Per-device sections
    for i, result in enumerate(results, start=1):
        pdf.device_header(result, i, len(results))

        # Passed rules
        pass_color = (22, 101, 52)  # green
        pdf.section_header(
            f"PASSED RULES ({len(result.passed_rules)})",
            color=pass_color,
        )
        if result.passed_rules:
            for r in result.passed_rules:
                pdf.passed_rule(r)
        else:
            pdf.set_font("Helvetica", "I", 9)
            pdf.set_text_color(*Colors.MUTED)
            pdf.cell(0, 7, "  No rules passed.", new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(*Colors.TEXT)

        # Failed rules
        fail_color = (153, 27, 27)  # red
        pdf.section_header(
            f"FAILED RULES ({len(result.failed_rules)})",
            color=fail_color,
        )
        if result.failed_rules:
            for r in result.failed_rules:
                pdf.failed_rule(r)
        else:
            pdf.set_font("Helvetica", "I", 9)
            pdf.set_text_color(*Colors.MUTED)
            pdf.cell(0, 7, "  All rules passed!", new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(*Colors.TEXT)

        # Unknown commands
        unk_color = (133, 100, 4)  # yellow-dark
        pdf.section_header(
            f"UNKNOWN COMMANDS — NEEDS HUMAN REVIEW "
            f"({len(result.unknown_commands)})",
            color=unk_color,
        )
        if result.unknown_commands:
            for u in result.unknown_commands:
                pdf.unknown_rule(u)
        else:
            pdf.set_font("Helvetica", "I", 9)
            pdf.set_text_color(*Colors.MUTED)
            pdf.cell(0, 7, "  All commands recognized.", new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(*Colors.TEXT)

    # Write PDF
    if output_path is None:
        os.makedirs(DEFAULT_RESULTS_DIR, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if len(results) == 1:
            name = results[0].device_name.replace(" ", "_")
            output_path = os.path.join(
                DEFAULT_RESULTS_DIR,
                f"{name}_audit_report.pdf",
            )
        else:
            output_path = os.path.join(
                DEFAULT_RESULTS_DIR,
                f"combined_audit_{timestamp}.pdf",
            )

    pdf.output(output_path)
    return os.path.abspath(output_path)
