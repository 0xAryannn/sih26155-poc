"""
Benchmark-driven rule engine for network device configuration auditing.

Evaluates configuration files against CIS, NIST SP 800-53, DISA STIG,
and ISO/IEC 27001 benchmark rules. Produces three-state output:
  - true:  benchmark rule is satisfied
  - false: benchmark rule is violated
  - UNKNOWN: command not in any benchmark, needs human review

Usage as library:
    from benchmark_audit import evaluate_config
    result = evaluate_config("path/to/config.txt")

Usage standalone:
    python -m benchmark_audit.rule_engine path/to/config.txt
"""

import json
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Optional


# --------------------------------------------------
# PATHS
# --------------------------------------------------

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_RULES_FILE = os.path.join(_THIS_DIR, "benchmark_rules.json")
DEFAULT_RESULTS_DIR = os.path.join(_THIS_DIR, "results")


# --------------------------------------------------
# DATA CLASSES
# --------------------------------------------------

@dataclass
class RuleResult:
    """Result of evaluating a single benchmark rule."""
    rule_id: str
    category: str
    description: str
    benchmark_sources: list
    severity: str
    status: bool  # True = pass, False = fail
    evidence: str
    remediation: str
    weight: int


@dataclass
class UnknownCommand:
    """A config line not matched by any benchmark rule."""
    line_number: int
    command: str
    status: str = "UNKNOWN — NEEDS HUMAN REVIEW"


@dataclass
class BenchmarkAuditResult:
    """Complete audit result — serializable to JSON for integration."""
    device_name: str
    config_file: str
    total_rules: int
    detected_vendor: str = "unknown"
    passed_rules: list = field(default_factory=list)
    failed_rules: list = field(default_factory=list)
    unknown_commands: list = field(default_factory=list)
    security_score: int = 0
    max_score: int = 0
    risk_level: str = "UNKNOWN"
    benchmark_coverage: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to a plain dictionary for JSON serialization."""
        return {
            "device_name": self.device_name,
            "config_file": self.config_file,
            "detected_vendor": self.detected_vendor,
            "total_rules": self.total_rules,
            "passed_rules": [
                asdict(r) if isinstance(r, RuleResult) else r
                for r in self.passed_rules
            ],
            "failed_rules": [
                asdict(r) if isinstance(r, RuleResult) else r
                for r in self.failed_rules
            ],
            "unknown_commands": [
                asdict(u) if isinstance(u, UnknownCommand) else u
                for u in self.unknown_commands
            ],
            "security_score": self.security_score,
            "max_score": self.max_score,
            "risk_level": self.risk_level,
            "benchmark_coverage": self.benchmark_coverage,
        }


# --------------------------------------------------
# LOAD RULES
# --------------------------------------------------

def load_rules(rules_file: Optional[str] = None) -> list[dict]:
    """
    Load benchmark rules from JSON file.

    Args:
        rules_file: Path to the rules JSON. Defaults to
                    benchmark_rules.json in this package.

    Returns:
        List of rule dictionaries.
    """
    path = rules_file or DEFAULT_RULES_FILE

    if not os.path.isfile(path):
        raise FileNotFoundError(
            f"Benchmark rules file not found: {path}"
        )

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return data.get("rules", [])


# --------------------------------------------------
# PARSE CONFIG
# --------------------------------------------------

def parse_config(config_path: str) -> list[tuple[int, str]]:
    """
    Read and normalize configuration lines from a file.

    Args:
        config_path: Path to the config file (e.g., ASA.txt).

    Returns:
        List of (line_number, stripped_line) tuples.
        Skips empty lines and comment-only lines ('!').
    """
    if not os.path.isfile(config_path):
        raise FileNotFoundError(
            f"Config file not found: {config_path}"
        )

    with open(config_path, "r", encoding="utf-8", errors="replace") as f:
        raw_lines = f.readlines()

    parsed = []
    for i, raw_line in enumerate(raw_lines, start=1):
        line = raw_line.strip().replace("\r", "")
        # Skip empty lines and comments (! or #)
        if not line or line.startswith("!") or line.startswith("#"):
            continue
        parsed.append((i, line))

    return parsed


def parse_config_text(config_text: str) -> list[tuple[int, str]]:
    """
    Parse configuration from a string (for programmatic use).

    Args:
        config_text: Raw configuration text.

    Returns:
        List of (line_number, stripped_line) tuples.
    """
    parsed = []
    for i, raw_line in enumerate(config_text.strip().splitlines(), start=1):
        line = raw_line.strip().replace("\r", "")
        # Skip empty lines and comments (! or #)
        if not line or line.startswith("!") or line.startswith("#"):
            continue
        parsed.append((i, line))

    return parsed


# --------------------------------------------------
# VENDOR DETECTION
# --------------------------------------------------

# Keyword signatures for auto-detecting vendor from config syntax.
# The vendor with the highest match count wins.
VENDOR_SIGNATURES = {
    "juniper": [
        "set system", "set interfaces", "set protocols",
        "set security", "set firewall", "set routing-options",
        "deactivate", "set groups",
    ],
    "paloalto": [
        "set deviceconfig", "set network", "set rulebase",
        "set vsys", "set shared", "set mgt-config",
        "set template",
    ],
    "fortinet": [
        "config system global", "config firewall policy",
        "config system interface", "config router static",
        "config log fortianalyzer", "config user local",
        "set admintimeout", "set admin-sport",
    ],
    "huawei": [
        "sysname", "acl number", "info-center",
        "display current", "hwtacacs-server",
        "undo", "quit",
    ],
    "arista": [
        "management api", "management ssh",
        "spanning-tree mode mstp",
        "daemon", "monitor session",
    ],
    "aruba": [
        "ssh server vrf", "https-server vrf",
        "no telnet-server", "vlan access",
        "user admin group administrators",
        "ntp enable", "aruba-central",
    ],
    "cisco_asa": [
        "nameif", "security-level", "threat-detection",
        "crypto ipsec", "crypto ca trustpool",
        "dynamic-access-policy-record",
        "asdm", "arp rate-limit",
    ],
    "cisco_ios": [
        "line vty", "line con", "router ospf",
        "router bgp", "ip route",
        "interface FastEthernet", "interface GigabitEthernet",
        "ip access-list",
    ],
}

# Additional structural patterns per vendor — used by
# classify_unknown_commands to skip vendor-specific boilerplate.
VENDOR_STRUCTURAL_PATTERNS = {
    "cisco_ios": [
        r"^interface\s", r"^ip address\s", r"^no shutdown",
        r"^line\s", r"^router\s", r"^ip route\s",
        r"^end$", r"^exit$", r"^version\s",
    ],
    "cisco_asa": [
        r"^interface\s", r"^nameif\s", r"^security-level\s",
        r"^ip address\s", r"^no nameif", r"^no security-level",
        r"^no ip address", r"^mtu\s", r"^timeout\s",
        r"^pager\s", r"^user-identity\s", r"^names$",
        r"^enable$", r"^configure terminal", r"^write memory",
        r"^prompt\s", r"^destination\s",
        r"^subscribe-to-alert-group\s",
        r"^destination transport-method",
        r"^profile\s", r"^call-home$",
    ],
    "juniper": [
        r"^set interfaces\s", r"^set routing-options\s",
        r"^set policy-options\s", r"^commit$",
        r"^set groups\s", r"^set apply-groups\s",
        r"^set routing-instances\s", r"^set class-of-service\s",
        r"^set forwarding-options\s", r"^set vlans\s",
        r"^set chassis\s", r"^set event-options\s",
        r"^set protocols (ospf|bgp|mpls|ldp|rsvp|lldp|rstp|stp|vstp|lacp)\s",
        r"^set protocols layer2-control\s",
        r"^set virtual-chassis\s",
        r"^set ethernet-switching-options\s",
        r"^set switch-options\s",
        r"^set system services netconf\s",
        r"^set system archival\s", r"^set system time-zone\s",
        r"^set system radius-server\s", r"^set system tacplus-server\s",
        r"^deactivate\s", r"^delete\s",
    ],
    "paloalto": [
        r"^set network interface\s", r"^set zone\s",
        r"^set address\s", r"^set service\s",
    ],
    "fortinet": [
        r"^config\s", r"^set\s", r"^end$",
        r"^edit\s", r"^next$", r"^unset\s",
    ],
    "huawei": [
        r"^interface\s", r"^ip route-static\s",
        r"^return$", r"^quit$", r"^undo\s",
    ],
    "arista": [
        r"^interface\s", r"^ip address\s",
        r"^no shutdown", r"^end$", r"^exit$",
    ],
    "aruba": [
        r"^vlan\s", r"^name\s", r"^description\s",
        r"^vlan access\s", r"^vlan trunk\s",
        r"^default-gateway\s", r"^ip static\s",
        r"^user\s", r"^https-server\s",
        r"^ssh server\s", r"^no telnet-server",
        r"^ntp enable", r"^aruba-central\s",
    ],
}

# Universal structural patterns (vendor-independent)
_UNIVERSAL_STRUCTURAL = [
    r"^interface\s", r"^ip address\s", r"^no ip address",
    r"^shutdown$", r"^no shutdown", r"^exit$", r"^end$",
    r"^version\s", r"^boot-", r"^no nameif",
    r"^no security-level", r"^mtu\s", r"^timeout\s",
    r"^pager\s", r"^user-identity\s", r"^names$",
    r"^enable$", r"^configure terminal", r"^write memory",
    r"^prompt\s", r"^destination\s",
    r"^subscribe-to-alert-group\s",
    r"^destination transport-method",
    r"^profile\s", r"^call-home$",
    r"^vlan\s", r"^name\s", r"^description\s",
    r"^default-gateway\s", r"^ip static\s",
]


def detect_vendor(
    config_lines: list[tuple[int, str]]
) -> str:
    """
    Auto-detect the vendor of a configuration file from its syntax.

    Uses keyword fingerprinting — counts how many signature
    keywords match across all lines. Highest score wins.

    Args:
        config_lines: Parsed config lines.

    Returns:
        Vendor key string (e.g., 'cisco_asa', 'juniper').
        Returns 'unknown' if no clear match.
    """
    scores = {vendor: 0 for vendor in VENDOR_SIGNATURES}

    for _, line_text in config_lines:
        lower = line_text.lower()
        for vendor, keywords in VENDOR_SIGNATURES.items():
            for keyword in keywords:
                if keyword.lower() in lower:
                    scores[vendor] += 1

    if not scores:
        return "unknown"

    best = max(scores, key=scores.get)

    # Require at least 2 matches to declare a vendor
    if scores[best] < 2:
        return "unknown"

    return best


# --------------------------------------------------
# EVALUATE SINGLE RULE
# --------------------------------------------------

def _match_pattern(pattern: str, line: str) -> bool:
    """Check if a line matches a command pattern (regex-capable)."""
    try:
        return bool(re.search(pattern, line, re.IGNORECASE))
    except re.error:
        # Fallback to simple prefix match if regex is invalid
        return line.lower().startswith(pattern.lower())


def _get_rule_pattern(rule: dict, vendor: str) -> str:
    """
    Get the command pattern for a rule, using vendor-specific
    pattern if available, otherwise falling back to the generic one.

    Args:
        rule: Rule dictionary.
        vendor: Detected vendor key.

    Returns:
        The regex pattern string to use for matching.
    """
    vendor_patterns = rule.get("vendor_patterns", {})

    # Try exact vendor match
    if vendor in vendor_patterns:
        vp = vendor_patterns[vendor]
        if vp is not None:
            return vp
        # null means "not applicable to this vendor" —
        # fall back to generic pattern
        return rule["command_pattern"]

    # For unknown vendor, combine all vendor patterns + generic
    if vendor == "unknown":
        all_patterns = set()
        all_patterns.add(rule["command_pattern"])
        for vp in vendor_patterns.values():
            if vp:  # skip None/empty
                all_patterns.add(vp)
        return "|".join(all_patterns)

    # Fallback to generic pattern
    return rule["command_pattern"]


def evaluate_rule(
    rule: dict,
    config_lines: list[tuple[int, str]],
    vendor: str = "unknown"
) -> RuleResult:
    """
    Evaluate a single benchmark rule against config lines.

    Args:
        rule: A rule dictionary from benchmark_rules.json.
        config_lines: List of (line_number, line_text) tuples.
        vendor: Detected vendor key for pattern selection.

    Returns:
        RuleResult with status=True (pass) or status=False (fail).
    """
    pattern = _get_rule_pattern(rule, vendor)
    check_type = rule["check_type"]
    expected = rule.get("expected_value")

    # Find all matching lines
    matches = []
    for line_num, line_text in config_lines:
        if _match_pattern(pattern, line_text):
            matches.append((line_num, line_text))

    # ---- PRESENCE CHECK ----
    if check_type == "presence":
        if matches:
            evidence_parts = [
                f"Line {ln}: {lt}" for ln, lt in matches[:3]
            ]
            return RuleResult(
                rule_id=rule["id"],
                category=rule["category"],
                description=rule["description"],
                benchmark_sources=rule["benchmark_sources"],
                severity="PASS",
                status=True,
                evidence=" | ".join(evidence_parts),
                remediation=rule["remediation"],
                weight=rule["weight"],
            )
        else:
            return RuleResult(
                rule_id=rule["id"],
                category=rule["category"],
                description=rule["description"],
                benchmark_sources=rule["benchmark_sources"],
                severity=rule["severity"],
                status=False,
                evidence="Configuration not found",
                remediation=rule["remediation"],
                weight=rule["weight"],
            )

    # ---- ABSENCE CHECK ----
    elif check_type == "absence":
        if matches:
            evidence_parts = [
                f"Line {ln}: {lt}" for ln, lt in matches[:3]
            ]
            return RuleResult(
                rule_id=rule["id"],
                category=rule["category"],
                description=rule["description"],
                benchmark_sources=rule["benchmark_sources"],
                severity=rule["severity"],
                status=False,
                evidence=(
                    "VIOLATION FOUND — "
                    + " | ".join(evidence_parts)
                ),
                remediation=rule["remediation"],
                weight=rule["weight"],
            )
        else:
            return RuleResult(
                rule_id=rule["id"],
                category=rule["category"],
                description=rule["description"],
                benchmark_sources=rule["benchmark_sources"],
                severity="PASS",
                status=True,
                evidence="Not present (compliant)",
                remediation=rule["remediation"],
                weight=rule["weight"],
            )

    # ---- VALUE CHECK ----
    elif check_type == "value_check":
        if not matches:
            return RuleResult(
                rule_id=rule["id"],
                category=rule["category"],
                description=rule["description"],
                benchmark_sources=rule["benchmark_sources"],
                severity=rule["severity"],
                status=False,
                evidence="Configuration not found",
                remediation=rule["remediation"],
                weight=rule["weight"],
            )

        # Evaluate the value from the matched line
        line_num, line_text = matches[0]
        passed = _evaluate_value(line_text, pattern, expected)

        if passed:
            return RuleResult(
                rule_id=rule["id"],
                category=rule["category"],
                description=rule["description"],
                benchmark_sources=rule["benchmark_sources"],
                severity="PASS",
                status=True,
                evidence=f"Line {line_num}: {line_text}",
                remediation=rule["remediation"],
                weight=rule["weight"],
            )
        else:
            return RuleResult(
                rule_id=rule["id"],
                category=rule["category"],
                description=rule["description"],
                benchmark_sources=rule["benchmark_sources"],
                severity=rule["severity"],
                status=False,
                evidence=(
                    f"VIOLATION — Line {line_num}: {line_text}"
                ),
                remediation=rule["remediation"],
                weight=rule["weight"],
            )

    # Fallback — unknown check type
    return RuleResult(
        rule_id=rule["id"],
        category=rule["category"],
        description=rule["description"],
        benchmark_sources=rule["benchmark_sources"],
        severity="MEDIUM",
        status=False,
        evidence=f"Unknown check type: {check_type}",
        remediation=rule["remediation"],
        weight=rule["weight"],
    )


def _evaluate_value(
    line_text: str,
    pattern: str,
    expected: dict
) -> bool:
    """
    Evaluate value-based checks against a config line.

    Supports:
        - password_strength: min length + reject patterns
        - not_in_list: value must not be in a reject list
        - non_zero: extracted numeric value must not be 0
    """
    if expected is None:
        return True

    check = expected.get("check", "")

    # ---- PASSWORD STRENGTH ----
    if check == "password_strength":
        # Extract password (last token on the line)
        parts = line_text.split()
        if not parts:
            return False

        password = parts[-1]
        min_length = expected.get("min_length", 8)
        reject_patterns = expected.get("reject_patterns", [])

        if len(password) < min_length:
            return False

        for bad in reject_patterns:
            if bad.lower() in password.lower():
                return False

        return True

    # ---- NOT IN LIST ----
    elif check == "not_in_list":
        reject_values = expected.get("reject_values", [])
        # Extract the value after the command pattern
        for val in reject_values:
            if val.lower() in line_text.lower():
                return False
        return True

    # ---- NON-ZERO ----
    elif check == "non_zero":
        # Extract any trailing number
        numbers = re.findall(r"\d+", line_text)
        if numbers:
            last_num = int(numbers[-1])
            return last_num != 0
        return False

    return True


# --------------------------------------------------
# CLASSIFY UNKNOWN COMMANDS
# --------------------------------------------------

def classify_unknown_commands(
    config_lines: list[tuple[int, str]],
    rules: list[dict],
    vendor: str = "unknown"
) -> list[UnknownCommand]:
    """
    Find config lines not matched by ANY benchmark rule.

    These require human review — they are neither known-good
    nor known-bad, just unrecognized.

    Args:
        config_lines: Parsed config lines.
        rules: Loaded benchmark rules.
        vendor: Detected vendor key.

    Returns:
        List of UnknownCommand objects.
    """
    # Collect all command patterns from the rules,
    # using vendor-specific patterns where available.
    # NOTE: We use the full pattern as a single regex —
    # do NOT split on "|" because that breaks regex
    # alternation groups like (idle-timeout|class .+)
    all_patterns = []
    for rule in rules:
        pattern = _get_rule_pattern(rule, vendor)
        if pattern:
            all_patterns.append(pattern)

    # Build structural patterns: universal + vendor-specific
    structural_patterns = list(_UNIVERSAL_STRUCTURAL)
    if vendor in VENDOR_STRUCTURAL_PATTERNS:
        structural_patterns.extend(
            VENDOR_STRUCTURAL_PATTERNS[vendor]
        )

    unknown = []

    for line_num, line_text in config_lines:
        matched = False

        # Check against all benchmark rule patterns
        for pattern in all_patterns:
            if _match_pattern(pattern, line_text):
                matched = True
                break

        # Check against structural patterns
        if not matched:
            for sp in structural_patterns:
                if re.search(sp, line_text, re.IGNORECASE):
                    matched = True
                    break

        if not matched:
            unknown.append(UnknownCommand(
                line_number=line_num,
                command=line_text,
            ))

    return unknown


# --------------------------------------------------
# SCORING
# --------------------------------------------------

def _calculate_score(
    passed: list[RuleResult],
    failed: list[RuleResult]
) -> tuple[int, int]:
    """
    Calculate security score based on rule weights.

    Returns:
        (earned_score, max_possible_score)
    """
    earned = sum(r.weight for r in passed)
    total = earned + sum(r.weight for r in failed)
    return earned, total


def _risk_level(score: int, max_score: int) -> str:
    """Determine risk level from score percentage."""
    if max_score == 0:
        return "UNKNOWN"

    pct = (score / max_score) * 100

    if pct >= 80:
        return "LOW"
    elif pct >= 60:
        return "MEDIUM"
    elif pct >= 40:
        return "HIGH"
    else:
        return "CRITICAL"


def _benchmark_coverage(rules: list[dict]) -> dict:
    """Count how many rules come from each benchmark source."""
    coverage = {}
    for rule in rules:
        for src in rule.get("benchmark_sources", []):
            coverage[src] = coverage.get(src, 0) + 1
    return coverage


# --------------------------------------------------
# MAIN EVALUATE FUNCTION
# --------------------------------------------------

def evaluate_config(
    config_path: str,
    rules_file: Optional[str] = None,
    device_name: Optional[str] = None,
    vendor: Optional[str] = None,
) -> BenchmarkAuditResult:
    """
    Main entry point — evaluate a config file against all benchmark rules.

    This is the function other modules should call for integration.
    Supports any vendor — auto-detects from config syntax if not
    specified.

    Args:
        config_path: Path to the configuration file (e.g., ASA.txt).
        rules_file:  Path to the benchmark rules JSON.
                     Defaults to benchmark_rules.json in this package.
        device_name: Optional device name override.
                     Defaults to the config filename.
        vendor:      Optional vendor override (e.g., 'cisco_asa',
                     'juniper', 'fortinet'). If None, auto-detected
                     from config syntax.

    Returns:
        BenchmarkAuditResult with passed_rules, failed_rules,
        unknown_commands, score, risk_level, and benchmark_coverage.
    """
    # Load rules
    rules = load_rules(rules_file)

    # Parse config
    config_lines = parse_config(config_path)

    # Auto-detect vendor if not provided
    detected_vendor = vendor or detect_vendor(config_lines)

    # Device name from filename if not provided
    if device_name is None:
        device_name = os.path.basename(config_path)

    # Evaluate each rule using vendor-specific patterns
    passed = []
    failed = []

    for rule in rules:
        result = evaluate_rule(rule, config_lines, detected_vendor)
        if result.status:
            passed.append(result)
        else:
            failed.append(result)

    # Find unknown commands
    unknown = classify_unknown_commands(
        config_lines, rules, detected_vendor
    )

    # Calculate score
    earned, max_possible = _calculate_score(passed, failed)
    risk = _risk_level(earned, max_possible)

    # Build result
    audit_result = BenchmarkAuditResult(
        device_name=device_name,
        config_file=config_path,
        total_rules=len(rules),
        detected_vendor=detected_vendor,
        passed_rules=passed,
        failed_rules=failed,
        unknown_commands=unknown,
        security_score=earned,
        max_score=max_possible,
        risk_level=risk,
        benchmark_coverage=_benchmark_coverage(rules),
    )

    return audit_result


def evaluate_config_text(
    config_text: str,
    rules_file: Optional[str] = None,
    device_name: str = "UNKNOWN",
    vendor: Optional[str] = None,
) -> BenchmarkAuditResult:
    """
    Evaluate raw config text (string) against benchmark rules.

    Convenience function for programmatic use where the config
    isn't stored on disk.

    Args:
        config_text: Raw configuration text.
        rules_file:  Path to benchmark rules JSON.
        device_name: Device identifier.
        vendor:      Optional vendor override. Auto-detected if None.

    Returns:
        BenchmarkAuditResult.
    """
    rules = load_rules(rules_file)
    config_lines = parse_config_text(config_text)

    detected_vendor = vendor or detect_vendor(config_lines)

    passed = []
    failed = []

    for rule in rules:
        result = evaluate_rule(rule, config_lines, detected_vendor)
        if result.status:
            passed.append(result)
        else:
            failed.append(result)

    unknown = classify_unknown_commands(
        config_lines, rules, detected_vendor
    )

    earned, max_possible = _calculate_score(passed, failed)
    risk = _risk_level(earned, max_possible)

    return BenchmarkAuditResult(
        device_name=device_name,
        config_file="<text-input>",
        total_rules=len(rules),
        detected_vendor=detected_vendor,
        passed_rules=passed,
        failed_rules=failed,
        unknown_commands=unknown,
        security_score=earned,
        max_score=max_possible,
        risk_level=risk,
        benchmark_coverage=_benchmark_coverage(rules),
    )


# --------------------------------------------------
# SAVE REPORT
# --------------------------------------------------

def save_report(
    result: BenchmarkAuditResult,
    output_path: Optional[str] = None
) -> str:
    """
    Save audit result as a JSON file.

    Args:
        result: The BenchmarkAuditResult to save.
        output_path: Where to write the JSON. Defaults to
                     results/<device_name>_audit.json.

    Returns:
        Path to the saved file.
    """
    if output_path is None:
        os.makedirs(DEFAULT_RESULTS_DIR, exist_ok=True)
        safe_name = re.sub(
            r"[^\w\-.]", "_", result.device_name
        )
        output_path = os.path.join(
            DEFAULT_RESULTS_DIR,
            f"{safe_name}_benchmark_audit.json"
        )

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=4)

    return output_path
