import json


# ==================================================
# LOAD LEARNED KNOWLEDGE
# ==================================================

with open("learned.json", "r") as f:
    LEARNED = json.load(f)


# ==================================================
# BUILT-IN KNOWN COMMANDS
# ==================================================

KNOWN = {
    "enable password": "enable_password",
    "transport input": "remote_access",
    "snmp-server community": "snmp",
    "service password-encryption": "pw_encryption",
}


# ==================================================
# PARSER
# ==================================================

def parse(text):
    settings = {}
    unknown = []
    lines = []

    for raw_line in text.strip().splitlines():

        line = raw_line.strip()

        if not line:
            continue

        lines.append(line)

        matched = False

        # Check built-in commands
        for key in KNOWN:

            if line.startswith(key):

                setting = KNOWN[key]
                value = line[len(key):].strip()

                settings[setting] = value
                matched = True
                break

        # Check learned commands
        if not matched:

            for key in LEARNED:

                if line.startswith(key):

                    setting = LEARNED[key]

                    if setting == "http_server_enabled":
                        settings[setting] = False

                    else:
                        value = line[len(key):].strip()
                        settings[setting] = value

                    matched = True
                    break

        # Unknown command
        if not matched:
            unknown.append(line)

    return settings, unknown, lines


# ==================================================
# COMPLIANCE CHECKS
# ==================================================

def run_checks(cfg):

    results = {}

    results["telnet_disabled"] = (
        cfg.get("remote_access") != "telnet"
    )

    results["snmp_not_default"] = (
        cfg.get("snmp", "").split()[0] != "public"
        if cfg.get("snmp")
        else True
    )

    results["passwords_encrypted"] = (
        cfg.get("pw_encryption") is not None
    )

    results["enable_password_not_weak"] = (
        cfg.get("enable_password")
        not in ["cisco123", "password", "admin"]
    )

    results["ssh_only_access"] = (
        cfg.get("remote_access") == "ssh"
    )

    results["http_server_disabled"] = (
        cfg.get("http_server_enabled") is False
    )

    return results


# ==================================================
# FIND ACTUAL EVIDENCE
# ==================================================

def find_evidence(lines, keyword):

    for line in lines:

        if keyword.lower() in line.lower():
            return line

    return None


# ==================================================
# GENERATE FINDINGS
# ==================================================

def generate_findings(cfg, results, lines):

    findings = []

    # Telnet
    if not results["telnet_disabled"]:

        evidence = find_evidence(
            lines,
            "transport input telnet"
        )

        findings.append({
            "check": "Telnet disabled",
            "severity": "HIGH",
            "status": "FAIL",
            "evidence": evidence or "No matching configuration line found"
        })

    else:

        evidence = find_evidence(
            lines,
            "transport input ssh"
        )

        findings.append({
            "check": "Telnet disabled",
            "severity": "PASS",
            "status": "PASS",
            "evidence": evidence or "No Telnet configuration found"
        })

    # SNMP
    if not results["snmp_not_default"]:

        evidence = find_evidence(
            lines,
            "snmp-server community public"
        )

        findings.append({
            "check": "Default SNMP community",
            "severity": "HIGH",
            "status": "FAIL",
            "evidence": evidence or "No matching configuration line found"
        })

    else:

        evidence = find_evidence(
            lines,
            "snmp-server community"
        )

        findings.append({
            "check": "Default SNMP community",
            "severity": "PASS",
            "status": "PASS",
            "evidence": evidence or "No default SNMP community found"
        })

    # Password encryption
    if not results["passwords_encrypted"]:

        findings.append({
            "check": "Password encryption",
            "severity": "MEDIUM",
            "status": "FAIL",
            "evidence": "service password-encryption not found"
        })

    else:

        evidence = find_evidence(
            lines,
            "service password-encryption"
        )

        findings.append({
            "check": "Password encryption",
            "severity": "PASS",
            "status": "PASS",
            "evidence": evidence or "Password encryption enabled"
        })

    # Weak enable password
    if not results["enable_password_not_weak"]:

        evidence = find_evidence(
            lines,
            "enable password"
        )

        findings.append({
            "check": "Weak enable password",
            "severity": "HIGH",
            "status": "FAIL",
            "evidence": evidence or "No matching configuration line found"
        })

    else:

        evidence = find_evidence(
            lines,
            "enable password"
        )

        findings.append({
            "check": "Weak enable password",
            "severity": "PASS",
            "status": "PASS",
            "evidence": evidence or "No weak password detected"
        })

    # SSH-only access
    if not results["ssh_only_access"]:

        evidence = find_evidence(
            lines,
            "transport input telnet"
        )

        findings.append({
            "check": "SSH-only remote access",
            "severity": "HIGH",
            "status": "FAIL",
            "evidence": evidence or "No SSH-only configuration found"
        })

    else:

        evidence = find_evidence(
            lines,
            "transport input ssh"
        )

        findings.append({
            "check": "SSH-only remote access",
            "severity": "PASS",
            "status": "PASS",
            "evidence": evidence or "SSH remote access configured"
        })

    # HTTP server
    if results["http_server_disabled"]:

        evidence = find_evidence(
            lines,
            "no ip http server"
        )

        findings.append({
            "check": "HTTP server disabled",
            "severity": "PASS",
            "status": "PASS",
            "evidence": evidence or "HTTP server disabled"
        })

    else:

        findings.append({
            "check": "HTTP server disabled",
            "severity": "HIGH",
            "status": "FAIL",
            "evidence": "HTTP server disable command not found"
        })

    return findings


# ==================================================
# SECURITY SCORE
# ==================================================

def calculate_score(results):

    weights = {
        "telnet_disabled": 25,
        "snmp_not_default": 20,
        "passwords_encrypted": 15,
        "enable_password_not_weak": 25,
        "ssh_only_access": 5,
        "http_server_disabled": 10,
    }

    score = 0

    for check, weight in weights.items():

        if results.get(check) is True:
            score += weight

    return score


# ==================================================
# RISK LEVEL
# ==================================================

def risk_level(score):

    if score >= 80:
        return "LOW"

    elif score >= 60:
        return "MEDIUM"

    elif score >= 40:
        return "HIGH"

    else:
        return "CRITICAL"


# ==================================================
# COMPLETE AUDIT FUNCTION
# ==================================================

def audit_configuration(config_text, device_name="UNKNOWN"):

    cfg, unknown, lines = parse(config_text)

    results = run_checks(cfg)

    score = calculate_score(results)

    risk = risk_level(score)

    findings = generate_findings(
        cfg,
        results,
        lines
    )

    report = {
        "device": device_name,
        "security_score": score,
        "risk_level": risk,
        "recognized_settings": cfg,
        "compliance_results": results,
        "findings": findings,
        "unknown_commands": unknown
    }

    return report


# ==================================================
# SAVE JSON REPORT
# ==================================================

def save_report(report, filename="audit_report.json"):

    with open(filename, "w") as f:

        json.dump(
            report,
            f,
            indent=4
        )

    print(f"\nAudit report saved to: {filename}")


# ==================================================
# DISPLAY REPORT
# ==================================================

def display_report(report, title):

    print("\n========================================")
    print(title)
    print("========================================")

    print(
        f"\nSecurity Score: "
        f"{report['security_score']}/100"
    )

    print(
        f"Risk Level: "
        f"{report['risk_level']}"
    )

    print("\nFINDINGS")
    print("----------------------------------------")

    for finding in report["findings"]:

        print(
            f"\n[{finding['severity']}] "
            f"{finding['check']}"
        )

        print(
            f"Status: "
            f"{finding['status']}"
        )

        print(
            f"Evidence: "
            f"{finding['evidence']}"
        )


# ==================================================
# TRAIN UNKNOWN COMMAND
# ==================================================

def train_unknown(command):

    print("\n========================================")
    print("UNKNOWN COMMAND DETECTED")
    print("========================================")

    print(command)

    print("\nWhat does this command represent?")
    print("1. HTTP disabled")
    print("2. Remote access")
    print("3. Authentication")
    print("4. Ignore")

    choice = input("\nChoose an option: ").strip()

    mappings = {
        "1": "http_server_enabled",
        "2": "remote_access",
        "3": "authentication"
    }

    if choice in mappings:

        LEARNED[command] = mappings[choice]

        with open("learned.json", "w") as f:

            json.dump(
                LEARNED,
                f,
                indent=4
            )

        print("\nLearned successfully!")

        print(command)

        print(
            f"        -> "
            f"{mappings[choice]}"
        )

    else:

        print("\nCommand ignored.")


# ==================================================
# SAMPLE CONFIGURATIONS
# ==================================================

config_bad = """
hostname EDGE-R1
enable password cisco123
line vty 0 4
 transport input telnet
snmp-server community public RO
no ip http server
"""


config_good = """
hostname EDGE-R1
enable password Str0ng!Pass
line vty 0 4
 transport input ssh
snmp-server community Xk7#pQz RO
service password-encryption
no ip http server
"""


# ==================================================
# MAIN DEMONSTRATION
# ==================================================

if __name__ == "__main__":

    # ----------------------------------------------
    # BAD CONFIGURATION
    # ----------------------------------------------

    bad_report = audit_configuration(
        config_bad,
        "EDGE-R1"
    )

    display_report(
        bad_report,
        "BAD CONFIGURATION"
    )


    # ----------------------------------------------
    # GOOD CONFIGURATION
    # ----------------------------------------------

    good_report = audit_configuration(
        config_good,
        "EDGE-R1"
    )

    display_report(
        good_report,
        "GOOD CONFIGURATION"
    )


    # ----------------------------------------------
    # UNKNOWN COMMANDS
    # ----------------------------------------------

    print("\n========================================")
    print("UNKNOWN COMMANDS IN BAD CONFIG")
    print("========================================")

    print(
        bad_report["unknown_commands"]
    )


    # ----------------------------------------------
    # TRAIN UNKNOWN COMMANDS
    # ----------------------------------------------

    for command in bad_report["unknown_commands"]:

        train_unknown(command)


    # ----------------------------------------------
    # RELOAD LEARNED KNOWLEDGE
    # ----------------------------------------------

    with open("learned.json", "r") as f:
        LEARNED = json.load(f)


    # ----------------------------------------------
    # RE-PARSE AFTER TRAINING
    # ----------------------------------------------

    print("\n========================================")
    print("RE-PARSING AFTER TRAINING")
    print("========================================")

    updated_report = audit_configuration(
        config_bad,
        "EDGE-R1"
    )

    print("\nRecognized settings:")

    print(
        updated_report["recognized_settings"]
    )

    print(
        f"\nUpdated Security Score: "
        f"{updated_report['security_score']}/100"
    )

    print(
        f"Updated Risk Level: "
        f"{updated_report['risk_level']}"
    )

    display_report(
        updated_report,
        "UPDATED AUDIT RESULTS"
    )

    print("\nRemaining unknown commands:")

    print(
        updated_report["unknown_commands"]
    )


    # ----------------------------------------------
    # SAVE FINAL REPORT
    # ----------------------------------------------

    save_report(
        updated_report,
        "audit_report.json"
    )