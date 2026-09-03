import sys
from config_loader import load_config
from auditor import audit_configuration, save_report


def main():
    if len(sys.argv) != 2:
        print("Usage: python run_audit.py <config_filename>")
        sys.exit(1)

    filename = sys.argv[1]

    try:
        vendor, raw_text = load_config(filename)
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}")
        sys.exit(1)

    print("=" * 40)
    print("NETWORK SECURITY AUDIT")
    print("=" * 40)

    print(f"\nFile: {filename}")
    print(f"Vendor: {vendor}")

    # Run the complete auditor
    report = audit_configuration(
        raw_text,
        filename
    )

    print("\n" + "=" * 40)
    print("AUDIT RESULTS")
    print("=" * 40)

    print(
        f"\nSecurity Score: "
        f"{report['security_score']}/100"
    )

    print(
        f"Risk Level: "
        f"{report['risk_level']}"
    )

    print("\nFINDINGS")
    print("-" * 40)

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

    print("\n" + "=" * 40)
    print("UNKNOWN COMMANDS")
    print("=" * 40)

    unknown = report.get("unknown_commands", [])

    if unknown:
        for command in unknown:
            print(f"  {command}")
    else:
        print("None")

    # Save report
    save_report(
        report,
        "audit_report.json"
    )


if __name__ == "__main__":
    main()