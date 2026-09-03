"""
Quick integration test: config_loader.py + auditor.py (teammate's parse function)

Run from /home/claude/ with:
    python3 run_audit.py cisco_bad.cfg
    python3 run_audit.py cisco_good.cfg
    python3 run_audit.py cisco_partial.cfg
"""

import sys
from config_loader import load_config
from auditor import parse  # teammate's file - must exist alongside this script


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 run_audit.py <config_filename>")
        sys.exit(1)

    filename = sys.argv[1]
    vendor, raw_text = load_config(filename)

    settings, unknown, lines = parse(raw_text)

    print(f"File: {filename}  |  Vendor: {vendor}")
    print(f"Total non-empty lines parsed: {len(lines)}")
    print("-" * 40)
    print("Recognized settings:")
    for k, v in settings.items():
        print(f"  {k}: {v}")
    print("-" * 40)
    print(f"Unknown commands ({len(unknown)}):")
    for line in unknown:
        print(f"  {line}")


if __name__ == "__main__":
    main()
