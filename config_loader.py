import os
import argparse

CONFIG_DIR = "configs/"


def list_configs(directory: str = CONFIG_DIR) -> list[str]:
    """Return all .cfg filenames in the configs directory."""
    if not os.path.isdir(directory):
        raise FileNotFoundError(f"Config directory not found: {directory}")
    return sorted(f for f in os.listdir(directory) if f.endswith(".cfg"))


def detect_vendor(filename: str) -> str:
    """
    Infer vendor from filename convention: <vendor>_<name>.cfg
    e.g. cisco_router1.cfg -> "cisco", juniper_fw2.cfg -> "juniper"
    """
    base = os.path.basename(filename)
    if "_" not in base:
        return "unknown"
    return base.split("_", 1)[0].lower()


def load_config(filename: str, directory: str = CONFIG_DIR) -> tuple[str, str]:
    """
    Load a single config file.
    Returns (vendor, raw_text) - vendor is inferred from filename,
    raw_text is exactly what gets passed into parse().
    """
    path = os.path.join(directory, filename)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Config file not found: {path}")

    vendor = detect_vendor(filename)

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        raw_text = f.read()

    if not raw_text.strip():
        raise ValueError(f"Config file is empty: {path}")

    return vendor, raw_text


def load_all_configs(directory: str = CONFIG_DIR) -> list[tuple[str, str, str]]:
    """
    Load every .cfg file in the directory.
    Returns list of (filename, vendor, raw_text) tuples.
    """
    results = []
    for filename in list_configs(directory):
        vendor, raw_text = load_config(filename, directory)
        results.append((filename, vendor, raw_text))
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Load network device config files for auditing")
    parser.add_argument("--file", help="Specific config file to load (e.g. cisco_bad.cfg)")
    parser.add_argument("--list", action="store_true", help="List available config files")
    parser.add_argument("--dir", default=CONFIG_DIR, help="Directory containing config files")
    args = parser.parse_args()

    if args.list:
        for f in list_configs(args.dir):
            print(f"{f}  ->  vendor: {detect_vendor(f)}")

    elif args.file:
        vendor, raw_text = load_config(args.file, args.dir)
        print(f"Loaded {args.file} (vendor: {vendor})")
        print("---")
        print(raw_text)
        # This is the handoff point - teammate's parse() takes raw_text directly:
        # from auditor import parse
        # settings, unknown, lines = parse(raw_text)

    else:
        print("Use --list to see configs, or --file <name> to load one.")
