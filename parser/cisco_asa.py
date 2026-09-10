"""
Deterministic Cisco ASA configuration parser.

This is a REAL ASA parser - it does not reuse or delegate to the IOS
parser. ASA syntax differs from IOS (e.g. `passwd` instead of
`enable password` for the login password, `ssh version` instead of
`ip ssh version`, no `line vty` blocks for basic SSH access).

Supports (minimal, POC scope):
    hostname <name>
    enable password <value>
    passwd <value>
    ssh version <version>

Extracts FACTS ONLY - no compliance/security judgements. Unrecognized
syntax is preserved as an UnknownCommand, never guessed at.
"""

from models import ParsedConfig, UnknownCommand
from parser.base import BaseConfigParser


class CiscoASAParser(BaseConfigParser):
    vendor = "cisco"
    platform = "asa"

    def parse(self, config_text: str) -> ParsedConfig:
        parsed = ParsedConfig(vendor=self.vendor, platform=self.platform)

        for raw_line in config_text.splitlines():
            stripped = raw_line.strip()

            # Ignore blank lines.
            if not stripped:
                continue

            # ASA config dumps use "!" as a section separator, ": ..."
            # header comments (e.g. ": Saved"), and an "ASA Version ..."
            # banner line. None of these are actual commands.
            if (
                stripped.startswith("!")
                or stripped.startswith(":")
                or stripped.startswith("ASA Version")
            ):
                continue

            if stripped.startswith("hostname "):
                parsed.hostname = stripped[len("hostname "):].strip()
                continue

            if stripped.startswith("enable password"):
                parsed.enable_password_configured = True
                parsed.enable_password_type = "password"
                continue

            if stripped.startswith("passwd "):
                parsed.passwd_configured = True
                continue

            if stripped.startswith("ssh version"):
                version = stripped[len("ssh version"):].strip()
                parsed.ssh_enabled = True
                parsed.ssh_version = version or None
                continue

            # Nothing matched - preserve for HITL, do not guess.
            parsed.unknown_commands.append(
                UnknownCommand(command=stripped)
            )

        return parsed
