"""
Deterministic Cisco IOS configuration parser.

Supports (see project spec for the full list this POC targets):
    hostname <name>
    enable password <password>
    enable secret <password>
    service password-encryption
    line vty <range>
      transport input ssh|telnet|ssh telnet
    snmp-server community <community> <options>
    no ip http server
    ip http server

This parser understands ONE level of hierarchy: commands indented under
a `line vty ...` block belong to that block, not to the top level. This
is the specific bug we are fixing relative to the old monolithic parser.

This module extracts FACTS ONLY. It never decides whether a fact is
secure or insecure - that is Team 2's job. Unrecognized syntax is
preserved as an UnknownCommand and is never guessed at.
"""

import re

from models import ParsedConfig, UnknownCommand
from parser.base import BaseConfigParser

_LINE_VTY_RE = re.compile(r"^line vty\s+(.+)$")


def _is_indented(raw_line: str) -> bool:
    """A line is a child of the previous block if it starts with whitespace."""
    return bool(raw_line) and raw_line[0] in (" ", "\t")


class CiscoIOSParser(BaseConfigParser):
    vendor = "cisco"
    platform = "ios"

    def parse(self, config_text: str) -> ParsedConfig:
        parsed = ParsedConfig(vendor=self.vendor, platform=self.platform)

        # Tracks whether we are currently "inside" a line vty block, and
        # which vty_lines entry child commands should attach to.
        in_vty_block = False
        current_vty_entry = None

        for raw_line in config_text.splitlines():
            stripped = raw_line.strip()

            # Ignore blank lines.
            if not stripped:
                continue

            # Ignore comments.
            if stripped.startswith("!") or stripped.startswith("#"):
                continue

            indented = _is_indented(raw_line)

            if indented and in_vty_block:
                self._handle_vty_child(stripped, parsed, current_vty_entry)
                continue

            # Any non-indented line ends the current vty block context.
            in_vty_block = False
            current_vty_entry = None

            # --- top-level commands ---

            match = _LINE_VTY_RE.match(stripped)
            if match:
                vty_range = match.group(1).strip()
                current_vty_entry = {"range": vty_range, "transport": []}
                parsed.vty_lines.append(current_vty_entry)
                in_vty_block = True
                continue

            if stripped.startswith("hostname "):
                parsed.hostname = stripped[len("hostname "):].strip()
                continue

            if stripped.startswith("enable secret"):
                parsed.enable_password_configured = True
                parsed.enable_password_type = "secret"
                continue

            if stripped.startswith("enable password"):
                parsed.enable_password_configured = True
                parsed.enable_password_type = "password"
                continue

            if stripped == "service password-encryption":
                parsed.password_encryption_enabled = True
                continue

            if stripped.startswith("snmp-server community"):
                parsed.snmp_community_configured = True
                continue

            if stripped == "no ip http server":
                parsed.http_server_enabled = False
                continue

            if stripped == "ip http server":
                parsed.http_server_enabled = True
                continue

            # Nothing matched - preserve for HITL, do not guess.
            parsed.unknown_commands.append(
                UnknownCommand(command=stripped)
            )

        return parsed

    @staticmethod
    def _handle_vty_child(line: str, parsed: ParsedConfig, vty_entry: dict | None) -> None:
        """Handle a command indented under a `line vty ...` block."""
        if line.startswith("transport input"):
            value = line[len("transport input"):].strip()
            protocols = value.split()

            # `transport input` fully specifies the allowed protocol set for
            # this vty block, so this is a direct factual read, not a guess.
            parsed.ssh_enabled = "ssh" in protocols
            parsed.telnet_enabled = "telnet" in protocols

            if vty_entry is not None:
                vty_entry["transport"] = protocols
            return

        # Unrecognized child command - preserve for HITL, do not guess.
        parsed.unknown_commands.append(
            UnknownCommand(command=line)
        )
