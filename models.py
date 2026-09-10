"""
Shared data structures for the parsing pipeline.

These are the common types passed between detector, parsers,
and normalizer. Compliance/scoring logic does NOT live here.
"""

from dataclasses import dataclass, field


@dataclass
class UnknownCommand:
    """A command the parser could not confidently interpret."""
    command: str
    reason: str = "unsupported_syntax"


@dataclass
class DetectionResult:
    """Output of the vendor/platform detector."""
    vendor: str          # e.g. "cisco", "juniper", "unknown"
    platform: str        # e.g. "ios", "asa", "unsupported"
    confidence: str      # "high", "medium", "low"


@dataclass
class ParsedConfig:
    """
    Vendor-specific parser output.

    Each parser fills this with whatever it extracted.
    The normalizer then converts it to a vendor-neutral form.
    """
    vendor: str
    platform: str
    hostname: str | None = None

    # Authentication — metadata only, never raw secrets
    enable_password_configured: bool = False
    enable_password_type: str | None = None   # "password" or "secret"
    passwd_configured: bool = False            # ASA 'passwd' command

    # Management
    ssh_enabled: bool | None = None
    ssh_version: str | None = None
    telnet_enabled: bool | None = None

    # VTY lines context
    vty_lines: list[dict] = field(default_factory=list)

    # SNMP — no community string value
    snmp_community_configured: bool = False

    # Services
    http_server_enabled: bool | None = None

    # Security features
    password_encryption_enabled: bool = False

    # Unknown commands for HITL
    unknown_commands: list[UnknownCommand] = field(default_factory=list)
