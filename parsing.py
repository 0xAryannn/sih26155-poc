"""
Team 3 configuration parsing pipeline.

RAW CONFIG
    -> vendor/platform detection
    -> appropriate vendor parser
    -> normalization
    -> common JSON output

HITL is handled by audit_configuration() as the Team 3 -> Team 2 handoff.

This module does NOT perform compliance scoring or PASS/FAIL decisions.
"""

from typing import Any

import hitl

from detector import detect_platform
from normalizer import normalize_parsed_config
from parser.cisco_asa import CiscoASAParser
from parser.cisco_ios import CiscoIOSParser


SCHEMA_VERSION = "1.0"


def _get_parser(vendor: str, platform: str):
    """Return the appropriate parser for the detected platform."""

    if vendor == "cisco" and platform == "ios":
        return CiscoIOSParser()

    if vendor == "cisco" and platform == "asa":
        return CiscoASAParser()

    return None


def parse_configuration(config_text: str) -> dict:
    """
    Parse raw configuration into the existing normalized structure.
    """

    detection = detect_platform(config_text)

    # Unsupported or ambiguous configuration.
    # Do NOT return vendor-specific/Cisco-shaped fields.
    if (
        detection.vendor == "unknown"
        or detection.platform == "unsupported"
    ):
        return {
            "vendor": detection.vendor,
            "platform": detection.platform,
            "confidence": detection.confidence,
            "supported": False,
            "unknown_commands": [],
        }

    parser = _get_parser(
        detection.vendor,
        detection.platform,
    )

    if parser is None:
        return {
            "vendor": detection.vendor,
            "platform": detection.platform,
            "confidence": detection.confidence,
            "supported": False,
            "unknown_commands": [],
        }

    # Vendor-specific parsing
    parsed = parser.parse(config_text)

    # Convert ParsedConfig into common vendor-neutral structure
    normalized = normalize_parsed_config(parsed)

    return {
        "vendor": normalized["vendor"],
        "platform": normalized["platform"],
        "confidence": detection.confidence,
        "supported": True,

        "identity": normalized["identity"],
        "management": normalized["management"],
        "authentication": normalized["authentication"],
        "snmp": normalized["snmp"],
        "services": normalized["services"],
        "security_features": normalized["security_features"],

        "unknown_commands": normalized["unknown_commands"],
    }


def audit_configuration(
    config_text: str,
    learned_path: str = "learned.json",
) -> dict[str, Any]:
    """
    Team 3 -> Team 2 handoff.

    RAW CONFIG
        |
        v
    Detection
        |
        v
    Vendor Parser
        |
        v
    Normalization
        |
        v
    Unknown Commands
        |
        v
    HITL
        |
        v
    Common JSON

    Compliance rules, scoring, risk and PASS/FAIL decisions
    are intentionally NOT performed here.
    """

    parsed_result = parse_configuration(config_text)

    unknown_commands = parsed_result.get(
        "unknown_commands",
        [],
    )

    # Pass parser-generated unknown syntax to HITL.
    hitl_commands = hitl.receive_unknown_commands(
        unknown_commands,
        learned_path,
    )

    # Generate HITL status summary.
    hitl_summary = hitl.summarize(
        unknown_commands,
        learned_path,
    )

    return {
        "schema_version": SCHEMA_VERSION,

        "detection": {
            "vendor": parsed_result.get("vendor"),
            "platform": parsed_result.get("platform"),
            "confidence": parsed_result.get("confidence"),
            "supported": parsed_result.get("supported"),
        },

        "facts": {
            "identity": parsed_result.get("identity", {}),
            "management": parsed_result.get("management", {}),
            "authentication": parsed_result.get("authentication", {}),
            "snmp": parsed_result.get("snmp", {}),
            "services": parsed_result.get("services", {}),
            "security_features": parsed_result.get(
                "security_features",
                {},
            ),
        },

        "unknown_commands": hitl_commands,

        "hitl": hitl_summary,
    }