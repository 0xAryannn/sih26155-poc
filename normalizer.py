"""
Converts a vendor-specific models.ParsedConfig into a common,
vendor-neutral dict structure that Team 2's compliance engine consumes.

This module does NOT make compliance decisions. It only reshapes facts
that the parser already extracted. It never invents values - fields the
parser left as None/False-by-absence stay that way.

Never exposes actual secret values (passwords, SNMP community strings).
Only metadata such as "configured: true" / "type: password".
"""

from models import ParsedConfig


def normalize_parsed_config(parsed: ParsedConfig) -> dict:
    return {
        "vendor": parsed.vendor,
        "platform": parsed.platform,

        "identity": {
            "hostname": parsed.hostname,
        },

        "management": {
            "ssh_enabled": parsed.ssh_enabled,
            "ssh_version": parsed.ssh_version,
            "telnet_enabled": parsed.telnet_enabled,
            "vty_lines": parsed.vty_lines,
        },

        "authentication": {
            "enable_password_configured": parsed.enable_password_configured,
            "enable_password_type": parsed.enable_password_type,
            "passwd_configured": parsed.passwd_configured,
        },

        "snmp": {
            "community_configured": parsed.snmp_community_configured,
        },

        "services": {
            "http_server_enabled": parsed.http_server_enabled,
        },

        "security_features": {
            "password_encryption_enabled": parsed.password_encryption_enabled,
        },

        "unknown_commands": [
            {"command": u.command, "reason": u.reason}
            for u in parsed.unknown_commands
        ],
    }
