"""
Public entry point for the parsing pipeline (Team 3 scope).

    raw config text
        -> detect vendor/platform     (detector.py)
        -> select correct parser      (parser/cisco_ios.py, parser/cisco_asa.py)
        -> parse                      (-> models.ParsedConfig)
        -> normalize                  (normalizer.py)
        -> vendor-neutral dict result

There is intentionally NO fallback such as:
    PARSERS.get(key, PARSERS[("cisco", "ios")])

If the platform is unsupported or detection is ambiguous, an explicit
unsupported result is returned instead of guessing.

This module does not touch compliance, scoring, HITL, or learned.json.
"""

from detector import detect_platform
from normalizer import normalize_parsed_config
from parser.cisco_asa import CiscoASAParser
from parser.cisco_ios import CiscoIOSParser

# Explicit registry - only platforms with a real, implemented parser
# appear here. There is no default/catch-all entry.
_PARSERS = {
    ("cisco", "ios"): CiscoIOSParser,
    ("cisco", "asa"): CiscoASAParser,
}


def parse_configuration(config_text: str) -> dict:
    """
    Run the full parsing pipeline on raw config text.

    Returns a vendor-neutral dict. When the vendor/platform is not
    supported (or detection was ambiguous), returns an explicit
    unsupported result with "supported": False - never a guessed parse.
    """
    detection = detect_platform(config_text)
    parser_cls = _PARSERS.get((detection.vendor, detection.platform))

    if parser_cls is None:
        return {
            "supported": False,
            "vendor": detection.vendor,
            "platform": detection.platform,
            "detection_confidence": detection.confidence,
            "error": "unsupported_vendor_or_platform",
            "unknown_commands": [],
        }

    parser = parser_cls()
    parsed = parser.parse(config_text)

    result = normalize_parsed_config(parsed)
    result["supported"] = True
    result["detection_confidence"] = detection.confidence
    return result
