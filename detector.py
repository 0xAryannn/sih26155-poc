"""
Deterministic vendor/platform detector.

Scope for this POC: Cisco IOS and Cisco ASA only.

Detection is CONTENT-based (looks at command syntax actually present in the
config), not filename-based. If the content does not clearly indicate one
of the supported platforms, detection returns an explicit
vendor="unknown" / platform="unsupported" result.

There is NO fallback to Cisco IOS for ambiguous or unrecognized input.
"""

import re

from models import DetectionResult


# --------------------------------------------------------------------------
# Marker patterns
#
# Each pattern is matched against a single stripped line. These are command
# prefixes/shapes that are characteristic of one platform and not the other.
# Keep this list intentionally small - this is a POC, not a full grammar.
# --------------------------------------------------------------------------

IOS_PATTERNS = [
    re.compile(r"^line vty\b"),
    re.compile(r"^line con\b"),
    re.compile(r"^enable secret\b"),
    re.compile(r"^service password-encryption\b"),
    re.compile(r"^(no )?ip http server\b"),
    re.compile(r"^ip ssh version\b"),
]

ASA_PATTERNS = [
    re.compile(r"^passwd\b"),
    re.compile(r"^ssh version\b"),
    re.compile(r"^nameif\b"),
    re.compile(r"^security-level\b"),
    re.compile(r"^same-security-traffic\b"),
    re.compile(r"^: Saved\b"),
    re.compile(r"^ASA Version\b"),
]


def _count_hits(lines: list[str], patterns: list[re.Pattern]) -> int:
    hits = 0
    for line in lines:
        for pattern in patterns:
            if pattern.match(line):
                hits += 1
                break
    return hits


def detect_platform(config_text: str) -> DetectionResult:
    """
    Inspect raw config text and return a DetectionResult.

    Only two supported outcomes for this POC:
      - ("cisco", "ios")
      - ("cisco", "asa")

    Anything else (no markers found, or markers for both platforms present
    in roughly equal measure) is returned as an explicit unsupported result:
      - ("unknown", "unsupported")

    This function never guesses and never defaults to Cisco IOS.
    """
    lines = [line.strip() for line in config_text.splitlines() if line.strip()]

    ios_hits = _count_hits(lines, IOS_PATTERNS)
    asa_hits = _count_hits(lines, ASA_PATTERNS)

    if ios_hits == 0 and asa_hits == 0:
        return DetectionResult(vendor="unknown", platform="unsupported", confidence="low")

    if ios_hits > 0 and asa_hits > 0:
        # Ambiguous - markers for both platforms present. Do not guess.
        return DetectionResult(vendor="unknown", platform="unsupported", confidence="low")

    if asa_hits > ios_hits:
        return DetectionResult(vendor="cisco", platform="asa", confidence="high")

    return DetectionResult(vendor="cisco", platform="ios", confidence="high")
