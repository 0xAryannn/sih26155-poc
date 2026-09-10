from detector import detect_platform


def test_detects_cisco_ios():
    text = """
hostname EDGE-R1
enable secret cisco123
line vty 0 4
 transport input ssh
no ip http server
"""
    result = detect_platform(text)
    assert result.vendor == "cisco"
    assert result.platform == "ios"
    assert result.confidence == "high"


def test_detects_cisco_asa():
    text = """
: Saved
ASA Version 9.12(4)
hostname FW-01
passwd DemoPassword123
ssh version 2
nameif outside
"""
    result = detect_platform(text)
    assert result.vendor == "cisco"
    assert result.platform == "asa"
    assert result.confidence == "high"


def test_asa_is_not_detected_as_ios():
    text = """
hostname FW-01
passwd DemoPassword123
ssh version 2
"""
    result = detect_platform(text)
    assert result.platform != "ios"
    assert result.platform == "asa"


def test_no_markers_returns_unsupported():
    text = """
system {
    host-name juniper-fw;
}
"""
    result = detect_platform(text)
    assert result.vendor == "unknown"
    assert result.platform == "unsupported"
    assert result.confidence == "low"


def test_empty_config_returns_unsupported():
    result = detect_platform("")
    assert result.vendor == "unknown"
    assert result.platform == "unsupported"


def test_ambiguous_mixed_markers_returns_unsupported_no_fallback():
    # Contains both an IOS-only marker and an ASA-only marker in equal
    # measure - detector must not guess or silently fall back to IOS.
    text = """
line vty 0 4
 transport input ssh
passwd DemoPassword123
"""
    result = detect_platform(text)
    assert result.vendor == "unknown"
    assert result.platform == "unsupported"
