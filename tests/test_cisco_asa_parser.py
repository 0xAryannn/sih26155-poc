import os

from detector import detect_platform
from parser.cisco_asa import CiscoASAParser
from parser.cisco_ios import CiscoIOSParser

CONFIGS_DIR = os.path.join(os.path.dirname(__file__), "..", "configs")


def load(filename):
    path = os.path.join(CONFIGS_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def test_asa_demo_config_detection_routes_to_asa():
    text = load("cisco_asa_demo.cfg")
    detection = detect_platform(text)
    assert detection.vendor == "cisco"
    assert detection.platform == "asa"


def test_asa_demo_config_parses_expected_facts():
    parsed = CiscoASAParser().parse(load("cisco_asa_demo.cfg"))

    assert parsed.vendor == "cisco"
    assert parsed.platform == "asa"
    assert parsed.hostname == "FW-01"

    assert parsed.enable_password_configured is True
    assert parsed.enable_password_type == "password"

    assert parsed.passwd_configured is True

    assert parsed.ssh_enabled is True
    assert parsed.ssh_version == "2"


def test_asa_demo_config_unknown_command_preserved():
    parsed = CiscoASAParser().parse(load("cisco_asa_demo.cfg"))
    unknown_commands = [u.command for u in parsed.unknown_commands]
    assert "some-completely-unknown-asa-command foo" in unknown_commands
    for u in parsed.unknown_commands:
        assert u.reason == "unsupported_syntax"


def test_asa_config_is_not_parsed_as_ios():
    # Run the ASA config through the IOS parser directly to prove the two
    # parsers are independent implementations, not one delegating to the
    # other. IOS-specific facts should NOT be populated from ASA syntax.
    parsed = CiscoIOSParser().parse(load("cisco_asa_demo.cfg"))

    # The IOS parser has no rule for "passwd" or "ssh version", so ASA's
    # login facts must not leak into IOS-shaped fields.
    assert parsed.passwd_configured is False
    assert parsed.ssh_enabled is None
    assert parsed.ssh_version is None

    # hostname line uses identical syntax across both platforms, so it is
    # still picked up - but everything ASA-specific should end up unknown.
    unknown_commands = [u.command for u in parsed.unknown_commands]
    assert "passwd DemoPassword123" in unknown_commands
    assert "ssh version 2" in unknown_commands


def test_hostname_only_asa_config():
    parsed = CiscoASAParser().parse("hostname FW-EMPTY\n")
    assert parsed.hostname == "FW-EMPTY"
    assert parsed.passwd_configured is False
    assert parsed.ssh_enabled is None


def test_asa_comments_and_saved_header_ignored():
    text = """
: Saved
ASA Version 9.12(4)
!
hostname FW-02
"""
    parsed = CiscoASAParser().parse(text)
    assert parsed.hostname == "FW-02"
    assert parsed.unknown_commands == []
