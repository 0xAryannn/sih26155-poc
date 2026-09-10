import os

from parser.cisco_ios import CiscoIOSParser

CONFIGS_DIR = os.path.join(os.path.dirname(__file__), "..", "configs")


def load(filename):
    path = os.path.join(CONFIGS_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def test_cisco_bad_config():
    parsed = CiscoIOSParser().parse(load("cisco_bad.cfg"))

    assert parsed.vendor == "cisco"
    assert parsed.platform == "ios"
    assert parsed.hostname == "EDGE-R1"

    assert parsed.enable_password_configured is True
    assert parsed.enable_password_type == "password"

    # line vty 0 4 / transport input telnet -> hierarchy respected
    assert parsed.telnet_enabled is True
    assert parsed.ssh_enabled is False
    assert parsed.vty_lines == [{"range": "0 4", "transport": ["telnet"]}]

    assert parsed.snmp_community_configured is True
    assert parsed.http_server_enabled is False
    assert parsed.password_encryption_enabled is False


def test_cisco_good_config():
    parsed = CiscoIOSParser().parse(load("cisco_good.cfg"))

    assert parsed.hostname == "EDGE-R1"
    assert parsed.enable_password_configured is True
    assert parsed.enable_password_type == "password"

    assert parsed.ssh_enabled is True
    assert parsed.telnet_enabled is False
    assert parsed.vty_lines == [{"range": "0 4", "transport": ["ssh"]}]

    assert parsed.snmp_community_configured is True
    assert parsed.password_encryption_enabled is True
    assert parsed.http_server_enabled is False


def test_cisco_partial_config_unknown_command_preserved():
    parsed = CiscoIOSParser().parse(load("cisco_partial.cfg"))

    assert parsed.hostname == "CORE-SW1"
    assert parsed.telnet_enabled is True
    assert parsed.ssh_enabled is False

    # "logging trap notifications" is not in our supported command set.
    unknown_commands = [u.command for u in parsed.unknown_commands]
    assert "logging trap notifications" in unknown_commands
    for u in parsed.unknown_commands:
        assert u.reason == "unsupported_syntax"


def test_enable_secret_sets_secret_type():
    text = "hostname R1\nenable secret MySecret1\n"
    parsed = CiscoIOSParser().parse(text)
    assert parsed.enable_password_configured is True
    assert parsed.enable_password_type == "secret"


def test_transport_input_ssh_and_telnet_both():
    text = """
line vty 0 4
 transport input ssh telnet
"""
    parsed = CiscoIOSParser().parse(text)
    assert parsed.ssh_enabled is True
    assert parsed.telnet_enabled is True


def test_ip_http_server_enabled():
    parsed = CiscoIOSParser().parse("ip http server\n")
    assert parsed.http_server_enabled is True


def test_comments_and_blank_lines_are_ignored():
    text = """
! this is a comment
hostname R1

# another comment style
enable secret Sup3rSecret
"""
    parsed = CiscoIOSParser().parse(text)
    assert parsed.hostname == "R1"
    assert parsed.enable_password_type == "secret"
    assert parsed.unknown_commands == []


def test_unknown_top_level_command():
    parsed = CiscoIOSParser().parse("some-completely-unknown-command foo\n")
    assert len(parsed.unknown_commands) == 1
    assert parsed.unknown_commands[0].command == "some-completely-unknown-command foo"
    assert parsed.unknown_commands[0].reason == "unsupported_syntax"


def test_unrecognized_vty_child_command_is_unknown_not_guessed():
    text = """
line vty 0 4
 login local
"""
    parsed = CiscoIOSParser().parse(text)
    unknown_commands = [u.command for u in parsed.unknown_commands]
    assert "login local" in unknown_commands
    # Must not have guessed ssh/telnet state from an unrelated child command.
    assert parsed.ssh_enabled is None
    assert parsed.telnet_enabled is None


def test_normalized_output_never_contains_secret_values():
    parsed = CiscoIOSParser().parse(load("cisco_bad.cfg"))
    from normalizer import normalize_parsed_config

    normalized = normalize_parsed_config(parsed)
    dumped = str(normalized)

    assert "cisco123" not in dumped
    assert "public RO" not in dumped
    assert "public" not in dumped
