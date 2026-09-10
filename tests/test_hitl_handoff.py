import json
import os

import hitl
from parser.cisco_ios import CiscoIOSParser
from parsing import audit_configuration, parse_configuration


def test_known_command_is_not_sent_to_hitl():
    config = """
service password-encryption
hostname R1
"""

    result = parse_configuration(config)

    assert result["unknown_commands"] == []


def test_unknown_command_is_captured():
    config = """
service password-encryption
hostname R1
some-new-command abc
"""

    result = parse_configuration(config)

    assert len(result["unknown_commands"]) == 1
    assert result["unknown_commands"][0]["command"] == "some-new-command abc"


def test_unknown_command_is_sent_to_hitl(tmp_path):
    learned_path = tmp_path / "learned.json"

    unknown_commands = [
        {
            "command": "some-new-command abc",
            "reason": "unsupported_syntax",
        }
    ]

    result = hitl.receive_unknown_commands(
        unknown_commands,
        str(learned_path),
    )

    assert len(result) == 1
    assert result[0]["command"] == "some-new-command abc"
    assert result[0]["hitl_status"] == "needs_review"


def test_hitl_approved_command(tmp_path):
    learned_path = tmp_path / "learned.json"

    hitl.record_decision(
        "some-new-command abc",
        "approved",
        "Reviewed by administrator",
        str(learned_path),
    )

    result = hitl.receive_unknown_commands(
        [
            {
                "command": "some-new-command abc",
                "reason": "unsupported_syntax",
            }
        ],
        str(learned_path),
    )

    assert result[0]["hitl_status"] == "approved"
    assert result[0]["hitl_note"] == "Reviewed by administrator"


def test_audit_pipeline_contains_hitl_information(tmp_path):
    learned_path = tmp_path / "learned.json"

    config = """
service password-encryption
hostname R1
some-new-command abc
"""

    result = audit_configuration(
        config,
        learned_path=str(learned_path),
    )

    assert "unknown_commands" in result
    assert "hitl" in result

    assert len(result["unknown_commands"]) == 1
    assert result["unknown_commands"][0]["command"] == "some-new-command abc"


def test_hitl_does_not_store_secret_values(tmp_path):
    learned_path = tmp_path / "learned.json"

    hitl.record_decision(
        "some-new-command abc",
        "approved",
        "Safe command",
        str(learned_path),
    )

    with open(learned_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    raw = json.dumps(data)

    assert "password123" not in raw
    assert "secret123" not in raw