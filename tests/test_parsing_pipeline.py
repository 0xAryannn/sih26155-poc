import os

from parsing import parse_configuration

CONFIGS_DIR = os.path.join(os.path.dirname(__file__), "..", "configs")


def load(filename):
    path = os.path.join(CONFIGS_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def test_pipeline_routes_ios_config_end_to_end():
    result = parse_configuration(load("cisco_good.cfg"))
    assert result["supported"] is True
    assert result["vendor"] == "cisco"
    assert result["platform"] == "ios"
    assert result["identity"]["hostname"] == "EDGE-R1"


def test_pipeline_routes_asa_config_end_to_end():
    result = parse_configuration(load("cisco_asa_demo.cfg"))
    assert result["supported"] is True
    assert result["vendor"] == "cisco"
    assert result["platform"] == "asa"
    assert result["identity"]["hostname"] == "FW-01"


def test_pipeline_unsupported_vendor_has_no_fallback():
    text = "system {\n    host-name juniper-fw;\n}\n"
    result = parse_configuration(text)
    assert result["supported"] is False
    assert result["vendor"] == "unknown"
    assert result["platform"] == "unsupported"
    # Must NOT have silently produced Cisco IOS-shaped output.
    assert "identity" not in result
