from models import ParsedConfig, UnknownCommand
from normalizer import normalize_parsed_config


def test_normalizer_shapes_ios_output():
    parsed = ParsedConfig(
        vendor="cisco",
        platform="ios",
        hostname="EDGE-R1",
        enable_password_configured=True,
        enable_password_type="password",
        ssh_enabled=False,
        telnet_enabled=True,
        vty_lines=[{"range": "0 4", "transport": ["telnet"]}],
        snmp_community_configured=True,
        http_server_enabled=False,
        password_encryption_enabled=False,
        unknown_commands=[UnknownCommand(command="foo bar")],
    )

    normalized = normalize_parsed_config(parsed)

    assert normalized["vendor"] == "cisco"
    assert normalized["platform"] == "ios"
    assert normalized["identity"]["hostname"] == "EDGE-R1"

    assert normalized["management"]["ssh_enabled"] is False
    assert normalized["management"]["telnet_enabled"] is True
    assert normalized["management"]["vty_lines"] == [
        {"range": "0 4", "transport": ["telnet"]}
    ]

    assert normalized["authentication"]["enable_password_configured"] is True
    assert normalized["authentication"]["enable_password_type"] == "password"
    assert normalized["authentication"]["passwd_configured"] is False

    assert normalized["snmp"]["community_configured"] is True
    assert normalized["services"]["http_server_enabled"] is False
    assert normalized["security_features"]["password_encryption_enabled"] is False

    assert normalized["unknown_commands"] == [
        {"command": "foo bar", "reason": "unsupported_syntax"}
    ]


def test_normalizer_uses_null_not_invented_values():
    parsed = ParsedConfig(vendor="cisco", platform="asa", hostname=None)
    normalized = normalize_parsed_config(parsed)

    # Nothing was observed in the (empty) source config, so these must
    # stay None/False-by-absence rather than being guessed.
    assert normalized["identity"]["hostname"] is None
    assert normalized["management"]["ssh_enabled"] is None
    assert normalized["management"]["telnet_enabled"] is None
    assert normalized["authentication"]["enable_password_configured"] is False
    assert normalized["authentication"]["enable_password_type"] is None
    assert normalized["snmp"]["community_configured"] is False
    assert normalized["services"]["http_server_enabled"] is None


def test_normalizer_never_includes_raw_secret_field_names():
    parsed = ParsedConfig(
        vendor="cisco",
        platform="ios",
        enable_password_configured=True,
        enable_password_type="password",
    )
    normalized = normalize_parsed_config(parsed)

    # The normalized structure must never carry a raw password/community
    # value anywhere - only booleans/metadata.
    def walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                assert k not in ("password", "community", "secret_value")
                walk(v)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(normalized)
