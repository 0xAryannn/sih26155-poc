KNOWN = {
    "enable password": "enable_password",
    "transport input": "remote_access",
    "snmp-server community": "snmp",
    "service password-encryption": "pw_encryption",
}


def parse(text):
    settings = {}
    unknown = []

    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        matched = False

        for prefix, key in KNOWN.items():

            if line.startswith(prefix):
                matched = True

                if key == "enable_password":
                    settings["enable_password"] = line.split(" ", 2)[2]

                elif key == "remote_access":
                    settings["remote_access"] = line.split(" ", 2)[2]

                elif key == "snmp":
                    parts = line.split()
                    settings["snmp_community"] = parts[2]

                elif key == "pw_encryption":
                    settings["pw_encryption"] = True

        if not matched:
            unknown.append(line)

    return settings, unknown


config_bad = """
hostname EDGE-R1
enable password cisco123
line vty 0 4
 transport input telnet
snmp-server community public RO
no ip http server
"""

config_good = """
hostname EDGE-R1
enable password Str0ng!Pass
line vty 0 4
 transport input ssh
snmp-server community Xk7#pQz RO
service password-encryption
no ip http server
"""


bad_settings, bad_unknown = parse(config_bad)

print("BAD CONFIGURATION")
print(bad_settings)
print("Unknown:", bad_unknown)

print()

good_settings, good_unknown = parse(config_good)

print("GOOD CONFIGURATION")
print(good_settings)
print("Unknown:", good_unknown)