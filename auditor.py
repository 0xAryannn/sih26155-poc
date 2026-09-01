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

print("Bad configuration:")
print(config_bad)

print("Good configuration:")
print(config_good)
