import psutil

# List available network interfaces using psutil
interfaces = psutil.net_if_addrs()
print("Available network interfaces:")
for interface in interfaces:
    print(interface)
