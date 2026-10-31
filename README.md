# Netscan

Concurrent IPv4 ICMP host discovery using the operating system's `ping` utility.
This is not a TCP/UDP port scanner. A host that blocks ICMP may be online but absent from results.

```sh
python netscan.py --help
python netscan.py 192.168.1.0/24
python -m unittest -v
```

Scan only a local network you own or are authorised to test. Explicit subnets, three-octet
prefixes and IPv4 addresses are accepted. IPv6 and subnets containing more than 4096 hosts
are rejected before allocating worker tasks. A single IPv4 address without `/32` retains
the original `/24` shorthand behaviour.

With no argument, Linux uses `ip -j address show up`, with `ifconfig` as a fallback; macOS
uses `ifconfig`, and Windows parses `ipconfig`. If multiple interfaces are active, the first
eligible address may not be your intended network; supplying the subnet explicitly is best.
Automatic discovery does not contact an external host or invent a subnet mask. On a localized
Windows system whose output cannot be parsed, supply an explicit IPv4 subnet.

Python 3.10+ and the OS `ping` executable are needed. Unit tests mock ping and interface
commands, so they do not probe any network. Exit status is 0 for a completed scan/help and 1
for invalid input or failed subnet discovery.
