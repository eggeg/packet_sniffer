Packet Sniffer
Description

This Packet Sniffer is a powerful tool for monitoring network traffic. It captures and logs various packet types, including Ethernet frames, IPv4, IPv6, TCP, UDP, and ARP packets. The program also includes functionality to filter traffic based on IP addresses, ports, and protocols, making it highly versatile for network analysis in a cybersecurity context.
Features

    Packet Logging: Logs details of Ethernet frames, IPv4 and IPv6 packets, TCP and UDP segments, and ARP packets.
    Uncommon Port Detection: Alerts when traffic is detected on non-standard ports.
    Protocol-Specific Analysis: Framework for analyzing specific protocols like HTTP, SSH, DNS, etc.
    Flexible Filtering: Ability to filter traffic by IP address, port, and protocol.

Requirements

    Python 3.x
    Scapy library

Installation

    Ensure Python 3.x is installed on your system.
    Install Scapy:

    bash

    pip install scapy

Usage

Run the script from the command line. You can provide optional arguments for filtering:

bash

python sniffer_project.py [--ip IP_ADDRESS] [--port PORT] [--protocol PROTOCOL]

    --ip: Filter traffic to and from the specified IP address.
    --port: Filter traffic on the specified port.
    --protocol: Filter traffic by protocol (tcp, udp, icmp).

Example:

bash

python sniffer_project.py --ip 192.168.1.1 --port 80 --protocol tcp

Logging

Packet details are logged to sniffer.log. The log is rotated when it reaches 1MB in size, with the 3 most recent logs being kept.
Customization

The script includes placeholder functions for protocol-specific analysis. These can be customized for detailed analysis of specific types of network traffic.
License

This software is released under the MIT License.