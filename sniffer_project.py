from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP
from scapy.all import sniff
import logging
from logging.handlers import RotatingFileHandler
import re 
import argparse

"""
    IS UNCOMMON PORT FUNCTION
    Determines if the given port is uncommon based on a predefined list of common ports.
    
    Parameters:
    port (int): The port number to be checked.

    Returns:
    bool: True if the port is not in the list of common ports, False otherwise.
    """
def is_uncommon_port(port):
    # List of common ports
    common_ports = [
        20, 21, 22, 23, 25, 53, 80, 110, 143, 443,
        465, 587, 993, 995, 3389, 5900, 8080
    ]
    return port not in common_ports

"""
    CONFIGURE LOGGING FUNCTION
    Configures the logging for the packet sniffer. 
    Sets up a log handler with a specific format and file rotation policy.
"""
def configure_logging():
    log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    # Create a handler that writes log messages to a file, with a maximum log file size of 1 MB, keeping 3 old log files.
    log_handler = RotatingFileHandler('sniffer.log', maxBytes=1e6, backupCount=3)
    log_handler.setFormatter(log_formatter)
    
    # Adding the handler to the root logger
    logging.getLogger().addHandler(log_handler)
    logging.getLogger().setLevel(logging.INFO)

"""
    LOG ETHERNET FRAME FUNCTION
    Logs the details of an Ethernet frame from the given packet.

    Parameters:
    packet (scapy.Packet): The packet containing the Ethernet frame to be logged.
"""
def log_ethernet_frame(packet):
    try:
        eth_frame = packet[Ether]
        logging.info(f'Ethernet Frame: Destination: {eth_frame.dst}, Source: {eth_frame.src}, Protocol: {eth_frame.type}')
    except Exception as e:
        logging.error(f'Error processing Ethernet frame: {e}. Packet details: {packet.summary()}')

"""
    LOG IPv4 PACKET FUNCTION
    Logs the details of an IPv4 packet.

    Parameters:
    packet (scapy.Packet): The packet containing the IPv4 packet to be logged.
"""
def log_ipv4_packet(packet):
    try:
        ipv4_packet = packet[IP]
        logging.info(f'IPv4 Packet: Version: {ipv4_packet.version}, Header Length: {ipv4_packet.ihl}, TTL: {ipv4_packet.ttl}, Protocol: {ipv4_packet.proto}, Source: {ipv4_packet.src}, Target: {ipv4_packet.dst}')
    except Exception as e:
        logging.error(f'Error processing IPv4 packet: {e}. Packet details: {packet.summary()}')


"""
    LOG IPv6 PACKET FUNCTION
    Logs the details of an IPv6 packet.

    Parameters:
    packet (scapy.Packet): The packet containing the IPv6 packet to be logged.
"""
def log_ipv6_packet(packet):
    try:
        ipv6_packet = packet[IPv6]
        logging.info(f'IPv6 Packet: Version: {ipv6_packet.version}, Traffic Class: {ipv6_packet.tc}, Flow Label: {ipv6_packet.fl}, Payload Length: {ipv6_packet.plen}, Next Header: {ipv6_packet.nh}, Hop Limit: {ipv6_packet.hlim}, Source: {ipv6_packet.src}, Target: {ipv6_packet.dst}')
    except Exception as e:
        logging.error(f'Error processing IPv6 packet: {e}. Packet details: {packet.summary()}')

"""
    LOG UDP SEGMENT FUNCTION
    Logs the details of a UDP segment.

    Parameters:
    packet (scapy.Packet): The packet containing the UDP segment to be logged.
"""
def log_udp_segment(packet):
    try:
        udp_segment = packet[UDP]
        logging.info(f'UDP Segment: Source Port: {udp_segment.sport}, Destination Port: {udp_segment.dport}')
    except Exception as e:
        logging.error(f'Error processing UDP segment: {e}. Packet details: {packet.summary()}')

"""
    LOG TCP SEGMENT FUNCTION
    Logs the details of a TCP segment.

    Parameters:
    packet (scapy.Packet): The packet containing the TCP segment to be logged.
"""
def log_tcp_segment(packet):
    try:
        tcp_segment = packet[TCP]
        logging.info(f'TCP Segment: Source Port: {tcp_segment.sport}, Destination Port: {tcp_segment.dport}')
    except Exception as e:
        logging.error(f'Error processing TCP segment: {e}. Packet details: {packet.summary()}')

"""
    LOG ICMP PACKET FUNCTION
    Logs the details of an ICMP packet.

    Parameters:
    packet (scapy.Packet): The packet containing the ICMP packet to be logged.
"""
def log_icmp_packet(packet):
    try:
        icmp_segment = packet[ICMP]
        logging.info(f'ICMP Segment: Source Port: {icmp_segment.sport}, Destination Port: {icmp_segment.dport}')
    except Exception as e:
        logging.error(f'Error processing ICMP segment: {e}. Packet details: {packet.summary()}')
        
"""
    LOG ARP PACKET FUNCTION
    Logs the details of an ARP packet.

    Parameters:
    packet (scapy.Packet): The packet containing the ARP packet to be logged.
"""
def log_arp_packet(packet):
    try:
        arp_packet = packet[ARP]
        logging.info(f'ARP Packet: Hardware Type: {arp_packet.hwtype}, Protocol Type: {arp_packet.ptype}, Operation: {arp_packet.op}, Sender MAC: {arp_packet.hwsrc}, Sender IP: {arp_packet.psrc}, Target MAC: {arp_packet.hwdst}, Target IP: {arp_packet.pdst}')
    except Exception as e:
        logging.error(f'Error processing ARP packet: {e}. Packet details: {packet.summary()}')


"""
    PROCESS PACKET FUNCTION
    Processes a packet, logging various layers (Ethernet, IP, TCP, etc.) and detecting uncommon ports.

    Parameters:
    packet (scapy.Packet): The packet to be processed and logged.
"""
def process_packet(packet):
    log_ethernet_frame(packet)
    if packet.haslayer(IP):
        log_ipv4_packet(packet)
    if packet.haslayer(UDP):
        log_udp_segment(packet)
    if packet.haslayer(TCP):
        log_tcp_segment(packet)
    if packet.haslayer(ARP):
        log_arp_packet(packet)
    if packet.haslayer(IPv6):
        log_ipv6_packet(packet)
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            
            if is_uncommon_port(src_port) or is_uncommon_port(dst_port):
                print(f"[!] Uncommon Port Detected! Source: {src_ip}:{src_port} -> Destination: {dst_ip}:{dst_port}")

        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            
            if is_uncommon_port(src_port) or is_uncommon_port(dst_port):
                print(f"[!] Uncommon Port Detected! Source: {src_ip}:{src_port} -> Destination: {dst_ip}:{dst_port}")
                
# Protocol analysis functions
def analyze_http(packet):
    if packet.haslayer(TCP) and (packet[TCP].sport == 80 or packet[TCP].dport == 80):
        # Analyze HTTP traffic
        # Example: Check for suspicious User-Agent strings or URL patterns
        pass  # Implement your analysis logic here

def analyze_ssh(packet):
    if packet.haslayer(TCP) and (packet[TCP].sport == 22 or packet[TCP].dport == 22):
        # Analyze SSH traffic
        # Example: Detect unusual SSH connections or failed authentication attempts
        pass  # Implement your analysis logic here

def analyze_dns(packet):
    if packet.haslayer(UDP) and (packet[UDP].sport == 53 or packet[UDP].dport == 53):
        # Analyze DNS queries and responses
        # Example: Look for domain name patterns associated with phishing or malware
        pass  # Implement your analysis logic here

# ... Additional protocol analysis functions ...

# Modify the packet processing function
def process_packet(packet):
    # Existing logging and analysis
    # ...

    # Protocol-specific analysis
    analyze_http(packet)
    analyze_ssh(packet)
    analyze_dns(packet)
    # ... Call additional protocol analysis functions ...


"""
    Main function of the packet sniffer. It configures logging, sets up packet sniffing with filters,
    and starts the sniffing process.
"""
def main():
    configure_logging()
    logging.basicConfig(filename='sniffer.log', level=logging.INFO)
    logging.info('Packet Sniffer started.')
    
    #argument parser
    parser = argparse.ArgumentParser(description='Packet Sniffer')
    parser.add_argument('--ip', help="IP address to sniff")
    parser.add_argument('--port', help="Port to sniff")
    parser.add_argument('--protocol', help="Protocol to filter (e.g., 'tcp', 'udp')")

    
    args = parser.parse_args()
    
    supported_protocols = ['tcp', 'udp', 'icmp']

    if args.protocol and args.protocol.lower() not in supported_protocols:
        print(f"Unsupported protocol: {args.protocol}. Supported protocols are: {', '.join(supported_protocols)}")
        exit(1)

    #build filter string
    filters = []
    if args.ip:
        filters.append(f'(src {args.ip} or dst {args.ip})')
    if args.port:
        filters.append(f'(port {args.port})')
    if args.protocol:
        filters.append(f'({args.protocol})')
    
    filter_str = ' and '.join(filters)
    logging.info(f'Sniffing with filter: {filter_str}')
    
    #start sniffing using filter
    sniff(filter=filter_str, prn=process_packet)
    

if __name__ == '__main__':
    main()
