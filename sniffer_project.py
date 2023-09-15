from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP
from scapy.all import sniff
import logging
from logging.handlers import RotatingFileHandler
import re 


def is_uncommon_port(port):
    # List of common ports
    common_ports = [
        20, 21, 22, 23, 25, 53, 80, 110, 143, 443,
        465, 587, 993, 995, 3389, 5900, 8080
    ]
    return port not in common_ports

def configure_logging():
    log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    # Create a handler that writes log messages to a file, with a maximum log file size of 1 MB, keeping 3 old log files.
    log_handler = RotatingFileHandler('sniffer.log', maxBytes=1e6, backupCount=3)
    log_handler.setFormatter(log_formatter)
    
    # Adding the handler to the root logger
    logging.getLogger().addHandler(log_handler)
    logging.getLogger().setLevel(logging.INFO)


def log_ethernet_frame(packet):
    try:
        eth_frame = packet[Ether]
        logging.info(f'Ethernet Frame: Destination: {eth_frame.dst}, Source: {eth_frame.src}, Protocol: {eth_frame.type}')
    except Exception as e:
        logging.error(f'Error processing Ethernet frame: {e}. Packet details: {packet.summary()}')

def log_ipv4_packet(packet):
    try:
        ipv4_packet = packet[IP]
        logging.info(f'IPv4 Packet: Version: {ipv4_packet.version}, Header Length: {ipv4_packet.ihl}, TTL: {ipv4_packet.ttl}, Protocol: {ipv4_packet.proto}, Source: {ipv4_packet.src}, Target: {ipv4_packet.dst}')
    except Exception as e:
        logging.error(f'Error processing IPv4 packet: {e}. Packet details: {packet.summary()}')

def log_ipv6_packet(packet):
    try:
        ipv6_packet = packet[IPv6]
        logging.info(f'IPv6 Packet: Version: {ipv6_packet.version}, Traffic Class: {ipv6_packet.tc}, Flow Label: {ipv6_packet.fl}, Payload Length: {ipv6_packet.plen}, Next Header: {ipv6_packet.nh}, Hop Limit: {ipv6_packet.hlim}, Source: {ipv6_packet.src}, Target: {ipv6_packet.dst}')
    except Exception as e:
        logging.error(f'Error processing IPv6 packet: {e}. Packet details: {packet.summary()}')
    
def log_udp_segment(packet):
    try:
        udp_segment = packet[UDP]
        logging.info(f'UDP Segment: Source Port: {udp_segment.sport}, Destination Port: {udp_segment.dport}')
    except Exception as e:
        logging.error(f'Error processing UDP segment: {e}. Packet details: {packet.summary()}')

def log_tcp_segment(packet):
    try:
        tcp_segment = packet[TCP]
        logging.info(f'TCP Segment: Source Port: {tcp_segment.sport}, Destination Port: {tcp_segment.dport}')
    except Exception as e:
        logging.error(f'Error processing TCP segment: {e}. Packet details: {packet.summary()}')

def log_icmp_packet(packet):
    try:
        icmp_segment = packet[ICMP]
        logging.info(f'ICMP Segment: Source Port: {icmp_segment.sport}, Destination Port: {icmp_segment.dport}')
    except Exception as e:
        logging.error(f'Error processing ICMP segment: {e}. Packet details: {packet.summary()}')
def log_arp_packet(packet):
    try:
        arp_packet = packet[ARP]
        logging.info(f'ARP Packet: Hardware Type: {arp_packet.hwtype}, Protocol Type: {arp_packet.ptype}, Operation: {arp_packet.op}, Sender MAC: {arp_packet.hwsrc}, Sender IP: {arp_packet.psrc}, Target MAC: {arp_packet.hwdst}, Target IP: {arp_packet.pdst}')
    except Exception as e:
        logging.error(f'Error processing ARP packet: {e}. Packet details: {packet.summary()}')
    
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


def main():
    configure_logging()
    logging.basicConfig(filename='sniffer.log', level=logging.INFO)
    logging.info('Packet Sniffer started.')
    sniff(prn=process_packet)

if __name__ == '__main__':
    main()
