import socket #so we can have two way communication across a network
import struct #for making and changing data structures as python tuples
import textwrap #for formatting text
import platform

def main():
    # Create a raw socket to listen for all Ethernet protocols (requires admin access)
    try:
        # Determine the platform and create the appropriate socket
        if platform.system() == 'Linux':
            conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) #create raw socket listening for all protocols
        elif platform.system() == 'Windows':
            conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            conn.bind((socket.gethostbyname(socket.gethostname()), 0))
            conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            print("This platform is not supported.")
            return
    except PermissionError:
        print("Admin access is required to run this program.")
        return
    except Exception as e:
        print(f"An error occurred while creating the socket: {e}")
        return

    # Continuously receive and process packets
    while True:
        try:
            # Receive raw data and unpack the Ethernet frame
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            print('\nEthernet Frame:')
            print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

            # Process IPv4 packets
            if eth_proto == 8:
                try:
                    (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
                    print('IPv4 Packet:')
                    print('Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
                    print('Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

                    # Process TCP segments
                    if proto == 6:
                        try:
                            src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                            print('TCP Segment:')
                            print('Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                            print('Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
                            print('Flags:')
                            print('URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN:{}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                        except Exception as e:
                            print(f"An error occurred while processing the TCP segment: {e}")
                except Exception as e:
                    print(f"An error occurred while processing the IPv4 packet: {e}")
        except Exception as e:
            print(f"An error occurred while processing the Ethernet frame: {e}")

# Unpack Ethernet frame and return source and destination MAC addresses, protocol, and payload
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Convert bytes to  MAC address format
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# Unpack IPv4 packet and return version, header length, TTL, protocol, source and target IPs, and payload
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Unpack TCP segment and return source and destination ports, sequence, acknowledgment, flags, and payload
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Convert IPv4 address bytes to standard readable format
def ipv4(addr):
    return '.'.join(map(str, addr))

if __name__ == '__main__':
    main()
