import socket #so we can have two way communication across a network
import struct #for making and changing data structures as python tuples
import textwrap #for formatting text

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))  #create raw socket listening for all ethernet protocols

    while True: #while true 
        raw_data, addr = conn.recvfrom(65536) #put data from socket into raw data up to 65536 bytes at a time addr has sending socket addr
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data) #unpack ethernet frame by calling ethernet_frame
        print('\nEthernet Frame:') 
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto)) #print info about frame

        # 8 for IPv4
        if eth_proto == 8: #Unpack as an IPv4 packet 
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print('IPv4 Packet:')
            print('Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print('Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))
            
        # 6 for TCP
            if proto == 6:
                src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(ipv4_data) #call tcp_seg with ipv4 data passed in, assigns values to all vars
                print('TCP Segment:')                                                   #print all vars
                print('Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print('Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
                print('Flags:')
                print('URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN:{}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))


# for unpacking the ethernet frame, returns src and dest mac addresses as well as the protocol and the rest of the payload
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Formatting function to print MAC address neatly
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr) #convert each byte to 2 digit hex string
    return ':'.join(bytes_str).upper() #join strings together and return

# Unpacks IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0] #first byte contains version and header length
    version = version_header_length >> 4 #seperate version and header
    header_length = (version_header_length & 15) * 4 #into two variables
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20]) #unpack info (ttl, proto, src IP, dest IP)
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:] #format src and dest IP's and return with the rest of the data

# Unpacks TCP packet
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

# Formats IPv4 address to standard readable
def ipv4(addr):
    return '.'.join(map(str, addr)) #convert to decimal string and join with dots

if __name__ == '__main__':
    main()
