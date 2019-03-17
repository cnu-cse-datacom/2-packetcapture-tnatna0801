import socket
import struct

def parsing_ethernet_header(data):
    ethernet_header = struct.unpack("!6c6c2s", data)
    ether_src = convert_ethernet_address(ethernet_header[0:6])
    ether_dest = convert_ethernet_address(ethernet_header[6:12])
    ip_header = "0x"+ethernet_header[12].hex()

    print("======ethernet header======")
    print("src_mac_address:", ether_src)
    print("dest_mac_address:", ether_dest)
    print("ip_version", ip_header)


def convert_ethernet_address(data):
    ethernet_addr = list()
    for i in data:
        ethernet_addr.append(i.hex())
    ethernet_addr = ":".join(ethernet_addr)
    return ethernet_addr



def parsing_ip_header(data):    
    ip_header = struct.unpack("!2B3H2B1H8B", data) 
    ip_version = ip_header[0]
    ip_service = ip_header[1]
    ip_total_length = ip_header[2]
    ip_identification = ip_header[3]
    ip_Fragment_Offset = ip_header[4]
    ip_Time_to_Live = ip_header[5]
    ip_Protocol = ip_header[6]
    ip_Header_Checksum = ip_header[7]
    flags = ( ip_Fragment_Offset >> 13 )& 7

    print("======ip header======")
    print("ip_version:", (ip_version & 240) >> 4) # because version 4bit
    print("ip_Length", (ip_version & 15))
    print("differentiated_service_codepoint:",(ip_service & 252) >> 2)
    print("explicit_congestion_notification:", (ip_service & 3)) 
    print("total_legnth:", ip_total_length)
    print("identification:", ip_identification)
    print("flags:", hex(flags))
    print(">>reserved_bit:", (flags & 4) >> 2)
    print(">>not_fragments:", (flags & 2) >> 1)
    print(">>flagments:", (flags & 1))
    print(">>flagments_offset:", ip_Fragment_Offset & 0x1fff) #8191
    print("Time_to_live:", ip_Time_to_Live)
    print("protocol:", ip_Protocol)
    print("headerchecksum:", hex(ip_Header_Checksum))
    print("Source_Address:", str(ip_header[8])+"."+str(ip_header[9])+"."+str(ip_header[10])+"."+str(ip_header[11]))
    print("Destination_Address:", str(ip_header[12])+"."+str(ip_header[13])+"."+str(ip_header[14])+"."+str(ip_header[15]))
    
    if ip_Protocol == 6:
        return  6
    elif ip_Protocol == 17:
        return  17


def parsing_tcp_header(data):
    tcp_header = struct.unpack("!2H2I4H", data)
    tcp_src_port = tcp_header[0]
    tcp_dec_port = tcp_header[1]
    tcp_seq_num = tcp_header[2]
    tcp_ack_num = tcp_header[3]
    tcp_flags = tcp_header[4]
    tcp_window_size_value = tcp_header[5]
    tcp_checksum = tcp_header[6]
    tcp_urgent_pointer = tcp_header[7] 

    print("======tcp header======")
    print("src_port:", tcp_src_port)
    print("dec_port:", tcp_dec_port)
    print("seq_num:", tcp_seq_num)
    print("ack_num:", tcp_ack_num)
    print("header_len:", (tcp_flags >> 12) & 15)
    print("flags:", tcp_flags & 255)
    print(">>>reserved:", (tcp_flags >> 8) & 15)
    print(">>>nonce:", (tcp_flags >> 7)  & 1)
    print(">>>cwr:", (tcp_flags >> 6) & 1) 
    print(">>>urgent:", (tcp_flags >> 5) & 1)
    print(">>>ack:", (tcp_flags >> 4) & 1)
    print(">>>push:", (tcp_flags >> 3) & 1)
    print(">>>reset:", (tcp_flags >> 2) & 1)
    print(">>>syn:", (tcp_flags >> 1) & 1)
    print(">>>fin:", (tcp_flags & 1))
    print("window_size_value:", tcp_window_size_value)
    print("checksum:", tcp_checksum)
    print("urgent_pointer:", tcp_urgent_pointer)


def parsing_udp_header(data):
    udp_header = struct.unpack("!4H", data)
    udp_src_port = udp_header[0]
    udp_dst_port = udp_header[1]
    udp_leng = udp_header[2]
    udp_checksum = udp_header[3]


    print("======udp header======")
    print("src_port:", udp_src_port)
    print("dst_port:", udp_dst_port)
    print("leng:", udp_leng)
    print("header_checksum", hex(udp_checksum))



recv_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

while True:
    print("<<<<Packet Capture Start>>>>")
    data = recv_socket.recvfrom(20000)
    parsing_ethernet_header(data[0][0:14])
    protocol = parsing_ip_header(data[0][14:34])
    if protocol == 6:
       parsing_tcp_header(data[0][34:54])
    elif protocol == 17:    
        parsing_udp_header(data[0][34:42])
