import socket
import struct

def ip_header(packet):
    iph = struct.unpack('!BBHHHBBH4s4s', packet[:20])
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    ttl = iph[5]
    proto = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    dest_ip = socket.inet_ntoa(iph[9])
    return version, ihl, ttl, proto, src_ip, dest_ip


try:
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sniffer.bind(("192.168.204.1", 0))  
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
except PermissionError:
    print("Run as Administrator to use raw sockets.")
    exit()
except Exception as e:
    print(f"Error: {e}")
    exit()

print("Starting IP sniffer... (Press Ctrl+C to stop)\n")

try:
    while True:
        raw_packet = sniffer.recvfrom(65565)[0]
        version, ihl, ttl, proto, src_ip, dest_ip = ip_header(raw_packet)
        print(f"IP Packet: Version={version}, Header Length={ihl*4}, TTL={ttl}, Protocol={proto}, Src={src_ip}, Dest={dest_ip}")

except KeyboardInterrupt:
    print("\nSniffer stopped.")
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    sniffer.close()
