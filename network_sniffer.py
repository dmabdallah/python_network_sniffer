import socket
import struct
import time
from datetime import datetime

# Define the IP protocol type (for Ethernet frames)
ETH_P_IP = 0x0800

# This class represents an Ethernet frame
class Ethernet:
    def __init__(self, raw_data):
        # Unpack the Ethernet header (destination MAC, source MAC, protocol)
        self.dest_mac, self.src_mac, self.proto = struct.unpack(
            '!6s6sH', raw_data[:14]
        )
        # Store the remaining data for further processing
        self.data = raw_data[14:]

    # This method provides a string representation of the Ethernet frame
    def __str__(self):
        # Format the MAC addresses for readability
        return (
            f"Ethernet Frame:\n"
            f"  Destination MAC: {':'.join(hex(int(b))[2:].zfill(2) for b in self.dest_mac)}\n"
            f"  Source MAC: {':'.join(hex(int(b))[2:].zfill(2) for b in self.src_mac)}\n"
            f"  Protocol: {self.proto}\n"
        )

# This class represents an IPv4 packet
class IPv4:
    def __init__(self, raw_data):
        # Extract version and header length from the first byte
        version_ihl = raw_data[0]
        self.version = version_ihl >> 4
        self.ihl = version_ihl & 0xF
        # Unpack the remaining IP header fields
        self.ttl, self.protocol, self.src, self.dst = struct.unpack(
            '!BBHLL', raw_data[8:20]
        )
        # Extract data after the IP header
        self.data = raw_data[self.ihl * 4:] 

    # This method provides a string representation of the IPv4 packet
    def __str__(self):
        return (
            f"IPv4 Packet:\n"
            f"  Version: {self.version}\n"
            f"  Header Length: {self.ihl}\n"
            f"  TTL: {self.ttl}\n"
            f"  Protocol: {self.protocol}\n"
            f"  Source IP: {socket.inet_ntoa(struct.pack('!L', self.src))}\n"
            f"  Destination IP: {socket.inet_ntoa(struct.pack('!L', self.dst))}\n"
        )

# This class represents a TCP segment
class TCP:
    def __init__(self, raw_data):
        # Unpack the TCP header fields
        self.src_port, self.dest_port, self.seq, self.ack_seq, self.offset_reserved_flags = struct.unpack(
            '!HHLLH', raw_data[:14]
        )
        # Calculate the offset based on the header length
        self.offset = (self.offset_reserved_flags >> 12) * 4
        self.reserved = (self.offset_reserved_flags >> 6) & 0x3F
        self.flags = self.offset_reserved_flags & 0x3F
        # Extract the TCP data
        self.data = raw_data[self.offset:]

    # This method provides a string representation of the TCP segment
    def __str__(self):
        return (
            f"TCP Segment:\n"
            f"  Source Port: {self.src_port}\n"
            f"  Destination Port: {self.dest_port}\n"
            f"  Sequence Number: {self.seq}\n"
            f"  Acknowledgment Number: {self.ack_seq}\n"
            f"  Flags: {self.flags}\n"
        )

# This class represents a UDP segment
class UDP:
    def __init__(self, raw_data):
        # Unpack the UDP header fields
        self.src_port, self.dest_port, self.length, self.checksum = struct.unpack(
            '!HHHH', raw_data[:8]
        )
        # Extract the UDP data
        self.data = raw_data[8:]

    # This method provides a string representation of the UDP segment
    def __str__(self):
        return (
            f"UDP Segment:\n"
            f"  Source Port: {self.src_port}\n"
            f"  Destination Port: {self.dest_port}\n"
            f"  Length: {self.length}\n"
            f"  Checksum: {hex(self.checksum)}\n"
        )

# This is the main function where the network sniffing happens
def main():
    try:
        # Create a raw socket to capture packets at the network layer (Ethernet)
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_IP))
    except socket.error as msg:
        # Print an error message if the socket creation fails
        print('Socket creation error: ', msg)
        exit()  # Exit the program

    # Continuously capture and analyze packets
    while True:
        # Receive a packet from the socket
        raw_data, addr = s.recvfrom(65536)
        # Create an Ethernet object to parse the Ethernet frame
        eth = Ethernet(raw_data)

        # Print the timestamp for the current packet capture
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        print(f"\nTimestamp: {timestamp}")

        # Print the details of the Ethernet frame
        print(eth)  

        # If the Ethernet frame contains an IP packet
        if eth.proto == ETH_P_IP:
            # Create an IPv4 object to parse the IP packet
            ip = IPv4(eth.data)
            # Print the details of the IPv4 packet
            print(ip)

            # If the IP protocol is TCP
            if ip.protocol == 6:
                # Create a TCP object to parse the TCP segment
                tcp = TCP(ip.data)
                # Print the details of the TCP segment
                print(tcp)

            # If the IP protocol is UDP
            elif ip.protocol == 17:
                # Create a UDP object to parse the UDP segment
                udp = UDP(ip.data)
                # Print the details of the UDP segment
                print(udp)

        # Wait for 1 second before capturing the next packet
        time.sleep(1)

# Run the main function if the script is executed directly
if __name__ == '__main__':
    main()
