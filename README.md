# Python Network Sniffer

This repository houses a basic network sniffer crafted in Python.  It's designed to capture network traffic and present you with valuable information about each packet it intercepts. 

## What It Does

This network sniffer works by listening for network packets on your system. It then dissects these packets, providing you with insights into the following:

* **Ethernet Frame:**  Details like the source and destination MAC addresses, and the protocol type being used.
* **IPv4 Packet:** Key information such as the IP version, header length, TTL (time-to-live), protocol used, and the source and destination IP addresses.
* **TCP/UDP Segments:** If the captured packet is using TCP or UDP protocols, you'll get details like the source and destination ports, sequence numbers, acknowledgment numbers (for TCP), and checksums (for UDP).

## Getting Started

1. **Requirements:** You'll need Python 3.x installed on your system. If you don't have it, download it from [https://www.python.org/downloads/](https://www.python.org/downloads/).

2. **Clone the Repository:**  
   ```bash
   git clone https://github.com/your-github-username/python-network-sniffer.git

## Output

The script outputs information about each captured packet, including:

* **Timestamp:** The time the packet was captured.
* **Ethernet Frame:** Source and destination MAC addresses, protocol type.
* **IPv4 Packet:** Version, header length, TTL, protocol, source IP, destination IP.
* **TCP Segment:** Source port, destination port, sequence number, acknowledgment number, flags.
* **UDP Segment:** Source port, destination port, length, checksum.

## Limitations

* **Limited Filtering:** The sniffer captures all network traffic.
* **No Payload Analysis:** It only displays header information.

## Notes

* **Windows Firewall:** You might need to temporarily disable Windows Firewall.
* **Security:** Use this tool responsibly and ethically.

## Disclaimer

This project is for educational purposes and should not be used for any illegal or unethical activities. 
