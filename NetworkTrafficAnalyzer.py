import sys
from scapy.all import sniff, Ether, IP, TCP, UDP


def analyze_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "IP"
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        print(f"Protocol: {protocol}")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print("-" * 40)


def main(interface="Wi-Fi"):  # Use "Wi-Fi" as the interface name
    print(f"Capturing traffic on interface {interface}. Press Ctrl+C to stop.")
    try:
        sniff(iface=interface, prn=analyze_packet)
    except KeyboardInterrupt:
        print("Capture stopped.")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        interface = sys.argv[1]
    else:
        interface = "Wi-Fi"  # Default network interface to capture traffic

    main(interface)
