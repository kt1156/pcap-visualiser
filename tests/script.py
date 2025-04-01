from scapy.all import *
import random

def generate_complex_traffic(filename, before_mud=True):
    packets = []
    for i in range(300): 
        src_ip = f"192.168.1.{random.randint(2, 50)}"
        dest_ip = f"192.168.1.{random.randint(51, 100)}"

        if before_mud:
            protocol_type = random.choices(
                ["http", "https", "dns", "ntp", "ftp", "icmp", "ssdp", "mdns"],
                weights=[20, 15, 15, 10, 10, 10, 8, 7],
                k=1
            )[0]
        else:
            protocol_type = random.choices(
                ["http", "dns", "ntp", "icmp"],
                weights=[40, 30, 20, 10],
                k=1
            )[0]

        # Generate packets based on protocols
        if protocol_type == "http":
            pkt = IP(src=src_ip, dst=dest_ip) / TCP(dport=80, sport=random.randint(1024, 65535), flags='S')
        elif protocol_type == "https":
            pkt = IP(src=src_ip, dst=dest_ip) / TCP(dport=443, sport=random.randint(1024, 65535), flags='S')
        elif protocol_type == "dns":
            pkt = IP(src=src_ip, dst="8.8.8.8") / UDP(dport=53, sport=random.randint(1024, 65535)) / DNS(rd=1, qd=DNSQR(qname="example.com"))
        elif protocol_type == "ntp":
            pkt = IP(src=src_ip, dst="129.6.15.28") / UDP(dport=123, sport=random.randint(1024, 65535))  # No fake raw payload
        elif protocol_type == "ftp":
            pkt = IP(src=src_ip, dst=dest_ip) / TCP(dport=21, sport=random.randint(1024, 65535), flags='S')
        elif protocol_type == "icmp":
            pkt = IP(src=src_ip, dst=dest_ip) / ICMP()
        elif protocol_type == "ssdp":
            pkt = IP(src=src_ip, dst="239.255.255.250") / UDP(sport=random.randint(1024, 65535), dport=1900)
        elif protocol_type == "mdns":
            pkt = IP(src=src_ip, dst="224.0.0.251") / UDP(sport=random.randint(1024, 65535), dport=5353) / DNS(rd=1, qd=DNSQR(qname="local."))
        else:
            continue

        # Clean packet
        pkt = pkt.__class__(bytes(pkt))
        packets.append(pkt)

    wrpcap(filename, packets)
    print(f"Generated complex PCAP saved to {filename}")

# Generate before and after MUD PCAPs
generate_complex_traffic('before_mud.pcap', before_mud=True)
generate_complex_traffic('after_mud.pcap', before_mud=False)

# graph js