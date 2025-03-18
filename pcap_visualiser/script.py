from scapy.all import *
import random

# Cample traffic for an IoT device (before and after MUD enforcement)
def generate_traffic(filename, before_mud=True):
    packets = []
    for i in range(100):  
        # Random source IP and destination IP
        src_ip = f"192.168.1.{random.randint(2, 10)}"
        dest_ip = f"192.168.1.{random.randint(11, 50)}"
        
        if before_mud:
            # Before MUD: Random traffic (HTTP, DNS, etc.)
            if random.random() < 0.5:
                # HTTP Traffic (IoT device communicating with server)
                packet = IP(src=src_ip, dst=dest_ip) / TCP(dport=80, sport=random.randint(1024, 65535)) / b"GET / HTTP/1.1\r\n"
            else:
                # DNS Query (Device resolving server addresses)
                packet = IP(src=src_ip, dst="8.8.8.8") / UDP(dport=53, sport=random.randint(1024, 65535)) / DNS(rd=1, qd=DNSQR(qname="example.com"))
        else:
            # After MUD: Only HTTP and DNS traffic allowed
            if random.random() < 0.5:
                # HTTP Traffic (IoT device communicating with server)
                packet = IP(src=src_ip, dst=dest_ip) / TCP(dport=80, sport=random.randint(1024, 65535)) / b"GET / HTTP/1.1\r\n"
            else:
                # DNS Query (Device resolving server addresses)
                packet = IP(src=src_ip, dst="8.8.8.8") / UDP(dport=53, sport=random.randint(1024, 65535)) / DNS(rd=1, qd=DNSQR(qname="example.com"))
        
        packets.append(packet)

    # Save to PCAP file
    wrpcap(filename, packets)

# Generate "before MUD" traffic
generate_traffic('before_mud.pcap', before_mud=True)

# Generate "after MUD" traffic
generate_traffic('after_mud.pcap', before_mud=False)

print("Sample PCAP files ('before_mud.pcap' and 'after_mud.pcap') have been generated.")