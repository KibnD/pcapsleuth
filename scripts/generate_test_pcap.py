#!/usr/bin/env python3
"""
Generate test PCAP file with various types of network traffic, including HTTP and TLS
"""
import os
import sys
from datetime import datetime, timedelta

def generate_test_pcap():
    """Generate a test PCAP file with various network traffic types"""
    
    try:
        from scapy.all import (
            Ether, IP, TCP, UDP, DNS, ICMP, DNSQR, DNSRR,
            wrpcap, Raw
        )
        print("✓ Scapy imports successful")
    except ImportError as e:
        print(f"❌ Scapy import failed: {e}")
        print("Please install scapy: pip install scapy")
        return False
    
    packets = []
    
    # Base timestamp
    base_time = datetime.now()
    
    print("🔧 Generating test packets...")
    
    # 1. Normal DNS queries
    print("  - Creating normal DNS queries...")
    normal_domains = [
        "google.com", "facebook.com", "github.com", "stackoverflow.com",
        "reddit.com", "youtube.com", "twitter.com", "linkedin.com",
        "amazon.com", "microsoft.com"
    ]
    
    for i, domain in enumerate(normal_domains):
        # DNS query
        dns_query = (
            Ether(dst="ff:ff:ff:ff:ff:ff") /
            IP(src="192.168.1.100", dst="8.8.8.8") /
            UDP(sport=53000+i, dport=53) /
            DNS(id=i, qd=DNSQR(qname=domain, qtype="A"))
        )
        packets.append(dns_query)
        
        # DNS response
        dns_response = (
            Ether(src="ff:ff:ff:ff:ff:ff") /
            IP(src="8.8.8.8", dst="192.168.1.100") /
            UDP(sport=53, dport=53000+i) /
            DNS(id=i, qr=1, an=DNSRR(rrname=domain, rdata="1.2.3.4"))
        )
        packets.append(dns_response)
    
    # 2. Suspicious DNS queries
    print("  - Creating suspicious DNS queries...")
    suspicious_domains = [
        "malware.example.com", "phishing.badsite.net", "trojan.evil.org",
        "ransomware.criminal.com", "botnet.command.net", "exploit.hack.org",
        "ddos.attack.com", "spam.sender.net", "scam.fishing.org",
        "virus.infection.com", "adware.popup.net", "spyware.track.org"
    ]
    
    for i, domain in enumerate(suspicious_domains):
        dns_query = (
            Ether(dst="ff:ff:ff:ff:ff:ff") /
            IP(src="192.168.1.100", dst="8.8.8.8") /
            UDP(sport=54000+i, dport=53) /
            DNS(id=100+i, qd=DNSQR(qname=domain, qtype="A"))
        )
        packets.append(dns_query)
    
    # 3. ICMP packets (ping)
    print("  - Creating ICMP packets...")
    for i in range(50):
        icmp_packet = (
            Ether(dst="ff:ff:ff:ff:ff:ff") /
            IP(src="192.168.1.100", dst=f"192.168.1.{i+1}") /
            ICMP(type=8, code=0, id=i)
        )
        packets.append(icmp_packet)
        
        # Some replies
        if i % 3 == 0:
            icmp_reply = (
                Ether(src="ff:ff:ff:ff:ff:ff") /
                IP(src=f"192.168.1.{i+1}", dst="192.168.1.100") /
                ICMP(type=0, code=0, id=i)
            )
            packets.append(icmp_reply)
    
    # 4. Web traffic (HTTP)
    print("  - Creating HTTP web traffic...")
    web_sites = [
        "192.168.1.50", "10.0.0.1", "172.16.0.1", "192.168.0.1"
    ]
    
    for i, site in enumerate(web_sites):
        # HTTP request
        http_request = (
            Ether(dst="ff:ff:ff:ff:ff:ff") /
            IP(src="192.168.1.100", dst=site) /
            TCP(sport=60000+i, dport=80, flags="PA") /  # PSH + ACK typical of HTTP payload
            Raw(load=f"GET / HTTP/1.1\r\nHost: {site}\r\n\r\n")
        )
        packets.append(http_request)
        
        # HTTP response
        http_response = (
            Ether(src="ff:ff:ff:ff:ff:ff") /
            IP(src=site, dst="192.168.1.100") /
            TCP(sport=80, dport=60000+i, flags="PA") /
            Raw(load="HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
        )
        packets.append(http_response)
    
    # 5. TLS traffic (simulated handshake packets)
    print("  - Creating TLS traffic (simulated handshake)...")
    tls_sites = [
        "192.168.1.60", "10.0.0.2"
    ]
    for i, site in enumerate(tls_sites):
        # TLS ClientHello (simplified Raw payload)
        tls_client_hello = (
            Ether(dst="ff:ff:ff:ff:ff:ff") /
            IP(src="192.168.1.100", dst=site) /
            TCP(sport=61000+i, dport=443, flags="PA") /
            Raw(load=b"\x16\x03\x01\x00\x31\x01\x00\x00\x2d\x03\x03" + b"\x00" * 34)  # partial ClientHello
        )
        packets.append(tls_client_hello)

        # TLS ServerHello (simplified Raw payload)
        tls_server_hello = (
            Ether(src="ff:ff:ff:ff:ff:ff") /
            IP(src=site, dst="192.168.1.100") /
            TCP(sport=443, dport=61000+i, flags="PA") /
            Raw(load=b"\x16\x03\x01\x00\x0a\x02\x00\x00\x06\x03\x03")  # partial ServerHello
        )
        packets.append(tls_server_hello)

    # 6. Some potentially suspicious TCP traffic
    print("  - Creating suspicious TCP traffic...")
    suspicious_ports = [4444, 6666, 31337, 1234, 9999]
    
    for i, port in enumerate(suspicious_ports):
        # Suspicious connection attempt
        tcp_sus = (
            Ether(dst="ff:ff:ff:ff:ff:ff") /
            IP(src="192.168.1.100", dst="192.168.1.200") /
            TCP(sport=60000+i, dport=port, flags="S")
        )
        packets.append(tcp_sus)
    
    # 7. Add some UDP traffic
    print("  - Creating UDP traffic...")
    for i in range(20):
        udp_packet = (
            Ether(dst="ff:ff:ff:ff:ff:ff") /
            IP(src="192.168.1.100", dst=f"10.0.0.{i+1}") /
            UDP(sport=50000+i, dport=53) /
            Raw(load=f"UDP test data {i}".encode())
        )
        packets.append(udp_packet)
    
    # Write to PCAP file
    output_file = "test_traffic.pcap"
    
    # If running from scripts directory, save to parent directory
    if os.path.basename(os.getcwd()) == "scripts":
        output_file = os.path.join("..", output_file)
    
    print(f"\n💾 Writing {len(packets)} packets to {output_file}...")
    
    try:
        wrpcap(output_file, packets)
        print(f"✅ Generated test PCAP: {output_file}")
        print(f"Total packets: {len(packets)}")
        print("Contents:")
        print(f"  - Normal DNS queries: {len(normal_domains) * 2}")
        print(f"  - Suspicious DNS queries: {len(suspicious_domains)}")
        print(f"  - ICMP packets: ~{50 + 17}")  # 50 requests + some replies
        print(f"  - HTTP traffic: {len(web_sites) * 2}")
        print(f"  - TLS traffic: {len(tls_sites) * 2}")
        print(f"  - Suspicious TCP: {len(suspicious_ports)}")
        print(f"  - UDP traffic: 20")
        
        return True
        
    except Exception as e:
        print(f"❌ Failed to write PCAP file: {e}")
        return False

if __name__ == "__main__":
    print("🚀 PCAP Test Data Generator\n")
    
    success = generate_test_pcap()
    
    if success:
        print(f"\n🎉 Test PCAP generated successfully!")
        print("You can now run: python main.py test_traffic.pcap")
    else:
        print(f"\n❌ Failed to generate test PCAP")
        sys.exit(1)
