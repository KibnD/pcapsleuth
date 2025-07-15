from collections import Counter
from typing import List
from scapy.all import TCP
from scapy.layers.tls.all import TLSClientHello, TLS_Ext_ServerName
from pcapsleuth.models import TLSAnalysisResult

class TLSAnalyzer:
    name = "TLS Analyzer"
    description = "Analyzes TLS traffic for sessions and versions"

    def __init__(self):
        self.total_tls_sessions = 0
        self.tls_versions_counter = Counter()
        self.cert_hosts_counter = Counter()
        self.errors = []

    def process_packet(self, packet, state, results, config):
        try:
            # Only process TCP packets on port 443 (HTTPS)
            if TCP in packet and (packet[TCP].sport == 443 or packet[TCP].dport == 443):
                if packet.haslayer(TLSClientHello):
                    self.total_tls_sessions += 1
                    client_hello = packet[TLSClientHello]
                    version = client_hello.version
                    self.tls_versions_counter[version] += 1

                    # Extract SNI (Server Name Indication) from TLS extensions if available
                    if hasattr(client_hello, 'ext'):
                        for ext in client_hello.ext:
                            if isinstance(ext, TLS_Ext_ServerName):
                                server_name = ext.servername.decode() if isinstance(ext.servername, bytes) else ext.servername
                                self.cert_hosts_counter[server_name] += 1
        except Exception as e:
            self.errors.append(f"Error parsing TLS packet: {e}")

    def finalize(self, state, results, config):
        results.tls_analysis = TLSAnalysisResult(
            total_tls_sessions=self.total_tls_sessions,
            tls_versions=dict(self.tls_versions_counter),
            certificate_hosts=dict(self.cert_hosts_counter),
            errors=self.errors
        )
