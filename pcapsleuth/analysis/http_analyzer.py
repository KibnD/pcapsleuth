from collections import Counter
from typing import List
from scapy.all import TCP, Raw
from pcapsleuth.models import HTTPAnalysisResult

class HTTPAnalyzer:
    name = "HTTP Analyzer"
    description = "Analyzes HTTP traffic for requests and statistics"

    def __init__(self):
        self.http_request_count = 0
        self.methods_counter = Counter()
        self.host_counter = Counter()
        self.url_counter = Counter()
        self.errors = []

    def process_packet(self, packet, state, results, config):
        try:
            # Only process TCP packets on ports 80 or 8080
            if TCP in packet and (packet[TCP].sport == 80 or packet[TCP].dport == 80 or
                                 packet[TCP].sport == 8080 or packet[TCP].dport == 8080):
                if Raw in packet:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    # Check for HTTP request pattern
                    if payload.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ')) and 'HTTP/' in payload:
                        self.http_request_count += 1
                        lines = payload.split('\r\n')
                        first_line = lines[0]
                        parts = first_line.split()
                        if len(parts) >= 2:
                            method = parts[0]
                            url = parts[1]
                            self.methods_counter[method] += 1
                            self.url_counter[url] += 1
                        # Extract Host header
                        for line in lines[1:]:
                            if line.lower().startswith('host:'):
                                host = line.split(':', 1)[1].strip()
                                self.host_counter[host] += 1
                                break
        except Exception as e:
            self.errors.append(f"Error parsing HTTP packet: {e}")

    def finalize(self, state, results, config):
        results.http_analysis = HTTPAnalysisResult(
            total_http_requests=self.http_request_count,
            http_methods=dict(self.methods_counter),
            hostnames=dict(self.host_counter),
            urls=dict(self.url_counter),
            errors=self.errors
        )
