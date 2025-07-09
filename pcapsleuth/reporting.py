import json
from datetime import datetime
from typing import Any, Dict

def generate_report(results, format_type: str = 'text') -> str:
    """Generate analysis report"""
    format_type = format_type.lower()
    
    if format_type == 'json':
        return _generate_json_report(results)
    elif format_type == 'markdown':
        return _generate_markdown_report(results)
    elif format_type == 'text':
        return _generate_text_report(results)
    else:
        raise ValueError(f"Unsupported format: {format_type}")

def _generate_json_report(results) -> str:
    """Generate JSON report"""
    report_dict = {
        'metadata': {
            'pcap_file': results.pcap_file,
            'analysis_time': results.analysis_start_time.isoformat(),
            'duration_seconds': results.analysis_duration,
            'total_packets': results.packet_count
        },
        'statistics': {
            'top_talkers': [
                {'conversation': conv, 'packets': count}
                for conv, count in results.top_talkers
            ],
            'protocols': results.protocol_distribution,
            'dns_queries': [
                {'domain': domain, 'count': count}
                for domain, count in results.dns_queries
            ]
        },
        'threats': {
            'dns_tunneling': {
                'suspicious_queries': results.dns_tunneling.total_suspicious_queries,
                'high_entropy_queries': results.dns_tunneling.high_entropy_queries,
                'excessive_txt_queries': results.dns_tunneling.excessive_txt_queries
            },
            'icmp_floods': {
                'total_packets': results.icmp_floods.total_icmp_packets,
                'detected_floods': results.icmp_floods.potential_floods
            },
            'port_scanning': {
                'total_scan_attempts': results.port_scanning.total_scan_attempts,
                'tcp_syn_scans': results.port_scanning.tcp_syn_scans,
                'udp_scans': results.port_scanning.udp_scans,
                'stealth_scans': results.port_scanning.stealth_scans,
                'rapid_scans': results.port_scanning.rapid_scans,
                'open_ports': results.port_scanning.open_ports
            }
        },
        'errors': results.errors
    }
    
    return json.dumps(report_dict, indent=2, default=str)

def _generate_markdown_report(results) -> str:
    """Generate Markdown report"""
    report = f"""# PcapSleuth Analysis Report

## Summary
- **File**: {results.pcap_file}
- **Analysis Time**: {results.analysis_start_time}
- **Duration**: {results.analysis_duration:.2f} seconds
- **Total Packets**: {results.packet_count:,}

## Network Statistics

### Top Conversations
"""
    
    for conv, count in results.top_talkers[:10]:
        report += f"- {conv}: {count:,} packets\n"
    
    report += "\n### Protocol Distribution\n"
    for proto, count in results.protocol_distribution.items():
        report += f"- {proto}: {count:,} packets\n"
    
    report += "\n### Top DNS Queries\n"
    for domain, count in results.dns_queries[:10]:
        report += f"- {domain}: {count} queries\n"
    
    report += f"""
## Threat Analysis

### DNS Tunneling
- **Suspicious Queries**: {results.dns_tunneling.total_suspicious_queries}
- **High Entropy Queries**: {len(results.dns_tunneling.high_entropy_queries)}
- **Excessive TXT Queries**: {len(results.dns_tunneling.excessive_txt_queries)} sources

### ICMP Floods
- **Total ICMP Packets**: {results.icmp_floods.total_icmp_packets}
- **Detected Floods**: {len(results.icmp_floods.potential_floods)}

### Port Scanning
- **Total Scan Attempts**: {results.port_scanning.total_scan_attempts}
- **TCP SYN Scans**: {len(results.port_scanning.tcp_syn_scans)}
- **UDP Scans**: {len(results.port_scanning.udp_scans)}
- **Stealth Scans**: {len(results.port_scanning.stealth_scans)}
- **Rapid Scans**: {len(results.port_scanning.rapid_scans)}
- **Discovered Open Ports**: {len(results.port_scanning.open_ports)} hosts
"""
    
    # Add detailed port scan information
    if results.port_scanning.tcp_syn_scans:
        report += "\n#### TCP SYN Scans Detected:\n"
        for scan in results.port_scanning.tcp_syn_scans[:5]:  # Show first 5
            report += f"- {scan['source_ip']} → {scan['target_ip']}: {scan['unique_ports']} unique ports\n"
    
    if results.port_scanning.udp_scans:
        report += "\n#### UDP Scans Detected:\n"
        for scan in results.port_scanning.udp_scans[:5]:  # Show first 5
            report += f"- {scan['source_ip']} → {scan['target_ip']}: {scan['unique_ports']} unique ports\n"
    
    if results.port_scanning.stealth_scans:
        report += "\n#### Stealth Scans Detected:\n"
        for scan in results.port_scanning.stealth_scans[:5]:  # Show first 5
            report += f"- {scan['source_ip']}: {scan['scan_type']} scan, {scan['target_count']} targets\n"
    
    if results.port_scanning.open_ports:
        report += "\n#### Open Ports Discovered:\n"
        for host, protocols in list(results.port_scanning.open_ports.items())[:10]:  # Show first 10
            for protocol, ports in protocols.items():
                ports_str = ', '.join(map(str, ports[:10]))  # Show first 10 ports
                if len(ports) > 10:
                    ports_str += f" (+{len(ports)-10} more)"
                report += f"- {host} ({protocol.upper()}): {ports_str}\n"
    
    if results.errors:
        report += f"\n## Errors\n"
        for error in results.errors:
            report += f"- {error}\n"
    
    return report

def _generate_text_report(results) -> str:
    """Generate text report"""
    report = f"""
PcapSleuth Analysis Report
==========================

File: {results.pcap_file}
Analysis Time: {results.analysis_start_time}
Duration: {results.analysis_duration:.2f} seconds
Total Packets: {results.packet_count:,}

NETWORK STATISTICS
------------------

Top Conversations:
"""
    
    for conv, count in results.top_talkers[:10]:
        report += f"  {conv}: {count:,} packets\n"
    
    report += "\nProtocol Distribution:\n"
    for proto, count in results.protocol_distribution.items():
        report += f"  {proto}: {count:,} packets\n"
    
    report += "\nTop DNS Queries:\n"
    for domain, count in results.dns_queries[:10]:
        report += f"  {domain}: {count} queries\n"
    
    report += f"""
THREAT ANALYSIS
---------------

DNS Tunneling:
  Suspicious Queries: {results.dns_tunneling.total_suspicious_queries}
  High Entropy Queries: {len(results.dns_tunneling.high_entropy_queries)}
  Excessive TXT Queries: {len(results.dns_tunneling.excessive_txt_queries)} sources

ICMP Floods:
  Total ICMP Packets: {results.icmp_floods.total_icmp_packets}
  Detected Floods: {len(results.icmp_floods.potential_floods)}

Port Scanning:
  Total Scan Attempts: {results.port_scanning.total_scan_attempts}
  TCP SYN Scans: {len(results.port_scanning.tcp_syn_scans)}
  UDP Scans: {len(results.port_scanning.udp_scans)}
  Stealth Scans: {len(results.port_scanning.stealth_scans)}
  Rapid Scans: {len(results.port_scanning.rapid_scans)}
  Discovered Open Ports: {len(results.port_scanning.open_ports)} hosts
"""
    
    # Add detailed port scan information
    if results.port_scanning.tcp_syn_scans:
        report += "\nTCP SYN Scans Detected:\n"
        for scan in results.port_scanning.tcp_syn_scans[:5]:  # Show first 5
            report += f"  {scan['source_ip']} → {scan['target_ip']}: {scan['unique_ports']} unique ports\n"
    
    if results.port_scanning.udp_scans:
        report += "\nUDP Scans Detected:\n"
        for scan in results.port_scanning.udp_scans[:5]:  # Show first 5
            report += f"  {scan['source_ip']} → {scan['target_ip']}: {scan['unique_ports']} unique ports\n"
    
    if results.port_scanning.stealth_scans:
        report += "\nStealth Scans Detected:\n"
        for scan in results.port_scanning.stealth_scans[:5]:  # Show first 5
            report += f"  {scan['source_ip']}: {scan['scan_type']} scan, {scan['target_count']} targets\n"
    
    if results.port_scanning.rapid_scans:
        report += "\nRapid Scans Detected:\n"
        for scan in results.port_scanning.rapid_scans[:5]:  # Show first 5
            report += f"  {scan['source_ip']}: {scan['packets_per_second']:.1f} packets/sec\n"
    
    if results.port_scanning.open_ports:
        report += "\nOpen Ports Discovered:\n"
        for host, protocols in list(results.port_scanning.open_ports.items())[:10]:  # Show first 10
            for protocol, ports in protocols.items():
                ports_str = ', '.join(map(str, ports[:10]))  # Show first 10 ports
                if len(ports) > 10:
                    ports_str += f" (+{len(ports)-10} more)"
                report += f"  {host} ({protocol.upper()}): {ports_str}\n"
    
    if results.errors:
        report += f"\nERRORS:\n"
        for error in results.errors:
            report += f"  - {error}\n"
    
    return report