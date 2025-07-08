"""
Utility scripts for PCAP analysis tool

This directory contains various utility scripts for:
- Fixing common issues (fix_datetime.py)
- Testing functionality (simple_test.py)  
- Generating test data (generate_test_pcap.py)
"""

__version__ = "1.0.0"

# Available scripts
SCRIPTS = {
    'fix_datetime': 'Fix datetime import issues in core.py',
    'simple_test': 'Run basic functionality tests',
    'generate_test_pcap': 'Generate test PCAP files for analysis'
}