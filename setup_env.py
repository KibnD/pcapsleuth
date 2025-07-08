#!/usr/bin/env python3
"""
Setup script to add current directory to Python path
"""

import sys
import os

# Add current directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

print(f"Added {current_dir} to Python path")
print("Current Python path:")
for i, path in enumerate(sys.path):
    print(f"  {i}: {path}")

# Test import
try:
    import pcapsleuth
    print(f"\n✓ PcapSleuth imported successfully!")
    print(f"✓ Version: {pcapsleuth.__version__}")
    print(f"✓ Location: {pcapsleuth.__file__}")
except ImportError as e:
    print(f"\n❌ Import failed: {e}")
    
    # Debug: Check if pcapsleuth directory exists
    pcap_dir = os.path.join(current_dir, "pcapsleuth")
    print(f"\nDebugging:")
    print(f"Current directory: {current_dir}")
    print(f"PcapSleuth directory exists: {os.path.exists(pcap_dir)}")
    
    if os.path.exists(pcap_dir):
        print(f"Contents of pcapsleuth directory:")
        for item in os.listdir(pcap_dir):
            print(f"  - {item}")