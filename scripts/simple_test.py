#!/usr/bin/env python3
"""
Simple test script to verify basic functionality including PCAP analysis
"""

import os
import sys

def test_imports():
    """Test if all required modules can be imported"""
    print("🧪 Testing imports...")
    
    try:
        # Test standard library imports
        import logging
        import json
        from datetime import datetime
        from pathlib import Path
        print("✓ Standard library imports OK")
        
        # Test third-party imports
        import scapy
        from scapy.all import rdpcap, IP, DNS, ICMP, TCP, UDP
        print("✓ Scapy imports OK")
        
        # Test local imports
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sys.path.insert(0, project_root)
        from pcapsleuth.core import PcapAnalysisEngine
        from pcapsleuth.models import AnalysisResult
        print("✓ Local imports OK")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def test_basic_functionality():
    """Test basic functionality without PCAP file"""
    print("\n🔧 Testing basic functionality...")
    
    try:
        from pcapsleuth.core import PcapAnalysisEngine
        
        # Create engine instance
        engine = PcapAnalysisEngine()
        print("✓ Engine creation OK")
        
        # Test configuration
        if hasattr(engine, 'config'):
            print("✓ Configuration OK")
        
        # Test analyzers
        if hasattr(engine, 'analyzers'):
            print(f"✓ Analyzers loaded: {len(engine.analyzers)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Basic functionality test failed: {e}")
        return False

def check_file_structure():
    """Check if all required files exist"""
    print("\n📁 Checking file structure...")
    
    # Get project root directory
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    required_files = [
        os.path.join(project_root, "pcapsleuth", "__init__.py"),
        os.path.join(project_root, "pcapsleuth", "core.py"),
        os.path.join(project_root, "pcapsleuth", "models.py"),
        os.path.join(project_root, "main.py")
    ]
    
    required_dirs = [
        os.path.join(project_root, "pcapsleuth"),
        os.path.join(project_root, "pcapsleuth", "analysis")
    ]
    
    all_good = True
    
    for directory in required_dirs:
        if os.path.exists(directory):
            print(f"✓ Directory exists: {os.path.relpath(directory, project_root)}")
        else:
            print(f"❌ Missing directory: {os.path.relpath(directory, project_root)}")
            all_good = False
    
    for file_path in required_files:
        if os.path.exists(file_path):
            print(f"✓ File exists: {os.path.relpath(file_path, project_root)}")
        else:
            print(f"❌ Missing file: {os.path.relpath(file_path, project_root)}")
            all_good = False
    
    return all_good

def test_full_analysis(pcap_path):
    """Run a full PCAP analysis and print summary for HTTP and TLS"""
    print("\n🕵️ Running full PCAP analysis test...")
    
    try:
        from pcapsleuth.core import PcapAnalysisEngine
        
        if not os.path.isfile(pcap_path):
            print(f"❌ PCAP file not found: {pcap_path}")
            return False
        
        engine = PcapAnalysisEngine()
        results = engine.analyze_pcap(pcap_path)
        
        print("\n--- HTTP Analysis Summary ---")
        http = results.http_analysis
        print(f"Total HTTP requests: {http.total_http_requests}")
        print(f"HTTP Methods: {http.http_methods}")
        print(f"Hostnames: {http.hostnames}")
        print(f"URLs: {http.urls}")
        if http.errors:
            print(f"HTTP Errors: {http.errors}")
        else:
            print("No HTTP errors detected.")
        
        print("\n--- TLS Analysis Summary ---")
        tls = results.tls_analysis
        print(f"Total TLS sessions: {tls.total_tls_sessions}")
        print(f"TLS Versions: {tls.tls_versions}")
        print(f"Certificate Hosts: {tls.certificate_hosts}")
        if tls.errors:
            print(f"TLS Errors: {tls.errors}")
        else:
            print("No TLS errors detected.")
        
        if results.errors:
            print("\nGeneral errors during analysis:")
            for err in results.errors:
                print(f" - {err}")
        
        print("\n✓ Full analysis test completed successfully.")
        return True
        
    except Exception as e:
        print(f"❌ Full analysis test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🚀 Running PCAP Analysis Tool Tests\n")
    
    # Check file structure
    structure_ok = check_file_structure()
    
    if not structure_ok:
        print("\n❌ File structure issues detected. Please ensure all files are in place.")
        return False
    
    # Test imports
    imports_ok = test_imports()
    
    if not imports_ok:
        print("\n❌ Import issues detected. Please check dependencies.")
        return False
    
    # Test basic functionality
    basic_ok = test_basic_functionality()
    
    if not basic_ok:
        print("\n❌ Basic functionality issues detected.")
        return False
    
    # Run a full analysis test if test_traffic.pcap is present in current directory
    pcap_file = "test_traffic.pcap"
    full_analysis_ok = test_full_analysis(pcap_file)
    
    if not full_analysis_ok:
        print(f"\n❌ Full analysis test failed or PCAP file '{pcap_file}' missing.")
        print("You can generate a test PCAP with: python scripts/generate_test_pcap.py")
        return False
    
    print("\n✅ All tests passed! The tool should be ready to use.")
    print("\nNext steps:")
    print(f"1. Run: python main.py {pcap_file}")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
