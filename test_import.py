#!/usr/bin/env python3
"""
Simple test to verify PcapSleuth installation
"""

import sys
import os

# Add current directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

def test_imports():
    """Test that all imports work correctly"""
    try:
        import pcapsleuth
        print("✓ PcapSleuth imported successfully!")
        print(f"✓ Version: {pcapsleuth.__version__}")
        
        from pcapsleuth import Config, PcapAnalysisEngine
        print("✓ Main classes imported successfully!")
        
        # Test basic instantiation
        config = Config()
        engine = PcapAnalysisEngine(config)
        print("✓ Objects created successfully!")
        
        print("\n🎉 All tests passed! PcapSleuth is ready to use.")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Make sure you've installed the package with: pip install -e .")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False
    
    return True

if __name__ == "__main__":
    test_imports()