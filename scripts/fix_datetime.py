#!/usr/bin/env python3
"""
Fix datetime import in core.py
"""
import os

def fix_datetime_import():
    """Add datetime import to core.py if missing"""
    
    # Get the parent directory (project root) from scripts directory
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    core_file = os.path.join(project_root, "pcapsleuth", "core.py")
    
    if not os.path.exists(core_file):
        print(f"❌ File not found: {core_file}")
        return False
    
    # Read the file
    with open(core_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check if datetime import exists
    if 'from datetime import datetime' in content or 'import datetime' in content:
        print("✓ datetime import already exists in core.py")
        return True
    
    # Add the import
    lines = content.split('\n')
    import_added = False
    
    # Find the best place to add the import
    for i, line in enumerate(lines):
        if line.startswith('from .models import') or line.startswith('from .analysis'):
            # Add datetime import before local imports
            lines.insert(i, 'from datetime import datetime')
            import_added = True
            break
    
    if not import_added:
        # Add after standard library imports
        for i, line in enumerate(lines):
            if line.startswith('import os') or line.startswith('import logging'):
                continue
            elif line.startswith('from pathlib') or line.startswith('from typing'):
                continue
            elif line.startswith('from .') or line.strip() == '':
                lines.insert(i, 'from datetime import datetime')
                import_added = True
                break
    
    if not import_added:
        # Fallback: add at the beginning after the first import
        for i, line in enumerate(lines):
            if line.startswith('import') or line.startswith('from'):
                lines.insert(i + 1, 'from datetime import datetime')
                import_added = True
                break
    
    if import_added:
        # Write back to file
        with open(core_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        print("✓ Added datetime import to core.py")
        return True
    else:
        print("❌ Could not add datetime import")
        return False

def check_and_fix_other_imports():
    """Check for other common missing imports"""
    
    # Get the parent directory (project root) from scripts directory
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    core_file = os.path.join(project_root, "pcapsleuth", "core.py")
    
    if not os.path.exists(core_file):
        return False
    
    with open(core_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check for common patterns that might need imports
    fixes_needed = []
    
    if 'datetime.now()' in content and 'datetime' not in content:
        fixes_needed.append('datetime')
    
    if 'json.dumps' in content and 'import json' not in content:
        fixes_needed.append('json')
    
    if 'time.time()' in content and 'import time' not in content:
        fixes_needed.append('time')
    
    if fixes_needed:
        print(f"Additional imports may be needed: {', '.join(fixes_needed)}")
    
    return True

if __name__ == "__main__":
    print("🔧 Fixing datetime import in core.py...")
    success = fix_datetime_import()
    
    if success:
        print("🔍 Checking for other potential import issues...")
        check_and_fix_other_imports()
        print("✅ Import fixes completed!")
    else:
        print("❌ Failed to fix imports")