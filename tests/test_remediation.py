#!/usr/bin/env python3
"""
Test script for verifying remediation capabilities.
Creates a dummy process and kills it.
"""
import subprocess
import time
import os
import sys

# Add project root to path (parent directory)
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.infrastructure import get_system_executor
from src.application import RemediationService

def test_kill_process():
    print("\n[Test] kill_process")
    
    # 1. Create a dummy sleep process
    print("   Creating dummy sleep process...")
    proc = subprocess.Popen(["sleep", "60"])
    pid = proc.pid
    print(f"   Dummy process created with PID: {pid}")
    
    # Check it exists
    if proc.poll() is None:
        print("   ✓ Process running")
    else:
        print("   ❌ Failed to create process")
        return False

    # 2. Try to kill it using our service
    print(f"   Attempting to kill PID {pid}...")
    executor = get_system_executor()
    service = RemediationService(executor)
    
    result = service.kill_process(pid=pid)
    
    # 3. Verify
    if result['success']:
        print("   Result: Success")
        time.sleep(1) # Give OS a moment
        if proc.poll() is not None:
             print("   ✅ VERIFIED: Process is dead")
             return True
        else:
             print("   ❌ FAILED: Process is still running")
             proc.kill() # Cleanup
             return False
    else:
        print(f"   ❌ Service returned failure: {result.get('message')}")
        proc.kill() # Cleanup
        return False

if __name__ == "__main__":
    if test_kill_process():
        print("\n🎉 Remediation test passed!")
        sys.exit(0)
    else:
        print("\n❌ Remediation test failed!")
        sys.exit(1)
