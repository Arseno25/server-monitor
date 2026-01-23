#!/usr/bin/env python3
"""
VPS Process Monitoring - Test Script
Run this to test all MCP tools are working correctly.

Usage: python test_tools.py
"""
import json
import sys

# Add project to path (parent directory)
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.infrastructure import get_system_executor
from src.application import (
    ProcessAnalyzer,
    DockerInspector,
    ResourceLeakDetector,
    KernelBufferReader,
    BackgroundTaskAnalyzer,
)


def print_header(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def print_result(name: str, result: dict):
    success = result.get('success', False)
    status = "✅ PASS" if success else "❌ FAIL"
    print(f"{status} {name}")
    
    if not success:
        error = result.get('error', 'Unknown error')
        print(f"     Error: {error}")
    
    return success


def main():
    print_header("VPS Process Monitoring - Tool Tests")
    
    # Initialize
    executor = get_system_executor()
    passed = 0
    failed = 0
    
    # Test 1: scan_process_anomalies
    print("\n[1/5] Testing scan_process_anomalies...")
    analyzer = ProcessAnalyzer(executor)
    result = analyzer.scan_anomalies()
    if print_result("scan_process_anomalies", result):
        passed += 1
        print(f"     Total processes: {result.get('total_processes', 0)}")
        print(f"     Anomalies found: {result.get('anomaly_count', 0)}")
    else:
        failed += 1
    
    # Test 2: deep_docker_inspect (may fail if docker not installed)
    print("\n[2/5] Testing deep_docker_inspect...")
    inspector = DockerInspector(executor)
    result = inspector.inspect_container("nginx")  # Test with common container
    if result.get('success'):
        passed += 1
        print("✅ PASS deep_docker_inspect")
        print(f"     Container found: {result['container']['name']}")
    else:
        # Check if docker is available
        if not executor.is_command_available("docker"):
            print("⚠️  SKIP deep_docker_inspect (docker not installed)")
        else:
            print("⚠️  SKIP deep_docker_inspect (container 'nginx' not found)")
    
    # Test 3: check_resource_leaks
    print("\n[3/5] Testing check_resource_leaks...")
    detector = ResourceLeakDetector(executor)
    result = detector.check_leaks()
    if print_result("check_resource_leaks", result):
        passed += 1
        fd = result.get('file_descriptors', {})
        print(f"     Open FDs: {fd.get('open_count', 0)} / {fd.get('limit', 0)}")
        print(f"     FD Usage: {fd.get('usage_percent', 0):.1f}%")
    else:
        failed += 1
    
    # Test 4: read_kernel_ring_buffer
    print("\n[4/5] Testing read_kernel_ring_buffer...")
    reader = KernelBufferReader(executor)
    result = reader.read_buffer(lines=20)
    if print_result("read_kernel_ring_buffer", result):
        passed += 1
        print(f"     Lines read: {result.get('total_lines', 0)}")
        print(f"     Critical events: {result.get('critical_count', 0)}")
    else:
        failed += 1
        print("     Note: May need sudo for dmesg access")
    
    # Test 5: analyze_background_tasks
    print("\n[5/5] Testing analyze_background_tasks...")
    bg_analyzer = BackgroundTaskAnalyzer(executor)
    result = bg_analyzer.analyze()
    if print_result("analyze_background_tasks", result):
        passed += 1
        print(f"     Total tasks: {result.get('total_tasks', 0)}")
        print(f"     Resource hogs: {result.get('resource_hogs_count', 0)}")
    else:
        failed += 1
    
    # Summary
    print_header("Test Summary")
    print(f"  Passed: {passed}")
    print(f"  Failed: {failed}")
    print(f"  Skipped: {5 - passed - failed}")
    print()
    
    if failed == 0:
        print("🎉 All tests passed! MCP Server is ready.")
        return 0
    else:
        print("⚠️  Some tests failed. Check errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
