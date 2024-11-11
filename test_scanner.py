#!/usr/bin/env python3
import os
import sys
from pathlib import Path

# Get the absolute path to the project root
PROJECT_ROOT = Path(__file__).parent.absolute()
sys.path.append(str(PROJECT_ROOT))

def test_scanner():
    try:
        print(f"Project root: {PROJECT_ROOT}")
        print("Attempting to import NetworkScanner...")
        
        from src.scanner.scanner import NetworkScanner
        print("Import successful!")
        
        scanner = NetworkScanner(output_dir='src/data')
        print("Scanner initialized!")
        
        print("Starting quick scan of localhost...")
        result = scanner.quick_scan('127.0.0.1')
        
        print("\nScan Results:")
        print(f"- Found {len(result.hosts)} hosts")
        print(f"- Scan time: {result.scan_stats['elapsed']} seconds")
        
        return True
    except Exception as e:
        print(f"\nError occurred: {str(e)}")
        print(f"Python path: {sys.path}")
        return False

if __name__ == "__main__":
    print("Starting scanner test...")
    success = test_scanner()
    if success:
        print("\nTest completed successfully!")
    else:
        print("\nTest failed!")