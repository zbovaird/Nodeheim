# test_scanner.py
import os
import sys

# Add project root to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.scanner import NetworkScanner

def test_scanner():
    try:
        scanner = NetworkScanner(output_dir='src/data')
        result = scanner.quick_scan('127.0.0.1')
        print("Scanner test successful!")
        print(f"Found {len(result.hosts)} hosts")
        return True
    except Exception as e:
        print(f"Scanner test failed: {str(e)}")
        return False

if __name__ == "__main__":
    test_scanner()