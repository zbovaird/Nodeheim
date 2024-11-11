# src/scanner/__init__.py
try:
    from src.scanner.scanner import NetworkScanner, ScanResult
except ImportError:
    from .scanner import NetworkScanner, ScanResult

__version__ = '0.1.0'
__all__ = ['NetworkScanner', 'ScanResult']