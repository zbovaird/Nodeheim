#!/usr/bin/env python3
"""
Test Suite for Nodeheim Splunk App
Tests version management, security, nmap integration, and command registration.
"""

import os
import sys
import json
import configparser
import unittest
from unittest.mock import MagicMock, patch

# Add the bin directory to Python path
bin_dir = os.path.dirname(os.path.abspath(__file__))
if bin_dir not in sys.path:
    sys.path.append(bin_dir)

# Mock Splunk modules
mock_auth = MagicMock()
mock_auth.getCapabilities.return_value = ['network_scan', 'raw_exec']
sys.modules['splunk'] = MagicMock()
sys.modules['splunk.Intersplunk'] = MagicMock()
sys.modules['splunk.auth'] = mock_auth

# Try to import nmap, skip tests if not available
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("Warning: python-nmap not installed, some tests will be skipped")

from network_scanner import NetworkScanner, SplunkNmapError

class NodeheimTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Set up test environment."""
        cls.app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
    def setUp(self):
        """Set up each test."""
        # Reset mock capabilities for each test
        mock_auth.getCapabilities.return_value = ['network_scan', 'raw_exec']
        
    def test_version_consistency(self):
        """Test that versions are consistent across files."""
        # Read app.conf version
        config = configparser.ConfigParser()
        config.read(os.path.join(self.app_root, 'default', 'app.conf'))
        app_conf_version = config['launcher']['version']
        
        # Read app.manifest version
        with open(os.path.join(self.app_root, 'app.manifest'), 'r') as f:
            manifest = json.load(f)
        manifest_version = manifest['info']['id']['version']
        
        # Check version consistency
        self.assertEqual(app_conf_version, manifest_version, 
                        "Version mismatch between app.conf and app.manifest")
        
        # Check version format
        parts = app_conf_version.split('.')
        self.assertEqual(len(parts), 3, "Version should be in MAJOR.MINOR.PATCH format")
        self.assertTrue(all(p.isdigit() for p in parts), 
                       "Version parts should be numeric")
                       
    def test_package_files(self):
        """Test that only one properly named package file exists."""
        package_files = [f for f in os.listdir(self.app_root) 
                        if f.endswith('.spl') or f.endswith('.tar.gz')]
        
        self.assertEqual(len(package_files), 1, 
                        "There should be exactly one package file")
        
        # Get version from app.conf
        config = configparser.ConfigParser()
        config.read(os.path.join(self.app_root, 'default', 'app.conf'))
        version = config['launcher']['version']
        
        expected_name = f'nodeheim-{version}.spl'
        self.assertEqual(package_files[0], expected_name,
                        "Package file should match version")
                        
    def test_command_registration(self):
        """Test command registration in commands.conf."""
        commands_conf = os.path.join(self.app_root, 'default', 'commands.conf')
        self.assertTrue(os.path.exists(commands_conf),
                       "commands.conf should exist")
                       
        config = configparser.ConfigParser()
        config.read(commands_conf)
        
        # Check nodeheim_scan command
        self.assertTrue('nodeheim_scan' in config,
                       "nodeheim_scan command should be registered")
        cmd = config['nodeheim_scan']
        self.assertEqual(cmd['filename'], 'network_scanner.py')
        self.assertEqual(cmd['type'], 'python')
        self.assertEqual(cmd['local'], 'true')
        
    def test_security_capabilities(self):
        """Test security capability declarations."""
        app_conf = os.path.join(self.app_root, 'default', 'app.conf')
        config = configparser.ConfigParser()
        config.read(app_conf)
        
        self.assertTrue('security' in config,
                       "Security section should exist in app.conf")
        security = config['security']
        self.assertEqual(security['capability.network_scan'], 'enabled')
        self.assertEqual(security['capability.raw_exec'], 'enabled')
    
    @unittest.skipIf(not NMAP_AVAILABLE, "python-nmap not installed")
    def test_nmap_initialization(self):
        """Test nmap scanner initialization."""
        scanner = NetworkScanner()
        self.assertIsNotNone(scanner.nm, "Nmap scanner should be initialized")
            
    @unittest.skipIf(not NMAP_AVAILABLE, "python-nmap not installed")
    def test_missing_capabilities(self):
        """Test behavior when capabilities are missing."""
        # Remove required capabilities
        mock_auth.getCapabilities.return_value = []
        
        with self.assertRaises(SplunkNmapError) as context:
            scanner = NetworkScanner()
        self.assertIn("Missing required capabilities", str(context.exception))
            
    @unittest.skipIf(not NMAP_AVAILABLE, "python-nmap not installed")
    def test_subnet_validation(self):
        """Test subnet validation in network scanner."""
        scanner = NetworkScanner()
        
        # Test invalid subnet
        with self.assertRaises(SplunkNmapError) as context:
            scanner.scan_network("invalid_subnet")
        self.assertIn("Invalid subnet format", str(context.exception))
        
        # Test valid subnet format (even if we can't actually scan)
        try:
            scanner.scan_network("192.168.1.0/24")
        except SplunkNmapError as e:
            # Other errors are okay, we just want to test the format validation
            self.assertNotIn("Invalid subnet format", str(e))
            
    @unittest.skipIf(not NMAP_AVAILABLE, "python-nmap not installed")
    def test_scan_type_validation(self):
        """Test scan type validation."""
        scanner = NetworkScanner()
        
        # Test invalid scan type
        with self.assertRaises(SplunkNmapError) as context:
            scanner.scan_network("192.168.1.0/24", scan_type="invalid_type")
        self.assertIn("Invalid scan type", str(context.exception))
        
        # Test all valid scan types
        valid_types = ["basic", "connect", "version"]
        for scan_type in valid_types:
            try:
                scanner.scan_network("192.168.1.0/24", scan_type=scan_type)
            except SplunkNmapError as e:
                # Other errors are okay, we just want to test the type validation
                self.assertNotIn("Invalid scan type", str(e))
                
    @unittest.skipIf(not NMAP_AVAILABLE, "python-nmap not installed")
    def test_scan_results_format(self):
        """Test that scan results have the correct format."""
        scanner = NetworkScanner()
        
        try:
            results = scanner.scan_network("127.0.0.1/32", scan_type="version")
            if results:  # If localhost is up
                result = results[0]
                # Check basic fields
                self.assertIn("_raw", result)
                self.assertIn("_time", result)
                self.assertIn("host", result)
                self.assertIn("status", result)
                self.assertIn("ip_address", result)
                self.assertIn("scan_type", result)
                
                # Check version scan specific fields
                if "open_ports" in result:
                    port_info = next(iter(result["open_ports"].values()))
                    self.assertIn("name", port_info)
                    self.assertIn("product", port_info)
                    self.assertIn("version", port_info)
        except SplunkNmapError as e:
            if "nmap not found" in str(e).lower():
                self.skipTest("Nmap not installed on system")
            else:
                raise

def main():
    """Run the test suite."""
    print("\nStarting Nodeheim test suite...")
    print(f"Testing from directory: {os.getcwd()}")
    print(f"Python path: {sys.path}")
    print(f"Nmap available: {NMAP_AVAILABLE}")
    print("\nRunning tests...")
    
    # Run tests
    unittest.main(argv=[''], verbosity=2, exit=False)
    print("\nTest suite complete!")

if __name__ == "__main__":
    main() 