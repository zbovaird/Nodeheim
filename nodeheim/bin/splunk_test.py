#!/usr/bin/env python3
"""
Splunk Integration Test Suite for Nodeheim
Tests app installation, configuration, and functionality in a Splunk environment.
"""

import os
import sys
import subprocess
import time
import json
import argparse
from datetime import datetime

class SplunkTestError(Exception):
    """Custom exception for Splunk test errors."""
    pass

class SplunkTester:
    def __init__(self, splunk_home=None, app_package=None):
        """Initialize the tester with Splunk paths."""
        self.splunk_home = splunk_home or os.environ.get('SPLUNK_HOME')
        if not self.splunk_home:
            raise SplunkTestError("SPLUNK_HOME not set")
            
        self.app_package = app_package
        self.splunk_cmd = os.path.join(self.splunk_home, 'bin', 'splunk')
        self.app_name = 'nodeheim'
        
    def _run_command(self, cmd, check=True):
        """Run a shell command and return output."""
        try:
            result = subprocess.run(
                cmd, 
                shell=True, 
                check=check,
                capture_output=True,
                text=True
            )
            return result
        except subprocess.CalledProcessError as e:
            raise SplunkTestError(f"Command failed: {e.stderr}")
            
    def verify_splunk(self):
        """Verify Splunk installation."""
        print("\n=== Verifying Splunk Installation ===")
        result = self._run_command(f'"{self.splunk_cmd}" version')
        print(f"Splunk version: {result.stdout.strip()}")
        
    def verify_nmap(self):
        """Verify nmap installation."""
        print("\n=== Verifying nmap Installation ===")
        result = self._run_command('nmap --version')
        print(f"nmap version: {result.stdout.split('\\n')[0]}")
        
    def verify_python_deps(self):
        """Verify Python dependencies."""
        print("\n=== Verifying Python Dependencies ===")
        cmd = f'"{self.splunk_cmd}" cmd python3 -c "import nmap; print(f\'python-nmap version: {nmap.__version__}\')"'
        result = self._run_command(cmd)
        print(result.stdout.strip())
        
    def install_app(self):
        """Install the Nodeheim app."""
        print("\n=== Installing Nodeheim App ===")
        if not self.app_package:
            raise SplunkTestError("No app package specified")
            
        cmd = f'"{self.splunk_cmd}" install app "{self.app_package}" -update 1'
        result = self._run_command(cmd)
        print(result.stdout.strip())
        
    def configure_capabilities(self):
        """Configure required capabilities."""
        print("\n=== Configuring Capabilities ===")
        authorize_conf = os.path.join(self.splunk_home, 'etc', 'system', 'local', 'authorize.conf')
        
        config = """
[capability::network_scan]

[capability::raw_exec]

[role_admin]
network_scan = enabled
raw_exec = enabled
"""
        os.makedirs(os.path.dirname(authorize_conf), exist_ok=True)
        with open(authorize_conf, 'w') as f:
            f.write(config)
        print("Added capabilities to authorize.conf")
        
    def restart_splunk(self):
        """Restart Splunk."""
        print("\n=== Restarting Splunk ===")
        cmd = f'"{self.splunk_cmd}" restart'
        result = self._run_command(cmd)
        print("Waiting for Splunk to restart...")
        time.sleep(30)  # Wait for Splunk to fully restart
        
    def test_basic_scan(self):
        """Test basic network scan."""
        print("\n=== Testing Basic Network Scan ===")
        cmd = f'"{self.splunk_cmd}" search "| nodeheim_scan subnet=\\"127.0.0.1/32\\"" -app {self.app_name}'
        result = self._run_command(cmd)
        print(result.stdout.strip())
        
    def test_connect_scan(self):
        """Test TCP connect scan."""
        print("\n=== Testing TCP Connect Scan ===")
        cmd = f'"{self.splunk_cmd}" search "| nodeheim_scan subnet=\\"127.0.0.1/32\\" scan_type=\\"connect\\"" -app {self.app_name}'
        result = self._run_command(cmd)
        print(result.stdout.strip())
        
    def test_version_scan(self):
        """Test version detection scan."""
        print("\n=== Testing Version Detection Scan ===")
        cmd = f'"{self.splunk_cmd}" search "| nodeheim_scan subnet=\\"127.0.0.1/32\\" scan_type=\\"version\\"" -app {self.app_name}'
        result = self._run_command(cmd)
        print(result.stdout.strip())
        
    def verify_logs(self):
        """Check app logs for errors."""
        print("\n=== Checking App Logs ===")
        log_file = os.path.join(self.splunk_home, 'var', 'log', 'splunk', 'nodeheim_debug.log')
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                logs = f.readlines()
            errors = [line for line in logs if 'ERROR' in line]
            if errors:
                print("Found errors in log:")
                for error in errors[-5:]:  # Show last 5 errors
                    print(error.strip())
            else:
                print("No errors found in log")
        else:
            print("Log file not found")
            
    def run_all_tests(self):
        """Run all tests in sequence."""
        try:
            print("Starting Nodeheim integration tests...")
            print(f"Time: {datetime.now()}")
            print(f"Splunk Home: {self.splunk_home}")
            
            self.verify_splunk()
            self.verify_nmap()
            self.verify_python_deps()
            self.install_app()
            self.configure_capabilities()
            self.restart_splunk()
            self.test_basic_scan()
            self.test_connect_scan()
            self.test_version_scan()
            self.verify_logs()
            
            print("\n=== Test Summary ===")
            print("All tests completed successfully!")
            
        except SplunkTestError as e:
            print(f"\nTest failed: {str(e)}")
            sys.exit(1)
        except Exception as e:
            print(f"\nUnexpected error: {str(e)}")
            sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Run Nodeheim Splunk integration tests')
    parser.add_argument('--splunk-home', help='Path to SPLUNK_HOME')
    parser.add_argument('--app-package', help='Path to nodeheim-VERSION.spl file')
    
    args = parser.parse_args()
    
    tester = SplunkTester(
        splunk_home=args.splunk_home,
        app_package=args.app_package
    )
    tester.run_all_tests()

if __name__ == '__main__':
    main() 