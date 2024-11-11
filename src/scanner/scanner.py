# src/scanner/scanner.py
import nmap
import json
import os
from datetime import datetime
from typing import Dict, List, Optional
import logging
import ipaddress
from dataclasses import dataclass, asdict
import csv
import platform
import subprocess

@dataclass
class ScanResult:
    """Data class for scan results"""
    timestamp: str
    scan_type: str
    hosts: List[Dict]
    ports: List[Dict]
    services: List[Dict]
    vulnerabilities: List[Dict]
    os_matches: List[Dict]
    scan_stats: Dict

class NetworkScanner:
    def __init__(self, output_dir: str = 'data'):
        """Initialize the network scanner"""
        self.nm = self._initialize_nmap()
        self.output_dir = output_dir
        self.setup_directories()
        self.setup_logging()
        
    def _initialize_nmap(self) -> nmap.PortScanner:
        """Initialize nmap with platform-specific paths"""
        system = platform.system().lower()
        print(f"Operating System: {system}")
        print(f"Current PATH: {os.environ['PATH']}")
        
        if system == "windows":
            # Primary path for Windows - Program Files (x86)
            nmap_path = r'C:\Program Files (x86)\Nmap\nmap.exe'
            
            # Add Nmap to system PATH at runtime if needed
            nmap_dir = os.path.dirname(nmap_path)
            if nmap_dir not in os.environ['PATH']:
                os.environ['PATH'] = nmap_dir + os.pathsep + os.environ['PATH']
                print(f"Added {nmap_dir} to PATH")
            
            print(f"Checking if Nmap exists at: {nmap_path}")
            print(f"Nmap exists: {os.path.exists(nmap_path)}")
            
            try:
                print("\nAttempting to initialize with Nmap...")
                scanner = nmap.PortScanner(nmap_search_path=[nmap_path])
                version = scanner.nmap_version()
                print(f"Success! Nmap version: {version}")
                return scanner
            except Exception as e:
                print(f"Failed to initialize with {nmap_path}. Error: {str(e)}")
                print("Trying alternative initialization...")
                try:
                    # Try initializing without explicit path
                    scanner = nmap.PortScanner()
                    version = scanner.nmap_version()
                    print(f"Success with default initialization! Nmap version: {version}")
                    return scanner
                except Exception as e:
                    print(f"All initialization attempts failed: {str(e)}")
                    raise nmap.PortScannerError(
                        "Could not find nmap executable. Please ensure Nmap is installed in "
                        "C:\\Program Files (x86)\\Nmap and Npcap is installed."
                    )
        else:  # macOS and Linux
            nmap_paths = [
                '/usr/local/bin/nmap',  # Common macOS location (Homebrew)
                '/usr/bin/nmap',        # Common Linux/macOS location
                '/opt/homebrew/bin/nmap',  # M1 Mac Homebrew location
                'nmap'                  # Try default PATH as fallback
            ]
            
            for path in nmap_paths:
                try:
                    scanner = nmap.PortScanner(nmap_search_path=[path])
                    version = scanner.nmap_version()
                    print(f"Success! Nmap version: {version}")
                    return scanner
                except Exception:
                    continue
            
            raise nmap.PortScannerError(
                "Could not find nmap executable. Please ensure Nmap is installed."
            )

    def setup_directories(self):
        """Create necessary directories for output"""
        directories = [
            self.output_dir,
            os.path.join(self.output_dir, 'scans'),
            os.path.join(self.output_dir, 'topology'),
            os.path.join(self.output_dir, 'reports'),
            os.path.join(self.output_dir, 'logs')
        ]
        for directory in directories:
            os.makedirs(directory, exist_ok=True)

    def setup_logging(self):
        """Configure logging"""
        log_file = os.path.join(self.output_dir, 'logs', 'scanner.log')
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def validate_target(self, target: str) -> bool:
        """Validate target IP address or network"""
        try:
            ipaddress.ip_network(target)
            return True
        except ValueError:
            return False

    def quick_scan(self, target: str) -> ScanResult:
        """
        Perform a quick ping scan
        Arguments: -sn (Ping Scan)
        """
        return self._run_scan(target, '-sn', 'quick_scan')

    def basic_scan(self, target: str) -> ScanResult:
        """
        Basic port scan with service detection
        Arguments: -sS -sV (SYN scan with service version detection)
        """
        return self._run_scan(target, '-sS -sV', 'basic_scan')

    def full_scan(self, target: str) -> ScanResult:
        """
        Comprehensive scan including OS detection and script scanning
        Arguments: -sS -sV -O -sC (SYN scan, service version, OS detection, default scripts)
        """
        return self._run_scan(target, '-sS -sV -O -sC', 'full_scan')

    def vulnerability_scan(self, target: str) -> ScanResult:
        """
        Vulnerability scan using NSE scripts
        Arguments: -sV --script vuln (Service version detection and vulnerability scripts)
        """
        return self._run_scan(target, '-sV --script vuln', 'vulnerability_scan')

    def stealth_scan(self, target: str) -> ScanResult:
        """
        Stealthy scan with minimal noise
        Arguments: -sS -T2 (SYN scan with timing template 2)
        """
        return self._run_scan(target, '-sS -T2', 'stealth_scan')

    def _run_scan(self, target: str, arguments: str, scan_type: str) -> ScanResult:
        """Execute nmap scan and process results"""
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        logging.info(f"Starting {scan_type} on {target}")

        try:
            self.nm.scan(hosts=target, arguments=arguments)
            results = self._process_results(scan_type, timestamp)
            self._save_results(results, target, scan_type)
            return results
        except Exception as e:
            logging.error(f"Scan failed: {str(e)}")
            raise

    def _process_results(self, scan_type: str, timestamp: str) -> ScanResult:
        """Process raw nmap results into structured data"""
        hosts = []
        ports = []
        services = []
        vulnerabilities = []
        os_matches = []

        for host in self.nm.all_hosts():
            # Basic host information
            host_info = {
                'ip': host,
                'status': self.nm[host].state(),
                'hostnames': self.nm[host].hostnames()
            }
            hosts.append(host_info)

            # OS detection results
            if 'osmatch' in self.nm[host]:
                for match in self.nm[host]['osmatch']:
                    os_info = {
                        'ip': host,
                        'name': match['name'],
                        'accuracy': match['accuracy']
                    }
                    os_matches.append(os_info)

            # Ports and services
            for proto in self.nm[host].all_protocols():
                for port in self.nm[host][proto]:
                    port_info = self.nm[host][proto][port]
                    ports.append({
                        'ip': host,
                        'port': port,
                        'protocol': proto,
                        'state': port_info['state']
                    })
                    
                    if 'service' in port_info:
                        services.append({
                            'ip': host,
                            'port': port,
                            'name': port_info['name'],
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', '')
                        })

            # Vulnerability detection
            if 'script' in self.nm[host]:
                for script_name, output in self.nm[host]['script'].items():
                    if 'VULNERABLE' in output:
                        vulnerabilities.append({
                            'ip': host,
                            'script': script_name,
                            'output': output
                        })

        return ScanResult(
            timestamp=timestamp,
            scan_type=scan_type,
            hosts=hosts,
            ports=ports,
            services=services,
            vulnerabilities=vulnerabilities,
            os_matches=os_matches,
            scan_stats=self.nm.scanstats()
        )

    def _save_results(self, results: ScanResult, target: str, scan_type: str):
        """Save scan results in multiple formats"""
        base_name = f"{target.replace('/', '_')}_{results.timestamp}_{scan_type}"
        
        # Save complete results as JSON
        json_path = os.path.join(self.output_dir, 'scans', f"{base_name}.json")
        with open(json_path, 'w') as f:
            json.dump(asdict(results), f, indent=2)

        # Save network topology data
        self._save_topology_data(results, base_name)

        # Save CSV reports
        self._save_csv_reports(results, base_name)

    def _save_topology_data(self, results: ScanResult, base_name: str):
        """Save network topology data for visualization"""
        nodes = []
        edges = []

        # Create nodes for hosts
        for host in results.hosts:
            nodes.append({
                'id': host['ip'],
                'type': 'host',
                'status': host['status']
            })

        # Create nodes and edges for services
        for service in results.services:
            service_id = f"{service['ip']}:{service['port']}"
            nodes.append({
                'id': service_id,
                'type': 'service',
                'name': service['name']
            })
            edges.append({
                'source': service['ip'],
                'target': service_id,
                'type': 'has_service'
            })

        # Save topology data
        topology_path = os.path.join(self.output_dir, 'topology', f"{base_name}_topology.json")
        with open(topology_path, 'w') as f:
            json.dump({
                'nodes': nodes,
                'edges': edges
            }, f, indent=2)

    def _save_csv_reports(self, results: ScanResult, base_name: str):
        """Save detailed CSV reports"""
        reports_dir = os.path.join(self.output_dir, 'reports')

        # Save hosts report
        if results.hosts:
            self._save_csv(
                os.path.join(reports_dir, f"{base_name}_hosts.csv"),
                results.hosts
            )

        # Save services report
        if results.services:
            self._save_csv(
                os.path.join(reports_dir, f"{base_name}_services.csv"),
                results.services
            )

        # Save vulnerabilities report
        if results.vulnerabilities:
            self._save_csv(
                os.path.join(reports_dir, f"{base_name}_vulnerabilities.csv"),
                results.vulnerabilities
            )

    def _save_csv(self, filepath: str, data: List[Dict]):
        """Save list of dictionaries as CSV"""
        if data:
            with open(filepath, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)

if __name__ == "__main__":
    scanner = NetworkScanner()
    try:
        print("Running quick scan on localhost...")
        results = scanner.quick_scan('127.0.0.1')
        print("\nScan completed successfully!")
        print("\nResults summary:")
        print(f"Hosts found: {len(results.hosts)}")
        print(f"Scan time: {results.scan_stats['elapsed']} seconds")
        print(f"\nResults saved in {scanner.output_dir}")
    except Exception as e:
        print(f"Scan failed: {str(e)}")