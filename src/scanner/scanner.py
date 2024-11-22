# src/scanner/scanner.py
import os
import json
import logging
import time
import csv
import platform
import subprocess
import signal
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import ipaddress
import ctypes
import socket
from threading import Thread
import re

# Third-party imports
import psutil
import nmap

# Local imports
from .vulnerability_checker import BatchVulnerabilityChecker

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
    def __init__(self, output_dir: str = None):
        """Initialize the network scanner"""
        # Set up logger
        self.logger = logging.getLogger(__name__)
        
        # Initialize scan control variables
        self.current_scan = None
        self.scan_stopped = False
        
        # Validate output directory if provided
        if output_dir is not None:
            # Check for directory traversal attempts
            clean_path = os.path.normpath(output_dir)
            if '..' in clean_path or not clean_path.replace('\\', '/').strip('/'):
                raise ValueError("Invalid output directory path")
            self.output_dir = clean_path
        else:
            self.output_dir = 'data'
            
        # Initialize components in correct order
        try:
            # 1. Initialize nmap first
            self.nm = self._initialize_nmap()
            
            # 2. Set up directories
            self.setup_directories()
            
            # 3. Check requirements
            requirements = self.check_requirements()
            if not all(requirements.values()):
                missing = [k for k, v in requirements.items() if not v]
                self.logger.error(f"Missing requirements: {missing}")
                raise RuntimeError(f"Scanner requirements not met: {missing}")
            
            # 4. Initialize vulnerability checker
            self.vuln_checker = BatchVulnerabilityChecker()
            
            self.logger.info("Scanner initialization completed successfully")
            
        except Exception as e:
            self.logger.error(f"Scanner initialization failed: {str(e)}")
            raise

    def _initialize_nmap(self) -> nmap.PortScanner:
        """Initialize nmap with platform-specific paths and robust error handling"""
        system = platform.system().lower()
        self.logger.info(f"Initializing Nmap on {system} platform")
        
        # Common nmap paths by OS
        nmap_paths = {
            'darwin': [  # macOS
                '/usr/local/bin/nmap',     # Intel Mac Homebrew location
                '/opt/homebrew/bin/nmap',  # M1/M2 Mac Homebrew location
                '/usr/bin/nmap',           # Default macOS location
                'nmap'                     # PATH lookup
            ],
            'linux': [
                '/usr/bin/nmap',
                '/usr/local/bin/nmap',
                '/opt/nmap/bin/nmap',
                'nmap'
            ],
            'windows': [
                r'C:\Program Files (x86)\Nmap\nmap.exe',
                r'C:\Program Files\Nmap\nmap.exe',
                'nmap'
            ]
        }
        
        # Get paths for current OS
        paths_to_try = nmap_paths.get(system, ['nmap'])
        
        # Try each path
        for nmap_path in paths_to_try:
            try:
                self.logger.info(f"Trying nmap path: {nmap_path}")
                # First check if the path exists and is executable
                if nmap_path != 'nmap':  # Skip check for PATH lookup
                    if not os.path.exists(nmap_path):
                        self.logger.debug(f"Nmap not found at {nmap_path}")
                        continue
                    if not os.access(nmap_path, os.X_OK):
                        self.logger.debug(f"Nmap at {nmap_path} is not executable")
                        continue
                
                # Try to run nmap version check
                result = subprocess.run([nmap_path, '--version'], 
                                    capture_output=True, 
                                    text=True)
                
                if result.returncode == 0:
                    self.logger.info(f"Nmap found at: {nmap_path}")
                    try:
                        scanner = nmap.PortScanner(nmap_search_path=[nmap_path])
                        version = scanner.nmap_version()
                        self.logger.info(f"Successfully initialized nmap {version}")
                        scanner.nmap_path = nmap_path
                        return scanner
                    except Exception as e:
                        self.logger.warning(f"Failed to initialize scanner with {nmap_path}: {e}")
                        continue
                    
            except FileNotFoundError:
                self.logger.warning(f"Nmap not found at {nmap_path}")
                continue
            except Exception as e:
                self.logger.warning(f"Error checking {nmap_path}: {e}")
                continue
        
        # If we get here, we couldn't find nmap
        error_msg = "Could not find or initialize nmap. Please ensure nmap is installed and accessible."
        self.logger.error(error_msg)
        raise RuntimeError(error_msg)

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
        """Enhanced basic port scan with OS and device type detection"""
        self.logger.info(f"Starting basic scan on {target}")
        
        try:
            # More conservative scan arguments - removed vulnerability checks
            arguments = (
                '-sT '               # TCP connect scan (more reliable than SYN)
                '-sV '               # Version detection
                '-O '               # OS detection
                '--osscan-limit '    # Limit OS detection to promising targets
                '--version-intensity 4 ' # Slightly lower intensity
                '--version-light '    # Try light probes first
                '-p 21-23,25,53,80,110,139,443,445,3306,3389 '  # Most common ports only
                '-T3 '               # Normal timing
                '--min-rate 50 '     # Lower minimum rate
                '--max-rate 150 '    # Lower maximum rate
                '--max-retries 3 '   # Slightly more retries
                '--host-timeout 15m ' # Shorter host timeout
                '--max-rtt-timeout 1000ms ' # Longer RTT timeout
                '--initial-rtt-timeout 500ms ' # Longer initial timeout
                '--min-hostgroup 32 '  # Smaller groups
                '--min-parallelism 5 ' # Less parallelization
                '--script banner'     # Only basic banner script
            )
            
            # Add progress monitoring
            def monitor_progress():
                while True:
                    time.sleep(5)  # Check every 5 seconds
                    if self.current_scan:
                        try:
                            stats = self.nm.scanstats()
                            progress = (int(stats.get('timestr', '0')) / 
                                      int(stats.get('totaltimestr', '100'))) * 100
                            self.logger.info(f"Scan progress: {progress:.1f}%")
                        except:
                            pass
                    else:
                        break

            # Start progress monitoring in separate thread
            progress_thread = Thread(target=monitor_progress)
            progress_thread.daemon = True
            progress_thread.start()

            self.logger.info(f"Using scan arguments: {arguments}")
            result = self._run_scan(target, arguments, 'basic_scan')
            
            # Process results without vulnerability checks
            for host in result.hosts:
                host['vulnerabilities'] = []  # Empty list for basic scan
            
            result.vulnerabilities = []  # No vulnerabilities in basic scan
            
            return result
            
        except Exception as e:
            self.logger.error(f"Basic scan failed: {e}")
            raise

    def _get_os_info(self, host: str) -> dict:
        """Extract detailed OS information from scan results"""
        os_info = {
            'os_match': 'unknown',
            'os_accuracy': 0,
            'os_type': 'unknown',
            'os_vendor': 'unknown',
            'os_family': 'unknown',
            'os_generation': 'unknown'
        }
        
        try:
            # Check for OS matches from nmap scan
            if 'osmatch' in self.nm[host]:
                os_matches = self.nm[host]['osmatch']
                if os_matches and len(os_matches) > 0:
                    best_match = os_matches[0]
                    os_info['os_match'] = best_match.get('name', 'unknown')
                    os_info['os_accuracy'] = int(best_match.get('accuracy', 0))
                    
                    # Get OS class information
                    if 'osclass' in best_match and len(best_match['osclass']) > 0:
                        os_class = best_match['osclass'][0]
                        os_info['os_type'] = os_class.get('type', 'unknown')
                        os_info['os_vendor'] = os_class.get('vendor', 'unknown')
                        os_info['os_family'] = os_class.get('osfamily', 'unknown')
                        os_info['os_generation'] = os_class.get('osgen', 'unknown')

            # Try SMB OS discovery
            if 'hostscript' in self.nm[host]:
                for script in self.nm[host]['hostscript']:
                    if script['id'] == 'smb-os-discovery':
                        smb_os = script['output']
                        if 'Windows' in smb_os:
                            os_info['os_family'] = 'Windows'
                            os_info['os_vendor'] = 'Microsoft'
                            os_info['os_accuracy'] = 95

            # Try service-based OS detection if still unknown
            if os_info['os_family'] == 'unknown':
                os_info = self._detect_os_from_services(host, os_info)

        except Exception as e:
            logging.warning(f"Error getting OS info for {host}: {e}")
        
        return os_info
    
    def _detect_os_from_services(self, host: str, os_info: dict) -> dict:
        """Detect OS based on running services"""
        try:
            services = []
            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                for port in ports:
                    service = self.nm[host][proto][port]
                    if 'name' in service:
                        services.append(service['name'].lower())

            # Windows indicators
            windows_indicators = ['microsoft-ds', 'netbios-ssn', 'ms-sql']
            if any(svc in services for svc in windows_indicators):
                os_info['os_family'] = 'Windows'
                os_info['os_vendor'] = 'Microsoft'
                os_info['os_accuracy'] = 75

            # Linux indicators
            linux_indicators = ['ssh', 'cups', 'nfs']
            if any(svc in services for svc in linux_indicators):
                os_info['os_family'] = 'Linux'
                os_info['os_accuracy'] = 75

            # Network device indicators
            network_indicators = ['snmp', 'telnet', 'cisco']
            if any(svc in services for svc in network_indicators):
                os_info['os_family'] = 'Network Device'
                os_info['os_type'] = 'Network Infrastructure'
                os_info['os_accuracy'] = 80

        except Exception as e:
            logging.warning(f"Error in service-based OS detection: {e}")

        return os_info
    
    def _determine_device_type(self, host_data: dict) -> str:
        """Determine device type based on OS, ports, and services"""
        try:
            services = [p['service'].lower() for p in host_data.get('ports', [])]
            os_info = host_data.get('os_info', {})
            os_family = os_info.get('os_family', '').lower()
            
            # Network infrastructure devices
            if any(s in services for s in ['snmp', 'telnet', 'cisco']):
                if 'router' in str(services):
                    return 'router'
                if 'switch' in str(services):
                    return 'switch'
                return 'network_device'

            # Domain controllers
            if any(s in services for s in ['ldap', 'kerberos', 'msrpc']) and 'windows' in os_family:
                return 'domain_controller'

            # Servers
            if 'windows' in os_family and 'server' in os_info.get('os_match', '').lower():
                return 'windows_server'
            if any(s in services for s in ['http', 'https', 'apache', 'nginx']):
                return 'web_server'
            if any(s in services for s in ['mysql', 'postgresql', 'oracle', 'mssql']):
                return 'database_server'
            if any(s in services for s in ['smtp', 'pop3', 'imap']):
                return 'mail_server'
            if any(s in services for s in ['ftp', 'smb', 'nfs']):
                return 'file_server'

            # Workstations
            if 'windows' in os_family:
                if any(v in os_info.get('os_match', '').lower() for v in ['10', '11']):
                    return 'windows_workstation'
            if 'linux' in os_family:
                return 'linux_workstation'
            if 'macos' in os_family or 'darwin' in os_family:
                return 'mac_workstation'

            # Printers
            if any(s in services for s in ['printer', 'ipp', 'jetdirect']):
                return 'printer'

            # IoT/Embedded
            if 'embedded' in os_info.get('os_type', '').lower():
                return 'iot_device'

            return 'unknown'

        except Exception as e:
            logging.warning(f"Error determining device type: {e}")
            return 'unknown'
        
    

    def full_scan(self, target: str) -> ScanResult:
        """
        Comprehensive scan including OS detection, service detection, and vulnerabilities
        Arguments: -sT -sV -O -sC --script vuln (SYN scan, service version, OS detection, default scripts)
        """
        try:
            # Do comprehensive port and service scan
            results = self._run_scan(target, '-sT -sV -O -sC --script vuln', 'full_scan')
            
            # Add vulnerability checking
            services = []
            for host in results.hosts:
                for service in host.get('services', []):
                    if service.get('product'):
                        services.append({
                            'host': host['ip_address'],
                            'product': service['product'],
                            'version': service.get('version', ''),
                            'name': service.get('name', '')
                        })
            
            # Use vulnerability checker to get CVE information
            if services:
                vuln_checker = BatchVulnerabilityChecker()
                vuln_results = vuln_checker.batch_check_services(services)
                
                # Add vulnerability information to scan results
                for host in results.hosts:
                    host_vulns = []
                    for service in host.get('services', []):
                        product = service.get('product', '')
                        version = service.get('version', '')
                        if product:
                            service_vulns = vuln_results.get((product, version), {}).get('vulnerabilities', [])
                            for vuln in service_vulns:
                                host_vulns.append({
                                    'service': f"{product} {version}",
                                    'port': service.get('port', ''),
                                    **vuln
                                })
                    host['vulnerabilities'] = host_vulns
                    
                # Update vulnerability count in scan results
                results.vulnerabilities = []
                for host in results.hosts:
                    results.vulnerabilities.extend(host.get('vulnerabilities', []))
                    
                self.logger.info(f"Found {len(results.vulnerabilities)} vulnerabilities across all hosts")
                
            return results
            
        except Exception as e:
            self.logger.error(f"Full scan failed: {str(e)}")
            raise

    def vulnerability_scan(self, target: str) -> ScanResult:
        """
        Optimized vulnerability scan including CVE checks
        Arguments: -sV --version-intensity 5 --script vulners --min-rate 1000
        """
        try:
            # Use faster service detection and optimized scanning parameters
            scan_args = (
                '-sV '                     # Service version detection
                '--version-intensity 5 '   # Lower intensity for faster scans
                '--min-rate 1000 '        # Minimum number of packets per second
                '--max-retries 2 '        # Reduce retry attempts
                '--host-timeout 30m '      # Host timeout of 30 minutes
                '-T4 '                     # Aggressive timing template
                '--max-rtt-timeout 500ms ' # Maximum round-trip timeout
                '--initial-rtt-timeout 300ms ' # Initial round-trip timeout
                '--min-hostgroup 64 '      # Scan larger groups of hosts simultaneously
                '--min-parallelism 10 '    # Minimum probe parallelization
                '--open'                   # Only show open ports
            )
            
            # First do a quick service scan
            basic_results = self._run_scan(target, scan_args, 'vulnerability_scan')
            
            # Extract only services with product information
            services = []
            for host in basic_results.hosts:
                host_services = []
                for service in host.get('services', []):
                    if service.get('product'):
                        host_services.append({
                            'host': host['ip_address'],
                            'product': service['product'],
                            'version': service.get('version', ''),
                            'name': service.get('name', '')
                        })
                if host_services:
                    services.extend(host_services)
            
            # Process vulnerabilities in smaller batches with timeouts
            batch_size = 5  # Reduced from 10
            all_vulns = {}
            
            for i in range(0, len(services), batch_size):
                try:
                    batch = services[i:i + batch_size]
                    batch_results = self.vuln_checker.batch_check_services(
                        batch,
                        timeout=45  # Increased from 30
                    )
                    all_vulns.update(batch_results)
                    
                    # Add delay between batches
                    time.sleep(2)  # 2 second delay between batches
                    
                    progress = min(100, (i + batch_size) * 100 // len(services))
                    self.logger.info(f"Vulnerability check progress: {progress}%")
                    
                except Exception as e:
                    self.logger.warning(f"Error checking batch {i//batch_size}: {e}")
                    time.sleep(5)  # Longer delay after error
                    continue
            
            # Add vulnerability information to scan results
            for host in basic_results.hosts:
                host_vulns = []
                for service in host.get('services', []):
                    product = service.get('product', '')
                    version = service.get('version', '')
                    if product:
                        service_vulns = all_vulns.get((product, version), {}).get('vulnerabilities', [])
                        for vuln in service_vulns:
                            if vuln.get('cvss_score', 0) >= 7.0:  # Only include high and critical vulnerabilities
                                host_vulns.append({
                                    'service': f"{product} {version}",
                                    'port': service.get('port', ''),
                                    **vuln
                                })
                host['vulnerabilities'] = host_vulns
            
            # Update vulnerability count in scan results
            basic_results.vulnerabilities = []
            for host in basic_results.hosts:
                basic_results.vulnerabilities.extend(host.get('vulnerabilities', []))
            
            self.logger.info(f"Found {len(basic_results.vulnerabilities)} significant vulnerabilities across all hosts")
            return basic_results
            
        except Exception as e:
            self.logger.error(f"Vulnerability scan failed: {str(e)}")
            raise

    def test_scanner(self) -> Dict[str, str]:
        """Test if nmap is properly initialized and working"""
        try:
            if not hasattr(self, 'nm'):
                return {
                    'status': 'error',
                    'error': 'Nmap not initialized'
                }
            
            # Get nmap version
            try:
                version = self.nm.nmap_version()
                version_str = '.'.join(map(str, version))
            except Exception as e:
                return {
                    'status': 'error',
                    'error': f'Failed to get nmap version: {str(e)}'
                }
            
            # Try to get nmap path
            try:
                nmap_path = getattr(self.nm, 'nmap_path', 'nmap')  # Default to 'nmap' if attribute not found
            except Exception:
                nmap_path = 'nmap'  # Fallback to default
            
            # Try a simple ping scan on localhost
            try:
                self.nm.scan('127.0.0.1', arguments='-sn')
                scan_works = True
                scan_error = None
            except Exception as e:
                scan_works = False
                scan_error = str(e)
            
            return {
                'status': 'operational' if scan_works else 'error',
                'nmap_version': version_str,
                'nmap_path': nmap_path,
                'scan_test': 'successful' if scan_works else f'failed: {scan_error}'
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }

    def _run_scan(self, target: str, arguments: str, scan_type: str) -> ScanResult:
        """Execute nmap scan and process results"""
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.logger.info(f"Starting {scan_type} on {target}")

        try:
            # Reset stop flag and set current scan
            self.scan_stopped = False
            self.current_scan = {
                'target': target,
                'type': scan_type,
                'start_time': timestamp
            }
            
            # Add timeout and rate limiting to arguments
            safe_arguments = (f"{arguments} "
                            "--max-retries 3 "
                            "--host-timeout 15m "
                            "--min-rate 50 "
                            "--max-rate 150")

            self.logger.info(f"Running nmap with arguments: {safe_arguments}")
            
            try:
                scan_results = self.nm.scan(
                    target,
                    arguments=safe_arguments,
                    timeout=900
                )
                
                if not scan_results:
                    raise Exception("Scan returned no results")
                    
                self.logger.info("Scan completed successfully")
                
                # Process results
                results = self._process_results(scan_type, timestamp)
                self._save_results(results, target, scan_type)
                return results
                
            except Exception as e:
                self.logger.error(f"Scan execution failed: {str(e)}")
                raise
            finally:
                # Clear current scan when done
                self.current_scan = None

        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")
            self.current_scan = None  # Make sure to clear current scan on error
            raise

    def _process_results(self, scan_type: str, timestamp: str) -> ScanResult:
        """Process raw nmap results into structured data"""
        hosts = []
        ports = []
        services = []
        vulnerabilities = []
        os_matches = []

        for host in self.nm.all_hosts():
            try:
                self.logger.info(f"\nProcessing host: {host}")
                
                # Basic host information - use 'host' as the IP address
                host_info = {
                    'ip_address': str(host),  # Ensure consistent key name
                    'status': self.nm[host].state(),
                    'hostnames': self.nm[host].hostnames(),
                    'os_info': self._get_os_info(host),
                    'ports': [],
                    'services': [],
                    'device_type': 'unknown'
                }

                # Process ports and services for this host
                host_ports = []
                host_services = []
                
                for proto in self.nm[host].all_protocols():
                    port_list = list(self.nm[host][proto].keys())
                    self.logger.info(f"Host {host} has {len(port_list)} ports for protocol {proto}")
                    
                    for port in port_list:
                        try:
                            port_info = self.nm[host][proto][port]
                            port_state = port_info.get('state', 'unknown')
                            
                            if port_state == 'open':
                                service_info = {
                                    'name': port_info.get('name', 'unknown'),
                                    'product': port_info.get('product', ''),
                                    'version': port_info.get('version', ''),
                                    'extra_info': port_info.get('extrainfo', ''),
                                    'tunnel': port_info.get('tunnel', '')
                                }
                                
                                port_entry = {
                                    'port': int(port),
                                    'protocol': str(proto),
                                    'state': str(port_state),
                                    'service': service_info['name'],
                                    'service_details': self._format_service_details(service_info),
                                    'ip_address': str(host)  # Ensure consistent key name
                                }
                                
                                host_ports.append(port_entry)
                                ports.append(port_entry)
                                
                                if service_info['product'] or service_info['version']:
                                    host_services.append(service_info)
                                    services.append({
                                        **service_info,
                                        'host': str(host),  # Change this to ip_address for consistency
                                        'ip_address': str(host),  # Add this line
                                        'port': int(port)
                                    })
                                
                                self.logger.info(f"Found open port on {host}: {port} - {port_entry['service_details']}")
                                
                        except Exception as e:
                            self.logger.warning(f"Error processing port {port} for host {host}: {e}")
                            continue

                # Add ports and services to host info
                host_info['ports'] = host_ports
                host_info['services'] = host_services
                host_info['open_ports_count'] = len(host_ports)
                
                # Add OS match if found
                if host_info['os_info']['os_match'] != 'unknown':
                    os_matches.append({
                        'ip_address': str(host),  # Ensure consistent key name
                        **host_info['os_info']
                    })

                hosts.append(host_info)

            except Exception as e:
                self.logger.error(f"Error processing host {host}: {e}")
                continue

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
                'id': host['ip_address'],
                'type': 'host',
                'status': host['status']
            })

        # Create nodes and edges for services
        for service in results.services:
            service_id = f"{service['ip_address']}:{service['port']}"
            nodes.append({
                'id': service_id,
                'type': 'service',
                'name': service['name']
            })
            edges.append({
                'source': service['ip_address'],
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

    def _monitor_scan_performance(self, scan_start_time: float) -> None:
        """Monitor scan performance and log warnings for slow responses"""
        current_time = time.time()
        elapsed = current_time - scan_start_time
        
        if hasattr(self, 'nm') and hasattr(self.nm, 'scanstats'):
            stats = self.nm.scanstats()
            if stats:
                try:
                    # Convert string values to integers
                    hosts_completed = int(stats.get('uphosts', 0)) + int(stats.get('downhosts', 0))
                    total_hosts = int(stats.get('totalhosts', 0))
                    
                    if total_hosts > 0:
                        progress = (hosts_completed / total_hosts) * 100
                        logging.info(f"Scan progress: {progress:.1f}% ({hosts_completed}/{total_hosts} hosts)")
                        
                        # Log warning if scan is taking too long
                        if elapsed > 300 and progress < 50:  # 5 minutes with < 50% progress
                            logging.warning("Scan is progressing slowly. Network may have mixed connectivity types.")
                except (ValueError, TypeError) as e:
                    logging.warning(f"Error processing scan statistics: {e}")

    def stop_scan(self, scan_id: Optional[str] = None) -> bool:
        """Stop a running scan
        
        Args:
            scan_id: Optional ID of specific scan to stop. If None, stops all scans.
            
        Returns:
            bool: True if scan was stopped successfully, False otherwise
        """
        try:
            if self.current_scan:
                if scan_id is None or self.current_scan.get('id') == scan_id:
                    # Stop the actual scanning process
                    if hasattr(self.current_scan.get('process'), 'terminate'):
                        self.current_scan['process'].terminate()
                    
                    self.current_scan = None
                    return True
                
            return False
            
        except Exception as e:
            self.logger.error(f"Error stopping scan: {str(e)}")
            return False

    def check_requirements(self) -> Dict[str, bool]:
        """Check if all required components are available"""
        requirements = {
            'nmap_installed': False,
            'root_privileges': False,
            'network_access': False
        }
        
        try:
            # Check nmap
            result = subprocess.run(['nmap', '--version'], 
                                capture_output=True, 
                                text=True)
            requirements['nmap_installed'] = result.returncode == 0
            
            # Check privileges
            if platform.system().lower() == 'windows':
                requirements['root_privileges'] = ctypes.windll.shell32.IsUserAnAdmin()
            else:
                requirements['root_privileges'] = os.geteuid() == 0
                
            # Check network access
            try:
                socket.create_connection(("8.8.8.8", 53), timeout=3)
                requirements['network_access'] = True
            except OSError:
                pass
                
            return requirements
        except Exception as e:
            logging.error(f"Error checking requirements: {e}")
            return requirements

    def diagnose_scan_issues(self, target: str) -> Dict[str, Any]:
        """Diagnose potential scan issues"""
        try:
            results = {
                'connectivity': False,
                'latency': None,
                'packet_loss': None,
                'firewall': False,
                'rate_limiting': False
            }
            
            # Test basic connectivity
            try:
                ping_result = subprocess.run(['ping', '-c', '1', '-W', '2', target], 
                                           capture_output=True, text=True)
                results['connectivity'] = ping_result.returncode == 0
                
                # Parse latency if ping successful
                if results['connectivity']:
                    latency_match = re.search(r'time=(\d+\.?\d*)', ping_result.stdout)
                    if latency_match:
                        results['latency'] = float(latency_match.group(1))
            except Exception as e:
                self.logger.warning(f"Ping test failed: {e}")
                
            # Test for packet loss
            try:
                loss_result = subprocess.run(['ping', '-c', '10', '-W', '2', target],
                                           capture_output=True, text=True)
                loss_match = re.search(r'(\d+)% packet loss', loss_result.stdout)
                if loss_match:
                    results['packet_loss'] = int(loss_match.group(1))
            except Exception as e:
                self.logger.warning(f"Packet loss test failed: {e}")
                
            return results
            
        except Exception as e:
            self.logger.error(f"Diagnosis failed: {e}")
            return {}

    def _format_service_details(self, service_info: Dict) -> str:
        """Format service information into a detailed string"""
        try:
            # Start with the basic service name
            service_details = service_info['name']
            details_parts = []
            
            # Add tunnel type if present (e.g., ssl/http)
            if service_info.get('tunnel'):
                service_details = f"{service_info['tunnel']}/{service_info['name']}"
            
            # Add product and version if available
            if service_info.get('product'):
                product_str = service_info['product']
                if service_info.get('version'):
                    product_str += f" {service_info['version']}"
                details_parts.append(product_str)
            
            # Add any extra information
            if service_info.get('extra_info'):
                details_parts.append(service_info['extra_info'])
            
            # Combine all parts
            if details_parts:
                service_details += f" ({'; '.join(details_parts)})"
            
            return service_details
        
        except Exception as e:
            self.logger.warning(f"Error formatting service details: {e}")
            return service_info.get('name', 'unknown')

if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    try:
        # Initialize scanner
        logging.info("Initializing NetworkScanner...")
        scanner = NetworkScanner()
        
        # Test scanner functionality
        logging.info("Testing scanner...")
        test_result = scanner.test_scanner()
        print("\nScanner Test Results:")
        for key, value in test_result.items():
            print(f"{key}: {value}")
        
        if test_result['status'] == 'operational':
            print("\nRunning quick scan on localhost...")
            results = scanner.quick_scan('127.0.0.1')
            print("\nScan completed successfully!")
            print("\nResults summary:")
            print(f"Hosts found: {len(results.hosts)}")
            print(f"Scan time: {results.scan_stats['elapsed']} seconds")
            print(f"\nResults saved in {scanner.output_dir}")
        else:
            print("\nScanner test failed - please check the error messages above")
            
    except Exception as e:
        logging.error(f"Error during scanner initialization/testing: {str(e)}")
        raise