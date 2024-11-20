# src/scanner/scanner.py
import nmap
import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Any
import logging
import ipaddress
from dataclasses import dataclass, asdict
import csv
import platform
import subprocess
import time

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
        """Initialize the network scanner
        
        Args:
            output_dir (str, optional): Directory for output files. Defaults to 'data' if None.
            
        Raises:
            ValueError: If output_dir contains invalid characters or path traversal attempts
        """
        # Validate output directory if provided
        if output_dir is not None:
            # Check for directory traversal attempts
            clean_path = os.path.normpath(output_dir)
            if '..' in clean_path or not clean_path.replace('\\', '/').strip('/'):
                raise ValueError("Invalid output directory path")
            self.output_dir = clean_path
        else:
            self.output_dir = 'data'
            
        # Initialize components
        self.nm = self._initialize_nmap()
        self.setup_directories()
        self.setup_logging()

    def _initialize_nmap(self) -> nmap.PortScanner:
        """Initialize nmap with platform-specific paths and robust error handling"""
        system = platform.system().lower()
        logging.info(f"Initializing Nmap on {system} platform")
        
        # Common nmap paths by OS
        nmap_paths = {
            'darwin': [  # macOS
                '/opt/homebrew/bin/nmap',  # M1/M2 Mac Homebrew location
                '/usr/local/bin/nmap',     # Intel Mac Homebrew location
                '/usr/bin/nmap',           # Default macOS location
            ],
            'linux': [
                '/usr/bin/nmap',
                '/usr/local/bin/nmap',
                '/opt/nmap/bin/nmap'
            ],
            'windows': [
                r'C:\Program Files (x86)\Nmap\nmap.exe',
                r'C:\Program Files\Nmap\nmap.exe',
            ]
        }
        
        # Get paths for current OS, add 'nmap' as fallback for all platforms
        paths_to_try = nmap_paths.get(system, []) + ['nmap']
        
        # Try to verify nmap installation first
        try:
            # Try running nmap version command directly
            result = subprocess.run(['nmap', '--version'], 
                                capture_output=True, 
                                text=True)
            if result.returncode == 0:
                logging.info(f"Nmap found in PATH: {result.stdout.splitlines()[0]}")
                try:
                    scanner = nmap.PortScanner()
                    version = scanner.nmap_version()
                    logging.info(f"Successfully initialized nmap {version}")
                    return scanner
                except Exception as e:
                    logging.warning(f"Default initialization failed: {str(e)}")
                    # Continue to path-based initialization
        except FileNotFoundError:
            logging.warning("Nmap not found in PATH, trying specific locations...")
        except Exception as e:
            logging.warning(f"Error checking nmap version: {str(e)}")
        
        # Try specific paths if default initialization failed
        for path in paths_to_try:
            try:
                logging.info(f"Trying nmap path: {path}")
                scanner = nmap.PortScanner(nmap_search_path=[path])
                version = scanner.nmap_version()
                logging.info(f"Successfully initialized nmap {version} from {path}")
                return scanner
            except Exception as e:
                logging.warning(f"Failed to initialize with {path}: {str(e)}")
                continue
        
        # If we get here, we couldn't find nmap
        error_messages = {
            'darwin': "Please install nmap using 'brew install nmap'",
            'linux': "Please install nmap using your package manager (e.g., 'apt install nmap' or 'yum install nmap')",
            'windows': "Please install Nmap from https://nmap.org/download.html and ensure Npcap is installed"
        }
        
        raise nmap.PortScannerError(
            f"Could not find or initialize nmap. {error_messages.get(system, 'Please install nmap')}"
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
        """Enhanced basic port scan with OS and device type detection"""
        logging.info(f"Starting enhanced basic port scan on {target}")
        
        try:
            # Enhanced scan arguments for better OS and service detection
            arguments = (
                '-sT '               # TCP connect scan
                '-sV '               # Version detection
                '-O '               # OS detection
                '--privileged '      #run with privleges
                '--osscan-guess '    # Make aggressive OS guesses
                '--version-intensity 9 '  # More aggressive service detection
                '--version-light '    # Try light probes first
                '--version-all '      # Try all probes
                '-p 1-1000 '         # Scan first 1000 ports
                '-T3 '               # Normal timing
                '--min-rate 100 '    # Minimum packet rate
                '--max-retries 2 '   # Limit retries
                '--host-timeout 15m ' # Host timeout
                '-sC '               # Default scripts
                '--script-args http.useragent="Mozilla/5.0" ' # Set user agent
                '--script banner,ssh-hostkey,ssl-cert,http-title,http-headers,'
                'smb-os-discovery,http-server-header,http-robots.txt'
            )
            
            logging.info("Using enhanced OS and service detection")
            result = self._run_scan(target, arguments, 'basic_scan')
            
            return result
            
        except Exception as e:
            logging.error(f"Basic scan failed: {e}")
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
        Comprehensive scan including OS detection and script scanning
        Arguments: -sT -sV -O -sC (SYN scan, service version, OS detection, default scripts)
        """
        return self._run_scan(target, '-sT -sV -O -sC', 'full_scan')

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
    
    def test_scanner(self) -> Dict[str, str]:
        """Test if nmap is properly initialized and working"""
        try:
            # Get nmap version
            version = self.nm.nmap_version()
            
            # Try a simple ping scan on localhost
            try:
                self.nm.scan('127.0.0.1', arguments='-sn')
                scan_works = True
            except Exception as e:
                scan_works = False
                scan_error = str(e)
            
            return {
                'status': 'operational' if scan_works else 'error',
                'nmap_version': '.'.join(map(str, version)),
                'nmap_path': self.nm.nmap_path,
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
            try:
                logging.info(f"\nProcessing host: {host}")
                
                # Get OS information first
                os_info = self._get_os_info(host)
                
                # Basic host information
                host_info = {
                    'ip_address': host,
                    'status': self.nm[host].state(),
                    'hostnames': self.nm[host].hostnames(),
                    'os_info': os_info,
                    'ports': []
                }

                # Process ports and services for this host
                host_ports = []  # Track ports for this specific host
                for proto in self.nm[host].all_protocols():
                    port_list = list(self.nm[host][proto].keys())
                    logging.info(f"Host {host} has {len(port_list)} ports for protocol {proto}")
                    
                    for port in port_list:
                        try:
                            port_num = int(port)
                            port_info = self.nm[host][proto][port]
                            port_state = port_info.get('state', 'unknown')
                            
                            # Log raw port info for debugging
                            logging.debug(f"Raw port info for {host}:{port} - {port_info}")
                            
                            # Only process open ports
                            if port_state == 'open':
                                # Get detailed service information
                                service_name = port_info.get('name', 'unknown')
                                service_product = port_info.get('product', '')
                                service_version = port_info.get('version', '')
                                service_extra = port_info.get('extrainfo', '')
                                tunnel_type = port_info.get('tunnel', '')  # For SSL/TLS services
                                
                                # Build detailed service string
                                service_details = service_name
                                if any([service_product, service_version, service_extra, tunnel_type]):
                                    service_details += " ("
                                    details_parts = []
                                    
                                    if tunnel_type:
                                        service_details = f"{tunnel_type}/{service_name}"
                                        
                                    if service_product:
                                        details_parts.append(service_product)
                                        if service_version:
                                            details_parts[-1] += f" {service_version}"
                                            
                                    if service_extra:
                                        details_parts.append(service_extra)
                                        
                                    if details_parts:
                                        service_details += f" ({'; '.join(details_parts)})"
                                
                                port_data = {
                                    'port': port_num,
                                    'protocol': proto,
                                    'state': port_state,
                                    'service': service_name,
                                    'service_details': service_details,
                                    'product': service_product,
                                    'version': service_version,
                                    'extra_info': service_extra,
                                    'tunnel_type': tunnel_type,
                                    'ip_address': host
                                }
                                
                                logging.info(f"Found open port on {host}: {port_num} - {service_details}")
                                
                                # Add to host's ports list
                                host_ports.append(port_data)
                                
                                # Add to global ports list with host information
                                ports.append(port_data)
                                
                                # Add detailed service information
                                services.append({
                                    'ip_address': host,
                                    'port': port_num,
                                    'name': service_name,
                                    'product': service_product,
                                    'version': service_version,
                                    'extra_info': service_extra,
                                    'protocol': proto,
                                    'service_details': service_details
                                })
                                
                        except (ValueError, TypeError) as e:
                            logging.warning(f"Error processing port {port} for host {host}: {e}")
                            continue

                # Add ports to host info
                host_info['ports'] = host_ports
                host_info['open_ports_count'] = len(host_ports)

                # Determine device type after processing ports
                host_info['device_type'] = self._determine_device_type({
                    'ports': host_ports,
                    'os_info': os_info
                })

                # Add to os_matches if we got valid OS info
                if os_info['os_match'] != 'unknown':
                    os_matches.append({
                        'ip_address': host,
                        **os_info
                    })
                
                # Log summary for this host
                if host_ports:
                    logging.info(f"\nHost {host} summary:")
                    logging.info(f"Open ports count: {len(host_ports)}")
                    logging.info(f"OS Info: {os_info['os_match']} ({os_info['os_accuracy']}% accuracy)")
                    logging.info(f"Device Type: {host_info['device_type']}")
                    for port in host_ports:
                        logging.info(f"  Port {port['port']}/{port['protocol']}: {port.get('service_details', 'unknown')}")

                hosts.append(host_info)

            except Exception as e:
                logging.error(f"Error processing host {host}: {e}")
                continue

        # Log final summary
        logging.info(f"\nFinal Scan Summary:")
        logging.info(f"Total hosts scanned: {len(hosts)}")
        logging.info(f"Total open ports found: {len(ports)}")
        logging.info(f"Total services identified: {len(services)}")
        logging.info(f"OS matches found: {len(os_matches)}")
        logging.info("\nPorts by host:")
        for host_info in hosts:
            if host_info['open_ports_count'] > 0:
                logging.info(f"\nHost {host_info['ip_address']}:")
                logging.info(f"Device Type: {host_info['device_type']}")
                logging.info(f"OS: {host_info['os_info']['os_match']}")
                for port in host_info['ports']:
                    logging.info(f"  {port['port']}/{port['protocol']} - {port.get('service_details', 'unknown')}")

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

    def _run_scan(self, target: str, arguments: str, scan_type: str) -> ScanResult:
        """Execute nmap scan and process results with performance monitoring"""
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        logging.info(f"Starting {scan_type} on {target}")
        
        scan_start_time = time.time()

        try:
            # Start the scan
            self.nm.scan(hosts=target, arguments=arguments)
            
            # Monitor performance
            self._monitor_scan_performance(scan_start_time)
            
            # Process results
            results = self._process_results(scan_type, timestamp)
            self._save_results(results, target, scan_type)
            
            # Log completion time
            scan_duration = time.time() - scan_start_time
            logging.info(f"Scan completed in {scan_duration:.1f} seconds")
            
            return results
        except Exception as e:
            logging.error(f"Scan failed: {str(e)}")
            raise

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