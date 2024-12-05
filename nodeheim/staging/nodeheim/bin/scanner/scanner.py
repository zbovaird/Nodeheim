import logging
import socket
import ipaddress
import concurrent.futures
import nmap
from datetime import datetime
from typing import List, Dict, Any, Optional
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NetworkScanner:
    def __init__(self, subnet: str, full_scan: bool = False):
        """
        Initialize network scanner
        
        Args:
            subnet: Network subnet to scan (e.g., '192.168.1.0/24')
            full_scan: Whether to perform a full port scan
        """
        self.subnet = subnet
        self.full_scan = full_scan
        self.nm = nmap.PortScanner()
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3389]

    def scan_network(self) -> List[Dict[str, Any]]:
        """
        Perform network scan and return results
        
        Returns:
            List of dictionaries containing scan results
        """
        try:
            network = ipaddress.ip_network(self.subnet)
            logger.info(f"Starting scan of network: {self.subnet}")
            
            # Scan hosts in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(self.scan_host, str(ip)) 
                          for ip in network.hosts()]
                scan_results = []
                for future in concurrent.futures.as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            scan_results.append(result)
                    except Exception as e:
                        logger.error(f"Error scanning host: {e}")

            logger.info(f"Scan complete. Found {len(scan_results)} hosts")
            return scan_results

        except Exception as e:
            logger.error(f"Error scanning network: {e}")
            return []

    def scan_host(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Scan individual host
        
        Args:
            ip: IP address to scan
            
        Returns:
            Dictionary containing host scan results or None if host is down
        """
        try:
            # Quick ping scan first
            ping_result = self.nm.scan(ip, arguments='-sn')
            if not self.nm.all_hosts():
                return None

            # Port scan
            ports = self.common_ports if not self.full_scan else '1-1024'
            scan_result = self.nm.scan(ip, arguments=f'-sS -sV -p{ports}')
            
            if ip not in self.nm.all_hosts():
                return None

            host_data = self.nm[ip]
            
            # Collect host information
            result = {
                'ip': ip,
                'status': host_data.state(),
                'hostname': host_data.hostname(),
                'timestamp': datetime.now().isoformat(),
                'mac_address': host_data.get('addresses', {}).get('mac', ''),
                'os_matches': host_data.get('osmatch', []),
                'ports': []
            }

            # Collect port information
            if 'tcp' in host_data:
                for port, port_data in host_data['tcp'].items():
                    port_info = {
                        'port': port,
                        'state': port_data['state'],
                        'service': port_data['name'],
                        'product': port_data.get('product', ''),
                        'version': port_data.get('version', '')
                    }
                    result['ports'].append(port_info)

            return result

        except Exception as e:
            logger.error(f"Error scanning host {ip}: {e}")
            return None

    def format_splunk_event(self, scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Format scan results as Splunk events
        
        Args:
            scan_results: List of scan results
            
        Returns:
            List of formatted Splunk events
        """
        events = []
        for result in scan_results:
            try:
                event = {
                    'source': 'nodeheim:scan',
                    'sourcetype': 'nodeheim:scan',
                    '_time': datetime.now().timestamp(),
                    '_raw': json.dumps(result),
                    'host': result['ip'],
                    'status': result['status'],
                    'hostname': result['hostname'],
                    'mac_address': result['mac_address'],
                    'num_open_ports': len([p for p in result['ports'] if p['state'] == 'open']),
                    'services': [p['service'] for p in result['ports'] if p['state'] == 'open']
                }
                events.append(event)
            except Exception as e:
                logger.error(f"Error formatting event for host {result.get('ip')}: {e}")

        return events

def scan_network(subnet: str, full_scan: bool = False) -> List[Dict[str, Any]]:
    """
    Main scanning function
    
    Args:
        subnet: Network subnet to scan
        full_scan: Whether to perform a full port scan
        
    Returns:
        List of scan results
    """
    scanner = NetworkScanner(subnet, full_scan)
    return scanner.scan_network()

def format_splunk_event(scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Format scan results for Splunk
    
    Args:
        scan_results: List of scan results
        
    Returns:
        List of formatted Splunk events
    """
    scanner = NetworkScanner('')  # subnet not needed for formatting
    return scanner.format_splunk_event(scan_results)