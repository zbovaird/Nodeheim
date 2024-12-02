import socket
import ipaddress
import concurrent.futures
from datetime import datetime
import json
import logging

def scan_host(ip, full_scan=False):
    """Scan a single host for open ports"""
    host_info = {
        'ip': str(ip),
        'status': 'down',
        'open_ports': [],
        'hostname': None
    }
    
    # Port ranges based on scan type
    ports = range(1, 1025) if full_scan else [80, 443, 22, 3389, 445, 139]
    
    try:
        # Try to get hostname
        try:
            host_info['hostname'] = socket.gethostbyaddr(str(ip))[0]
        except socket.herror:
            pass
        
        # Check if host is up by attempting to connect to ports
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5 if full_scan else 1)
                    result = s.connect_ex((str(ip), port))
                    if result == 0:
                        host_info['status'] = 'up'
                        host_info['open_ports'].append(port)
            except (socket.timeout, ConnectionRefusedError):
                continue
            
    except Exception as e:
        logging.error(f"Error scanning host {ip}: {str(e)}")
        host_info['error'] = str(e)
    
    return host_info

def scan_network(subnet, full_scan=False):
    """Scan a network subnet and return results"""
    try:
        logging.info(f"Starting network scan of {subnet} (full_scan={full_scan})")
        network = ipaddress.ip_network(subnet)
        results = []
        
        # Adjust workers based on scan type
        max_workers = 10 if full_scan else 20
        
        # Use ThreadPoolExecutor for parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {executor.submit(scan_host, ip, full_scan): ip 
                          for ip in network.hosts()}
            
            for future in concurrent.futures.as_completed(future_to_ip):
                try:
                    host_info = future.result()
                    if host_info['status'] == 'up':
                        results.append(host_info)
                        logging.info(f"Found active host: {host_info['ip']}")
                except Exception as e:
                    logging.error(f"Error processing scan result: {e}")
        
        scan_result = {
            'timestamp': datetime.now().isoformat(),
            'subnet': subnet,
            'scan_type': 'full_scan' if full_scan else 'basic_scan',
            'hosts': results
        }
        
        logging.info(f"Scan completed. Found {len(results)} active hosts")
        return scan_result
        
    except Exception as e:
        logging.error(f"Error in scan_network: {str(e)}", exc_info=True)
        return {
            'error': str(e),
            'timestamp': datetime.now().isoformat(),
            'subnet': subnet,
            'scan_type': 'full_scan' if full_scan else 'basic_scan',
            'hosts': []
        }

def format_splunk_event(scan_result):
    """Format scan results as Splunk events"""
    events = []
    timestamp = scan_result.get('timestamp')
    subnet = scan_result.get('subnet')
    scan_type = scan_result.get('scan_type', 'basic_scan')
    
    for host in scan_result.get('hosts', []):
        event = {
            '_time': timestamp,
            'subnet': subnet,
            'scan_type': scan_type,
            'host': host['ip'],
            'hostname': host.get('hostname'),
            'status': host['status'],
            'open_ports': ','.join(map(str, host.get('open_ports', []))),
            'source': 'nodeheim:scanner',
            'sourcetype': 'nodeheim:scan',
            '_raw': json.dumps(host)
        }
        events.append(event)
    
    logging.info(f"Formatted {len(events)} events for Splunk")
    return events 