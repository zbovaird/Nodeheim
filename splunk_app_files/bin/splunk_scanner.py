import splunk.Intersplunk
import sys
import os
import json
from datetime import datetime
import socket
import subprocess

class SplunkNetworkScanner:
    def __init__(self):
        self.scan_data = {
            "scan_id": "",
            "timestamp": "",
            "subnet": "",
            "scan_type": "",
            "hosts": []
        }
        
    def run_scan(self, subnet, scan_type="basic_scan"):
        """
        Run network scan using Splunk-friendly methods while maintaining
        compatibility with original Nodeheim data format
        """
        try:
            self.scan_data["scan_id"] = self.generate_scan_id()
            self.scan_data["timestamp"] = datetime.now().isoformat()
            self.scan_data["subnet"] = subnet
            self.scan_data["scan_type"] = scan_type
            
            # First, check Splunk\'s asset database
            existing_hosts = self.get_splunk_assets()
            
            # Then do a basic network discovery
            discovered_hosts = self.discover_network(subnet)
            
            # Merge and deduplicate hosts
            self.scan_data["hosts"] = self.merge_host_data(existing_hosts, discovered_hosts)
            
            return self.scan_data
            
        except Exception as e:
            return {"error": str(e)}
    
    def get_splunk_assets(self):
        """Get existing host data from Splunk"""
        try:
            # Try multiple Splunk sources
            searches = [
                "| inputlookup asset_list_lookup | table ip_address hostname os ports services",
                "| tstats count from datamodel=Network_Traffic by All_Traffic.dest_ip | rename All_Traffic.dest_ip as ip_address",
                "| metadata type=hosts | table host | rename host as ip_address"
            ]
            
            hosts = []
            for search in searches:
                try:
                    _, content = splunk.Intersplunk.getOrganizedResults(search)
                    if content:
                        hosts.extend(content)
                except:
                    continue
                    
            return hosts
        except:
            return []
    
    def discover_network(self, subnet):
        """Basic network discovery using Python socket"""
        hosts = []
        try:
            # Parse subnet (e.g., "192.168.1.0/24")
            base_ip = subnet.split(\'/\')[0]
            ip_parts = base_ip.split(\'.\')
            
            # Scan last octet range
            for i in range(1, 255):
                ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.{i}"
                host_info = self.get_host_info(ip)
                if host_info:
                    hosts.append(host_info)
                    
            return hosts
            
        except Exception as e:
            return []
    
    def get_host_info(self, ip):
        """Get detailed host information"""
        try:
            # Check if host is up
            if not self.is_host_up(ip):
                return None
                
            # Basic host information
            host_info = {
                "ip_address": ip,
                "hostname": "",
                "status": "up",
                "os_info": {
                    "os_match": "",
                    "accuracy": 0
                },
                "ports": [],
                "services": []
            }
            
            # Try to get hostname
            try:
                host_info["hostname"] = socket.gethostbyaddr(ip)[0]
            except:
                pass
            
            # Check common ports
            common_ports = {
                80: "http", 443: "https", 22: "ssh",
                21: "ftp", 3389: "rdp", 445: "smb",
                139: "netbios", 135: "msrpc"
            }
            
            for port, service in common_ports.items():
                if self.check_port(ip, port):
                    port_info = {
                        "port": port,
                        "protocol": "tcp",
                        "state": "open",
                        "service": service,
                        "version": ""
                    }
                    host_info["ports"].append(port_info)
                    host_info["services"].append(service)
            
            return host_info
            
        except:
            return None
    
    def is_host_up(self, ip):
        """Check if host responds to ping"""
        try:
            if os.name == "nt":  # Windows
                response = subprocess.run(["ping", "-n", "1", "-w", "500", ip], 
                                       capture_output=True)
            else:  # Linux/Unix
                response = subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                                       capture_output=True)
            return response.returncode == 0
        except:
            return False
    
    def check_port(self, ip, port):
        """Check if port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def generate_scan_id(self):
        """Generate unique scan ID"""
        import uuid
        return str(uuid.uuid4())
    
    def merge_host_data(self, existing_hosts, discovered_hosts):
        """Merge and deduplicate host data"""
        merged = {}
        
        # Add existing hosts
        for host in existing_hosts:
            ip = host.get("ip_address")
            if ip:
                merged[ip] = host
        
        # Add/update discovered hosts
        for host in discovered_hosts:
            ip = host.get("ip_address")
            if ip:
                if ip in merged:
                    # Update existing host data
                    merged[ip].update(host)
                else:
                    # Add new host
                    merged[ip] = host
        
        return list(merged.values())
