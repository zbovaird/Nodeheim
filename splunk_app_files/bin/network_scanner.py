import splunk.Intersplunk
import sys
import os
import json
from datetime import datetime
import socket
import subprocess

class NetworkScanner:
    def __init__(self):
        self.known_ports = {
            80: "http",
            443: "https",
            22: "ssh",
            21: "ftp",
            3389: "rdp",
            445: "smb"
            # Add more common ports
        }
        
    def scan_host(self, ip):
        host_info = {
            "ip_address": ip,
            "hostname": "",
            "status": "down",
            "ports": [],
            "services": []
        }
        
        try:
            # Try to get hostname
            try:
                host_info["hostname"] = socket.gethostbyaddr(ip)[0]
            except:
                pass
                
            # Check if host is up
            if self.is_host_up(ip):
                host_info["status"] = "up"
                
                # Scan common ports
                for port in self.known_ports.keys():
                    if self.check_port(ip, port):
                        service = self.known_ports[port]
                        host_info["ports"].append({
                            "port": port,
                            "protocol": "tcp",
                            "state": "open",
                            "service": service
                        })
                        host_info["services"].append(service)
            
            return host_info
            
        except Exception as e:
            return host_info
    
    def is_host_up(self, ip):
        try:
            # Use ping to check if host is up
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
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
            
    def run_scan(self, subnet, scan_type="basic_scan"):
        try:
            # Parse subnet (e.g., "192.168.1.0/24")
            base_ip = subnet.split('/')[0]
            ip_parts = base_ip.split('.')
            
            hosts = []
            # Scan last octet range (1-254)
            for i in range(1, 255):
                ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.{i}"
                host_info = self.scan_host(ip)
                if host_info["status"] == "up":
                    hosts.append(host_info)
            
            return {
                "timestamp": datetime.now().isoformat(),
                "subnet": subnet,
                "scan_type": scan_type,
                "hosts": hosts
            }
            
        except Exception as e:
            return {"error": str(e)}
