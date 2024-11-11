# src/scanner/network_discovery.py
import netifaces
import ipaddress
import logging
from typing import List, Dict

class NetworkDiscovery:
    @staticmethod
    def get_local_networks() -> List[Dict[str, str]]:
        """Discover available local networks"""
        networks = []
        try:
            # Get all network interfaces
            interfaces = netifaces.interfaces()
            
            for iface in interfaces:
                try:
                    # Get interface addresses
                    addrs = netifaces.ifaddresses(iface)
                    
                    # Look for IPv4 addresses
                    if netifaces.AF_INET in addrs:
                        for addr in addrs[netifaces.AF_INET]:
                            ip = addr['addr']
                            netmask = addr['netmask']
                            
                            # Skip localhost
                            if ip.startswith('127.'):
                                continue
                                
                            # Calculate network address
                            try:
                                network = ipaddress.IPv4Network(
                                    f"{ip}/{netmask}", 
                                    strict=False
                                )
                                networks.append({
                                    'network': str(network),
                                    'interface': iface,
                                    'ip': ip,
                                    'netmask': netmask
                                })
                            except ValueError as e:
                                logging.warning(f"Error calculating network for {ip}/{netmask}: {e}")
                                
                except ValueError as e:
                    logging.warning(f"Error processing interface {iface}: {e}")
                    continue
                    
        except Exception as e:
            logging.error(f"Error discovering networks: {e}")
            
        return networks