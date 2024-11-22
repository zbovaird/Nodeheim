# src/scanner/network_discovery.py
import netifaces
import ipaddress
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

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
                            ip = addr.get('addr')
                            netmask = addr.get('netmask')
                            
                            if not ip or not netmask:
                                continue
                                
                            # Skip localhost
                            if ip.startswith('127.'):
                                continue
                                
                            # Calculate network address
                            try:
                                network = ipaddress.IPv4Network(
                                    f"{ip}/{netmask}", 
                                    strict=False
                                )
                                # Clean up interface name - remove GUID
                                clean_iface = iface.split('{')[0].strip()
                                networks.append({
                                    'network': str(network),
                                    'interface': clean_iface,
                                    'ip': ip,
                                    'netmask': netmask,
                                    'name': str(network),  # Use network address as name instead of interface
                                    'description': f'Network on {clean_iface}'
                                })
                            except ValueError as e:
                                logger.warning(f"Error calculating network for {ip}/{netmask}: {e}")
                                
                except ValueError as e:
                    logger.warning(f"Error processing interface {iface}: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error discovering networks: {e}")
            
        # Add default networks if none were found
        if not networks:
            logger.warning("No networks discovered, adding default networks")
            default_networks = [
                ('192.168.1.0/24', '192.168.1.1'),
                ('192.168.0.0/24', '192.168.0.1'),
                ('10.0.0.0/24', '10.0.0.1'),
                ('172.16.0.0/24', '172.16.0.1')
            ]
            
            for net, ip in default_networks:
                network = ipaddress.IPv4Network(net)
                networks.append({
                    'network': str(network),
                    'interface': 'default',
                    'ip': ip,
                    'netmask': str(network.netmask),
                    'name': str(network),  # Use network address as name
                    'description': 'Default Network'
                })
                
        # Always add manual input option
        networks.append({
            'interface': 'manual',
            'network': 'custom',
            'ip': '',
            'netmask': '',
            'name': 'Custom Network',  # Clean name for manual option
            'description': 'Enter custom network/IP'
        })
        
        return networks