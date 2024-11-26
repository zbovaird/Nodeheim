# src/scanner/network_discovery.py
import netifaces
import ipaddress
import logging
import platform
import socket
import subprocess
from typing import List, Dict

logger = logging.getLogger(__name__)

class NetworkDiscovery:
    # List of interface name patterns to exclude
    EXCLUDED_INTERFACES = [
        'docker', 'veth', 'br-', 'vmnet', 'virtual',
        'VirtualBox', 'WSL', 'Hyper-V', 'bridge'
    ]

    @staticmethod
    def should_exclude_interface(iface: str, ip: str) -> bool:
        """Check if interface should be excluded"""
        iface_lower = iface.lower()
        
        # Skip localhost
        if ip.startswith('127.'):
            return True
            
        # Skip Docker and other virtual interfaces
        if any(pattern.lower() in iface_lower for pattern in NetworkDiscovery.EXCLUDED_INTERFACES):
            return True
            
        # Skip interfaces without valid IP
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            return True
            
        return False

    @staticmethod
    def get_local_networks() -> List[Dict[str, str]]:
        """Discover available local networks"""
        networks = []
        try:
            # Get all network interfaces
            interfaces = netifaces.interfaces()
            logger.info(f"Found interfaces: {interfaces}")
            
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
                                
                            # Check if interface should be excluded
                            if NetworkDiscovery.should_exclude_interface(iface, ip):
                                logger.debug(f"Skipping interface {iface} with IP {ip}")
                                continue
                                
                            # Calculate network address
                            try:
                                network = ipaddress.IPv4Network(
                                    f"{ip}/{netmask}", 
                                    strict=False
                                )
                                # Clean up interface name - remove GUID
                                clean_iface = iface.split('{')[0].strip()
                                
                                # Try to get interface description on Windows
                                description = NetworkDiscovery.get_interface_description(clean_iface)
                                
                                networks.append({
                                    'network': str(network),
                                    'interface': clean_iface,
                                    'ip': ip,
                                    'netmask': netmask,
                                    'name': description or str(network),  # Use description if available
                                    'description': f'Network on {description or clean_iface}'
                                })
                                logger.info(f"Added network: {networks[-1]}")
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

    @staticmethod
    def get_interface_description(interface_name: str) -> str:
        """Get friendly description for network interface on Windows"""
        if platform.system() != 'Windows':
            return interface_name
            
        try:
            # Use PowerShell to get interface description
            cmd = f'powershell -Command "Get-NetAdapter -Name \'{interface_name}\' | Select-Object -ExpandProperty InterfaceDescription"'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except Exception as e:
            logger.warning(f"Error getting interface description: {e}")
            
        return interface_name