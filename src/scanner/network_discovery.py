# src/scanner/network_discovery.py
import netifaces
import ipaddress
import socket
import logging
import platform
from typing import List, Dict

class NetworkDiscovery:
    @staticmethod
    def get_local_networks() -> List[Dict[str, str]]:
        """Discover available local networks"""
        networks = []
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.DEBUG)  # Set to DEBUG level
        
        try:
            # Print system information
            system = platform.system()
            logger.info(f"Operating System: {system}")
            
            # Get all network interfaces
            interfaces = netifaces.interfaces()
            logger.info(f"Found interfaces: {interfaces}")
            
            # Get gateways
            gateways = netifaces.gateways()
            logger.info(f"Found gateways: {gateways}")
            
            # Try to get default gateway
            default_gw = gateways.get('default', {}).get(netifaces.AF_INET, [None])[0]
            if default_gw:
                logger.info(f"Default gateway: {default_gw}")
                # Add network based on default gateway
                try:
                    gw_ip = default_gw[0]  # Get gateway IP
                    network = ipaddress.IPv4Network(f"{gw_ip}/24", strict=False)
                    networks.append({
                        'network': str(network),
                        'interface': 'default_gw',
                        'ip': gw_ip,
                        'netmask': '255.255.255.0'
                    })
                    logger.info(f"Added network from default gateway: {network}")
                except Exception as e:
                    logger.error(f"Error processing default gateway: {e}")
            
            # Process each interface
            for iface in interfaces:
                logger.info(f"\nProcessing interface: {iface}")
                
                # Skip loopback interfaces
                if iface.lower().startswith(('lo', 'loop')):
                    logger.info(f"Skipping loopback interface: {iface}")
                    continue
                
                try:
                    # Get interface addresses
                    addrs = netifaces.ifaddresses(iface)
                    logger.info(f"Addresses for {iface}: {addrs}")
                    
                    # Look for IPv4 addresses
                    if netifaces.AF_INET in addrs:
                        for addr in addrs[netifaces.AF_INET]:
                            ip = addr.get('addr')
                            netmask = addr.get('netmask')
                            logger.info(f"Found IP: {ip}, Netmask: {netmask}")
                            
                            # Skip localhost and empty addresses
                            if not ip or not netmask or ip.startswith('127.'):
                                logger.info(f"Skipping invalid address: {ip}")
                                continue
                            
                            try:
                                # Calculate network address
                                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                                network_info = {
                                    'network': str(network),
                                    'interface': iface,
                                    'ip': ip,
                                    'netmask': netmask
                                }
                                networks.append(network_info)
                                logger.info(f"Successfully added network: {network_info}")
                                
                            except ValueError as e:
                                logger.error(f"Error calculating network for {ip}/{netmask}: {e}")
                                
                except Exception as e:
                    logger.error(f"Error processing interface {iface}: {e}")
                    continue
            
            # Always add common private networks if no networks found
            if not networks:
                logger.info("No networks found, adding default networks")
                default_networks = [
                    ('192.168.1.0/24', '192.168.1.1'),
                    ('192.168.0.0/24', '192.168.0.1'),
                    ('10.0.0.0/24', '10.0.0.1'),
                    ('172.16.0.0/24', '172.16.0.1')
                ]
                
                for net, ip in default_networks:
                    network = ipaddress.IPv4Network(net)
                    network_info = {
                        'network': str(network),
                        'interface': 'default',
                        'ip': ip,
                        'netmask': str(network.netmask)
                    }
                    networks.append(network_info)
                    logger.info(f"Added default network: {network_info}")
            
            logger.info(f"Final network list: {networks}")
            return networks
            
        except Exception as e:
            logger.error(f"Error in network discovery: {e}", exc_info=True)
            # Return at least one default network
            default_network = {
                'network': '192.168.1.0/24',
                'interface': 'default',
                'ip': '192.168.1.1',
                'netmask': '255.255.255.0'
            }
            logger.info(f"Returning default network due to error: {default_network}")
            return [default_network]

    @staticmethod
    def get_hostname(ip: str) -> str:
        """Get hostname for IP address"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return ip