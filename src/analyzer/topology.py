# src/analyzer/topology.py
import networkx as nx
from typing import Dict, List, Any
import json
import ipaddress

class TopologyAnalyzer:
    def __init__(self):
        self.G = nx.Graph()

    def create_network_graph(self, scan_result) -> Dict[str, Any]:
        """Convert scan results into a format compatible with Vis.js"""
        self.G.clear()
        nodes = []
        edges = []
        
        # First, identify the router/gateway
        network_ips = [host['ip_address'] for host in scan_result.hosts if host.get('status') == 'up']
        gateway_ip = self._find_gateway_ip(network_ips)
        
        # Add nodes (hosts)
        for host in scan_result.hosts:
            if host.get('status') == 'up':
                ip = host['ip_address']
                
                # Get hostname - handle different possible formats
                hostname = None
                if isinstance(host.get('hostname'), str):
                    hostname = host['hostname']
                elif isinstance(host.get('hostnames'), list) and host['hostnames']:
                    hostname = host['hostnames'][0].get('name') if isinstance(host['hostnames'][0], dict) else host['hostnames'][0]
                
                # Format label to show both hostname and IP
                if hostname and hostname.strip():
                    label = f"{hostname}\n{ip}"
                    display_name = hostname
                else:
                    label = ip
                    display_name = ip

                host_services = [
                    service for service in scan_result.services 
                    if service.get('ip_address') == ip
                ]
                
                host_vulns = [
                    vuln for vuln in scan_result.vulnerabilities 
                    if vuln.get('ip_address') == ip
                ]
                
                # Determine node type
                is_gateway = ip == gateway_ip
                node_type = 'gateway' if is_gateway else 'host'
                
                # Calculate risk and size
                risk_level = self._calculate_risk_level(len(host_vulns), len(host_services))
                node_size = 30 if is_gateway else (20 + len(host_services))
                
                # Create node with enhanced properties
                node_data = {
                    'id': ip,
                    'label': label,
                    'title': self._generate_tooltip(
                        ip,
                        display_name,
                        host_services,
                        len(host_vulns),
                        node_type
                    ),
                    'color': self._get_risk_color(risk_level, is_gateway),
                    'value': node_size,
                    'shape': 'diamond' if is_gateway else 'dot',
                    'font': {
                        'multi': 'md',
                        'size': 14,
                        'color': '#ffffff',
                        'strokeWidth': 2,
                        'strokeColor': '#000000',
                        'align': 'center'
                    },
                    'services': len(host_services),
                    'vulnerabilities': len(host_vulns),
                    'type': node_type
                }
                
                if is_gateway:
                    node_data['fixed'] = True
                    node_data['physics'] = False
                
                nodes.append(node_data)
                
                # Add to NetworkX graph
                self.G.add_node(
                    ip,
                    type=node_type,
                    hostname=display_name,
                    services=host_services,
                    vulnerabilities=len(host_vulns)
                )

        # Add edges with enhanced logic
        for host in scan_result.hosts:
            if host.get('status') != 'up':
                continue
                
            source_ip = host['ip_address']
            
            # Always connect to gateway if it exists
            if gateway_ip and source_ip != gateway_ip:
                edges.append({
                    'from': source_ip,
                    'to': gateway_ip,
                    'width': 2,
                    'length': 200,  # Fixed length for better layout
                    'title': 'Network Connection',
                    'color': {'opacity': 0.5},
                    'arrows': {
                        'to': {
                            'enabled': True,
                            'scaleFactor': 0.5
                        }
                    },
                    'smooth': {'type': 'curvedCW', 'roundness': 0.2}
                })
                self.G.add_edge(source_ip, gateway_ip, type='network')
            
            # Add direct connections based on services
            for target_host in scan_result.hosts:
                if (target_host.get('status') != 'up' or 
                    target_host['ip_address'] == source_ip):
                    continue
                    
                target_ip = target_host['ip_address']
                
                # Skip if this would be a duplicate gateway connection
                if gateway_ip and (source_ip == gateway_ip or target_ip == gateway_ip):
                    continue
                
                # Check for service-based connections
                source_services = {
                    s['name'] for s in scan_result.services 
                    if s.get('ip_address') == source_ip
                }
                target_services = {
                    s['name'] for s in scan_result.services 
                    if s.get('ip_address') == target_ip
                }
                
                common_services = source_services & target_services
                if common_services:
                    edges.append({
                        'from': source_ip,
                        'to': target_ip,
                        'width': 1 + len(common_services),
                        'length': 250,  # Slightly longer for service connections
                        'title': f"Common services: {', '.join(common_services)}",
                        'color': {'opacity': 0.3},
                        'dashes': [5, 5],
                        'arrows': {'to': {'enabled': True, 'scaleFactor': 0.3}}
                    })
                    self.G.add_edge(
                        source_ip,
                        target_ip,
                        type='service',
                        services=list(common_services)
                    )

        # Calculate network statistics
        stats = {
            'total_nodes': self.G.number_of_nodes(),
            'total_edges': self.G.number_of_edges(),
            'density': nx.density(self.G),
            'avg_degree': (sum(dict(self.G.degree()).values()) / 
                         self.G.number_of_nodes() if self.G.number_of_nodes() > 0 else 0)
        }

        # Also return vis.js physics options for better layout
        options = {
            'physics': {
                'enabled': True,
                'barnesHut': {
                    'gravitationalConstant': -3000,
                    'centralGravity': 0.3,
                    'springLength': 200,
                    'springConstant': 0.04,
                    'damping': 0.09,
                    'avoidOverlap': 0.1
                },
                'minVelocity': 0.75,
                'stabilization': {
                    'enabled': True,
                    'iterations': 1000,
                    'updateInterval': 25
                }
            }
        }

        return {
            'nodes': nodes,
            'edges': edges,
            'stats': stats,
            'options': options
        }

    def _find_gateway_ip(self, ips: List[str]) -> str:
        """Attempt to identify the gateway IP"""
        # Common gateway patterns
        gateway_patterns = ['.1', '.254']  # Common last octets for gateways
        
        if not ips:
            return None
            
        # Try to find a gateway IP
        for ip in ips:
            last_octet = ip.split('.')[-1]
            if last_octet in ['1', '254']:
                return ip
                
        # If no gateway found, return None
        return None

    def _calculate_risk_level(self, vuln_count: int, service_count: int) -> float:
        """Calculate risk level based on vulnerabilities and services"""
        risk = 0.0
        risk += min(vuln_count * 0.3, 0.6)  # Up to 60% from vulnerabilities
        risk += min(service_count * 0.1, 0.4)  # Up to 40% from services
        return min(risk, 1.0)

    def _get_risk_color(self, risk_level: float, is_gateway: bool = False) -> Dict[str, str]:
        """Get color configuration for Vis.js node based on risk level"""
        if is_gateway:
            return {
                'background': '#4a90e2',
                'border': '#357abd',
                'highlight': {'background': '#5d9fee', 'border': '#4a90e2'}
            }
        elif risk_level >= 0.7:
            return {
                'background': '#dc3545',
                'border': '#b02a37',
                'highlight': {'background': '#ef4655', 'border': '#dc3545'}
            }
        elif risk_level >= 0.4:
            return {
                'background': '#ffc107',
                'border': '#d39e00',
                'highlight': {'background': '#ffcd39', 'border': '#ffc107'}
            }
        else:
            return {
                'background': '#28a745',
                'border': '#208637',
                'highlight': {'background': '#34ce57', 'border': '#28a745'}
            }

    def _generate_tooltip(self, ip: str, hostname: str, services: List[Dict], 
                         vuln_count: int, node_type: str) -> str:
        """Generate HTML tooltip for node"""
        service_names = [s.get('name', 'unknown') for s in services]
        node_type_display = 'Gateway' if node_type == 'gateway' else 'Host'
        
        return f"""
            <div style='padding:10px; max-width:300px;'>
                <div style='font-weight:bold; margin-bottom:5px;'>{node_type_display}</div>
                <strong>IP:</strong> {ip}<br>
                {f"<strong>Hostname:</strong> {hostname}<br>" if hostname else ""}
                <strong>Services:</strong> {len(services)}<br>
                {f"<strong>Open Services:</strong> {', '.join(service_names)}<br>" if service_names else ""}
                <strong>Vulnerabilities:</strong> {vuln_count}
            </div>
        """.strip()