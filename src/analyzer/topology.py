# src/analyzer/topology.py
import os
import json
import logging
import networkx as nx
import matplotlib.pyplot as plt
from datetime import datetime
from typing import Dict, Any

__all__ = ['TopologyAnalyzer', 'updateTopologyVisualization']

logger = logging.getLogger(__name__)

class TopologyAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def analyze_topology(self, scan_data: Dict) -> Dict[str, Any]:
        """Analyze network topology from scan data"""
        try:
            # Create graph
            G = nx.Graph()
            
            # Add nodes
            for host in scan_data.get('hosts', []):
                G.add_node(
                    host.get('ip_address'),
                    **{
                        'type': host.get('device_type', 'unknown'),
                        'services': host.get('services', []),
                        'os': host.get('os_info', {}).get('os_match', 'unknown')
                    }
                )
            
            # Add edges based on subnet relationships
            nodes = list(G.nodes())
            for i, node1 in enumerate(nodes):
                for node2 in nodes[i+1:]:
                    # If nodes are in same subnet, add edge
                    if node1.split('.')[:3] == node2.split('.')[:3]:
                        G.add_edge(node1, node2)
            
            return {
                'node_count': G.number_of_nodes(),
                'edge_count': G.number_of_edges(),
                'density': nx.density(G),
                'average_degree': sum(dict(G.degree()).values()) / G.number_of_nodes() if G.number_of_nodes() > 0 else 0
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing topology: {e}")
            return {}

def updateTopologyVisualization(scan_data: Dict, base_dir: str) -> bool:
    """Update network topology visualization"""
    try:
        logger.info("Starting topology visualization update")
        
        # Create topology data structure
        topology_data = {
            'nodes': [],
            'links': []
        }

        # Process hosts into nodes
        for host in scan_data.get('hosts', []):
            # Ensure we have an ip_address
            ip_address = host.get('ip_address', host.get('ip', None))
            if not ip_address:
                logger.warning(f"Host missing IP address: {host}")
                continue
                
            node = {
                'id': ip_address,
                'type': host.get('device_type', 'unknown'),
                'services': host.get('services', []),
                'os': host.get('os_info', {}).get('os_match', 'unknown'),
                'ports': [p for p in host.get('ports', []) if p.get('state') == 'open']
            }
            topology_data['nodes'].append(node)

        # Create links based on network relationships
        processed_links = set()
        for host in scan_data.get('hosts', []):
            source = host.get('ip_address', host.get('ip', None))
            if not source:
                continue
                
            # Add subnet-based connections
            source_parts = source.split('.')
            for other_host in scan_data.get('hosts', []):
                target = other_host.get('ip_address', other_host.get('ip', None))
                if not target or source == target:
                    continue
                    
                target_parts = target.split('.')
                if source_parts[:3] == target_parts[:3]:  # Same /24 subnet
                    link_id = tuple(sorted([source, target]))
                    if link_id not in processed_links:
                        topology_data['links'].append({
                            'source': source,
                            'target': target,
                            'type': 'subnet'
                        })
                        processed_links.add(link_id)

        # Save topology data
        topology_dir = os.path.join(base_dir, 'src', 'data', 'topology')
        os.makedirs(topology_dir, exist_ok=True)
        
        topology_file = os.path.join(
            topology_dir, 
            f"topology_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        with open(topology_file, 'w') as f:
            json.dump(topology_data, f, indent=2)
            
        logger.info(f"Saved topology data to {topology_file}")
        logger.info(f"Generated topology with {len(topology_data['nodes'])} nodes and {len(topology_data['links'])} links")
        
        return True
        
    except Exception as e:
        logger.error(f"Error updating topology visualization: {e}")
        return False