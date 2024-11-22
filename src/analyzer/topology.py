# src/analyzer/topology.py
import os
import logging
import networkx as nx
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from datetime import datetime
from typing import Dict, Any, List
import community.community_louvain as community
import json

logger = logging.getLogger(__name__)

class TopologyAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.graph = None
        
    def create_graph_from_scan(self, scan_data: Dict) -> nx.Graph:
        """Create NetworkX graph from scan data"""
        self.graph = create_network_from_scan(scan_data)
        return self.graph
        
    def analyze_topology(self, scan_data: Dict) -> Dict[str, Any]:
        """Analyze network topology"""
        try:
            if not self.graph:
                self.graph = self.create_graph_from_scan(scan_data)
            
            # Convert connected components from sets to lists
            connected_components = [list(comp) for comp in nx.connected_components(self.graph)]
            
            # Calculate centrality measures
            centrality = {
                'degree': dict(nx.degree_centrality(self.graph)),
                'betweenness': dict(nx.betweenness_centrality(self.graph)),
                'closeness': dict(nx.closeness_centrality(self.graph))
            }
            
            # Get communities
            communities = self.detect_communities()
            if 'communities' in communities:
                # Convert community dictionary values to strings (they might be non-serializable)
                communities['communities'] = {str(k): v for k, v in communities['communities'].items()}
            
            analysis = {
                'node_count': self.graph.number_of_nodes(),
                'edge_count': self.graph.number_of_edges(),
                'density': float(nx.density(self.graph)),  # Ensure float
                'average_degree': float(sum(dict(self.graph.degree()).values()) / self.graph.number_of_nodes()),
                'connected_components': connected_components,  # Now a list of lists
                'centrality': centrality,  # All values are now regular dictionaries
                'communities': communities,
                'critical_nodes': self.identify_critical_nodes()  # Already returns a list
            }
            
            # Ensure all values are JSON serializable
            return self._ensure_serializable(analysis)
            
        except Exception as e:
            self.logger.error(f"Error in topology analysis: {str(e)}")
            return {
                'error': str(e),
                'node_count': 0,
                'edge_count': 0,
                'density': 0.0,
                'average_degree': 0.0,
                'connected_components': [],
                'centrality': {},
                'communities': {},
                'critical_nodes': []
            }

    def _ensure_serializable(self, obj):
        """Recursively convert all values to JSON serializable types"""
        if isinstance(obj, dict):
            return {str(k): self._ensure_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple, set)):
            return [self._ensure_serializable(item) for item in obj]
        elif isinstance(obj, (int, float, str, bool, type(None))):
            return obj
        else:
            return str(obj)  # Convert any other types to strings
        
    def detect_communities(self) -> Dict[str, Any]:
        """Detect network communities"""
        if not self.graph:
            return {}
            
        communities = community.best_partition(self.graph)
        modularity = community.modularity(communities, self.graph)
        
        return {
            'communities': communities,
            'modularity': modularity,
            'count': len(set(communities.values()))
        }
        
    def identify_critical_nodes(self) -> List[str]:
        """Identify critical nodes in the network"""
        if not self.graph:
            return []
            
        betweenness = nx.betweenness_centrality(self.graph)
        degree = nx.degree_centrality(self.graph)
        
        critical_nodes = []
        for node in self.graph.nodes():
            if betweenness[node] > 0.5 or degree[node] > 0.5:
                critical_nodes.append(node)
                
        return critical_nodes
        
    def visualize_topology(self, output_path: str) -> bool:
        """Generate topology visualization"""
        if not self.graph:
            return False
            
        try:
            plt.figure(figsize=(12, 8))
            pos = nx.spring_layout(self.graph, k=1, iterations=50)
            
            # Draw nodes
            nx.draw_networkx_nodes(self.graph, pos,
                                 node_color='lightblue',
                                 node_size=500,
                                 alpha=0.7)
            
            # Draw edges
            nx.draw_networkx_edges(self.graph, pos,
                                 edge_color='gray',
                                 alpha=0.5)
            
            # Add labels
            labels = {node: node for node in self.graph.nodes()}
            nx.draw_networkx_labels(self.graph, pos,
                                  labels=labels,
                                  font_size=8,
                                  font_weight='bold')
            
            plt.title("Network Topology", pad=20)
            plt.savefig(output_path, bbox_inches='tight')
            plt.close()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error visualizing topology: {e}")
            return False

# Keep the existing functions
def create_network_from_scan(scan_data: Dict) -> nx.Graph:
    """Convert scan data to NetworkX graph"""
    G = nx.Graph()
    
    # Add nodes first
    for host in scan_data.get('hosts', []):
        G.add_node(host['ip_address'], **{
            'type': host.get('device_type', 'unknown'),
            'services': host.get('services', []),
            'os': host.get('os_info', {}).get('os_match', 'unknown')
        })
    
    # Add edges based on various connection types
    for host in scan_data.get('hosts', []):
        source_ip = host['ip_address']
        
        # 1. Direct connections from scan data
        if 'connections' in host:
            for target_ip in host['connections']:
                if target_ip in G.nodes():
                    G.add_edge(source_ip, target_ip)
        
        # 2. Subnet-based connections
        ip_parts = source_ip.split('.')
        for other_host in scan_data.get('hosts', []):
            other_ip = other_host['ip_address']
            if other_ip != source_ip:
                other_parts = other_ip.split('.')
                # Same /24 subnet
                if ip_parts[:3] == other_parts[:3]:
                    G.add_edge(source_ip, other_ip)
    
    return G

def updateTopologyVisualization(scan_data: Dict[str, Any], base_dir: str) -> bool:
    """Update network topology visualization based on scan data"""
    try:
        # Create network graph from scan data
        G = nx.Graph()
        
        # Add nodes with simplified data
        for host in scan_data.get('hosts', []):
            if host.get('status') == 'up':
                G.add_node(host['ip_address'], 
                          type='host',  # Simplified type
                          status='up')   # Add status
        
        # Add edges based on subnet relationships
        nodes = list(G.nodes())
        for i in range(len(nodes)):
            for j in range(i + 1, len(nodes)):
                ip1_parts = nodes[i].split('.')
                ip2_parts = nodes[j].split('.')
                if ip1_parts[:3] == ip2_parts[:3]:  # Same /24 subnet
                    G.add_edge(nodes[i], nodes[j])
        
        # Save topology data as JSON with simplified format
        topology_data = {
            'nodes': [{
                'id': node,
                'type': 'host',
                'status': 'up'
            } for node in G.nodes()],
            'edges': []  # Keep edges empty for now
        }
        
        output_dir = os.path.join(base_dir, 'src', 'data', 'topology')
        os.makedirs(output_dir, exist_ok=True)
        
        # Save JSON data with scan-specific filename
        subnet = scan_data.get('subnet', '').replace('/', '_')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        scan_type = scan_data.get('scan_type', 'scan')
        json_path = os.path.join(output_dir, f"{subnet}_{timestamp}_{scan_type}_topology.json")
        
        with open(json_path, 'w') as f:
            json.dump(topology_data, f, indent=2)
        
        # Generate visualization
        plt.figure(figsize=(15, 10))
        pos = nx.spring_layout(G, k=2, iterations=50)
        
        # Draw nodes with simple coloring
        nx.draw_networkx_nodes(G, pos,
                             node_color='lightblue',
                             node_size=800,
                             alpha=0.7)
        
        nx.draw_networkx_edges(G, pos,
                             edge_color='gray',
                             alpha=0.5,
                             width=2)
        
        # Add simple labels
        labels = {node: node for node in G.nodes()}
        nx.draw_networkx_labels(G, pos,
                              labels=labels,
                              font_size=8,
                              font_weight='bold',
                              font_color='black')
        
        plt.title("Network Topology", pad=20)
        
        # Save PNG with same naming convention
        png_path = os.path.join(output_dir, f"{subnet}_{timestamp}_{scan_type}_topology.png")
        plt.savefig(png_path, bbox_inches='tight', dpi=300)
        plt.close()
        
        logger.info(f"Updated topology visualization saved to {png_path}")
        logger.info(f"Topology data saved to {json_path}")
        return True
        
    except Exception as e:
        logger.error(f"Error updating topology visualization: {str(e)}")
        return False