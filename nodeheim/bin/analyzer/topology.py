import networkx as nx
import json

def create_network_topology(scan_results):
    """Create a network topology from scan results."""
    G = nx.Graph()
    
    for result in scan_results:
        ip = result.get('ip_address')
        if ip:
            G.add_node(ip, **result)
    
    # Add edges between nodes that can communicate
    nodes = list(G.nodes())
    for i in range(len(nodes)):
        for j in range(i + 1, len(nodes)):
            G.add_edge(nodes[i], nodes[j])
    
    # Convert to JSON-serializable format
    topology = {
        'nodes': [{'id': n, 'data': G.nodes[n]} for n in G.nodes()],
        'edges': [{'source': u, 'target': v} for (u, v) in G.edges()]
    }
    
    return topology

def analyze_topology(G):
    metrics = {
        'node_count': G.number_of_nodes(),
        'edge_count': G.number_of_edges(),
        'density': nx.density(G),
        'average_degree': sum(dict(G.degree()).values()) / G.number_of_nodes()
    }
    return metrics 