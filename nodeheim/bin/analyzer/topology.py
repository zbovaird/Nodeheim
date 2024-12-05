import networkx as nx
import matplotlib.pyplot as plt
import json

def create_network_topology(data):
    G = nx.Graph()
    # Add nodes and edges based on data
    for node in data.get('nodes', []):
        G.add_node(node['id'], **node.get('attributes', {}))
    for edge in data.get('edges', []):
        G.add_edge(edge['source'], edge['target'], **edge.get('attributes', {}))
    return G

def analyze_topology(G):
    metrics = {
        'node_count': G.number_of_nodes(),
        'edge_count': G.number_of_edges(),
        'density': nx.density(G),
        'average_degree': sum(dict(G.degree()).values()) / G.number_of_nodes()
    }
    return metrics 