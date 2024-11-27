import networkx as nx
import json

def analyze_network(topology):
    """Analyze network topology and return metrics"""
    metrics = {
        'centrality': nx.degree_centrality(topology),
        'betweenness': nx.betweenness_centrality(topology),
        'clustering': nx.clustering(topology)
    }
    return metrics

def compare_networks(topology1, topology2):
    """Compare two network topologies"""
    comparison = {
        'node_diff': topology2.number_of_nodes() - topology1.number_of_nodes(),
        'edge_diff': topology2.number_of_edges() - topology1.number_of_edges(),
        'density_diff': nx.density(topology2) - nx.density(topology1)
    }
    return comparison 