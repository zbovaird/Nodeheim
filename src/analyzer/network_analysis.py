# src/analyzer/network_analysis.py

# Standard library imports
import os
import json
import logging
import warnings
from datetime import datetime
from pathlib import Path
from collections import Counter, defaultdict
from itertools import combinations
from typing import Dict, List, Tuple

# Third-party imports
import numpy as np
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
import community
import matplotlib.colors as mcolors
import matplotlib.patches as mpatches

# Configure warnings
warnings.filterwarnings('ignore', category=FutureWarning)

# Configure logger
logger = logging.getLogger(__name__)

def create_network_from_scan(scan_data: Dict) -> nx.Graph:
    """Create a NetworkX graph from scan data"""
    G = nx.Graph()
    
    # Add nodes
    hosts = scan_data.get('hosts', [])
    for host in hosts:
        ip = host.get('ip_address')
        if ip:
            # Add node with host data
            G.add_node(ip, **{
                'status': host.get('status'),
                'os': host.get('os_info', {}).get('os_match', 'unknown'),
                'services': [s.get('name') for s in host.get('services', [])],
                'ports': [p.get('port') for p in host.get('ports', []) if p.get('state') == 'open']
            })
    
    # Infer connections based on network topology
    for host in hosts:
        source_ip = host.get('ip_address')
        if not source_ip:
            continue
            
        # Get open ports for this host
        source_ports = set(p.get('port') for p in host.get('ports', []) if p.get('state') == 'open')
        
        for other_host in hosts:
            target_ip = other_host.get('ip_address')
            if not target_ip or target_ip == source_ip:
                continue
                
            # Check for potential connections based on open ports
            target_ports = set(p.get('port') for p in other_host.get('ports', []) if p.get('state') == 'open')
            
            # Common services that indicate connections
            common_ports = source_ports.intersection(target_ports)
            if common_ports:
                G.add_edge(source_ip, target_ip, ports=list(common_ports))
            
            # Check for client-server relationships
            for port in target_ports:
                if port in [80, 443, 22, 21, 3389, 445, 139]:  # Common server ports
                    G.add_edge(source_ip, target_ip, service=f'port_{port}')
    
    return G

def calculate_network_metrics(G: nx.Graph) -> Dict:
    """Calculate comprehensive network metrics"""
    try:
        metrics = {}
        
        # Basic metrics
        n_nodes = G.number_of_nodes()
        n_edges = G.number_of_edges()
        
        if n_nodes < 2:
            return {
                'Average_Clustering': 0.0,
                'Network_Density': 0.0,
                'Average_Degree': 0.0,
                'Components': 1
            }
        
        # Calculate clustering coefficient
        metrics['Average_Clustering'] = nx.average_clustering(G)
        
        # Calculate network density
        metrics['Network_Density'] = (2.0 * n_edges) / (n_nodes * (n_nodes - 1))
        
        # Calculate average degree
        metrics['Average_Degree'] = (2.0 * n_edges) / n_nodes
        
        # Count connected components
        metrics['Components'] = nx.number_connected_components(G)
        
        # Additional metrics for connected graphs
        if nx.is_connected(G):
            metrics['Average_Path_Length'] = nx.average_shortest_path_length(G)
            metrics['Network_Diameter'] = nx.diameter(G)
            
            # Spectral metrics
            L = nx.laplacian_matrix(G).todense()
            eigvals = np.linalg.eigvalsh(L)
            metrics['Fiedler_Eigenvalue'] = eigvals[1] if len(eigvals) > 1 else 0
            
            A = nx.adjacency_matrix(G).todense()
            eigvals_A = np.linalg.eigvals(A)
            metrics['Spectral_Radius'] = np.max(np.abs(eigvals_A))
        
        # Community detection
        try:
            communities = community.best_partition(G)
            metrics['Number_of_Communities'] = len(set(communities.values()))
        except:
            metrics['Number_of_Communities'] = 1
        
        return metrics
        
    except Exception as e:
        logger.error(f"Error calculating network metrics: {str(e)}")
        return {
            'Average_Clustering': 0.0,
            'Network_Density': 0.0,
            'Average_Degree': 0.0,
            'Components': 0
        }

def analyze_changes(G1: nx.Graph, G2: nx.Graph) -> Dict:
    """Analyze structural changes between two network snapshots"""
    changes = {
        'New_Nodes': len(set(G2.nodes()) - set(G1.nodes())),
        'Removed_Nodes': len(set(G1.nodes()) - set(G2.nodes())),
        'New_Edges': len(set(G2.edges()) - set(G1.edges())),
        'Removed_Edges': len(set(G1.edges()) - set(G2.edges()))
    }
    
    # Calculate degree distribution changes
    degrees1 = Counter(dict(G1.degree()).values())
    degrees2 = Counter(dict(G2.degree()).values())
    changes['Degree_Distribution_Change'] = sum((degrees2 - degrees1).values())
    
    return changes

def identify_critical_paths(G: nx.Graph) -> Dict:
    """Identify critical paths between high-centrality nodes"""
    betweenness = nx.betweenness_centrality(G)
    threshold = np.percentile(list(betweenness.values()), 90)
    critical_nodes = [n for n, c in betweenness.items() if c >= threshold]
    
    critical_paths = {}
    for source in critical_nodes:
        for target in critical_nodes:
            if source != target:
                try:
                    path = nx.shortest_path(G, source, target)
                    if len(path) > 2:  # Only paths with intermediate nodes
                        critical_paths[f"{source}->{target}"] = path
                except nx.NetworkXNoPath:
                    continue
    return critical_paths

def identify_bridge_nodes(G: nx.Graph) -> List:
    """Find nodes that would fragment the network if removed"""
    bridges = []
    for node in G.nodes():
        G_temp = G.copy()
        G_temp.remove_node(node)
        original_components = nx.number_connected_components(G)
        new_components = nx.number_connected_components(G_temp)
        if new_components > original_components:
            bridges.append((node, new_components - original_components))
    return sorted(bridges, key=lambda x: x[1], reverse=True)

def calculate_network_segmentation(G: nx.Graph) -> Dict:
    """Analyze network segmentation and containment boundaries"""
    try:
        # Detect communities
        communities = community.best_partition(G)
        modularity = community.modularity(communities, G)
        
        # Count nodes in each segment
        segment_sizes = Counter(communities.values())
        
        # Count edges between segments
        cross_segment_edges = sum(1 for u, v in G.edges() 
                                    if communities[u] != communities[v])
        
        # Calculate isolation score
        total_edges = G.number_of_edges()
        isolation_score = 1 - (cross_segment_edges / total_edges) if total_edges > 0 else 0
        
        return {
            'num_segments': len(set(communities.values())),
            'modularity': modularity,
            'segment_sizes': segment_sizes,
            'cross_segment_edges': cross_segment_edges,
            'isolation_score': isolation_score,
            'communities': communities
        }
    except Exception as e:
        logger.error(f"Error calculating network segmentation: {str(e)}")
        return {
            'num_segments': 0,
            'modularity': 0,
            'segment_sizes': Counter(),
            'cross_segment_edges': 0,
            'isolation_score': 0,
            'communities': {}
        }

# Export all functions
__all__ = [
    'create_network_from_scan',
    'calculate_network_metrics',
    'analyze_changes',
    'identify_critical_paths',
    'identify_bridge_nodes',
    'calculate_network_segmentation'
]