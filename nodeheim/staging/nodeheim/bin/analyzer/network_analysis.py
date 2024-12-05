import networkx as nx
import json
from typing import Dict, Any, List
from datetime import datetime

def analyze_network(topology: nx.Graph) -> Dict[str, Any]:
    """
    Comprehensive network topology analysis including security metrics
    
    Args:
        topology: NetworkX graph representing network topology
        
    Returns:
        Dictionary containing various network metrics and security insights
    """
    try:
        # Basic network metrics
        basic_metrics = {
            'total_nodes': topology.number_of_nodes(),
            'total_edges': topology.number_of_edges(),
            'density': nx.density(topology),
            'average_degree': sum(dict(topology.degree()).values()) / topology.number_of_nodes(),
            'is_connected': nx.is_connected(topology)
        }

        # Centrality metrics
        centrality_metrics = {
            'degree_centrality': nx.degree_centrality(topology),
            'betweenness_centrality': nx.betweenness_centrality(topology),
            'closeness_centrality': nx.closeness_centrality(topology),
            'eigenvector_centrality': nx.eigenvector_centrality(topology, max_iter=1000)
        }

        # Critical node identification
        critical_nodes = identify_critical_nodes(topology)

        # Security metrics
        security_metrics = analyze_security(topology)

        # Vulnerability assessment
        vulnerability_metrics = assess_vulnerabilities(topology)

        # Combine all metrics
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'basic_metrics': basic_metrics,
            'centrality_metrics': centrality_metrics,
            'critical_nodes': critical_nodes,
            'security_metrics': security_metrics,
            'vulnerability_metrics': vulnerability_metrics
        }

        return metrics

    except Exception as e:
        return {
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

def identify_critical_nodes(topology: nx.Graph) -> Dict[str, List[str]]:
    """Identify critical nodes in the network"""
    try:
        # Find articulation points (nodes that would disconnect the network if removed)
        articulation_points = list(nx.articulation_points(topology))
        
        # Find nodes with highest degree centrality
        degree_cent = nx.degree_centrality(topology)
        high_degree_nodes = sorted(degree_cent.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Find nodes with highest betweenness centrality
        between_cent = nx.betweenness_centrality(topology)
        critical_paths = sorted(between_cent.items(), key=lambda x: x[1], reverse=True)[:5]

        return {
            'articulation_points': [str(node) for node in articulation_points],
            'high_degree_nodes': [str(node) for node, _ in high_degree_nodes],
            'critical_path_nodes': [str(node) for node, _ in critical_paths]
        }
    except Exception as e:
        return {'error': str(e)}

def analyze_security(topology: nx.Graph) -> Dict[str, Any]:
    """Analyze network security metrics"""
    try:
        # Calculate network exposure metrics
        exposure_metrics = {
            'external_facing_nodes': sum(1 for node, data in topology.nodes(data=True) 
                                      if data.get('external_access', False)),
            'average_path_length': nx.average_shortest_path_length(topology) if nx.is_connected(topology) else float('inf'),
            'network_diameter': nx.diameter(topology) if nx.is_connected(topology) else float('inf')
        }

        # Analyze network segmentation
        communities = list(nx.community.greedy_modularity_communities(topology))
        segmentation_metrics = {
            'number_of_segments': len(communities),
            'segment_sizes': [len(c) for c in communities],
            'modularity_score': nx.community.modularity(topology, communities)
        }

        return {
            'exposure_metrics': exposure_metrics,
            'segmentation_metrics': segmentation_metrics
        }
    except Exception as e:
        return {'error': str(e)}

def assess_vulnerabilities(topology: nx.Graph) -> Dict[str, Any]:
    """Assess network vulnerabilities"""
    try:
        # Analyze node connectivity
        connectivity_metrics = {
            'min_node_connectivity': nx.node_connectivity(topology),
            'min_edge_connectivity': nx.edge_connectivity(topology),
            'average_clustering': nx.average_clustering(topology)
        }

        # Identify potential bottlenecks
        bottlenecks = {
            'high_load_nodes': [str(node) for node, cent in 
                              sorted(nx.load_centrality(topology).items(), 
                                    key=lambda x: x[1], reverse=True)[:3]]
        }

        # Assess redundancy
        redundancy_metrics = {
            'edge_redundancy': topology.number_of_edges() / topology.number_of_nodes(),
            'alternative_paths': analyze_path_redundancy(topology)
        }

        return {
            'connectivity_metrics': connectivity_metrics,
            'bottlenecks': bottlenecks,
            'redundancy_metrics': redundancy_metrics
        }
    except Exception as e:
        return {'error': str(e)}

def analyze_path_redundancy(topology: nx.Graph) -> Dict[str, Any]:
    """Analyze path redundancy between critical nodes"""
    try:
        # Get top 5 critical nodes
        critical_nodes = list(nx.degree_centrality(topology).keys())[:5]
        
        path_metrics = {}
        for i, source in enumerate(critical_nodes):
            for target in critical_nodes[i+1:]:
                try:
                    # Count number of edge-disjoint paths
                    num_paths = len(list(nx.edge_disjoint_paths(topology, source, target)))
                    path_metrics[f'{source}-{target}'] = num_paths
                except Exception:
                    continue

        return path_metrics
    except Exception as e:
        return {'error': str(e)}

def compare_networks(topology1: nx.Graph, topology2: nx.Graph) -> Dict[str, Any]:
    """
    Compare two network topologies and identify changes
    
    Args:
        topology1: First network topology (older)
        topology2: Second network topology (newer)
        
    Returns:
        Dictionary containing comparison metrics and changes
    """
    try:
        # Basic change metrics
        changes = {
            'nodes_added': len(set(topology2.nodes()) - set(topology1.nodes())),
            'nodes_removed': len(set(topology1.nodes()) - set(topology2.nodes())),
            'edges_added': len(set(topology2.edges()) - set(topology1.edges())),
            'edges_removed': len(set(topology1.edges()) - set(topology2.edges())),
            'density_change': nx.density(topology2) - nx.density(topology1)
        }

        # Compare security metrics
        security1 = analyze_security(topology1)
        security2 = analyze_security(topology2)
        
        # Compare vulnerability metrics
        vuln1 = assess_vulnerabilities(topology1)
        vuln2 = assess_vulnerabilities(topology2)

        return {
            'timestamp': datetime.now().isoformat(),
            'topology_changes': changes,
            'security_changes': {
                'old': security1,
                'new': security2
            },
            'vulnerability_changes': {
                'old': vuln1,
                'new': vuln2
            }
        }
    except Exception as e:
        return {
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        } 