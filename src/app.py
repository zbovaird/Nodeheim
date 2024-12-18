# src/app.py
from flask import Flask, render_template, jsonify, request, send_file, make_response, Response, send_from_directory
import sys
import os
import json
import logging
import netifaces  # Add this import
import platform  # Add this import
from typing import Dict, Any
from datetime import datetime
from uuid import uuid4
import networkx as nx
import inspect
import base64
from io import BytesIO
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from typing import Dict, List
from collections import Counter, defaultdict
import os.path
import community  # For community detection
import pandas as pd
import seaborn as sns
from threading import Thread, Lock  # Add Lock to the import
import subprocess
import ctypes
import socket
import ipaddress

# Add these imports at the top with the other imports
import uuid
from threading import Thread

# Add this import at the top with the other imports
from analyzer.topology import TopologyAnalyzer, updateTopologyVisualization  # Add updateTopologyVisualization to import

# Add this after the imports and before the logging configuration
SECURITY_ZONES = {
    'DMZ': {'level': 1, 'allowed_services': ['http', 'https', 'smtp']},
    'INTERNAL': {'level': 2, 'allowed_services': ['ldap', 'dns', 'sql']},
    'PRODUCTION': {'level': 3, 'allowed_services': ['scada', 'modbus', 'dnp3']},
    'MANAGEMENT': {'level': 4, 'allowed_services': ['ssh', 'rdp', 'snmp']},
    'CRITICAL': {'level': 5, 'allowed_services': ['proprietary', 'control']}
}

# Configure logging first
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('src/data/logs/app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Add the project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

# Set up base directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
logger.info(f"Base directory set to: {BASE_DIR}")

# Local imports
from scanner.scanner import NetworkScanner, ScanResult
from scanner.network_discovery import NetworkDiscovery
from analyzer.network_analysis import (
    create_network_from_scan,
    calculate_network_metrics,
    analyze_changes,
    identify_critical_paths,
    identify_bridge_nodes,
    calculate_network_segmentation
)
from analyzer.visualization import (
    visualize_network_overview,
    visualize_critical_infrastructure,
    visualize_node_metrics_heatmap,
    create_markdown_report
)
from api.analysis import analysis_bp
from scanner.vulnerability_checker import BatchVulnerabilityChecker

# Initialize Flask app
app = Flask(__name__, static_url_path='/static')   

# Register the blueprint
app.register_blueprint(analysis_bp)

# Initialize scanner and output directories
try:
    data_dir = os.path.join(BASE_DIR, 'src', 'data')
    analysis_dir = os.path.join(data_dir, 'analysis')
    os.makedirs(analysis_dir, exist_ok=True)
    
    scanner = NetworkScanner(output_dir=data_dir)
    test_result = scanner.test_scanner()
    if test_result['status'] != 'operational':
        raise Exception(f"Scanner initialization failed: {test_result}")
    logger.info("Scanner initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize scanner: {str(e)}")
    raise

# Add after the imports and before app initialization
scan_statuses = {}

# Initialize vulnerability checker
vuln_checker = BatchVulnerabilityChecker()

# Add these global variables after the other globals
scan_locks: Dict[str, Lock] = {}
active_scans: Dict[str, Any] = {}

# Initialize the topology analyzer with other initializations
topology_analyzer = TopologyAnalyzer()

def process_scan_results(results: ScanResult, scan_id: str):
    """Process and save scan results"""
    try:
        # Create scans directory if it doesn't exist
        scans_dir = os.path.join(BASE_DIR, 'src', 'data', 'scans')
        os.makedirs(scans_dir, exist_ok=True)

        # Get subnet from first host's IP address
        subnet = '0.0.0.0'
        if results.hosts:
            first_host = results.hosts[0].get('ip_address', '')
            if first_host:
                subnet_parts = first_host.split('.')
                if len(subnet_parts) == 4:
                    subnet = f"{'.'.join(subnet_parts[:3])}.0/24"

        # Format timestamp consistently
        timestamp = datetime.now()
        timestamp_str = timestamp.strftime('%Y%m%d_%H%M%S')
        
        # Format results for saving
        formatted_results = {
            'scan_id': scan_id,
            'timestamp': timestamp.isoformat(),  # ISO format for the actual timestamp
            'scan_type': results.scan_type,
            'subnet': subnet,
            'hosts': results.hosts,
            'ports': results.ports,
            'services': results.services,
            'vulnerabilities': results.vulnerabilities,
            'os_matches': results.os_matches,
            'scan_stats': results.scan_stats,
            'summary': {
                'total_hosts': len(results.hosts),
                'active_hosts': len([h for h in results.hosts if h.get('status') == 'up']),
                'total_ports': len(results.ports),
                'total_services': len(results.services),
                'total_vulnerabilities': len(results.vulnerabilities)
            }
        }
        
        # Sanitize subnet for filename (replace / with _)
        safe_subnet = subnet.replace('/', '_')
        
        # Save with consistent naming format: subnet_timestamp_scanid.json
        scan_file = os.path.join(scans_dir, f'{safe_subnet}_{timestamp_str}_{scan_id}.json')
        with open(scan_file, 'w') as f:
            json.dump(formatted_results, f, indent=2)
            
        logger.info(f"Scan results saved to {scan_file}")
        
        try:
            # Run network analysis
            analysis_results = topology_analyzer.analyze_topology(formatted_results)
            
            # Save analysis results
            analysis_file = os.path.join(scans_dir, f'{scan_id}_analysis.json')
            with open(analysis_file, 'w') as f:
                json.dump(analysis_results, f, indent=2)
            
            # Update topology visualization
            updateTopologyVisualization(formatted_results, BASE_DIR)
            
            # Update scan status with analysis results
            formatted_results['network_analysis'] = analysis_results
            
            # Update scan status
            scan_statuses[scan_id].update({
                'status': 'completed',
                'progress': 100,
                'end_time': datetime.now().isoformat(),
                'summary': formatted_results['summary']
            })
            
        except Exception as analysis_error:
            logger.error(f"Error in network analysis: {str(analysis_error)}")
            scan_statuses[scan_id].update({
                'status': 'failed',
                'error': str(analysis_error)
            })
            
    except Exception as e:
        logger.error(f"Error processing scan results: {str(e)}", exc_info=True)
        scan_statuses[scan_id].update({
            'status': 'failed',
            'error': str(e)
        })

def visualize_network_overview(G1: nx.Graph, G2: nx.Graph, output_folder: str) -> bool:
    """Generate network overview visualization"""
    try:
        plt.style.use('dark_background')
        
        # Generate "before" network visualization
        plt.figure(figsize=(10, 8))
        pos1 = nx.spring_layout(G1, k=1, iterations=50)
        nx.draw(G1, pos1, 
               node_size=500,
               node_color='lightblue',
               edge_color='gray',
               alpha=0.6,
               with_labels=True,
               font_size=8,
               font_color='white',
               font_weight='bold')
        plt.title('Network Before', color='white', pad=20)
        before_path = os.path.join(output_folder, 'network_overview_before.png')
        plt.savefig(before_path, bbox_inches='tight', facecolor='#1a1a1a')
        plt.close()
        
        # Generate "after" network visualization with highlighted new connections
        plt.figure(figsize=(10, 8))
        pos2 = nx.spring_layout(G2, k=1, iterations=50)
        
        # Draw existing edges first
        existing_edges = set(G1.edges())
        new_edges = set(G2.edges()) - existing_edges
        
        # Draw old edges in gray
        nx.draw_networkx_edges(G2, pos2,
                             edgelist=[e for e in G2.edges() if e in existing_edges],
                             edge_color='gray',
                             alpha=0.6)
        
        # Draw new edges in red
        nx.draw_networkx_edges(G2, pos2,
                             edgelist=[e for e in G2.edges() if e in new_edges],
                             edge_color='red',
                             alpha=0.8,
                             width=2)
        
        # Draw nodes
        nx.draw_networkx_nodes(G2, pos2,
                             node_size=500,
                             node_color='lightgreen',
                             alpha=0.6)
        
        # Add labels
        nx.draw_networkx_labels(G2, pos2,
                              font_size=8,
                              font_color='white',
                              font_weight='bold')
        
        plt.title('Network After (New Connections in Red)', color='white', pad=20)
        after_path = os.path.join(output_folder, 'network_overview_after.png')
        plt.savefig(after_path, bbox_inches='tight', facecolor='#1a1a1a')
        plt.close()

        return True
    except Exception as e:
        logger.error(f"Error in visualize_network_overview: {str(e)}")
        return False

def identify_bridge_nodes(G: nx.Graph) -> List:
    """Find nodes that would fragment the network if removed"""
    try:
        bridges = []
        for node in G.nodes():
            G_temp = G.copy()
            G_temp.remove_node(node)
            original_components = nx.number_connected_components(G)
            new_components = nx.number_connected_components(G_temp)
            if new_components > original_components:
                bridges.append((node, new_components - original_components))
        return sorted(bridges, key=lambda x: x[1], reverse=True)
    except Exception as e:
        logger.error(f"Error in identify_bridge_nodes: {str(e)}")
        return []

def identify_critical_paths(G: nx.Graph) -> Dict:
    """Identify critical paths between high-centrality nodes"""
    try:
        betweenness = nx.betweenness_centrality(G)
        threshold = np.percentile(list(betweenness.values()), 90) if betweenness else 0
        critical_nodes = [n for n, c in betweenness.items() if c >= threshold]
        
        critical_paths = {}
        for source in critical_nodes:
            for target in critical_nodes:
                if source != target:
                    try:
                        path = nx.shortest_path(G, source, target)
                        if len(path) > 2:
                            critical_paths[f"{source}->{target}"] = path
                    except nx.NetworkXNoPath:
                        continue
        return critical_paths
    except Exception as e:
        logger.error(f"Error in identify_critical_paths: {str(e)}")
        return {}

def visualize_critical_infrastructure(G: nx.Graph, bridge_nodes: List, 
                                    critical_paths: Dict, output_folder: str) -> bool:
    """Visualize critical infrastructure components"""
    try:
        plt.style.use('dark_background')
        plt.figure(figsize=(15, 10))
        
        pos = nx.spring_layout(G, k=1, iterations=50)
        
        # Draw base network
        nx.draw_networkx_edges(G, pos, alpha=0.2, edge_color='gray')
        
        # Highlight bridge nodes
        bridge_nodes_set = {node for node, _ in bridge_nodes}
        node_colors = ['red' if node in bridge_nodes_set else 'lightblue' 
                    for node in G.nodes()]
        node_sizes = [1000 if node in bridge_nodes_set else 300 
                    for node in G.nodes()]
        
        nx.draw_networkx_nodes(G, pos, 
                             node_color=node_colors,
                             node_size=node_sizes)
        
        # Add labels
        nx.draw_networkx_labels(G, pos, 
                              font_size=8,
                              font_color='white',
                              font_weight='bold')
        
        # Highlight critical paths
        for path in list(critical_paths.values())[:3]:
            path_edges = list(zip(path[:-1], path[1:]))
            nx.draw_networkx_edges(G, pos, 
                                 edgelist=path_edges,
                                 edge_color='yellow', 
                                 width=2)
        
        plt.title("Critical Infrastructure Analysis", color='white', pad=20)
        output_path = os.path.join(output_folder, 'critical_infrastructure.png')
        plt.savefig(output_path, bbox_inches='tight', facecolor='#1a1a1a')
        plt.close()

        return True
    except Exception as e:
        logger.error(f"Error in visualize_critical_infrastructure: {str(e)}")
        return False

def analyze_network_changes(G1: nx.Graph, G2: nx.Graph) -> Dict:
    """Analyze changes between two network snapshots"""
    try:
        # Get sets of nodes and edges
        nodes1 = set(G1.nodes())
        nodes2 = set(G2.nodes())
        edges1 = set(G1.edges())
        edges2 = set(G2.edges())
        
        # Calculate changes
        new_nodes = nodes2 - nodes1
        removed_nodes = nodes1 - nodes2
        new_edges = edges2 - edges1
        removed_edges = edges1 - edges2
        
        # Return changes dictionary
        return {
            'new_nodes': new_nodes,
            'removed_nodes': removed_nodes,
            'new_edges': new_edges,
            'removed_edges': removed_edges,
            'degree_distribution_change': sum((Counter(dict(G2.degree()).values()) - 
                                          Counter(dict(G1.degree()).values())).values())
        }
    except Exception as e:
        logger.error(f"Error analyzing network changes: {str(e)}", exc_info=True)
        return {
            'new_nodes': set(),
            'removed_nodes': set(),
            'new_edges': set(),
            'removed_edges': set(),
            'degree_distribution_change': 0
        }

def calculate_node_centrality_metrics(G: nx.Graph) -> Dict:
    """Calculate comprehensive node centrality metrics"""
    try:
        metrics = {
            'degree_centrality': nx.degree_centrality(G),
            'betweenness_centrality': nx.betweenness_centrality(G),
            'closeness_centrality': nx.closeness_centrality(G)
        }
        
        # Try to calculate eigenvector centrality, but handle potential convergence issues
        try:
            metrics['eigenvector_centrality'] = nx.eigenvector_centrality(G, max_iter=1000)
        except:
            logger.warning("Eigenvector centrality calculation failed, using degree centrality as fallback")
            metrics['eigenvector_centrality'] = metrics['degree_centrality']
            
        return metrics
    except Exception as e:
        logger.error(f"Error calculating centrality metrics: {str(e)}")
        return {}

def calculate_node_metrics_comparison(G1: nx.Graph, G2: nx.Graph) -> Dict:
    """Calculate comprehensive node-level metrics for comparison"""
    try:
        # Calculate basic centrality metrics
        metrics_before = {
            'Degree': dict(G1.degree()),  # Use actual degree instead of centrality
            'Clustering': nx.clustering(G1),
            'Betweenness': nx.betweenness_centrality(G1),
            'Closeness': nx.closeness_centrality(G1)
        }
        
        metrics_after = {
            'Degree': dict(G2.degree()),
            'Clustering': nx.clustering(G2),
            'Betweenness': nx.betweenness_centrality(G2),
            'Closeness': nx.closeness_centrality(G2)
        }
        
        # Calculate changes for each metric
        changes = {}
        all_nodes = set(G1.nodes()) | set(G2.nodes())
        
        for metric in metrics_before:
            changes[metric] = {}
            for node in all_nodes:
                # Get values with default of 0 if node doesn't exist in either graph
                before_val = float(metrics_before[metric].get(node, 0))
                after_val = float(metrics_after[metric].get(node, 0))
                change = after_val - before_val
                if abs(change) > 0.0001:  # Only include non-zero changes
                    changes[metric][node] = change
        
        logger.info(f"Calculated metric changes for {len(changes)} metrics across {len(all_nodes)} nodes")
        logger.debug(f"Sample of changes: {dict(list(changes.items())[:2])}")
        return changes

    except Exception as e:
        logger.error(f"Error calculating node metrics comparison: {str(e)}")
        return {}

def analyze_network_robustness(G: nx.Graph) -> Dict:
    """Analyze network robustness and vulnerability"""
    try:
        # Bridge node identification
        bridge_nodes = []
        for node in G.nodes():
            G_temp = G.copy()
            G_temp.remove_node(node)
            original_components = nx.number_connected_components(G)
            new_components = nx.number_connected_components(G_temp)
            if new_components > original_components:
                bridge_nodes.append({
                    'node': node,
                    'impact': new_components - original_components
                })
        
        # Community detection
        communities = community.best_partition(G)
        modularity = community.modularity(communities, G)
        
        # Network segmentation analysis
        segment_sizes = Counter(communities.values())
        cross_segment_edges = sum(1 for u, v in G.edges() 
                                if communities[u] != communities[v])
        isolation_score = 1 - (cross_segment_edges / G.number_of_edges()) if G.number_of_edges() > 0 else 0
        
        # Vulnerability paths
        centrality = nx.betweenness_centrality(G)
        threshold = np.mean(list(centrality.values()))
        high_centrality_nodes = [n for n, c in centrality.items() if c > threshold]
        vulnerability_paths = []
        
        for source in high_centrality_nodes:
            for target in high_centrality_nodes:
                if source != target and nx.has_path(G, source, target):
                    path = nx.shortest_path(G, source, target)
                    if len(path) > 2:
                        vulnerability_paths.append({
                            'path': path,
                            'length': len(path),
                            'risk_score': sum(G.degree(n) for n in path)
                        })
        
        return {
            'bridge_nodes': bridge_nodes,
            'communities': {str(k): v for k, v in communities.items()},
            'modularity': modularity,
            'segment_analysis': {
                'segment_sizes': dict(segment_sizes),
                'cross_segment_edges': cross_segment_edges,
                'isolation_score': isolation_score
            },
            'vulnerability_paths': sorted(vulnerability_paths, 
                                        key=lambda x: x['risk_score'], 
                                        reverse=True)[:5]  # Top 5 risky paths
        }
    except Exception as e:
        logger.error(f"Error in network robustness analysis: {str(e)}")
        return {}

def analyze_kcore_security(G: nx.Graph) -> Dict:
    """Enhanced k-core analysis for security insights"""
    try:
        # Calculate k-core decomposition
        core_numbers = nx.core_number(G)
        max_core = max(core_numbers.values()) if core_numbers else 0
        
        # Get all k-cores
        cores = {k: nx.k_core(G, k) for k in range(1, max_core + 1)}
        # Calculate core metrics
        core_metrics = {}
        for k, subgraph in cores.items():
            metrics = {
                'size': len(subgraph),
                'density': nx.density(subgraph),
                'avg_degree': sum(dict(subgraph.degree()).values()) / len(subgraph) if len(subgraph) > 0 else 0,
                'nodes': list(subgraph.nodes()),
                'connectivity': nx.node_connectivity(subgraph) if len(subgraph) > 1 else 0
            }
            core_metrics[k] = metrics
        
        # Identify critical cores
        critical_cores = {}
        for k, metrics in core_metrics.items():
            if k >= max_core - 1:  # Focus on highest cores
                critical_cores[k] = {
                    'nodes': metrics['nodes'],
                    'risk_score': calculate_core_risk(G, metrics, k, max_core)
                }
        
        return {
            'core_numbers': core_numbers,
            'core_metrics': core_metrics,
            'critical_cores': critical_cores,
            'max_core': max_core
        }
    except Exception as e:
        logger.error(f"Error in k-core analysis: {str(e)}")
        return {}

def calculate_core_risk(G: nx.Graph, metrics: Dict, k: int, max_core: int) -> float:
    """Calculate risk score for a k-core"""
    try:
        # Normalize factors
        core_level = k / max_core if max_core > 0 else 0
        density = metrics['density']
        size_ratio = metrics['size'] / G.number_of_nodes() if G.number_of_nodes() > 0 else 0
        connectivity = metrics['connectivity'] / (G.number_of_nodes() - 1) if G.number_of_nodes() > 1 else 0
        
        # Weighted risk calculation
        risk_score = (
            0.35 * core_level +      # Higher cores are more critical
            0.25 * density +         # Denser cores are more vulnerable
            0.20 * size_ratio +      # Larger cores have more impact
            0.20 * connectivity      # Higher connectivity means more attack paths
        ) * 100
        
        return risk_score
    except Exception as e:
        logger.error(f"Error calculating core risk: {str(e)}")
        return 0.0

def visualize_kcore_security(G: nx.Graph, core_analysis: Dict, output_path: str):
    """Generate security-focused k-core visualizations"""
    try:
        # Create figure with multiple subplots
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(20, 10))
        
        # 1. Core distribution heatmap
        core_numbers = core_analysis['core_numbers']
        pos = nx.spring_layout(G)
        nodes = list(G.nodes())
        adjacency_matrix = nx.adjacency_matrix(G).todense()
        
        # Create core relationship matrix
        core_matrix = np.zeros((len(nodes), len(nodes)))
        for i, node1 in enumerate(nodes):
            for j, node2 in enumerate(nodes):
                if adjacency_matrix[i,j]:
                    core_matrix[i,j] = min(core_numbers[node1], core_numbers[node2])
        
        sns.heatmap(core_matrix, ax=ax1, cmap='YlOrRd')
        ax1.set_title('K-Core Connectivity Heatmap', color='white')
        
        # 2. Risk-based core visualization
        node_colors = [core_numbers[node] for node in G.nodes()]
        nx.draw(G, pos, node_color=node_colors, cmap=plt.cm.YlOrRd,
                node_size=500, ax=ax2)
        ax2.set_title('Network K-Core Structure', color='white')
        
        plt.tight_layout()
        plt.savefig(output_path, facecolor='#1a1a1a', bbox_inches='tight')
        plt.close()
        
        return True
    except Exception as e:
        logger.error(f"Error visualizing k-core security: {str(e)}")
        return False

def generate_kcore_security_report(core_analysis: Dict) -> pd.DataFrame:
    """Generate security-focused k-core report"""
    try:
        core_metrics = core_analysis['core_metrics']
        critical_cores = core_analysis['critical_cores']
        
        report_data = []
        for k, metrics in core_metrics.items():
            risk_level = 'HIGH' if k in critical_cores else 'MEDIUM' if k >= core_analysis['max_core']/2 else 'LOW'
            
            report_data.append({
                'Core_Level': k,
                'Size': metrics['size'],
                'Density': f"{metrics['density']:.2f}",
                'Avg_Degree': f"{metrics['avg_degree']:.2f}",
                'Risk_Level': risk_level,
                'Risk_Score': f"{critical_cores.get(k, {}).get('risk_score', 0):.1f}",
                'Monitoring_Priority': 'Critical' if risk_level == 'HIGH' else 'Standard',
                'Recommended_Actions': get_core_recommendations(k, metrics, risk_level)
            })
        
        return pd.DataFrame(report_data)
    except Exception as e:
        logger.error(f"Error generating k-core report: {str(e)}")
        return pd.DataFrame()

def get_core_recommendations(k: int, metrics: Dict, risk_level: str) -> str:
    """Generate security recommendations based on core characteristics"""
    try:
        if risk_level == 'HIGH':
            return (f"Implement strict monitoring; "
                    f"Consider network segmentation; "
                    f"Monitor all {metrics['size']} nodes for suspicious activity")
        elif risk_level == 'MEDIUM':
            return (f"Regular monitoring; "
                    f"Review access controls; "
                    f"Document communication patterns")
        else:
            return "Standard security controls; Periodic review"
    except Exception as e:
        logger.error(f"Error generating recommendations: {str(e)}")
        return "Error generating recommendations"

def track_kcore_changes(G1: nx.Graph, G2: nx.Graph) -> pd.DataFrame:
    """Track changes in k-core structure between two network states"""
    try:
        cores1 = nx.core_number(G1)
        cores2 = nx.core_number(G2)
        
        changes = []
        all_nodes = set(G1.nodes()) | set(G2.nodes())
        
        for node in all_nodes:
            old_core = cores1.get(node, 0)
            new_core = cores2.get(node, 0)
            if old_core != new_core:
                changes.append({
                    'Node': node,
                    'Old_Core': old_core,
                    'New_Core': new_core,
                    'Change': new_core - old_core,
                    'Impact': 'High' if abs(new_core - old_core) > 1 else 'Medium',
                    'Action_Required': 'Yes' if new_core > old_core else 'Monitor'
                })
        
        return pd.DataFrame(changes)
    except Exception as e:
        logger.error(f"Error tracking k-core changes: {str(e)}")
        return pd.DataFrame()

def analyze_lateral_movement(G: nx.Graph) -> Dict:
    """Analyze potential lateral movement paths in network"""
    paths = {}
    high_value_targets = identify_high_value_targets(G)
    entry_points = identify_entry_points(G)
    
    # Analyze paths between entry points and targets
    for source in entry_points:
        for target in high_value_targets:
            if source != target:
                try:
                    # Find all simple paths (not just shortest)
                    all_paths = list(nx.all_simple_paths(G, source, target, cutoff=10))
                    if all_paths:
                        risk_scores = []
                        for path in all_paths:
                            score = calculate_path_risk(G, path)
                            risk_scores.append((path, score))
                        
                        # Sort paths by risk score
                        risk_scores.sort(key=lambda x: x[1], reverse=True)
                        paths[f"{source}->{target}"] = {
                            'paths': risk_scores,
                            'total_paths': len(all_paths),
                            'min_hops': len(min(all_paths, key=len)),
                            'avg_risk': sum(s for _, s in risk_scores) / len(risk_scores)
                        }
                except nx.NetworkXNoPath:
                    continue
    
    # Get segmentation violations directly without passing paths
    segmentation_violations = analyze_segmentation_violations(G)
    
    return {
        'lateral_paths': paths,
        'high_risk_paths': identify_high_risk_paths(paths),
        'segmentation_issues': segmentation_violations,  # Use the result directly
        'critical_junctions': find_critical_junctions(G, paths)
    }

def identify_high_value_targets(G: nx.Graph) -> List[str]:
    """Identify high-value targets based on node attributes and topology"""
    targets = []
    degrees = [G.degree(n) for n in G.nodes()]
    avg_degree = np.mean(degrees) if degrees else 0
    std_degree = np.std(degrees) if degrees else 0
    
    for node in G.nodes():
        node_data = G.nodes[node]
        # More lenient conditions for high-value targets
        if any([
            node_data.get('type', '').lower() in ['server', 'database', 'dc', 'admin', 'router', 'gateway'],
            node_data.get('service', '').lower() in ['sql', 'domain', 'admin', 'ssh', 'rdp', 'smb'],
            G.degree(node) > avg_degree,  # Changed from avg + std to just avg
            len(node_data.get('services', [])) > 2,  # Added service count check
            node_data.get('os_info', {}).get('os_match', '').lower().startswith('windows')  # Added OS check
        ]):
            targets.append(node)
            logger.info(f"Identified high-value target: {node}")
    
    logger.info(f"Found {len(targets)} high-value targets")
    return targets

def identify_entry_points(G: nx.Graph) -> List[str]:
    """Identify potential network entry points"""
    entry_points = []
    degrees = [G.degree(n) for n in G.nodes()]
    avg_degree = np.mean(degrees) if degrees else 0
    
    for node in G.nodes():
        node_data = G.nodes[node]
        # More lenient conditions for entry points
        if any([
            node_data.get('exposed', False),
            'external' in str(node_data.get('connections', [])),
            node_data.get('type', '').lower() in ['workstation', 'endpoint', 'client', 'unknown'],
            G.degree(node) < avg_degree,  # Changed from avg - std to just avg
            len(node_data.get('services', [])) < 3,  # Added service count check
            any(port.get('state') == 'open' for port in node_data.get('ports', []))  # Added open ports check
        ]):
            entry_points.append(node)
            logger.info(f"Identified entry point: {node}")
    
    logger.info(f"Found {len(entry_points)} entry points")
    return entry_points

def calculate_path_risk(G: nx.Graph, path: List) -> float:
    """Calculate risk score for a potential lateral movement path"""
    risk_score = 0
    for i in range(len(path)):
        node = path[i]
        node_data = G.nodes[node]
        
        # Enhanced risk factors
        risk_factors = {
            'privilege_level': node_data.get('privilege_level', 1),
            'vulnerabilities': len(node_data.get('vulnerabilities', [])) * 2,  # Doubled vulnerability impact
            'exposed_services': len(node_data.get('services', [])),
            'degree': G.degree(node) / G.number_of_nodes(),
            'open_ports': len([p for p in node_data.get('ports', []) if p.get('state') == 'open']) * 1.5,  # Added open ports factor
            'critical_service': 2 if any(s.get('name', '').lower() in ['rdp', 'ssh', 'smb'] 
                                       for s in node_data.get('services', [])) else 0,  # Added critical service factor
        }
        
        # Position risk (nodes in middle of path are more critical)
        position_multiplier = 2.0 if 0 < i < len(path)-1 else 1.0,  # Increased multiplier
        
        # Calculate step risk
        step_risk = sum(risk_factors.values()) * position_multiplier
        
        # Add edge risk if not last node
        if i < len(path)-1:
            next_node = path[i+1]
            edge_data = G.get_edge_data(node, next_node)
            edge_risk = assess_edge_risk(edge_data)
            step_risk += edge_risk
        
        risk_score += step_risk
    
    return risk_score / len(path)  # Normalize by path length

def assess_edge_risk(edge_data: Dict) -> float:
    """Assess risk of network connection"""
    risk = 1.0
    if edge_data:
        if edge_data.get('encrypted', True):
            risk *= 0.7
        if edge_data.get('monitored', False):
            risk *= 0.8
        if edge_data.get('authenticated', False):
            risk *= 0.6
    return risk

def identify_high_risk_paths(paths: Dict) -> List[Dict]:
    """Identify highest risk lateral movement paths"""
    high_risk_paths = []
    for path_key, path_data in paths.items():
        if path_data['avg_risk'] > 7.0 or any(score > 8.0 for _, score in path_data['paths']):
            high_risk_paths.append({
                'path': path_key,
                'risk_score': path_data['avg_risk'],
                'num_paths': path_data['total_paths'],
                'min_hops': path_data['min_hops'],
                'highest_risk_route': path_data['paths'][0]
            })
    return sorted(high_risk_paths, key=lambda x: x['risk_score'], reverse=True)

def analyze_segmentation_violations(G: nx.Graph) -> Dict:
    """Comprehensive analysis of network segmentation violations"""
    
    violations = {
        'direct_violations': [],
        'trust_violations': [],
        'service_violations': [],
        'path_violations': [],
        'summary': {
            'total_violations': 0,
            'critical_violations': 0,
            'affected_segments': set()
        }
    }

    def check_direct_violations():
        """Check for direct unauthorized connections between segments"""
        for edge in G.edges():
            source, target = edge
            source_zone = G.nodes[source].get('zone', 'UNKNOWN')
            target_zone = G.nodes[target].get('zone', 'UNKNOWN')
            
            if source_zone != target_zone:
                # Check if connection is allowed
                source_level = SECURITY_ZONES.get(source_zone, {}).get('level', 0)
                target_level = SECURITY_ZONES.get(target_zone, {}).get('level', 0)
                
                if abs(source_level - target_level) > 1:  # Only adjacent levels should connect
                    violations['direct_violations'].append({
                        'type': 'unauthorized_connection',
                        'source': {
                            'node': source,
                            'zone': source_zone,
                            'level': source_level
                        },
                        'target': {
                            'node': target,
                            'zone': target_zone,
                            'level': target_level
                        },
                        'severity': 'HIGH' if abs(source_level - target_level) > 2 else 'MEDIUM',
                        'risk_score': calculate_violation_risk(source_level, target_level)
                    })

    def check_trust_violations():
        """Analyze trust relationship violations"""
        for node in G.nodes():
            node_zone = G.nodes[node].get('zone', 'UNKNOWN')
            node_level = SECURITY_ZONES.get(node_zone, {}).get('level', 0)
            
            # Check node's connections
            for neighbor in G.neighbors(node):
                neighbor_zone = G.nodes[neighbor].get('zone', 'UNKNOWN')
                neighbor_level = SECURITY_ZONES.get(neighbor_zone, {}).get('level', 0)
                
                # Check trust relationship violations
                edge_data = G.edges[node, neighbor]
                if not edge_data.get('authenticated', False) and abs(node_level - neighbor_level) > 0:
                    violations['trust_violations'].append({
                        'type': 'unauthenticated_cross_zone',
                        'source_node': node,
                        'target_node': neighbor,
                        'zones': (node_zone, neighbor_zone),
                        'severity': 'HIGH',
                        'risk_score': 8.0
                    })

    def check_service_violations():
        """Check for prohibited services across zones"""
        for node in G.nodes():
            node_zone = G.nodes[node].get('zone', 'UNKNOWN')
            node_services = G.nodes[node].get('services', [])
            
            allowed_services = SECURITY_ZONES.get(node_zone, {}).get('allowed_services', [])
            
            for service in node_services:
                if service not in allowed_services:
                    # Check if service is exposed to other zones
                    for neighbor in G.neighbors(node):
                        neighbor_zone = G.nodes[neighbor].get('zone', 'UNKNOWN')
                        if neighbor_zone != node_zone:
                            violations['service_violations'].append({
                                'type': 'prohibited_service',
                                'node': node,
                                'service': service,
                                'zone': node_zone,
                                'exposed_to_zone': neighbor_zone,
                                'severity': 'HIGH' if service in ['telnet', 'ftp'] else 'MEDIUM',
                                'risk_score': 7.0
                            })

    def check_path_violations():
        """Analyze multi-hop paths between zones"""
        for source in G.nodes():
            source_zone = G.nodes[source].get('zone', 'UNKNOWN')
            
            for target in G.nodes():
                if source != target:
                    target_zone = G.nodes[target].get('zone', 'UNKNOWN')
                    
                    if source_zone != target_zone:
                        try:
                            paths = list(nx.all_simple_paths(G, source, target, cutoff=5))
                            for path in paths:
                                zones_crossed = [G.nodes[n].get('zone', 'UNKNOWN') for n in path]
                                transitions = count_zone_transitions(zones_crossed)
                                
                                if transitions > 2:  # More than 2 zone transitions is suspicious
                                    violations['path_violations'].append({
                                        'type': 'excessive_zone_crossing',
                                        'path': path,
                                        'zones_crossed': zones_crossed,
                                        'transitions': transitions,
                                        'severity': 'HIGH' if transitions > 3 else 'MEDIUM',
                                        'risk_score': 6.0 + transitions
                                    })
                        except nx.NetworkXNoPath:
                            continue

    def calculate_violation_risk(source_level: int, target_level: int) -> float:
        """Calculate risk score for a violation"""
        level_difference = abs(source_level - target_level)
        base_risk = 5.0
        
        risk_factors = {
            'level_gap': level_difference * 2,
            'critical_zone': 3.0 if max(source_level, target_level) >= 4 else 0,
            'multi_level': 2.0 if level_difference > 2 else 0
        }
        
        return min(10.0, base_risk + sum(risk_factors.values()))

    def count_zone_transitions(zones: List[str]) -> int:
        """Count number of zone transitions in a path"""
        transitions = 0
        for i in range(len(zones)-1):
            if zones[i] != zones[i+1]:
                transitions += 1
        return transitions

    # Run all checks
    check_direct_violations()
    check_trust_violations()
    check_service_violations()
    check_path_violations()

    # Calculate summary statistics
    violations['summary']['total_violations'] = (
        len(violations['direct_violations']) +
        len(violations['trust_violations']) +
        len(violations['service_violations']) +
        len(violations['path_violations'])
    )
    
    violations['summary']['critical_violations'] = sum(
        1 for v in violations['direct_violations'] + 
                  violations['trust_violations'] + 
                  violations['service_violations'] + 
                  violations['path_violations']
        if v.get('severity') == 'HIGH'
    )
    
    # Get all affected segments
    for violation_type in ['direct_violations', 'trust_violations', 'service_violations', 'path_violations']:
        for v in violations[violation_type]:
            if 'zones' in v:
                violations['summary']['affected_segments'].update(v['zones'])
            elif 'zone' in v:
                violations['summary']['affected_segments'].add(v['zone'])
    
    violations['summary']['affected_segments'] = list(violations['summary']['affected_segments'])
    
    return violations

def generate_segmentation_report(violations: Dict) -> str:
    """Generate a detailed report of segmentation violations"""
    # ... (paste the generate_segmentation_report function you provided)

def visualize_segmentation_violations(G: nx.Graph, violations: Dict, output_path: str):
    """Create visualization of segmentation violations"""
    # ... (paste the visualize_segmentation_violations function you provided)

def find_critical_junctions(G: nx.Graph, paths: Dict) -> Dict[str, float]:
    """Identify nodes that appear frequently in lateral movement paths"""
    try:
        junction_counts = Counter()
        junction_risks = defaultdict(float)
        
        for path_data in paths.values():
            for path, risk_score in path_data['paths']:
                for node in path[1:-1]:  # Exclude start/end nodes
                    junction_counts[node] += 1
                    junction_risks[node] += risk_score
        
        # Calculate final risk scores
        critical_junctions = {
            node: (count / len(paths) * junction_risks[node] / junction_counts[node])
            for node, count in junction_counts.items()
            if len(paths) > 0  # Prevent division by zero
        }
        
        return dict(sorted(critical_junctions.items(), key=lambda x: x[1], reverse=True))
    except Exception as e:
        logger.error(f"Error finding critical junctions: {str(e)}")
        return {}

def visualize_lateral_paths(G: nx.Graph, analysis_result: Dict, output_path: str) -> bool:
    """Visualize lateral movement paths and critical nodes"""
    try:
        plt.figure(figsize=(20, 15))
        pos = nx.spring_layout(G, k=2, iterations=100)
        
        # Draw base network with improved visibility
        nx.draw_networkx_edges(G, pos, alpha=0.2, edge_color='gray', width=1)
        
        # Prepare node attributes and tooltips
        node_colors = []
        node_sizes = []
        labels = {}
        node_data = {}  # Store detailed node information
        
        for node in G.nodes():
            # Get node attributes
            node_attrs = G.nodes[node]
            services = node_attrs.get('services', [])
            ports = node_attrs.get('ports', [])
            
            # Calculate node metrics
            degree = G.degree(node)
            neighbors = list(G.neighbors(node))
            
            # Store detailed node information
            node_data[node] = {
                'type': node_attrs.get('type', 'unknown'),
                'services': services,
                'open_ports': [p for p in ports if p.get('state') == 'open'],
                'os': node_attrs.get('os_info', {}).get('os_match', 'unknown'),
                'degree': degree,
                'neighbors': neighbors,
                'is_critical': node in analysis_result.get('critical_junctions', {}),
                'risk_score': analysis_result.get('critical_junctions', {}).get(node, 0),
                'vulnerabilities': node_attrs.get('vulnerabilities', []),
                'zone': node_attrs.get('zone', 'unknown')
            }
            
            # Determine node visualization attributes
            if node in analysis_result.get('critical_junctions', {}):
                node_colors.append('red')
                node_sizes.append(1000)
                labels[node] = f"{node}\n(Critical)"
            elif any(node in path['path'] for path in analysis_result.get('high_risk_paths', [])):
                node_colors.append('orange')
                node_sizes.append(800)
                labels[node] = f"{node}\n(Risk Path)"
            else:
                node_colors.append('lightblue')
                node_sizes.append(500)
                labels[node] = node
        
        # Save node data to file for frontend use
        node_data_path = os.path.join(os.path.dirname(output_path), 'node_data.json')
        with open(node_data_path, 'w') as f:
            json.dump(node_data, f, indent=2)
        
        # Draw nodes with improved visibility
        nx.draw_networkx_nodes(G, pos,
                             node_color=node_colors,
                             node_size=node_sizes,
                             alpha=0.7)
        
        # Add labels with better formatting
        nx.draw_networkx_labels(G, pos,
                              labels=labels,
                              font_size=10,
                              font_weight='bold',
                              font_color='white')
        
        # Highlight high-risk paths with different colors
        colors = ['red', 'yellow', 'orange']  # Different colors for different paths
        for i, path_info in enumerate(analysis_result.get('high_risk_paths', [])[:3]):
            if 'highest_risk_route' in path_info:
                path = path_info['highest_risk_route'][0]
                edges = list(zip(path[:-1], path[1:]))
                nx.draw_networkx_edges(G, pos,
                                     edgelist=edges,
                                     edge_color=colors[i],
                                     width=3,
                                     alpha=0.8)
        
        # Add legend
        legend_elements = [
            plt.Line2D([0], [0], color='red', lw=3, label='Highest Risk Path'),
            plt.Line2D([0], [0], color='yellow', lw=3, label='Second Risk Path'),
            plt.Line2D([0], [0], color='orange', lw=3, label='Third Risk Path'),
            plt.scatter([0], [0], c='red', s=200, label='Critical Junction'),
            plt.scatter([0], [0], c='orange', s=200, label='Risk Path Node'),
            plt.scatter([0], [0], c='lightblue', s=200, label='Regular Node')
        ]
        plt.legend(handles=legend_elements, loc='upper left', fontsize=12)
        
        plt.title("Lateral Movement Analysis\nRed: Critical Paths, Orange: High-Risk Nodes",
                 color='white',
                 pad=20,
                 fontsize=16)
        
        # Set dark background
        plt.gca().set_facecolor('#1a1a1a')
        plt.gcf().set_facecolor('#1a1a1a')
        
        # Remove axes
        plt.axis('off')
        
        # Save with high quality
        plt.savefig(output_path,
                   facecolor='#1a1a1a',
                   bbox_inches='tight',
                   dpi=300)
        plt.close()
        
        return True
    except Exception as e:
        logger.error(f"Error visualizing lateral paths: {str(e)}")
        return False

def format_scan_result(result: ScanResult) -> Dict[str, Any]:
    """Format scan result for JSON response"""
    try:
        hosts_with_ports = []
        for host in result.hosts:
            # Start with the basic host info
            formatted_host = {
                'ip_address': host.get('ip_address', host.get('ip', '')),
                'status': host.get('status', 'unknown'),
                'hostnames': host.get('hostnames', []),
                'ports': []
            }

            # Add ports for this host
            host_ports = [p for p in result.ports if p.get('ip_address', p.get('ip', '')) == formatted_host['ip_address']]
            formatted_host['ports'] = [{
                'port': p.get('port', 0),
                'state': p.get('state', 'unknown'),
                'service': p.get('service', 'unknown'),
                'protocol': p.get('protocol', 'tcp')
            } for p in host_ports]

        formatted_result = {
            'timestamp': result.timestamp,
            'scan_type': result.scan_type,
            'hosts': hosts_with_ports,
            'ports': result.ports,
            'services': result.services,
            'vulnerabilities': result.vulnerabilities,
            'os_matches': result.os_matches,
            'scan_stats': result.scan_stats,
            'summary': {
                'total_hosts': len(result.hosts),
                'active_hosts': len([h for h in result.hosts if h.get('status') == 'up']),
                'total_ports': len(result.ports),
                'total_services': len(result.services),
                'total_vulnerabilities': len(result.vulnerabilities)
            }
        }

        return formatted_result

    except Exception as e:
        logger.error(f"Error formatting scan result: {str(e)}")
        raise

@app.route('/api/scan', methods=['POST'])
def start_scan():
    try:
        data = request.get_json()
        subnet = data.get('subnet')
        scan_type = data.get('scan_type', 'basic_scan')
        
        if not subnet:
            return jsonify({'error': 'No subnet provided'}), 400
            
        try:
            # Generate scan ID first
            scan_id = str(uuid.uuid4())
            
            # Initialize scan status before starting scan
            scan_statuses[scan_id] = {
                'status': 'initializing',
                'progress': 0,
                'start_time': datetime.now().isoformat(),
                'scan_type': scan_type,
                'subnet': subnet
            }
            
            logger.info(f"Initialized scan status for {scan_id}: {scan_statuses[scan_id]}")
            
            # Map scan type to scanner method
            scan_methods = {
                'quick_scan': scanner.quick_scan,
                'basic_scan': scanner.basic_scan,
                'full_scan': scanner.full_scan,
                'vulnerability_scan': scanner.vulnerability_scan
            }
            
            if scan_type not in scan_methods:
                scan_statuses[scan_id]['status'] = 'failed'
                scan_statuses[scan_id]['error'] = 'Invalid scan type'
                return jsonify({'error': 'Invalid scan type'}), 400
            
            # Initialize scan lock
            scan_locks[scan_id] = Lock()
            
            # Update status to running
            scan_statuses[scan_id]['status'] = 'running'
            
            # Start scan in background thread
            def run_scan():
                try:
                    with scan_locks[scan_id]:
                        active_scans[scan_id] = True
                        results = scan_methods[scan_type](subnet)
                        process_scan_results(results, scan_id)
                except Exception as e:
                    logger.error(f"Scan failed: {str(e)}")
                    scan_statuses[scan_id].update({
                        'status': 'failed',
                        'error': str(e),
                        'end_time': datetime.now().isoformat()
                    })
                finally:
                    active_scans.pop(scan_id, None)
                    scan_locks.pop(scan_id, None)

            thread = Thread(target=run_scan)
            thread.daemon = True
            thread.start()
            
            return jsonify({
                'status': 'started',
                'scan_id': scan_id,
                'message': f'Started {scan_type} scan on {subnet}'
            })
            
        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            if scan_id in scan_statuses:
                scan_statuses[scan_id].update({
                    'status': 'failed',
                    'error': str(e),
                    'end_time': datetime.now().isoformat()
                })
            return jsonify({
                'status': 'error',
                'error': str(e)
            }), 500
            
    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/api/results')
def get_results():
    try:
        results_dir = os.path.join(BASE_DIR, 'src', 'data', 'scans')
        if not os.path.exists(results_dir):
            return jsonify([])

        scan_results = []
        for file in os.listdir(results_dir):
            if file.endswith('.json'):
                file_path = os.path.join(results_dir, file)
                with open(file_path, 'r') as f:
                    result = json.load(f)
                    scan_results.append({
                        'filename': file,
                        'timestamp': result.get('timestamp'),
                        'scan_type': result.get('scan_type'),
                        'summary': {
                            'total_hosts': len(result.get('hosts', [])),
                            'active_hosts': len([h for h in result.get('hosts', []) 
                                               if h.get('status') == 'up']),
                            'total_ports': len(result.get('ports', [])),
                            'total_services': len(result.get('services', [])),
                            'total_vulnerabilities': len(result.get('vulnerabilities', []))
                        }
                    })

        return jsonify(scan_results)

    except Exception as e:
        logger.error(f"Error retrieving results: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/comparison')
def comparison():
    return render_template('comparison.html')

@app.route('/api/snapshots')
def get_snapshots():
    """Get list of available network snapshots (scans)"""
    try:
        scans_dir = os.path.join(BASE_DIR, 'src', 'data', 'scans')
        if not os.path.exists(scans_dir):
            return jsonify({'snapshots': []})

        # Get all scan files
        scan_files = [f for f in os.listdir(scans_dir) 
                     if f.endswith('.json') and not f.endswith('_analysis.json')]
        
        snapshots = []
        for filename in scan_files:
            file_path = os.path.join(scans_dir, filename)
            try:
                # Get file creation time
                file_time = datetime.fromtimestamp(os.path.getctime(file_path))
                
                # Parse scan ID and network from filename
                # Example filename: 192.168.1.0_24_20241126_142203_d3716d5b-909b-4e9c-affb-18f2e63c7cc6.json
                parts = filename.split('_')
                network = parts[0].replace('-', '.')  # Get network part
                scan_id = parts[-1].replace('.json', '')  # Get scan ID
                
                # Read scan data for summary
                with open(file_path, 'r') as f:
                    scan_data = json.load(f)
                    summary = scan_data.get('summary', {})
                    total_hosts = summary.get('total_hosts', 0)
                    active_hosts = summary.get('active_hosts', 0)
                
                snapshots.append({
                    'id': scan_id,
                    'timestamp': file_time.isoformat(),
                    'network': network,
                    'filename': filename,
                    'total_hosts': total_hosts,
                    'active_hosts': active_hosts
                })
            except Exception as e:
                logger.error(f"Error processing scan file {filename}: {str(e)}")
                continue
        
        # Sort snapshots by timestamp, most recent first
        snapshots.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return jsonify({
            'status': 'success',
            'snapshots': snapshots
        })
        
    except Exception as e:
        logger.error(f"Error getting snapshots: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/comparison/<comparison_id>/<image_name>')
def get_comparison_image(comparison_id, image_name):
    """Serve comparison visualization images"""
    try:
        image_path = os.path.join(BASE_DIR, 'src', 'data', 'comparisons', comparison_id, image_name)
        logger.info(f"Looking for image at: {image_path}")
        
        if not os.path.exists(image_path):
            logger.error(f"Image not found: {image_path}")
            return jsonify({'error': 'Image not found'}), 404
            
        logger.info(f"Serving image from: {image_path}")
        return send_file(image_path, mimetype='image/png')
    except Exception as e:
        logger.error(f"Error serving comparison image: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/topology/image/<scan_id>')
def get_topology_image(scan_id):
    """Get the topology visualization image for a scan"""
    try:
        topology_dir = os.path.join(BASE_DIR, 'src', 'data', 'topology')
        image_file = os.path.join(topology_dir, f'topology_{scan_id}.png')
        
        if not os.path.exists(image_file):
            # Try to generate the image
            topology_file = os.path.join(topology_dir, f'topology_{scan_id}.json')
            if not os.path.exists(topology_file):
                return jsonify({'error': 'Topology data not found'}), 404
                
            with open(topology_file, 'r') as f:
                topology_data = json.load(f)
                
            # Generate and save the visualization
            updateTopologyVisualization(topology_data, BASE_DIR)
            
        if not os.path.exists(image_file):
            return jsonify({'error': 'Failed to generate topology image'}), 500
            
        return send_file(image_file, mimetype='image/png')
        
    except Exception as e:
        logger.error(f"Error getting topology image: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/topology/latest')
def get_latest_topology():
    """Get latest network topology data"""
    try:
        topology_dir = os.path.join(BASE_DIR, 'src', 'data', 'topology')
        if not os.path.exists(topology_dir):
            return jsonify({'error': 'No topology data found'}), 404
            
        # Get all topology files
        topology_files = [f for f in os.listdir(topology_dir) 
                         if f.endswith('_topology.json')]
        
        if not topology_files:
            return jsonify({'error': 'No topology data found'}), 404
            
        # Get the most recent topology file
        latest_file = max(topology_files, 
                         key=lambda x: os.path.getctime(os.path.join(topology_dir, x)))
        topology_path = os.path.join(topology_dir, latest_file)
        
        logger.info(f"Serving topology data from: {topology_path}")
        
        # Read and return the JSON data
        with open(topology_path, 'r') as f:
            topology_data = json.load(f)
            
        return jsonify(topology_data)
        
    except Exception as e:
        logger.error(f"Error serving topology data: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/analysis/ports/<scan_id>')
def get_port_analysis(scan_id):
    """Get detailed port analysis for a specific scan"""
    try:
        scans_dir = os.path.join(BASE_DIR, 'src', 'data', 'scans')
        
        # Look for files containing the scan_id
        matching_files = [f for f in os.listdir(scans_dir) 
                         if scan_id in f and not f.endswith('_analysis.json')]
        
        if not matching_files:
            logger.error(f"No scan results found for ID: {scan_id}")
            return jsonify({'error': 'Scan results not found'}), 404
            
        # Use the most recent file if multiple matches
        scan_file = os.path.join(scans_dir, matching_files[0])
        if len(matching_files) > 1:
            scan_file = os.path.join(scans_dir, 
                max(matching_files, key=lambda f: os.path.getctime(os.path.join(scans_dir, f))))
            
        logger.info(f"Loading port analysis data from: {scan_file}")
        with open(scan_file, 'r') as f:
            scan_data = json.load(f)

        # Initialize port analysis structure
        port_analysis = {
            'total_open_ports': 0,
            'hosts_with_open_ports': 0,
            'common_ports': {},
            'services': {},
            'interesting_ports': {
                'high_risk': set(),
                'remote_access': set(),
                'industrial': set(),
                'web_services': set(),
                'databases': set()
            },
            'port_details': []  # List to store detailed port information
        }

        # Process ports from scan data
        hosts_with_ports = 0
        for host in scan_data.get('hosts', []):
            host_has_ports = False
            ip_address = host.get('ip_address')
            
            # Get services info for mapping to ports
            services_map = {
                s.get('name'): {
                    'product': s.get('product', ''),
                    'version': s.get('version', '')
                }
                for s in host.get('services', [])
            }
            
            for port in host.get('ports', []):
                if port.get('state') == 'open':
                    port_num = str(port.get('port', ''))
                    service = port.get('service', 'unknown')
                    protocol = port.get('protocol', 'tcp')
                    service_details = port.get('service_details', '')
                    
                    # Get service details
                    service_info = services_map.get(service, {})
                    
                    # Count total open ports
                    port_analysis['total_open_ports'] += 1
                    host_has_ports = True
                    
                    # Track common ports
                    port_analysis['common_ports'][port_num] = \
                        port_analysis['common_ports'].get(port_num, 0) + 1
                    
                    # Track services
                    port_analysis['services'][service] = \
                        port_analysis['services'].get(service, 0) + 1
                    
                    # Add detailed port information
                    port_analysis['port_details'].append({
                        'ip_address': ip_address,
                        'port': port_num,
                        'service': service,
                        'protocol': protocol,
                        'product': service_info.get('product', ''),
                        'version': service_info.get('version', ''),
                        'details': service_details
                    })
                    
                    # Categorize interesting ports
                    if port_num in ['21', '23', '445', '3389']:
                        port_analysis['interesting_ports']['high_risk'].add(port_num)
                    if port_num in ['22', '3389', '5900']:
                        port_analysis['interesting_ports']['remote_access'].add(port_num)
                    if port_num in ['502', '102', '44818']:
                        port_analysis['interesting_ports']['industrial'].add(port_num)
                    if port_num in ['80', '443', '8080', '8443']:
                        port_analysis['interesting_ports']['web_services'].add(port_num)
                    if port_num in ['1433', '3306', '5432', '27017', '6379']:
                        port_analysis['interesting_ports']['databases'].add(port_num)
            
            if host_has_ports:
                hosts_with_ports += 1
        
        # Update final statistics
        port_analysis['hosts_with_open_ports'] = hosts_with_ports
        
        # Convert sets to lists for JSON serialization
        port_analysis['interesting_ports'] = {
            category: list(ports)
            for category, ports in port_analysis['interesting_ports'].items()
        }
        
        # Sort port details by IP address and port number
        port_analysis['port_details'].sort(key=lambda x: (
            tuple(int(p) for p in x['ip_address'].split('.')),
            int(x['port'])
        ))
        
        # Calculate most common ports and services
        port_analysis['most_common_ports'] = sorted(
            port_analysis['common_ports'].items(),
            key=lambda x: (-x[1], int(x[0]))  # Sort by count (descending) then port number
        )[:10]  # Top 10 most common ports
        
        port_analysis['most_common_services'] = sorted(
            port_analysis['services'].items(),
            key=lambda x: (-x[1], x[0])  # Sort by count (descending) then service name
        )[:10]  # Top 10 most common services

        logger.info(f"Completed port analysis for scan {scan_id}")
        return jsonify(port_analysis)

    except Exception as e:
        logger.error(f"Error analyzing ports: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/<scan_id>/status')
def get_scan_status(scan_id):
    """Get the status of a running scan"""
    try:
        logger.info(f"Checking status for scan {scan_id}")
        logger.debug(f"Current scan_statuses: {scan_statuses}")
        
        # Check if scan exists
        if scan_id not in scan_statuses:
            logger.warning(f"Scan ID {scan_id} not found in scan_statuses")
            # Try to load from file as fallback
            scan_file = os.path.join(BASE_DIR, 'src', 'data', 'scans', f'{scan_id}.json')
            if os.path.exists(scan_file):
                logger.info(f"Found completed scan file for {scan_id}")
                with open(scan_file, 'r') as f:
                    scan_data = json.load(f)
                return jsonify({
                    'status': 'completed',
                    'progress': 100,
                    'end_time': scan_data.get('timestamp'),
                    'summary': scan_data.get('summary', {})
                })
            return jsonify({
                'error': 'Scan not found',
                'scan_id': scan_id
            }), 404
            
        status = scan_statuses[scan_id]
        logger.info(f"Scan status for {scan_id}: {status}")
        return jsonify(status)
        
    except Exception as e:
        logger.error(f"Error getting scan status: {str(e)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/api/scan/<scan_id>/results')
def get_scan_results(scan_id):
    """Get the results of a completed scan"""
    try:
        scans_dir = os.path.join(BASE_DIR, 'src', 'data', 'scans')
        
        # Look for files containing the scan_id
        matching_files = [f for f in os.listdir(scans_dir) 
                         if scan_id in f and not f.endswith('_analysis.json')]
        
        if not matching_files:
            logger.error(f"No scan results found for ID: {scan_id}")
            return jsonify({'error': 'Scan results not found'}), 404
            
        # Use the most recent file if multiple matches
        results_file = os.path.join(scans_dir, matching_files[0])
        if len(matching_files) > 1:
            results_file = os.path.join(scans_dir, 
                max(matching_files, key=lambda f: os.path.getctime(os.path.join(scans_dir, f))))
            
        logger.info(f"Loading scan results from: {results_file}")
        with open(results_file, 'r') as f:
            results = json.load(f)
            
        return jsonify(results)
    except Exception as e:
        logger.error(f"Error retrieving scan results: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/vulnerabilities/<scan_id>')
def get_vulnerabilities(scan_id):
    try:
        # Get scan results
        results_file = os.path.join(BASE_DIR, 'src', 'data', 'scans', f'{scan_id}.json')
        if not os.path.exists(results_file):
            return jsonify({'error': 'Scan results not found'}), 404
            
        with open(results_file, 'r') as f:
            scan_data = json.load(f)
            
        # Extract services from scan data
        services = []
        for host in scan_data.get('hosts', []):
            for service in host.get('services', []):
                if service.get('product'):
                    services.append({
                        'host': host['ip_address'],
                        'product': service['product'],
                        'version': service.get('version', ''),
                        'name': service.get('name', '')
                    })
        
        # Batch check vulnerabilities
        vuln_results = vuln_checker.batch_check_services(services)
        
        # Process results
        all_vulns = []
        for service_key, vuln_data in vuln_results.items():
            product, version = service_key
            for vuln in vuln_data['vulnerabilities']:
                all_vulns.append({
                    'host': next((s['host'] for s in services 
                                if s['product'] == product and s['version'] == version), 'unknown'),
                    'service': f"{product} {version}",
                    **vuln
                })
        
        # Calculate summary statistics
        total_cves = len(all_vulns)
        critical_cves = len([v for v in all_vulns if v['cvss_score'] >= 9.0])
        avg_cvss = sum(v['cvss_score'] for v in all_vulns) / total_cves if total_cves > 0 else 0
        
        return jsonify({
            'total_cves': total_cves,
            'critical_cves': critical_cves,
            'average_cvss': avg_cvss,
            'vulnerabilities': sorted(all_vulns, key=lambda x: x['cvss_score'], reverse=True)
        })
        
    except Exception as e:
        logger.error(f"Error getting vulnerabilities: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/<scan_id>/stop', methods=['POST'])
def stop_scan(scan_id: str):
    """Stop a running scan"""
    try:
        logger.info(f"Attempting to stop scan {scan_id}")
        
        # Check if scan exists
        if scan_id not in scan_statuses:
            logger.warning(f"Scan {scan_id} not found")
            return jsonify({
                'status': 'error',
                'message': 'Scan not found'
            }), 404
            
        # Get current scan status
        current_status = scan_statuses[scan_id]['status']
        logger.info(f"Current scan status: {current_status}")
        
        # Check if scan is actually running
        if current_status not in ['running', 'in_progress']:
            logger.warning(f"Cannot stop scan {scan_id} - current status: {current_status}")
            return jsonify({
                'status': 'error',
                'message': f'Scan cannot be stopped - current status: {current_status}'
            }), 400
            
        # Attempt to stop the scan
        try:
            # Get scan lock
            scan_lock = scan_locks.get(scan_id)
            if scan_lock:
                scan_lock.acquire(timeout=5)  # Wait up to 5 seconds for lock
            
            # Stop the actual scanning process
            if scanner.stop_scan(scan_id):
                scan_statuses[scan_id].update({
                    'status': 'stopped',
                    'end_time': datetime.now().isoformat(),
                    'message': 'Scan stopped by user'
                })
                
                logger.info(f"Successfully stopped scan {scan_id}")
                return jsonify({
                    'status': 'success',
                    'message': 'Scan stopped successfully',
                    'scan_info': scan_statuses[scan_id]
                })
            else:
                logger.error(f"Failed to stop scan {scan_id}")
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to stop scan - scanner returned failure'
                }), 500
                
        finally:
            # Always release the lock if we acquired it
            if scan_lock and scan_lock.locked():
                scan_lock.release()
            
    except TimeoutError:
        logger.error(f"Timeout while attempting to stop scan {scan_id}")
        return jsonify({
            'status': 'error',
            'message': 'Timeout while attempting to stop scan'
        }), 504
        
    except Exception as e:
        logger.error(f"Error stopping scan {scan_id}: {str(e)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': f'Internal error while stopping scan: {str(e)}'
        }), 500

@app.after_request
def add_security_headers(response: Response) -> Response:
    """Add security headers to each response"""
    # Allow necessary JavaScript functionality while maintaining security
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com https://code.highcharts.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
        "img-src 'self' data: blob:; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "connect-src 'self'"
    )
    # Add other security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    return response

@app.after_request
def add_cors_headers(response: Response) -> Response:
    """Add CORS headers to allow necessary cross-origin requests"""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

# Add at the start of app.py
import ctypes
import sys

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    try:
        if ctypes.windll.shell32.IsUserAnAdmin():
            return True
            
        # If not admin, relaunch the script with admin rights
        script = os.path.abspath(sys.argv[0])
        params = ' '.join(sys.argv[1:])
        
        # Use subprocess to keep the window open
        cmd = f'powershell Start-Process -Verb RunAs python "{script}" {params}'
        subprocess.run(cmd, shell=True)
        sys.exit()
        
    except Exception as e:
        logger.error(f"Error in admin check: {e}")
        return False

@app.route('/api/networks/diagnostic')
def network_diagnostic():
    """Get diagnostic information about network interfaces"""
    try:
        info = NetworkDiscovery.get_system_info()
        return jsonify({
            'status': 'success',
            'diagnostic_info': info
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# Add these imports at the top
from flask_cors import CORS

# After creating the Flask app
CORS(app)

@app.route('/api/analysis/<scan_id>')
def get_network_analysis(scan_id):
    """Get network analysis results for a scan"""
    try:
        logger.info(f"Starting network analysis for scan {scan_id}")
        
        # Check for existing analysis
        analysis_dir = os.path.join(BASE_DIR, 'src', 'data', 'analysis')
        analysis_file = os.path.join(analysis_dir, f"{scan_id}_analysis.json")
        
        if os.path.exists(analysis_file):
            logger.info(f"Loading existing analysis from {analysis_file}")
            with open(analysis_file, 'r') as f:
                return jsonify(json.load(f))
                
        # Load scan data
        scans_dir = os.path.join(BASE_DIR, 'src', 'data', 'scans')
        scan_file = os.path.join(scans_dir, f"{scan_id}.json")
        
        if not os.path.exists(scan_file):
            logger.error(f"Scan file not found: {scan_file}")
            return jsonify({'error': 'Scan data not found'}), 404
            
        with open(scan_file, 'r') as f:
            scan_data = json.load(f)
        
        # Create network graph
        G = create_network_from_scan(scan_data)
        
        # Calculate metrics
        metrics = calculate_network_metrics(G)
        
        # Additional analysis
        critical_paths = identify_critical_paths(G)
        bridge_nodes = identify_bridge_nodes(G)
        segmentation = calculate_network_segmentation(G)
        
        # Prepare analysis results
        analysis_results = {
            'scan_id': scan_id,
            'timestamp': datetime.now().isoformat(),
            'metrics': metrics,
            'critical_paths': critical_paths,
            'bridge_nodes': bridge_nodes,
            'segmentation': segmentation
        }
        
        # Save analysis results
        os.makedirs(analysis_dir, exist_ok=True)
        with open(analysis_file, 'w') as f:
            json.dump(analysis_results, f, indent=2)
            
        return jsonify(analysis_results)
        
    except Exception as e:
        logger.error(f"Error analyzing network: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/analysis/history')
def get_analysis_history():
    """Get history of network analyses"""
    try:
        analysis_dir = os.path.join(BASE_DIR, 'src', 'data', 'analysis')
        if not os.path.exists(analysis_dir):
            return jsonify([])
            
        analyses = []
        for file in os.listdir(analysis_dir):
            if file.endswith('_analysis.json'):
                file_path = os.path.join(analysis_dir, file)
                with open(file_path, 'r') as f:
                    analysis_data = json.load(f)
                    analyses.append(analysis_data)
        
        # Sort by timestamp, most recent first
        analyses.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return jsonify(analyses)
        
    except Exception as e:
        logger.error(f"Error getting analysis history: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/topology')
def get_topology():
    """Get latest network topology data"""
    try:
        topology_dir = os.path.join(BASE_DIR, 'src', 'data', 'topology')
        if not os.path.exists(topology_dir):
            logger.error("Topology directory not found")
            return jsonify({'error': 'No topology data found'}), 404
            
        # Get all topology files
        topology_files = [f for f in os.listdir(topology_dir) 
                         if f.endswith('_topology.json')]
        
        if not topology_files:
            logger.error("No topology files found")
            return jsonify({'error': 'No topology data found'}), 404
            
        # Get the most recent topology file
        latest_file = max(topology_files, 
                         key=lambda x: os.path.getctime(os.path.join(topology_dir, x)))
        topology_path = os.path.join(topology_dir, latest_file)
        
        logger.info(f"Serving topology data from: {topology_path}")
        
        # Read and return the JSON data
        with open(topology_path, 'r') as f:
            topology_data = json.load(f)
            
        return jsonify(topology_data)
        
    except Exception as e:
        logger.error(f"Error serving topology data: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/networks')
def get_networks():
    """Get available networks for scanning"""
    try:
        logger.info("Starting network discovery...")
        
        # Test if netifaces is working
        try:
            interfaces = netifaces.interfaces()
            logger.info(f"Available interfaces: {interfaces}")
        except Exception as e:
            logger.error(f"Error getting interfaces: {e}", exc_info=True)
            
        # Get networks from discovery
        discovery = NetworkDiscovery()
        networks = discovery.get_local_networks()
        
        return jsonify({
            'status': 'success',
            'networks': networks,
            'message': 'Successfully retrieved networks'
        })
        
    except Exception as e:
        logger.error(f"Error getting networks: {str(e)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'networks': [],
            'message': str(e)
        })

@app.route('/api/comparison/<comparison_id>/report', methods=['GET'])
def download_analysis_report(comparison_id):
    """Download analysis report for a comparison"""
    try:
        report_dir = os.path.join(BASE_DIR, 'src', 'data', 'comparisons', comparison_id)
        
        # Check if report already exists
        report_file = os.path.join(report_dir, 'network_analysis_report.md')
        if os.path.exists(report_file):
            return send_file(
                report_file,
                mimetype='text/markdown',
                as_attachment=True,
                download_name=f'network_analysis_report_{comparison_id}.md'
            )
        
        # Load analysis results
        results_file = os.path.join(report_dir, 'results.json')
        if not os.path.exists(results_file):
            return jsonify({'error': 'Analysis results not found'}), 404
            
        with open(results_file, 'r') as f:
            results = json.load(f)
            
        # Generate report using the visualization module
        create_markdown_report(
            before_data=results.get('before_data', {}),
            after_data=results.get('after_data', {}),
            changes=results.get('structural_changes', {}),
            metrics_before=results.get('before_metrics', {}),
            metrics_after=results.get('after_metrics', {}),
            critical_paths=results.get('critical_paths', {}),
            bridge_nodes=results.get('bridge_nodes', []),
            segmentation=results.get('segmentation', {}),
            output_folder=report_dir
        )
            
        return send_file(
            report_file,
            mimetype='text/markdown',
            as_attachment=True,
            download_name=f'network_analysis_report_{comparison_id}.md'
        )
        
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/<file_id>')
def get_scan_file(file_id):
    """Get scan file by ID"""
    try:
        scans_dir = os.path.join(BASE_DIR, 'src', 'data', 'scans')
        scan_file = os.path.join(scans_dir, f"{file_id}.json")
        
        # If file doesn't exist directly, try to find it by matching pattern
        if not os.path.exists(scan_file):
            matching_files = [f for f in os.listdir(scans_dir) 
                            if f.startswith(file_id) and f.endswith('.json')]
            if matching_files:
                scan_file = os.path.join(scans_dir, matching_files[0])
            else:
                logger.error(f"Scan file not found: {scan_file}")
                return jsonify({'error': f'Scan file not found: {file_id}'}), 404

        logger.info(f"Loading scan file: {scan_file}")
        with open(scan_file, 'r') as f:
            scan_data = json.load(f)
            
        return jsonify(scan_data)
        
    except Exception as e:
        logger.error(f"Error loading scan file: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/topology/scan/<scan_id>')
def get_topology_by_scan_id(scan_id):
    """Get network topology data for a specific scan"""
    try:
        scans_dir = os.path.join(BASE_DIR, 'src', 'data', 'scans')
        
        # Look for files containing the scan_id
        matching_files = [f for f in os.listdir(scans_dir) 
                         if scan_id in f and not f.endswith('_analysis.json')]
        
        if not matching_files:
            logger.error(f"No scan results found for ID: {scan_id}")
            return jsonify({'error': 'Scan results not found'}), 404
            
        # Use the most recent file if multiple matches
        scan_file = os.path.join(scans_dir, matching_files[0])
        if len(matching_files) > 1:
            scan_file = os.path.join(scans_dir, 
                max(matching_files, key=lambda f: os.path.getctime(os.path.join(scans_dir, f))))
            
        logger.info(f"Loading topology data from: {scan_file}")
        with open(scan_file, 'r') as f:
            scan_data = json.load(f)
            
            # Extract topology data from scan results
            hosts = scan_data.get('hosts', [])
            nodes = []
            links = []
            
            # Create nodes for each host
            for host in hosts:
                if host.get('status') == 'up':
                    node = {
                        'id': host.get('ip_address'),
                        'label': host.get('ip_address'),
                        'services': [f"{p.get('service', 'unknown')}:{p.get('port')}" 
                                   for p in host.get('ports', []) if p.get('state') == 'open']
                    }
                    nodes.append(node)
            
            # Create links between nodes based on network proximity
            for i, node1 in enumerate(nodes):
                ip1 = ipaddress.ip_address(node1['id'])
                for node2 in nodes[i+1:]:
                    ip2 = ipaddress.ip_address(node2['id'])
                    # Link nodes in the same subnet
                    if ip1.version == ip2.version and ip1.is_private == ip2.is_private:
                        links.append({
                            'source': node1['id'],
                            'target': node2['id']
                        })
            
            topology_data = {
                'nodes': nodes,
                'links': links
            }
            
            return jsonify(topology_data)
            
    except Exception as e:
        logger.error(f"Error getting topology data: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/comparison/create', methods=['POST'])
def create_comparison():
    """Create a comparison between two network snapshots"""
    try:
        data = request.get_json()
        before_scan_id = data.get('before_scan')
        after_scan_id = data.get('after_scan')
        
        if not before_scan_id or not after_scan_id:
            return jsonify({'error': 'Both before and after scan IDs are required'}), 400
            
        # Load scan data
        scans_dir = os.path.join(BASE_DIR, 'src', 'data', 'scans')
        before_files = [f for f in os.listdir(scans_dir) if before_scan_id in f and not f.endswith('_analysis.json')]
        after_files = [f for f in os.listdir(scans_dir) if after_scan_id in f and not f.endswith('_analysis.json')]
        
        if not before_files or not after_files:
            return jsonify({'error': 'Scan files not found'}), 404
            
        # Load scan data
        with open(os.path.join(scans_dir, before_files[0])) as f:
            before_data = json.load(f)
        with open(os.path.join(scans_dir, after_files[0])) as f:
            after_data = json.load(f)
            
        # Create NetworkX graphs
        before_graph = create_network_from_scan(before_data)
        after_graph = create_network_from_scan(after_data)
        
        logger.info(f"Before graph: {len(before_graph.nodes())} nodes, {len(before_graph.edges())} edges")
        logger.info(f"After graph: {len(after_graph.nodes())} nodes, {len(after_graph.edges())} edges")
            
        # Calculate changes and metrics
        changes = analyze_changes(before_graph, after_graph)
        before_metrics = calculate_network_metrics(before_graph)
        after_metrics = calculate_network_metrics(after_graph)
        
        # Additional analysis
        critical_paths = identify_critical_paths(after_graph)
        bridge_nodes = identify_bridge_nodes(after_graph)
        segmentation = calculate_network_segmentation(after_graph)
        
        # Create comparison result
        comparison_id = f"comparison_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        output_dir = os.path.join(BASE_DIR, 'src', 'data', 'comparisons', comparison_id)
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate visualizations
        visualize_network_overview(before_graph, after_graph, output_dir)
        visualize_critical_infrastructure(after_graph, bridge_nodes, critical_paths, output_dir)
        
        # Calculate centrality changes for heatmap
        centrality_metrics = {
            'Degree': nx.degree_centrality,
            'Betweenness': nx.betweenness_centrality,
            'Closeness': nx.closeness_centrality,
            'Eigenvector': nx.eigenvector_centrality
        }
        
        centrality_changes = pd.DataFrame()
        for metric_name, metric_func in centrality_metrics.items():
            try:
                before_values = pd.Series(metric_func(before_graph))
                after_values = pd.Series(metric_func(after_graph))
                centrality_changes[metric_name] = after_values - before_values.reindex(after_values.index)
            except:
                logger.warning(f"Could not calculate {metric_name} centrality changes")
        
        if not centrality_changes.empty:
            visualize_node_metrics_heatmap(centrality_changes, output_dir)
        
        # Create markdown report
        create_markdown_report(
            before_data=before_data,
            after_data=after_data,
            changes=changes,
            metrics_before=before_metrics,
            metrics_after=after_metrics,
            critical_paths=critical_paths,
            bridge_nodes=bridge_nodes,
            segmentation=segmentation,
            output_folder=output_dir
        )
        
        # Prepare response
        result = {
            'comparison_id': comparison_id,
            'timestamp': datetime.now().isoformat(),
            'structural_changes': changes,
            'before_metrics': before_metrics,
            'after_metrics': after_metrics,
            'metric_changes': {
                'Average_Clustering': after_metrics['Average_Clustering'] - before_metrics['Average_Clustering'],
                'Network_Density': after_metrics['Network_Density'] - before_metrics['Network_Density'],
                'Average_Degree': after_metrics['Average_Degree'] - before_metrics['Average_Degree'],
                'Components': after_metrics['Components'] - before_metrics['Components']
            },
            'analysis': {
                'critical_paths': len(critical_paths),
                'bridge_nodes': len(bridge_nodes),
                'segments': segmentation['num_segments'],
                'isolation_score': segmentation['isolation_score']
            },
            'report_url': f'/api/comparisons/{comparison_id}/report',
            'visualizations': {
                'network_overview': f'/api/comparisons/{comparison_id}/network_overview.png',
                'critical_infrastructure': f'/api/comparisons/{comparison_id}/critical_infrastructure.png',
                'node_metrics': f'/api/comparisons/{comparison_id}/node_metrics_changes_heatmap.png'
            }
        }
        
        # Save result
        with open(os.path.join(output_dir, 'results.json'), 'w') as f:
            json.dump(result, f, indent=2)
            
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error creating comparison: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/comparisons/<comparison_id>/report')
def get_comparison_report(comparison_id):
    """Get the markdown report for a comparison"""
    try:
        report_path = os.path.join(BASE_DIR, 'src', 'data', 'comparisons', comparison_id, 'network_analysis_report.md')
        if not os.path.exists(report_path):
            return jsonify({'error': 'Report not found'}), 404
            
        with open(report_path, 'r') as f:
            content = f.read()
            
        return Response(content, mimetype='text/markdown')
        
    except Exception as e:
        logger.error(f"Error getting comparison report: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/comparisons/<comparison_id>/<path:filename>')
def get_comparison_file(comparison_id, filename):
    """Get a file from a comparison (visualization or report)"""
    try:
        file_path = os.path.join(BASE_DIR, 'src', 'data', 'comparisons', comparison_id, filename)
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404
            
        return send_file(file_path)
        
    except Exception as e:
        logger.error(f"Error getting comparison file: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    try:
        logger.info("Starting Flask server...")
        # Bind to all interfaces on port 5050
        app.run(host='0.0.0.0', port=5050, debug=True)
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        input("Press Enter to exit...")  # Keep window open on error