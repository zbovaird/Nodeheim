# src/app.py
from flask import Flask, render_template, jsonify, request, send_file, make_response
import sys
import os
import json
import logging
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
from collections import Counter
import os.path
import community  # For community detection
import pandas as pd
import seaborn as sns

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
from analyzer.topology import TopologyAnalyzer
from analyzer.network_analysis import NetworkAnalyzer
from api.analysis import analysis_bp

# Initialize Flask app
app = Flask(__name__)   

# Register the blueprint
app.register_blueprint(analysis_bp)

# Initialize analyzer
try:
    data_dir = os.path.join(BASE_DIR, 'src', 'data')
    analyzer = NetworkAnalyzer()
    analyzer.data_dir = data_dir
    analyzer.output_dir = os.path.join(data_dir, 'analysis')
    os.makedirs(analyzer.output_dir, exist_ok=True)
    analyzer.logger = logging.getLogger(__name__)
    logger.info("Network analyzer initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize analyzer: {str(e)}")
    raise

# Initialize scanner
try:
    scanner = NetworkScanner(output_dir=os.path.join(BASE_DIR, 'src', 'data'))
    logger.info("Scanner initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize scanner: {str(e)}")
    raise

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
    changes = {
        'New_Nodes': len(set(G2.nodes()) - set(G1.nodes())),
        'Removed_Nodes': len(set(G1.nodes()) - set(G2.nodes())),
        'New_Edges': len(set(G2.edges()) - set(G1.edges())),
        'Removed_Edges': len(set(G1.edges()) - set(G2.edges())),
        'Degree_Distribution_Change': sum((Counter(dict(G2.degree()).values()) - 
                                         Counter(dict(G1.degree()).values())).values())
    }
    
    metrics1 = {
        'Average_Clustering': nx.average_clustering(G1),
        'Network_Density': nx.density(G1),
        'Average_Degree': sum(dict(G1.degree()).values()) / G1.number_of_nodes(),
        'Components': nx.number_connected_components(G1)
    }
    
    metrics2 = {
        'Average_Clustering': nx.average_clustering(G2),
        'Network_Density': nx.density(G2),
        'Average_Degree': sum(dict(G2.degree()).values()) / G2.number_of_nodes(),
        'Components': nx.number_connected_components(G2)
    }
    
    return {
        'structural_changes': changes,
        'metric_changes': {k: metrics2[k] - metrics1[k] for k in metrics1},
        'before_metrics': metrics1,
        'after_metrics': metrics2
    }

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
        
        # 2. Port-based connections
        for port in host.get('ports', []):
            if port.get('state') == 'open':
                port_num = port.get('port')
                # Connect to other hosts with the same open port
                for other_host in scan_data.get('hosts', []):
                    if other_host['ip_address'] != source_ip:
                        other_ports = [p.get('port') for p in other_host.get('ports', []) 
                                     if p.get('state') == 'open']
                        if port_num in other_ports:
                            G.add_edge(source_ip, other_host['ip_address'])
        
        # 3. Service-based connections
        host_services = [s.get('name') for s in host.get('services', [])]
        for other_host in scan_data.get('hosts', []):
            if other_host['ip_address'] != source_ip:
                other_services = [s.get('name') for s in other_host.get('services', [])]
                # If hosts share any services, they might be connected
                if set(host_services) & set(other_services):
                    G.add_edge(source_ip, other_host['ip_address'])
        
        # 4. Subnet-based connections
        ip_parts = source_ip.split('.')
        for other_host in scan_data.get('hosts', []):
            other_ip = other_host['ip_address']
            if other_ip != source_ip:
                other_parts = other_ip.split('.')
                # Same /24 subnet
                if ip_parts[:3] == other_parts[:3]:
                    G.add_edge(source_ip, other_ip)
        
        # 5. Gateway connections
        gateway_ips = [h['ip_address'] for h in scan_data.get('hosts', [])
                      if h.get('device_type') in ['router', 'gateway']]
        for gateway_ip in gateway_ips:
            if gateway_ip != source_ip:
                G.add_edge(source_ip, gateway_ip)

    logger.info(f"Created network graph with {len(G.nodes())} nodes and {len(G.edges())} edges")
    logger.debug(f"Edge list: {list(G.edges())}")
    return G

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

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/comparison')
def comparison():
    return render_template('comparison.html')

@app.route('/api/snapshots')
def get_snapshots():
    """Get list of available network snapshots"""
    try:
        scans_dir = os.path.join(BASE_DIR, 'src', 'data', 'scans')
        if not os.path.exists(scans_dir):
            return jsonify({'snapshots': []})

        snapshots = []
        for file in os.listdir(scans_dir):
            if file.endswith('.json'):
                with open(os.path.join(scans_dir, file), 'r') as f:
                    data = json.load(f)
                    snapshots.append({
                        'id': file.replace('.json', ''),
                        'timestamp': data.get('timestamp'),
                        'type': data.get('scan_type')
                    })

        return jsonify({'snapshots': snapshots})
    except Exception as e:
        logger.error(f"Error getting snapshots: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/compare', methods=['POST'])
def compare_networks():
    try:
        data = request.json
        logger.info(f"Received comparison request with data: {data}")
        
        if not data or 'files' not in data:
            return jsonify({'error': 'No files specified'}), 400

        file_ids = data['files']
        if len(file_ids) < 2:
            return jsonify({'error': 'At least 2 files required'}), 400

        networks = []
        for file_id in file_ids:
            scan_file = os.path.join(BASE_DIR, 'src', 'data', 'scans', f'{file_id}.json')
            logger.info(f"Looking for scan file at: {scan_file}")
            
            if not os.path.exists(scan_file):
                logger.error(f"Scan file not found: {scan_file}")
                return jsonify({'error': f'Scan file not found: {file_id}'}), 404

            with open(scan_file, 'r') as f:
                scan_data = json.load(f)
                network = create_network_from_scan(scan_data)
                networks.append(network)
                logger.info(f"Loaded network with {len(network.nodes)} nodes and {len(network.edges)} edges")

        comparison_id = f"comparison_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        output_dir = os.path.join(BASE_DIR, 'src', 'data', 'comparisons', comparison_id)
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"Created output directory: {output_dir}")

        # Generate all analysis results
        results = analyze_network_changes(networks[0], networks[-1])
        centrality_before = calculate_node_centrality_metrics(networks[0])
        centrality_after = calculate_node_centrality_metrics(networks[-1])
        metric_changes = calculate_node_metrics_comparison(networks[0], networks[-1])
        robustness_analysis = analyze_network_robustness(networks[-1])
        kcore_analysis = analyze_kcore_security(networks[-1])
        kcore_changes = track_kcore_changes(networks[0], networks[-1])

        # Generate visualizations
        viz_success = visualize_network_overview(networks[0], networks[-1], output_dir)
        logger.info(f"Network overview visualization success: {viz_success}")

        bridge_nodes = identify_bridge_nodes(networks[-1])
        critical_paths = identify_critical_paths(networks[-1])
        infra_success = visualize_critical_infrastructure(networks[-1], bridge_nodes, critical_paths, output_dir)
        logger.info(f"Critical infrastructure visualization success: {infra_success}")

        kcore_viz_path = os.path.join(output_dir, 'kcore_analysis.png')
        visualize_kcore_security(networks[-1], kcore_analysis, kcore_viz_path)

        # Prepare complete analysis results
        complete_results = {
            'comparison_id': comparison_id,
            'timestamp': datetime.now().isoformat(),
            'structural_changes': results['structural_changes'],
            'metric_changes': metric_changes,
            'before_metrics': results['before_metrics'],
            'after_metrics': results['after_metrics'],
            'centrality_before': centrality_before,
            'centrality_after': centrality_after,
            'robustness_analysis': robustness_analysis,
            'kcore_analysis': kcore_analysis,
            'kcore_changes': kcore_changes.to_dict('records') if not kcore_changes.empty else [],
            'bridge_nodes': bridge_nodes,
            'critical_paths': critical_paths
        }

        # Save complete results
        results_file = os.path.join(output_dir, 'results.json')
        with open(results_file, 'w') as f:
            json.dump(complete_results, f, indent=2, default=str)
        logger.info(f"Saved complete analysis results to {results_file}")

        return jsonify(complete_results)

    except Exception as e:
        logger.error(f"Comparison failed: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

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

@app.route('/api/networks')
def get_networks():
    """Get available networks for scanning"""
    try:
        networks = NetworkDiscovery.get_local_networks()
        logger.info(f"Found networks: {networks}")
        return jsonify({
            'status': 'success',
            'networks': networks
        })
    except Exception as e:
        logger.error(f"Error getting networks: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/comparison/<comparison_id>/report', methods=['GET'])
def download_analysis_report(comparison_id):
    try:
        report_dir = os.path.join(BASE_DIR, 'src', 'data', 'comparisons', comparison_id)
        
        # Load analysis results
        with open(os.path.join(report_dir, 'results.json'), 'r') as f:
            results = json.load(f)
        
        # Generate comprehensive report
        report = {
            'timestamp': datetime.now().isoformat(),
            'comparison_id': comparison_id,
            'structural_changes': results.get('structural_changes', {}),
            'metric_changes': results.get('metric_changes', {}),
            'kcore_analysis': results.get('kcore_analysis', {}),
            'kcore_changes': results.get('kcore_changes', []),
            'robustness_analysis': results.get('robustness_analysis', {})
        }
        
        # Convert to JSON
        report_json = json.dumps(report, indent=2)
        
        # Create response
        response = make_response(report_json)
        response.headers['Content-Type'] = 'application/json'
        response.headers['Content-Disposition'] = f'attachment; filename=analysis_report_{comparison_id}.json'
        
        return response
        
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050, debug=True)