# src/app.py
from flask import Flask, render_template, jsonify, request, send_file
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
        
        # Generate "after" network visualization
        plt.figure(figsize=(10, 8))
        pos2 = nx.spring_layout(G2, k=1, iterations=50)
        nx.draw(G2, pos2, 
               node_size=500,
               node_color='lightgreen',
               edge_color='gray',
               alpha=0.6,
               with_labels=True,
               font_size=8,
               font_color='white',
               font_weight='bold')
        plt.title('Network After', color='white', pad=20)
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
    
    # Add nodes
    for host in scan_data.get('hosts', []):
        G.add_node(host['ip_address'], **{
            'type': host.get('device_type', 'unknown'),
            'services': host.get('services', []),
            'os': host.get('os_info', {}).get('os_match', 'unknown')
        })
    
    return G

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
    """Compare multiple network snapshots"""
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

        results = analyze_network_changes(networks[0], networks[-1])
        logger.info(f"Analysis results: {results}")

        viz_success = visualize_network_overview(networks[0], networks[-1], output_dir)
        logger.info(f"Network overview visualization success: {viz_success}")

        bridge_nodes = identify_bridge_nodes(networks[-1])
        critical_paths = identify_critical_paths(networks[-1])
        infra_success = visualize_critical_infrastructure(networks[-1], bridge_nodes, critical_paths, output_dir)
        logger.info(f"Critical infrastructure visualization success: {infra_success}")

        response_data = {
            'comparison_id': comparison_id,
            **results
        }
        logger.info(f"Sending response: {response_data}")
        return jsonify(response_data)

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050, debug=True)