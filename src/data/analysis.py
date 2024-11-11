# src/analyzer/network_analysis.py

import pandas as pd
import numpy as np
import networkx as nx
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import logging
from pathlib import Path
import os
import json
from datetime import datetime

class NetworkAnalyzer:
    def __init__(self, data_dir='src/data'):
        """Initialize the Network Analyzer"""
        self.data_dir = data_dir
        self.output_dir = os.path.join(data_dir, 'analysis')
        os.makedirs(self.output_dir, exist_ok=True)
        
        logging.basicConfig(
            filename=os.path.join(self.output_dir, 'analysis.log'),
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def create_graph_from_scan(self, scan_result):
        """Create a NetworkX graph from scan results"""
        self.G = nx.Graph()
        
        # Add nodes from hosts
        for host in scan_result.hosts:
            node_id = host['ip_address']
            self.G.add_node(
                node_id,
                label=host.get('hostname', node_id),
                type=host.get('device_type', 'unknown'),
                os=host.get('os_match', 'unknown')
            )
            
        # Add edges based on discovered connections
        for host in scan_result.hosts:
            source = host['ip_address']
            for port in host.get('open_ports', []):
                if 'connections' in port:
                    for target in port['connections']:
                        self.G.add_edge(source, target)
        
        return self.G

    def analyze_network_structure(self):
        """Analyze basic network structure"""
        self.logger.info("Analyzing network structure")
        
        try:
            components = list(nx.connected_components(self.G))
            cycles = list(nx.cycle_basis(self.G))
            endpoints = [node for node, degree in dict(self.G.degree()).items() if degree == 1]
            
            self.centrality_measures = {
                'Degree_Centrality': nx.degree_centrality(self.G),
                'Betweenness_Centrality': nx.betweenness_centrality(self.G),
                'Closeness_Centrality': nx.closeness_centrality(self.G),
                'Eigenvector_Centrality': nx.eigenvector_centrality(self.G, max_iter=1000)
            }
            
            return {
                'components': [list(comp) for comp in components],
                'cycles': cycles,
                'endpoints': endpoints,
                'density': nx.density(self.G),
                'is_tree': nx.is_tree(self.G),
                'is_forest': nx.is_forest(self.G),
                'average_degree': sum(dict(self.G.degree()).values()) / self.G.number_of_nodes(),
                'centrality': self.centrality_measures
            }
        except Exception as e:
            self.logger.error(f"Error in network structure analysis: {e}")
            raise

    def analyze_security_metrics(self):
        """Calculate security metrics for each node"""
        try:
            metrics = {}
            for node in self.G.nodes():
                node_type = self.G.nodes[node].get('type', 'unknown')
                metrics[node] = {
                    'degree': self.G.degree(node),
                    'betweenness': self.centrality_measures['Betweenness_Centrality'][node],
                    'neighbors': list(self.G.neighbors(node)),
                    'is_endpoint': self.G.degree(node) == 1,
                    'device_type': node_type,
                    'os': self.G.nodes[node].get('os', 'unknown')
                }
            return metrics
        except Exception as e:
            self.logger.error(f"Error calculating security metrics: {e}")
            raise

    def detect_anomalies(self):
        """Detect network anomalies using Isolation Forest"""
        try:
            features = pd.DataFrame()
            
            # Add centrality measures as features
            for measure, values in self.centrality_measures.items():
                features[measure] = pd.Series(values)
            
            # Add degree as a feature
            features['degree'] = pd.Series(dict(self.G.degree()))
            
            # Scale features
            scaler = StandardScaler()
            features_scaled = scaler.fit_transform(features)
            
            # Detect anomalies
            iso_forest = IsolationForest(contamination=0.1, random_state=42)
            features['anomaly'] = iso_forest.fit_predict(features_scaled)
            features['anomaly_score'] = iso_forest.score_samples(features_scaled)
            
            # Calculate risk scores (0-100)
            min_score = features['anomaly_score'].min()
            max_score = features['anomaly_score'].max()
            features['risk_score'] = 100 * (features['anomaly_score'] - max_score) / (min_score - max_score)
            
            return features.to_dict(orient='index')
        except Exception as e:
            self.logger.error(f"Error in anomaly detection: {e}")
            raise

    def analyze_network(self, scan_result):
        """Run complete network analysis"""
        try:
            # Create graph from scan results
            self.create_graph_from_scan(scan_result)
            
            # Run analyses
            structure = self.analyze_network_structure()
            security_metrics = self.analyze_security_metrics()
            anomalies = self.detect_anomalies()
            
            # Compile results
            analysis_result = {
                'timestamp': datetime.now().isoformat(),
                'network_structure': structure,
                'security_metrics': security_metrics,
                'anomalies': anomalies,
                'summary': {
                    'total_nodes': self.G.number_of_nodes(),
                    'total_edges': self.G.number_of_edges(),
                    'high_risk_nodes': sum(1 for node in anomalies.values() 
                                         if node['risk_score'] > 75),
                    'isolated_nodes': len(structure['endpoints']),
                    'components': len(structure['components'])
                }
            }
            
            # Save analysis results
            output_file = os.path.join(self.output_dir, 
                                     f'analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
            with open(output_file, 'w') as f:
                json.dump(analysis_result, f, indent=2, default=str)
            
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"Error in network analysis: {e}")
            raise