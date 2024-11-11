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
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter
import warnings
from itertools import combinations

warnings.filterwarnings('ignore')

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

    def get_host_identifier(self, host):
        """Extract host identifier from host data with fallbacks"""
        try:
            # Try different common field names for host identification
            for field in ['ip_address', 'ip', 'address', 'host', 'hostname']:
                if field in host and host[field]:
                    return str(host[field])
            
            # If no standard fields found, look for any field containing 'ip' or 'address'
            for field in host.keys():
                if 'ip' in field.lower() or 'address' in field.lower():
                    return str(host[field])
            
            # If still no identifier found, use the first value that looks like an IP
            for value in host.values():
                if isinstance(value, str) and '.' in value:
                    parts = value.split('.')
                    if len(parts) == 4 and all(part.isdigit() for part in parts):
                        return value
            
            raise ValueError(f"No valid host identifier found in host data: {host}")
            
        except Exception as e:
            self.logger.error(f"Error extracting host identifier: {str(e)}")
            raise

    def create_graph_from_scan(self, scan_result):
        """Create a NetworkX graph from scan results"""
        self.logger.info("Creating network graph from scan results")
        self.G = nx.Graph()
        
        try:
            # First pass - collect all nodes
            for host in scan_result.hosts:
                try:
                    node_id = self.get_host_identifier(host)
                    node_attrs = {
                        'label': host.get('hostname', node_id),
                        'type': host.get('device_type', host.get('type', 'unknown')),
                        'os': host.get('os_match', host.get('os', 'unknown')),
                        'status': host.get('status', 'unknown')
                    }
                    self.G.add_node(node_id, **node_attrs)
                    self.logger.debug(f"Added node: {node_id}")
                except Exception as e:
                    self.logger.warning(f"Error processing host: {str(e)}")
                    continue

            # Second pass - add edges
            for host in scan_result.hosts:
                try:
                    source = self.get_host_identifier(host)
                    # Check for open_ports and their connections
                    if 'open_ports' in host:
                        for port in host['open_ports']:
                            if isinstance(port, dict) and 'connections' in port:
                                for target in port['connections']:
                                    if isinstance(target, str):
                                        self.G.add_edge(source, target)
                                        self.logger.debug(f"Added edge: {source} -> {target}")
                    
                    # Also check direct connections if present
                    if 'connections' in host:
                        for target in host['connections']:
                            if isinstance(target, str):
                                self.G.add_edge(source, target)
                                self.logger.debug(f"Added direct edge: {source} -> {target}")
                except Exception as e:
                    self.logger.warning(f"Error processing connections for host: {str(e)}")
                    continue

            # If no edges were added, try to infer connections from common network topology
            if self.G.number_of_edges() == 0:
                self.logger.info("No explicit connections found, inferring network topology")
                nodes = list(self.G.nodes())
                # Look for potential router/gateway nodes
                potential_routers = [n for n in nodes if any(x in str(n).lower() 
                                   for x in ['router', 'gateway', '192.168.1.1', '192.168.0.1'])]
                
                if potential_routers:
                    router = potential_routers[0]
                    # Connect all other nodes to the router
                    for node in nodes:
                        if node != router:
                            self.G.add_edge(router, node)
                            self.logger.debug(f"Added inferred edge: {router} -> {node}")

            self.logger.info(f"Created graph with {self.G.number_of_nodes()} nodes and {self.G.number_of_edges()} edges")
            return self.G
        
        except Exception as e:
            self.logger.error(f"Error creating graph: {str(e)}")
            raise

    def analyze_network_structure(self):
        """Analyze basic network structure"""
        self.logger.info("Analyzing network structure")
        
        try:
            if self.G.number_of_nodes() == 0:
                raise ValueError("Graph is empty - no nodes found")

            # Calculate basic metrics
            components = list(nx.connected_components(self.G))
            cycles = list(nx.cycle_basis(self.G))
            endpoints = [node for node, degree in dict(self.G.degree()).items() if degree == 1]
            
            # Calculate density correctly
            num_nodes = self.G.number_of_nodes()
            num_edges = self.G.number_of_edges()
            density = 0 if num_nodes <= 1 else (2.0 * num_edges) / (num_nodes * (num_nodes - 1))
            
            # Calculate average degree directly
            total_degree = sum(dict(self.G.degree()).values())
            avg_degree = 0 if num_nodes == 0 else total_degree / num_nodes
            
            # Calculate centrality measures
            self.centrality_measures = {
                'Degree_Centrality': nx.degree_centrality(self.G),
                'Betweenness_Centrality': nx.betweenness_centrality(self.G),
                'Closeness_Centrality': nx.closeness_centrality(self.G),
                'Eigenvector_Centrality': nx.eigenvector_centrality(self.G, max_iter=1000)
            }
            
            # Log the calculations for debugging
            self.logger.debug(f"Number of nodes: {num_nodes}")
            self.logger.debug(f"Number of edges: {num_edges}")
            self.logger.debug(f"Density calculation: {density}")
            self.logger.debug(f"Average degree calculation: {avg_degree}")
            self.logger.debug(f"Number of endpoints: {len(endpoints)}")
            
            return {
                'components': [list(comp) for comp in components],
                'cycles': cycles,
                'endpoints': endpoints,
                'density': density,
                'is_tree': nx.is_tree(self.G),
                'is_forest': nx.is_forest(self.G),
                'average_degree': avg_degree,
                'centrality': self.centrality_measures,
                'total_nodes': num_nodes,
                'total_edges': num_edges,
                'connected_components': len(components)
            }
            
        except Exception as e:
            self.logger.error(f"Error in network structure analysis: {e}")
            raise

    def analyze_bottlenecks(self):
        """Analyze network bottlenecks using spectral properties"""
        try:
            if self.G.number_of_nodes() == 0:
                return {}

            laplacian = nx.laplacian_matrix(self.G).todense()
            eigenvalues, eigenvectors = np.linalg.eigh(laplacian)
            
            n_components = min(3, self.G.number_of_nodes() - 1)
            bottleneck_scores = {}
            
            for node in self.G.nodes():
                idx = list(self.G.nodes()).index(node)
                score = 0
                for i in range(1, n_components + 1):
                    weight = 1 / i
                    score += weight * abs(eigenvectors[idx, i])
                    
                degree = self.G.degree(node)
                if degree > 0:
                    score = score / np.sqrt(degree)
                    
                bottleneck_scores[node] = score

            # Calculate threshold based on non-zero scores
            non_zero_scores = [s for s in bottleneck_scores.values() if s > 0]
            threshold = np.percentile(non_zero_scores, 75) if non_zero_scores else 0
            
            critical_bottlenecks = {
                node: score for node, score in bottleneck_scores.items() 
                if score > threshold
            }

            # Calculate flow centrality using random walks
            n_walks = min(1000, self.G.number_of_nodes() * 10)
            walk_length = min(5, self.G.number_of_nodes())
            flow_counts = {node: 0 for node in self.G.nodes()}
            
            for _ in range(n_walks):
                for start in self.G.nodes():
                    current = start
                    for _ in range(walk_length):
                        neighbors = list(self.G.neighbors(current))
                        if not neighbors:
                            break
                        current = np.random.choice(neighbors)
                        flow_counts[current] += 1
            
            max_flow = max(flow_counts.values()) if flow_counts else 1
            flow_centrality = {
                node: count/max_flow 
                for node, count in flow_counts.items()
            }
            
            bottleneck_analysis = {}
            for node in self.G.nodes():
                label = self.G.nodes[node].get('label', str(node))
                bottleneck_analysis[label] = {
                    'spectral_score': bottleneck_scores[node],
                    'flow_centrality': flow_centrality[node],
                    'is_critical': node in critical_bottlenecks,
                    'degree': self.G.degree(node),
                    'betweenness': self.centrality_measures['Betweenness_Centrality'][node]
                }
            
            return bottleneck_analysis
            
        except Exception as e:
            self.logger.error(f"Error in bottleneck analysis: {e}")
            return {}

    def analyze_security_metrics(self):
        """Calculate security metrics for each node"""
        try:
            if not hasattr(self, 'centrality_measures'):
                raise ValueError("Centrality measures not calculated. Run analyze_network_structure first.")

            metrics = {}
            for node in self.G.nodes():
                try:
                    node_type = self.G.nodes[node].get('type', 'unknown')
                    metrics[node] = {
                        'degree': self.G.degree(node),
                        'betweenness': self.centrality_measures['Betweenness_Centrality'][node],
                        'neighbors': list(self.G.neighbors(node)),
                        'is_endpoint': self.G.degree(node) == 1,
                        'device_type': node_type,
                        'os': self.G.nodes[node].get('os', 'unknown'),
                        'local_clustering': nx.clustering(self.G, node),
                        'connectivity_risk': len(list(self.G.neighbors(node))) / self.G.number_of_nodes()
                    }
                except Exception as e:
                    self.logger.warning(f"Error calculating metrics for node {node}: {str(e)}")
                    continue
                    
            return metrics
        except Exception as e:
            self.logger.error(f"Error calculating security metrics: {e}")
            raise

    def detect_anomalies(self):
        """Detect network anomalies using Isolation Forest"""
        try:
            if not hasattr(self, 'centrality_measures'):
                raise ValueError("Centrality measures not calculated. Run analyze_network_structure first.")

            if len(self.G.nodes()) < 2:
                self.logger.warning("Not enough nodes for meaningful anomaly detection")
                return {}

            features = pd.DataFrame()
            
            # Add centrality measures as features
            for measure, values in self.centrality_measures.items():
                features[measure] = pd.Series(values)
            
            # Add degree as a feature
            features['degree'] = pd.Series(dict(self.G.degree()))
            
            # Add clustering coefficient
            features['clustering'] = pd.Series(nx.clustering(self.G))
            
            # Handle edge cases
            if features.empty or features.isnull().all().all():
                raise ValueError("No valid features for anomaly detection")
            
            # Fill any remaining NaN values with 0
            features = features.fillna(0)
            
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
            
            # Handle edge case where min_score equals max_score
            if min_score == max_score:
                features['risk_score'] = 50  # Assign neutral risk score
            else:
                features['risk_score'] = 100 * (features['anomaly_score'] - max_score) / (min_score - max_score)
            
            return features.to_dict(orient='index')
        except Exception as e:
            self.logger.error(f"Error in anomaly detection: {e}")
            raise

    def calculate_spectral_metrics(self):
        """Calculate spectral metrics of the network"""
        try:
            if self.G.number_of_nodes() < 2:
                return {
                    'spectral_radius': 0,
                    'fiedler_value': 0,
                    'fiedler_components': []
                }

            laplacian_matrix = nx.laplacian_matrix(self.G).todense()
            eigenvalues, eigenvectors = np.linalg.eigh(laplacian_matrix)
            
            spectral_radius = float(max(abs(eigenvalues)))
            
            # Get Fiedler value (second smallest eigenvalue)
            idx = eigenvalues.argsort()
            fiedler_value = float(eigenvalues[idx[1]])
            fiedler_vector = eigenvectors[:, idx[1]]
            
            # Get node contributions to Fiedler vector
            node_labels = list(self.G.nodes())
            fiedler_components = list(zip(node_labels, fiedler_vector))
            fiedler_components.sort(key=lambda x: abs(x[1]), reverse=True)
            
            return {
                'spectral_radius': spectral_radius,
                'fiedler_value': fiedler_value,
                'fiedler_components': fiedler_components
            }
        except Exception as e:
            self.logger.error(f"Error calculating spectral metrics: {e}")
            return {
                'spectral_radius': 0,
                'fiedler_value': 0,
                'fiedler_components': []
            }

    def analyze_network(self, scan_result):
        """Run complete network analysis"""
        try:
            if not hasattr(scan_result, 'hosts') or not scan_result.hosts:
                raise ValueError("Invalid scan result: no hosts data found")

            # Create graph from scan results
            self.create_graph_from_scan(scan_result)
            
            if self.G.number_of_nodes() == 0:
                raise ValueError("No valid nodes could be created from scan results")
            
            # Run analyses
            structure = self.analyze_network_structure()
            security_metrics = self.analyze_security_metrics()
            bottleneck_analysis = self.analyze_bottlenecks()
            anomalies = self.detect_anomalies()
            spectral_metrics = self.calculate_spectral_metrics()
            
            # Compile results
            analysis_result = {
                'timestamp': datetime.now().isoformat(),
                'network_structure': structure,
                'security_metrics': security_metrics,
                'bottleneck_analysis': bottleneck_analysis,
                'anomalies': anomalies,
                'spectral_metrics': spectral_metrics,
                'summary': {
                    'total_nodes': self.G.number_of_nodes(),
                    'total_edges': self.G.number_of_edges(),
                    'high_risk_nodes': sum(1 for node in anomalies.values() 
                                         if node.get('risk_score', 0) > 75),
                    'isolated_nodes': len(structure['endpoints']),
                    'components': len(structure['components']),
                    'average_degree': structure['average_degree'],
                    'network_density': structure['density'],
                    'critical_bottlenecks': sum(1 for metrics in bottleneck_analysis.values() 
                                              if metrics['is_critical']),
                    'spectral_radius': spectral_metrics['spectral_radius'],
                }
            }
            
            # Save analysis results
            try:
                output_file = os.path.join(self.output_dir, 
                                         f'analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
                with open(output_file, 'w') as f:
                    json.dump(analysis_result, f, indent=2, default=str)
                self.logger.info(f"Analysis results saved to {output_file}")
            except Exception as e:
                self.logger.error(f"Failed to save analysis results: {str(e)}")
                # Continue since analysis was successful
            
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"Error in network analysis: {e}")
            raise

    def visualize_network(self):
        """Generate network visualization"""
        try:
            plt.figure(figsize=(12, 8))
            pos = nx.spring_layout(self.G)
            
            # Draw nodes with different sizes based on degree
            node_sizes = [3000 * (0.1 + self.G.degree(node)) for node in self.G.nodes()]
            node_colors = [self.G.degree(node) for node in self.G.nodes()]
            
            nx.draw_networkx_nodes(self.G, pos, 
                                 node_size=node_sizes,
                                 node_color=node_colors,
                                 cmap=plt.cm.YlOrRd)
            
            # Draw edges
            nx.draw_networkx_edges(self.G, pos, alpha=0.2)
            
            # Add labels
            labels = nx.get_node_attributes(self.G, 'label')
            nx.draw_networkx_labels(self.G, pos, labels, font_size=8)
            
            plt.title("Network Topology Visualization")
            plt.axis('off')
            
            # Save visualization
            viz_file = os.path.join(self.output_dir, 'network_visualization.png')
            plt.savefig(viz_file, bbox_inches='tight', dpi=300)
            plt.close()
            
            self.logger.info(f"Network visualization saved to {viz_file}")
            
        except Exception as e:
            self.logger.error(f"Error generating network visualization: {e}")
            raise

    def generate_network_stats(self):
        """Generate detailed network statistics"""
        try:
            stats = {
                'Basic Metrics': {
                    'Nodes': self.G.number_of_nodes(),
                    'Edges': self.G.number_of_edges(),
                    'Density': nx.density(self.G),
                    'Average Degree': sum(dict(self.G.degree()).values()) / self.G.number_of_nodes(),
                    'Average Clustering': nx.average_clustering(self.G),
                    'Number of Components': nx.number_connected_components(self.G)
                },
                'Centrality Statistics': {
                    measure: {
                        'max': max(values.values()),
                        'min': min(values.values()),
                        'mean': sum(values.values()) / len(values)
                    }
                    for measure, values in self.centrality_measures.items()
                },
                'Path Statistics': {
                    'Diameter': nx.diameter(self.G) if nx.is_connected(self.G) else 'Infinite',
                    'Average Path Length': nx.average_shortest_path_length(self.G) 
                                         if nx.is_connected(self.G) else 'Infinite'
                }
            }
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error generating network statistics: {e}")
            raise

    def calculate_vulnerability_score(self):
        """Calculate overall network vulnerability score"""
        try:
            # Collect various network metrics
            density = nx.density(self.G)
            avg_clustering = nx.average_clustering(self.G)
            avg_degree = sum(dict(self.G.degree()).values()) / self.G.number_of_nodes()
            
            # Calculate vulnerability components
            structural_vulnerability = (1 - density) * 0.3  # Less dense networks are more vulnerable
            degree_vulnerability = min(1, avg_degree / (self.G.number_of_nodes() - 1)) * 0.3
            clustering_vulnerability = (1 - avg_clustering) * 0.2
            
            # Add centralization component
            degree_centralization = max(dict(self.G.degree()).values()) / (self.G.number_of_nodes() - 1)
            centralization_vulnerability = degree_centralization * 0.2
            
            # Calculate total vulnerability score (0-100)
            total_score = 100 * (structural_vulnerability + 
                               degree_vulnerability + 
                               clustering_vulnerability + 
                               centralization_vulnerability)
            
            return {
                'total_score': total_score,
                'components': {
                    'structural': structural_vulnerability * 100,
                    'degree': degree_vulnerability * 100,
                    'clustering': clustering_vulnerability * 100,
                    'centralization': centralization_vulnerability * 100
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error calculating vulnerability score: {e}")
            raise