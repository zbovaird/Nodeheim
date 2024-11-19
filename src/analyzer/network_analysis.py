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
    def __init__(self, data_dir=None):
        """Initialize the Network Analyzer"""
        self.data_dir = data_dir or 'src/data'
        self.output_dir = os.path.join(self.data_dir, 'analysis')
        os.makedirs(self.output_dir, exist_ok=True)
        
        logging.basicConfig(
            filename=os.path.join(self.output_dir, 'analysis.log'),
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Define system classifications for ICS/SCADA analysis
        #self.control_systems = ['PLC 1', 'PLC 2', 'PLC 3', 'PLC 4', 'PLC 5']
        #self.hmi_systems = ['HMI 1', 'HMI 2', 'HMI 3']
        #self.field_devices = ['Sensor 1', 'Actuator 1'] + [f'Device {i}' for i in range(1, 12)]

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
                        'status': host.get('status', 'unknown'),
                        'services': host.get('services', []),
                        'vulnerabilities': host.get('vulnerabilities', [])
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
                                        self.G.add_edge(source, target, port=port.get('port_number'))
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
            
            # Find articulation points (critical nodes)
            articulation_points = list(nx.articulation_points(self.G))
            
            # Calculate bridge edges
            bridges = list(nx.bridges(self.G))
            
            # Calculate clustering coefficient per node
            clustering = nx.clustering(self.G)
            
            # Identify potential bottlenecks
            potential_bottlenecks = [node for node, degree in dict(self.G.degree()).items()
                                   if degree > avg_degree * 1.5]
            
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
                'connected_components': len(components),
                'articulation_points': articulation_points,
                'bridges': bridges,
                'clustering': clustering,
                'potential_bottlenecks': potential_bottlenecks,
                'average_clustering': nx.average_clustering(self.G),
                'degree_histogram': nx.degree_histogram(self.G)
            }
            
        except Exception as e:
            self.logger.error(f"Error in network structure analysis: {e}")
            raise

    def analyze_bottlenecks(self):
        """Analyze network bottlenecks using spectral properties and flow analysis"""
        try:
            if self.G.number_of_nodes() == 0:
                return {}

            # Calculate spectral metrics
            laplacian = nx.laplacian_matrix(self.G).todense()
            eigenvalues, eigenvectors = np.linalg.eigh(laplacian)
            
            n_components = min(3, self.G.number_of_nodes() - 1)
            bottleneck_scores = {}
            
            # Calculate node importance using eigenvectors
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

            # Calculate edge betweenness
            edge_betweenness = nx.edge_betweenness_centrality(self.G)
            
            # Calculate flow using random walks
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
            flow_centrality = {node: count/max_flow for node, count in flow_counts.items()}

            # Identify critical bottlenecks
            non_zero_scores = [s for s in bottleneck_scores.values() if s > 0]
            threshold = np.percentile(non_zero_scores, 75) if non_zero_scores else 0
            
            critical_bottlenecks = {
                node: score for node, score in bottleneck_scores.items() 
                if score > threshold
            }
            
            # Compile comprehensive bottleneck analysis
            bottleneck_analysis = {}
            for node in self.G.nodes():
                label = self.G.nodes[node].get('label', str(node))
                bottleneck_analysis[label] = {
                    'spectral_score': bottleneck_scores[node],
                    'flow_centrality': flow_centrality[node],
                    'is_critical': node in critical_bottlenecks,
                    'degree': self.G.degree(node),
                    'betweenness': self.centrality_measures['Betweenness_Centrality'][node],
                    'edge_impact': sum(score for (u, v), score in edge_betweenness.items() 
                                     if u == node or v == node)
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
        """Run complete network analysis with IT security focus"""
        try:
            if not hasattr(scan_result, 'hosts') or not scan_result.hosts:
                raise ValueError("Invalid scan result: no hosts data found")

            self.create_graph_from_scan(scan_result)
            
            if self.G.number_of_nodes() == 0:
                raise ValueError("No valid nodes could be created from scan results")
            
            default_metrics = {
                'spectral_radius': 0.0,
                'fiedler_value': 0.0,
                'network_density': 0.0,
                'average_degree': 0.0,
                'total_nodes': 0,
                'total_edges': 0,
                'components': 0,
                'high_risk_nodes': 0
            }
            
            try:
                structure = self.analyze_network_structure()
                security_metrics = self.analyze_security_metrics()
                bottleneck_analysis = self.analyze_bottlenecks()
                anomalies = self.detect_anomalies()
                spectral_metrics = self.calculate_spectral_metrics()
                port_analysis = self.analyze_port_data(scan_result)
                zone_analysis = self.analyze_zone_isolation()
                attack_paths = self.analyze_attack_paths()
                node_criticality = self.analyze_node_criticality()
                
                # Calculate risk scores with validation
                risk_scores = {}
                for node in self.G.nodes():
                    try:
                        anomaly_risk = float(anomalies.get(node, {}).get('risk_score', 50))
                        centrality_risk = float(self.centrality_measures['Betweenness_Centrality'][node] * 100)
                        security_risk = float(security_metrics[node]['connectivity_risk'] * 100)
                        node_crit = float(node_criticality['node_criticality'].get(node, {}).get('total_impact', 0) * 20)
                        
                        weighted_risk = (
                            0.3 * anomaly_risk +
                            0.2 * centrality_risk +
                            0.2 * security_risk +
                            0.3 * node_crit
                        )
                        risk_scores[node] = min(100, max(0, weighted_risk))
                    except (KeyError, TypeError, ValueError) as e:
                        logging.warning(f"Error calculating risk score for node {node}: {e}")
                        risk_scores[node] = 50
                        
                metrics = default_metrics.copy()
                metrics.update({
                    'spectral_radius': float(spectral_metrics.get('spectral_radius', 0.0)),
                    'fiedler_value': float(spectral_metrics.get('fiedler_value', 0.0)),
                    'network_density': float(structure.get('density', 0.0)),
                    'average_degree': float(structure.get('average_degree', 0.0)),
                    'total_nodes': self.G.number_of_nodes(),
                    'total_edges': self.G.number_of_edges(),
                    'components': len(structure.get('components', [])),
                    'high_risk_nodes': sum(1 for score in risk_scores.values() if score > 75)
                })

                analysis_result = {
                    'timestamp': datetime.now().isoformat(),
                    'network_structure': structure,
                    'security_metrics': security_metrics,
                    'bottleneck_analysis': bottleneck_analysis,
                    'anomalies': anomalies,
                    'spectral_metrics': spectral_metrics,
                    'risk_scores': risk_scores,
                    'port_analysis': port_analysis,
                    'zone_analysis': zone_analysis,
                    'attack_paths': attack_paths,
                    'node_criticality': node_criticality,
                    'summary': {
                        'total_nodes': metrics['total_nodes'],
                        'total_edges': metrics['total_edges'],
                        'total_open_ports': port_analysis.get('total_open_ports', 0),
                        'high_risk_nodes': metrics['high_risk_nodes'],
                        'isolated_nodes': len(structure.get('endpoints', [])),
                        'components': metrics['components'],
                        'average_degree': metrics['average_degree'],
                        'network_density': metrics['network_density'],
                        'critical_bottlenecks': sum(1 for metrics in bottleneck_analysis.values() 
                                                if metrics.get('is_critical', False)),
                        'spectral_radius': metrics['spectral_radius'],
                        'fiedler_value': metrics['fiedler_value'],
                        'zone_violations': zone_analysis['summary']['total_violations'],
                        'high_risk_attack_paths': attack_paths['summary']['high_risk_paths'],
                        'critical_assets': attack_paths['summary']['total_critical_assets'],
                        'high_risk_services': len(port_analysis['interesting_ports']['high_risk']),
                        'remote_access_services': len(port_analysis['interesting_ports']['remote_access']),
                        'database_services': len(port_analysis['interesting_ports']['databases']),
                        'web_services': len(port_analysis['interesting_ports']['web_services'])
                    }
                }
                
                try:
                    output_file = os.path.join(self.output_dir, 
                                            f'analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
                    with open(output_file, 'w') as f:
                        json.dump(analysis_result, f, indent=2, default=str)
                    logging.info(f"Analysis results saved to {output_file}")
                except Exception as e:
                    logging.error(f"Failed to save analysis results: {str(e)}")
                
                return analysis_result
                
            except Exception as e:
                logging.error(f"Error in analysis components: {e}")
                return {
                    'timestamp': datetime.now().isoformat(),
                    'error': str(e),
                    'summary': default_metrics
                }
                
        except Exception as e:
            logging.error(f"Critical error in network analysis: {e}")
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

    def analyze_vulnerability_paths(self):
        """Analyze vulnerability propagation paths"""
        try:
            vulnerability_paths = {}
            # Identify critical systems - include PLCs, HMIs, and any high-value targets
            critical_systems = [n for n in self.G.nodes() 
                             if any(sys_type in str(self.G.nodes[n].get('type', '')).lower() 
                                   for sys_type in ['plc', 'hmi', 'scada', 'server', 'controller'])]
            
            # If no systems are explicitly marked as critical, use high centrality nodes
            if not critical_systems:
                betweenness = nx.betweenness_centrality(self.G)
                critical_systems = [node for node, score in betweenness.items() 
                                  if score > np.mean(list(betweenness.values()))]
            
            for system in critical_systems:
                paths = []
                for node in self.G.nodes():
                    if node != system and nx.has_path(self.G, node, system):
                        path = nx.shortest_path(self.G, node, system)
                        # Calculate vulnerability score based on multiple factors
                        vulnerability_score = 0
                        for n in path:
                            node_data = self.G.nodes[n]
                            # Count vulnerabilities
                            vulns = len(node_data.get('vulnerabilities', []))
                            # Check exposed services
                            exposed_services = len(node_data.get('services', []))
                            # Consider node degree (more connections = more risk)
                            degree_factor = self.G.degree(n) / self.G.number_of_nodes()
                            
                            # Combine factors into a weighted score
                            node_score = (vulns * 3) + (exposed_services * 2) + (degree_factor * 5)
                            vulnerability_score += node_score
                        
                        paths.append({
                            'path': path,
                            'length': len(path),
                            'vulnerability_score': vulnerability_score,
                            'details': {
                                'total_vulnerabilities': sum(len(self.G.nodes[n].get('vulnerabilities', [])) 
                                                          for n in path),
                                'exposed_services': sum(len(self.G.nodes[n].get('services', [])) 
                                                     for n in path),
                                'critical_nodes': sum(1 for n in path 
                                                    if n in critical_systems)
                            }
                        })
                
                # Sort paths by vulnerability score
                paths.sort(key=lambda x: x['vulnerability_score'], reverse=True)
                vulnerability_paths[system] = paths
            
            return vulnerability_paths
            
        except Exception as e:
            self.logger.error(f"Error analyzing vulnerability paths: {e}")
            return {}

    def generate_executive_report(self, analysis_data):
        """Generate an executive summary report from analysis data"""
        try:
            # Extract results and summary data
            network_structure = analysis_data.get('network_structure', {})
            security_metrics = analysis_data.get('security_metrics', {})
            bottleneck_analysis = analysis_data.get('bottleneck_analysis', {})
            anomalies = analysis_data.get('anomalies', {})
            risk_scores = analysis_data.get('risk_scores', {})
            spectral_metrics = analysis_data.get('spectral_metrics', {})
            port_analysis = analysis_data.get('port_analysis', {})
            zone_analysis = analysis_data.get('zone_analysis', {})
            attack_paths = analysis_data.get('attack_paths', {})

            # Generate report sections
            report = []
            
            # Executive Summary
            report.append("# Network Security Analysis Executive Report")
            report.append(f"\nAnalysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            report.append("\n## Executive Summary")
            report.append(f"- Total Nodes Analyzed: {self.G.number_of_nodes()}")
            report.append(f"- High Risk Nodes: {sum(1 for score in risk_scores.values() if score > 75)}")
            report.append(f"- Critical Bottlenecks: {sum(1 for node in bottleneck_analysis.values() if node.get('is_critical', False))}")
            report.append(f"- Network Density: {network_structure.get('density', 0):.2%}")

            # Key Findings
            report.append("\n## Key Findings")
            
            # Network Structure Analysis
            report.append("\n### Network Structure")
            report.append(f"- Network Density: {network_structure.get('density', 0):.2%}")
            report.append(f"- Average Node Connections: {network_structure.get('average_degree', 0):.1f}")
            report.append(f"- Number of Components: {len(network_structure.get('components', []))}")
            
            # High Risk Systems
            report.append("\n### High Risk Systems")
            high_risk_nodes = [node for node, score in risk_scores.items() if score > 75]
            for node in high_risk_nodes:
                metrics = security_metrics.get(node, {})
                report.append(f"\nNode: {node}")
                report.append(f"- Device Type: {metrics.get('device_type', 'Unknown')}")
                report.append(f"- Risk Score: {risk_scores.get(node, 0):.1f}")
                report.append(f"- Critical Path: {'Yes' if metrics.get('betweenness', 0) > 0.5 else 'No'}")

            # Spectral Analysis Summary
            report.append("\n### Network Cohesion Analysis")
            fiedler_value = spectral_metrics.get('fiedler_value', 0)
            spectral_radius = spectral_metrics.get('spectral_radius', 0)
            report.append(f"- Network Connectivity Index: {fiedler_value:.3f}")
            report.append(f"- Network Robustness Score: {spectral_radius:.3f}")
            
            # Add connectivity interpretation
            if fiedler_value < 0.1:
                report.append("- WARNING: Network shows signs of fragility and poor connectivity")
            elif fiedler_value < 0.5:
                report.append("- NOTICE: Network has moderate connectivity structure")
            else:
                report.append("- Network shows strong connectivity patterns")

            # Critical Bottlenecks
            report.append("\n### Critical Bottlenecks")
            critical_bottlenecks = [node for node, data in bottleneck_analysis.items() 
                                  if data.get('is_critical', False)]
            for node in critical_bottlenecks:
                data = bottleneck_analysis[node]
                report.append(f"\nNode: {node}")
                report.append(f"- Flow Centrality: {data.get('flow_centrality', 0):.3f}")
                report.append(f"- Spectral Score: {data.get('spectral_score', 0):.3f}")
                report.append(f"- Connected Nodes: {data.get('degree', 0)}")

            # Security Analysis
            report.append("\n### Security Analysis")
            report.append("\n#### Top Security Concerns:")
            
            # Count nodes with various risk factors
            exposed_nodes = sum(1 for m in security_metrics.values() 
                              if m.get('connectivity_risk', 0) > 0.5)
            critical_path_nodes = sum(1 for m in security_metrics.values() 
                                    if m.get('betweenness', 0) > 0.5)
            
            report.append(f"- {exposed_nodes} nodes with high exposure risk")
            report.append(f"- {critical_path_nodes} nodes on critical network paths")
            report.append(f"- {len(critical_bottlenecks)} critical bottleneck points")

            # Vulnerability Path Analysis
            report.append("\n## Vulnerability Analysis")
            vuln_paths = self.analyze_vulnerability_paths()
            
            if vuln_paths:
                report.append("\n### Critical System Access Paths")
                total_high_risk_paths = 0
                
                for system, paths in vuln_paths.items():
                    if paths:
                        high_risk_paths = [p for p in paths if p['vulnerability_score'] > 5]
                        total_high_risk_paths += len(high_risk_paths)
                        
                        report.append(f"\n#### Critical System: {system}")
                        report.append(f"- Total Access Paths: {len(paths)}")
                        report.append(f"- High Risk Paths: {len(high_risk_paths)}")
                        
                        if high_risk_paths:
                            report.append("\nTop Risk Paths:")
                            for path in high_risk_paths[:3]:  # Show top 3 riskiest paths
                                report.append(f"\n* Path: {' → '.join(path['path'])}")
                                report.append(f"  - Risk Score: {path['vulnerability_score']:.2f}")
                                report.append(f"  - Path Length: {path['length']}")
                                report.append(f"  - Total Vulnerabilities: {path['details']['total_vulnerabilities']}")
                                report.append(f"  - Exposed Services: {path['details']['exposed_services']}")
                                report.append(f"  - Critical Nodes Traversed: {path['details']['critical_nodes']}")
                
                # Add summary section
                report.append("\n### Vulnerability Summary")
                report.append(f"- Total Critical Systems Analyzed: {len(vuln_paths)}")
                report.append(f"- Total High Risk Paths: {total_high_risk_paths}")
                
                # Add specific recommendations based on findings
                report.append("\n### Risk Mitigation Recommendations")
                if total_high_risk_paths > 0:
                    report.append("1. Implement network segmentation to reduce access paths")
                    report.append("2. Add access controls on critical path nodes")
                    report.append("3. Increase monitoring on high-risk paths")
                    report.append("4. Consider implementing honeypots to detect potential attacks")
                    report.append("5. Regular vulnerability scanning and patching for nodes on critical paths")

            # Recommendations
            report.append("\n## Recommendations")
            
            # High-priority recommendations based on findings
            if high_risk_nodes:
                report.append("\n### Immediate Actions Required:")
                report.append("1. Audit and secure high-risk nodes")
                report.append("2. Implement additional monitoring for critical systems")
                report.append("3. Review and restrict unnecessary connections")

            # General recommendations based on network structure
            report.append("\n### General Recommendations:")
            if network_structure.get('density', 0) > 0.7:
                report.append("- Reduce network complexity and unnecessary connections")
            if len(network_structure.get('endpoints', [])) > 0:
                report.append("- Review and secure network endpoints")
            if critical_bottlenecks:
                report.append("- Implement redundancy for critical bottleneck points")
            if fiedler_value < 0.1:
                report.append("- Improve network connectivity to reduce fragility")

            # Technical Details
            report.append("\n## Technical Details")
            report.append("\n### Network Metrics")
            report.append("```")
            report.append(f"Density: {network_structure.get('density', 0):.3f}")
            report.append(f"Average Clustering: {network_structure.get('average_clustering', 0):.3f}")
            
            # Spectral Analysis Details
            report.append(f"\nSpectral Analysis:")
            report.append(f"Spectral Radius: {spectral_metrics.get('spectral_radius', 0):.3f}")
            report.append(f"Fiedler Value: {spectral_metrics.get('fiedler_value', 0):.3f}")
            
            # Top contributing nodes
            report.append("\nMost Critical Nodes for Network Cohesion:")
            fiedler_components = spectral_metrics.get('fiedler_components', [])
            for node, value in fiedler_components[:5]:  # Show top 5 contributors
                report.append(f"- Node {node}: Impact Score {abs(value):.3f}")
            report.append("```")

            # Node Classification
            report.append("\n### Node Classification")
            report.append("```")
            device_types = Counter(m.get('device_type', 'Unknown') for m in security_metrics.values())
            for device_type, count in device_types.most_common():
                report.append(f"{device_type}: {count}")
            report.append("```")

            return "\n".join(report)

        except Exception as e:
            self.logger.error(f"Error generating executive report: {e}")
            raise

    def save_report(self, report, analysis_id):
        """Save the generated report to a file"""
        try:
            # Create reports directory if it doesn't exist
            reports_dir = os.path.join(self.data_dir, 'reports')
            os.makedirs(reports_dir, exist_ok=True)
            
            # Save report
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = os.path.join(reports_dir, f'report_{analysis_id}_{timestamp}.md')
            
            with open(report_file, 'w') as f:
                f.write(report)
            
            return report_file
        
        except Exception as e:
            self.logger.error(f"Error saving report: {e}")
            raise

    def analyze_port_data(self, scan_result=None):
        """Analyze port and service data from scan results"""
        try:
            port_analysis = {
                'total_open_ports': 0,
                'hosts_with_ports': {},  # Track ports by host
                'common_ports': {},
                'services': {},
                'port_states': {},
                'interesting_ports': {
                    'remote_access': [],
                    'web_services': [],
                    'databases': [],
                    'industrial': [],
                    'high_risk': []
                }
            }

            # Define port categories
            port_categories = {
                'remote_access': [22, 23, 3389, 5900],
                'web_services': [80, 443, 8080, 8443],
                'databases': [1433, 3306, 5432, 27017],
                'industrial': [502, 102, 44818, 47808],
                'high_risk': [21, 23, 445, 135, 137, 138, 139]
            }

            # Log analysis start
            logging.info(f"\nStarting port analysis:")
            logging.info(f"Total hosts in scan: {len(scan_result.hosts)}")

            # Process each host
            for host in scan_result.hosts:
                host_ip = host.get('ip_address')
                if not host_ip:
                    logging.warning(f"Found host without IP address: {host}")
                    continue

                # Initialize host entry
                port_analysis['hosts_with_ports'][host_ip] = {
                    'open_ports': [],
                    'services': [],
                    'high_risk_ports': []
                }

                # Process ports for this host
                logging.info(f"\nAnalyzing ports for host {host_ip}")
                for port_info in host.get('ports', []):
                    if isinstance(port_info, dict):
                        port_num = port_info.get('port')
                        state = port_info.get('state')
                        service = port_info.get('service', 'unknown')
                        service_details = port_info.get('service_details', '')
                        product = port_info.get('product', '')
                        version = port_info.get('version', '')
                        extra_info = port_info.get('extra_info', '')
                        tunnel_type = port_info.get('tunnel_type', '')
                        protocol = port_info.get('protocol', 'tcp')

                        if state == 'open':
                            # Build detailed service string
                            service_key = service
                            details_parts = []

                            if tunnel_type:
                                service_key = f"{tunnel_type}/{service}"

                            if product or version or extra_info:
                                if product:
                                    details_parts.append(product)
                                    if version:
                                        details_parts[-1] += f" {version}"
                                if extra_info:
                                    details_parts.append(extra_info)
                                service_key += f" ({'; '.join(details_parts)})"

                            # Create detailed port entry
                            port_entry = {
                                'port': port_num,
                                'service': service,
                                'service_details': service_key,
                                'product': product,
                                'version': version,
                                'extra_info': extra_info,
                                'tunnel_type': tunnel_type,
                                'protocol': protocol
                            }

                            # Add to host's open ports
                            port_analysis['hosts_with_ports'][host_ip]['open_ports'].append(port_entry)

                            # Update total open ports
                            port_analysis['total_open_ports'] += 1

                            # Count common ports
                            port_analysis['common_ports'][port_num] = \
                                port_analysis['common_ports'].get(port_num, 0) + 1

                            # Count services with details
                            port_analysis['services'][service_key] = \
                                port_analysis['services'].get(service_key, 0) + 1

                            # Categorize ports
                            for category, port_list in port_categories.items():
                                if port_num in port_list:
                                    port_data = {
                                        'host': host_ip,
                                        'port': port_num,
                                        'service': service,
                                        'service_details': service_key,
                                        'product': product,
                                        'version': version,
                                        'protocol': protocol,
                                        'tunnel_type': tunnel_type
                                    }
                                    port_analysis['interesting_ports'][category].append(port_data)
                                    
                                    if category == 'high_risk':
                                        port_analysis['hosts_with_ports'][host_ip]['high_risk_ports'].append(port_num)

                            logging.info(f"Added open port for {host_ip}: {port_num} - {service_key}")

            # Generate detailed summary
            logging.info("\nPort Analysis Summary:")
            for host_ip, host_data in port_analysis['hosts_with_ports'].items():
                if host_data['open_ports']:
                    logging.info(f"\nHost {host_ip}:")
                    for port in host_data['open_ports']:
                        service_str = port['service_details'] if port.get('service_details') else port['service']
                        logging.info(f"  Port {port['port']}/{port['protocol']}: {service_str}")

            # Log statistics
            logging.info(f"\nTotal Statistics:")
            logging.info(f"Total open ports found: {port_analysis['total_open_ports']}")
            logging.info(f"Unique services found: {len(port_analysis['services'])}")
            logging.info(f"Hosts with open ports: {len([h for h in port_analysis['hosts_with_ports'].values() if h['open_ports']])}")

            return port_analysis

        except Exception as e:
            logging.error(f"Error analyzing port data: {e}", exc_info=True)
            return {
                'total_open_ports': 0,
                'hosts_with_ports': {},
                'common_ports': {},
                'services': {},
                'port_states': {},
                'interesting_ports': {
                    'remote_access': [],
                    'web_services': [],
                    'databases': [],
                    'industrial': [],
                    'high_risk': []
                }
            }
        
    def analyze_zone_isolation(self):
        """Analyze network zone isolation"""
        try:
            zone_violations = {}
            zone_nodes = {
                'DMZ': [n for n in self.G.nodes() 
                        if self.G.nodes[n].get('type', '').lower() in ['proxy', 'gateway', 'firewall']],
                'Internal': [n for n in self.G.nodes() 
                            if self.G.nodes[n].get('type', '').lower() in ['server', 'workstation']],
                'Management': [n for n in self.G.nodes() 
                            if self.G.nodes[n].get('type', '').lower() in ['admin', 'management']]
            }
            
            for zone, nodes in zone_nodes.items():
                violations = []
                for node in nodes:
                    neighbors = list(self.G.neighbors(node))
                    for neighbor in neighbors:
                        if not any(neighbor in zone_nodes[z] for z in zone_nodes):
                            violations.append({
                                'source': node,
                                'target': neighbor,
                                'source_type': self.G.nodes[node].get('type', 'unknown'),
                                'target_type': self.G.nodes[neighbor].get('type', 'unknown')
                            })
                zone_violations[zone] = violations
                
            return {
                'zone_violations': zone_violations,
                'summary': {
                    'total_violations': sum(len(v) for v in zone_violations.values()),
                    'violations_by_zone': {zone: len(violations) 
                                        for zone, violations in zone_violations.items()}
                }
            }
        except Exception as e:
            self.logger.error(f"Error analyzing zone isolation: {e}")
            return {'zone_violations': {}, 'summary': {'total_violations': 0, 'violations_by_zone': {}}}

    def analyze_attack_paths(self):
        """Analyze potential attack paths to critical assets"""
        try:
            critical_assets = [n for n in self.G.nodes() 
                            if self.G.nodes[n].get('type', '').lower() in 
                            ['server', 'database', 'firewall', 'domain_controller']]
            
            attack_paths = {}
            for asset in critical_assets:
                paths = []
                for node in self.G.nodes():
                    if node != asset and nx.has_path(self.G, node, asset):
                        path = nx.shortest_path(self.G, node, asset)
                        
                        risk_score = 0
                        for n in path:
                            node_data = self.G.nodes[n]
                            vulns = len(node_data.get('vulnerabilities', []))
                            exposed_services = len(node_data.get('services', []))
                            degree_factor = self.G.degree(n) / self.G.number_of_nodes()
                            
                            node_score = (vulns * 3) + (exposed_services * 2) + (degree_factor * 5)
                            risk_score += node_score
                        
                        paths.append({
                            'path': path,
                            'length': len(path),
                            'risk_score': risk_score,
                            'details': {
                                'total_vulnerabilities': sum(len(self.G.nodes[n].get('vulnerabilities', [])) 
                                                        for n in path),
                                'exposed_services': sum(len(self.G.nodes[n].get('services', [])) 
                                                    for n in path),
                                'critical_nodes': sum(1 for n in path if n in critical_assets)
                            }
                        })
                
                paths.sort(key=lambda x: x['risk_score'], reverse=True)
                attack_paths[asset] = paths
                
            return {
                'attack_paths': attack_paths,
                'summary': {
                    'total_critical_assets': len(critical_assets),
                    'high_risk_paths': sum(1 for paths in attack_paths.values() 
                                        for path in paths if path['risk_score'] > 10),
                    'assets_by_risk': sorted(
                        [(asset, max(p['risk_score'] for p in paths) if paths else 0) 
                        for asset, paths in attack_paths.items()],
                        key=lambda x: x[1],
                        reverse=True
                    )
                }
            }
        except Exception as e:
            self.logger.error(f"Error analyzing attack paths: {e}")
            return {'attack_paths': {}, 'summary': {
                'total_critical_assets': 0, 
                'high_risk_paths': 0, 
                'assets_by_risk': []
            }}

    def analyze_node_criticality(self):
        """Analyze node criticality based on network segmentation impact"""
        try:
            original_components = nx.number_connected_components(self.G)
            node_criticality = {}
            
            for node in self.G.nodes():
                G_temp = self.G.copy()
                G_temp.remove_node(node)
                
                new_components = nx.number_connected_components(G_temp)
                component_impact = new_components - original_components
                
                orig_reachable = sum(1 for _ in nx.all_pairs_shortest_path_length(self.G))
                new_reachable = sum(1 for _ in nx.all_pairs_shortest_path_length(G_temp))
                reachability_impact = 1 - (new_reachable / orig_reachable if orig_reachable > 0 else 0)
                
                node_criticality[node] = {
                    'component_impact': component_impact,
                    'reachability_impact': reachability_impact,
                    'total_impact': component_impact + reachability_impact,
                    'node_type': self.G.nodes[node].get('type', 'unknown'),
                    'degree': self.G.degree(node),
                    'betweenness': self.centrality_measures['Betweenness_Centrality'][node]
                }
                
            return {
                'node_criticality': node_criticality,
                'summary': {
                    'high_impact_nodes': sum(1 for n in node_criticality.values() 
                                        if n['total_impact'] > 1.5),
                    'critical_by_type': Counter(
                        n['node_type'] for n in node_criticality.values() 
                        if n['total_impact'] > 1.5
                    )
                }
            }
        except Exception as e:
            self.logger.error(f"Error analyzing node criticality: {e}")
            return {'node_criticality': {}, 'summary': {
                'high_impact_nodes': 0, 
                'critical_by_type': Counter()
            }}
        
    