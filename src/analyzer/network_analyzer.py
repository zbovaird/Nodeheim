# src/analyzer/network_analyzer.py
from typing import Dict, Any, List, Optional
import networkx as nx
import pandas as pd
import numpy as np
from datetime import datetime
import os
import logging
from pathlib import Path
from dataclasses import dataclass
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

@dataclass
class AnalysisResult:
    """Data class to store network analysis results"""
    timestamp: str
    network_stats: Dict[str, Any]
    critical_nodes: List[Dict[str, Any]]
    bottlenecks: List[Dict[str, Any]]
    security_metrics: Dict[str, Any]
    risk_scores: Dict[str, float]
    recommendations: List[str]

class NetworkAnalyzer:
    """Network Analysis integration for the scanner application"""
    def __init__(self, output_dir: str = 'src/data'):
        self.output_dir = output_dir
        self.analysis_dir = os.path.join(output_dir, 'analysis')
        os.makedirs(self.analysis_dir, exist_ok=True)
        
        self.logger = logging.getLogger(__name__)
    
    def create_network_graph(self, scan_result) -> nx.Graph:
        """Convert scan results into a NetworkX graph"""
        G = nx.Graph()
        
        # Add nodes (hosts)
        for host in scan_result.hosts:
            G.add_node(
                host['ip_address'],
                status=host['status'],
                hostname=host.get('hostname', ''),
                os=host.get('os', 'Unknown'),
                services=host.get('services', [])
            )
        
        # Add edges based on discovered connections
        for host in scan_result.hosts:
            source_ip = host['ip_address']
            # Create edges based on common services and ports
            for target_host in scan_result.hosts:
                if source_ip != target_host['ip_address']:
                    common_services = set(host.get('services', [])) & set(target_host.get('services', []))
                    if common_services:
                        G.add_edge(
                            source_ip,
                            target_host['ip_address'],
                            weight=len(common_services),
                            services=list(common_services)
                        )
        
        return G

    def analyze_network_structure(self, G: nx.Graph) -> Dict[str, Any]:
        """Analyze basic network structure metrics"""
        try:
            return {
                'num_nodes': G.number_of_nodes(),
                'num_edges': G.number_of_edges(),
                'density': nx.density(G),
                'avg_degree': sum(dict(G.degree()).values()) / G.number_of_nodes(),
                'diameter': nx.diameter(G) if nx.is_connected(G) else float('inf'),
                'avg_path_length': nx.average_shortest_path_length(G) if nx.is_connected(G) else float('inf'),
                'clustering_coefficient': nx.average_clustering(G),
                'connected_components': list(nx.connected_components(G))
            }
        except Exception as e:
            self.logger.error(f"Error analyzing network structure: {str(e)}")
            raise

    def identify_critical_nodes(self, G: nx.Graph) -> List[Dict[str, Any]]:
        """Identify critical nodes based on centrality metrics"""
        try:
            critical_nodes = []
            centrality_measures = {
                'degree': nx.degree_centrality(G),
                'betweenness': nx.betweenness_centrality(G),
                'closeness': nx.closeness_centrality(G),
                'eigenvector': nx.eigenvector_centrality(G, max_iter=1000)
            }
            
            for node in G.nodes():
                node_data = G.nodes[node]
                criticality_score = sum(
                    measures[node] for measures in centrality_measures.values()
                ) / len(centrality_measures)
                
                if criticality_score > 0.5:  # Threshold for critical nodes
                    critical_nodes.append({
                        'ip_address': node,
                        'hostname': node_data.get('hostname', ''),
                        'criticality_score': criticality_score,
                        'degree': centrality_measures['degree'][node],
                        'betweenness': centrality_measures['betweenness'][node],
                        'services': node_data.get('services', [])
                    })
            
            return sorted(critical_nodes, key=lambda x: x['criticality_score'], reverse=True)
        except Exception as e:
            self.logger.error(f"Error identifying critical nodes: {str(e)}")
            raise

    def analyze_bottlenecks(self, G: nx.Graph) -> List[Dict[str, Any]]:
        """Identify network bottlenecks"""
        try:
            bottlenecks = []
            # Calculate edge betweenness centrality
            edge_bc = nx.edge_betweenness_centrality(G)
            
            # Identify potential bottleneck paths
            for (u, v), bc in edge_bc.items():
                if bc > 0.5:  # Threshold for bottleneck identification
                    bottlenecks.append({
                        'nodes': [u, v],
                        'betweenness_centrality': bc,
                        'services': G.edges[u, v].get('services', []),
                        'weight': G.edges[u, v].get('weight', 1)
                    })
            
            return sorted(bottlenecks, key=lambda x: x['betweenness_centrality'], reverse=True)
        except Exception as e:
            self.logger.error(f"Error analyzing bottlenecks: {str(e)}")
            raise

    def calculate_security_metrics(self, G: nx.Graph, scan_result) -> Dict[str, Any]:
        """Calculate security-related metrics"""
        try:
            security_metrics = {
                'exposure_points': [],
                'vulnerable_services': [],
                'isolation_metrics': {}
            }
            
            # Identify exposure points (nodes with high connectivity and vulnerabilities)
            for node in G.nodes():
                node_data = G.nodes[node]
                vulnerabilities = next(
                    (h['vulnerabilities'] for h in scan_result.hosts 
                     if h['ip_address'] == node),
                    []
                )
                
                if len(vulnerabilities) > 0 and G.degree(node) > 2:
                    security_metrics['exposure_points'].append({
                        'ip_address': node,
                        'hostname': node_data.get('hostname', ''),
                        'num_vulnerabilities': len(vulnerabilities),
                        'degree': G.degree(node),
                        'services': node_data.get('services', [])
                    })
            
            # Analyze service vulnerabilities
            all_services = {}
            for host in scan_result.hosts:
                for service in host.get('services', []):
                    if service not in all_services:
                        all_services[service] = {
                            'count': 0,
                            'vulnerable_hosts': set()
                        }
                    all_services[service]['count'] += 1
                    if len(host.get('vulnerabilities', [])) > 0:
                        all_services[service]['vulnerable_hosts'].add(host['ip_address'])
            
            security_metrics['vulnerable_services'] = [
                {
                    'service': service,
                    'total_count': data['count'],
                    'vulnerable_hosts': len(data['vulnerable_hosts'])
                }
                for service, data in all_services.items()
                if len(data['vulnerable_hosts']) > 0
            ]
            
            # Calculate network isolation metrics
            security_metrics['isolation_metrics'] = {
                'avg_path_length': nx.average_shortest_path_length(G) if nx.is_connected(G) else float('inf'),
                'clustering': nx.average_clustering(G),
                'assortativity': nx.degree_assortativity_coefficient(G)
            }
            
            return security_metrics
        except Exception as e:
            self.logger.error(f"Error calculating security metrics: {str(e)}")
            raise

    def generate_recommendations(self, critical_nodes: List[Dict[str, Any]], 
                               security_metrics: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        # Critical node recommendations
        if critical_nodes:
            recommendations.append(
                "Critical nodes identified with high centrality - consider implementing "
                "redundancy and enhanced monitoring for these nodes"
            )
            for node in critical_nodes[:3]:  # Top 3 most critical
                recommendations.append(
                    f"Implement additional security controls for {node['ip_address']} "
                    f"({node['hostname']}) - criticality score: {node['criticality_score']:.2f}"
                )
        
        # Exposure point recommendations
        exposure_points = security_metrics.get('exposure_points', [])
        if exposure_points:
            recommendations.append(
                "Multiple exposure points detected - consider network segmentation "
                "and access control reviews"
            )
            for point in exposure_points[:3]:  # Top 3 exposure points
                recommendations.append(
                    f"Review access controls and patch vulnerabilities for {point['ip_address']} "
                    f"- {point['num_vulnerabilities']} vulnerabilities found"
                )
        
        # Service vulnerability recommendations
        vulnerable_services = security_metrics.get('vulnerable_services', [])
        if vulnerable_services:
            recommendations.append(
                "Vulnerable services detected - consider service hardening and patch management"
            )
            for service in vulnerable_services[:3]:  # Top 3 vulnerable services
                recommendations.append(
                    f"Review and patch {service['service']} - affecting {service['vulnerable_hosts']} hosts"
                )
        
        return recommendations

    def analyze_scan_result(self, scan_result) -> AnalysisResult:
        """Analyze network scan results"""
        try:
            # Create network graph
            G = self.create_network_graph(scan_result)
            
            # Perform analysis
            network_stats = self.analyze_network_structure(G)
            critical_nodes = self.identify_critical_nodes(G)
            bottlenecks = self.analyze_bottlenecks(G)
            security_metrics = self.calculate_security_metrics(G, scan_result)
            
            # Calculate risk scores
            risk_scores = {
                node: (0.4 * next(
                    (cn['criticality_score'] for cn in critical_nodes 
                     if cn['ip_address'] == node),
                    0
                ) + 0.6 * len(next(
                    (h['vulnerabilities'] for h in scan_result.hosts 
                     if h['ip_address'] == node),
                    []
                )) / 10)
                for node in G.nodes()
            }
            
            # Generate recommendations
            recommendations = self.generate_recommendations(critical_nodes, security_metrics)
            
            # Create analysis result
            result = AnalysisResult(
                timestamp=datetime.now().isoformat(),
                network_stats=network_stats,
                critical_nodes=critical_nodes,
                bottlenecks=bottlenecks,
                security_metrics=security_metrics,
                risk_scores=risk_scores,
                recommendations=recommendations
            )
            
            # Save analysis result
            self._save_analysis_result(result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error in network analysis: {str(e)}")
            raise

    def _save_analysis_result(self, result: AnalysisResult):
        """Save analysis result to file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'analysis_result_{timestamp}.json'
        filepath = os.path.join(self.analysis_dir, filename)
        
        # Convert result to dictionary
        result_dict = {
            'timestamp': result.timestamp,
            'network_stats': result.network_stats,
            'critical_nodes': result.critical_nodes,
            'bottlenecks': result.bottlenecks,
            'security_metrics': result.security_metrics,
            'risk_scores': result.risk_scores,
            'recommendations': result.recommendations
        }
        
        # Save to file
        with open(filepath, 'w') as f:
            json.dump(result_dict, f, indent=2)

# Update app.py to include new endpoint
@app.route('/api/analyze', methods=['POST'])
def analyze_network():
    """Endpoint to analyze network scan results"""
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        scan_id = data.get('scan_id')
        if not scan_id:
            return jsonify({'error': 'No scan ID provided'}), 400

        # Load scan result
        scan_file = os.path.join('src', 'data', 'scans', f'{scan_id}.json')
        if not os.path.exists(scan_file):
            return jsonify({'error': 'Scan result not found'}), 404

        with open(scan_file, 'r') as f:
            scan_data = json.load(f)

        # Convert scan data back to ScanResult object
        scan_result = ScanResult(
            timestamp=scan_data['timestamp'],
            scan_type=scan_data['scan_type'],
            hosts=scan_data['hosts'],
            ports=scan_data['ports'],
            services=scan_data['services'],
            vulnerabilities=scan_data['vulnerabilities'],
            os_matches=scan_data['os_matches'],
            scan_stats=scan_data['scan_stats']
        )

        # Perform network analysis
        analyzer = NetworkAnalyzer()
        analysis_result = analyzer.analyze_scan_result(scan_result)

        # Format and return results
        return jsonify({
            'timestamp': analysis_result.timestamp,
            'network_stats': analysis_result.network_stats,
            'critical_nodes': analysis_result.critical_nodes,
            'bottlenecks': analysis_result.bottlenecks,
            'security_metrics': analysis_result.security_metrics,
            'risk_scores': analysis_result.risk_scores,
            'recommendations': analysis_result.recommendations
        })

    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500