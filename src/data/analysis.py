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

    # Add to network_analysis.py

    def generate_executive_report(self, analysis_result):
        """Generate security-focused report with improved formatting"""
        try:
            bottleneck_analysis = analysis_result.get('bottleneck_analysis', {})
            risk_scores = analysis_result.get('anomalies', {})
            security_metrics = analysis_result.get('security_metrics', {})
            
            # Executive Summary section
            high_risk_nodes = sum(1 for node, data in risk_scores.items() 
                                if data.get('risk_score', 0) >= 75)
            critical_bottlenecks = sum(1 for m in bottleneck_analysis.values() 
                                    if m.get('is_critical', False))
            exposed_assets = sum(1 for m in security_metrics.values() 
                            if m.get('min_path_to_plc', float('inf')) <= 2 or 
                                m.get('min_path_to_hmi', float('inf')) <= 2)

            report = f"""# Network Security Analysis Report

    ## Executive Summary

    CRITICAL FINDINGS:
    • {high_risk_nodes} nodes identified as high-risk requiring immediate attention
    • {critical_bottlenecks} critical network bottlenecks that could impact operations
    • {exposed_assets} potentially exposed critical assets

    ## Network Vulnerability Assessment

    ### High-Risk Nodes
    ```
    Node         | Risk Score | Connections | Risk Level | Exposure
    -------------|------------|-------------|------------|----------"""

            # Add high-risk nodes details
            high_risk = {node: data for node, data in risk_scores.items() 
                        if data.get('risk_score', 0) >= 75}
            
            for node, data in sorted(high_risk.items(), 
                                key=lambda x: x[1].get('risk_score', 0), 
                                reverse=True):
                metrics = security_metrics.get(node, {})
                risk_score = data.get('risk_score', 0)
                connections = metrics.get('degree', 0)
                exposure = data.get('exposure_score', 0)
                risk_level = "HIGH" if risk_score >= 75 else "MODERATE"
                
                report += f"\n{node:<12} | {risk_score:^10.1f} | {connections:^11} | {risk_level:^10} | {exposure:^8.2f}"

            report += "\n```\n"

            # Network Structure section
            report += """
    ## Network Structure Analysis

    ```
    Metric               | Value
    --------------------|-------"""
            
            structure = analysis_result.get('network_structure', {})
            report += f"""
    Total Nodes         | {structure.get('total_nodes', 0)}
    Network Density     | {structure.get('density', 0):.3f}
    Average Degree      | {structure.get('average_degree', 0):.2f}
    Components          | {len(structure.get('components', []))}
    Endpoint Nodes      | {len(structure.get('endpoints', []))}
    """

            # Add security zone analysis if available
            if 'security_zones' in analysis_result:
                report += """
    ## Security Zone Analysis

    Zone isolation status:
    ```
    Zone         | Violations | Risk Level | Recommended Action
    -------------|------------|------------|-------------------"""
                
                zones = analysis_result['security_zones']
                for zone, data in zones.items():
                    violations = len(data.get('violations', []))
                    risk_level = "HIGH" if violations > 3 else "MODERATE"
                    action = "IMMEDIATE REVIEW" if violations > 3 else "Monitor and Review"
                    report += f"\n{zone:<12} | {violations:^10} | {risk_level:<10} | {action}"
                
                report += "\n```"

            # Add recommendations section
            report += """
    ## Security Recommendations

    1. High-Risk Node Mitigation:"""
            
            for node, data in high_risk.items():
                report += f"\n   • Review security controls for {node} (Risk Score: {data.get('risk_score', 0):.1f})"

            report += """
    2. Network Segmentation:
    • Implement network segmentation for critical systems
    • Review access controls between zones
    • Monitor inter-zone communications

    3. Monitoring Recommendations:
    • Implement continuous monitoring for high-risk nodes
    • Setup alerts for anomalous behavior
    • Regular security assessments
    """

            return report
                
        except Exception as e:
            self.logger.error(f"Error generating executive report: {str(e)}")
            return f"Error generating report: {str(e)}"

    def save_report(self, report, analysis_id):
        """Save the generated report to file"""
        try:
            report_file = os.path.join(self.output_dir, f'analysis_report_{analysis_id}.md')
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(report)
            return report_file
        except Exception as e:
            self.logger.error(f"Error saving report: {str(e)}")
            raise

            