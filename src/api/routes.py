# src/api/routes.py

from flask import jsonify, request
import os
import json
from datetime import datetime
from pathlib import Path

class APIRoutes:
    def __init__(self, data_dir='src/data'):
        self.data_dir = data_dir
        self.analysis_dir = os.path.join(data_dir, 'analysis')
        
    def register_routes(self, app):
        @app.route('/api/analysis/list', methods=['GET'])
        def get_analysis_list():
            try:
                analyses = []
                analysis_files = Path(self.analysis_dir).glob('*.json')
                
                for file_path in analysis_files:
                    with open(file_path, 'r') as f:
                        analysis_data = json.load(f)
                        analyses.append({
                            'id': file_path.stem,
                            'timestamp': analysis_data.get('timestamp'),
                            'summary': analysis_data.get('summary', {})
                        })
                
                # Sort by timestamp descending
                analyses.sort(key=lambda x: x['timestamp'], reverse=True)
                return jsonify(analyses)
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @app.route('/api/analysis/<analysis_id>/report', methods=['GET'])
        def get_analysis_report(analysis_id):
            try:
                file_path = os.path.join(self.analysis_dir, f'{analysis_id}.json')
                if not os.path.exists(file_path):
                    return jsonify({'error': 'Analysis not found'}), 404
                    
                with open(file_path, 'r') as f:
                    analysis_data = json.load(f)
                
                # Generate report from analysis data
                report = self.generate_report(analysis_data)
                return jsonify({'report': report})
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500

    def generate_report(self, analysis_data):
        """Generate a markdown report from analysis data"""
        summary = analysis_data.get('summary', {})
        
        report = f"""# Network Security Analysis Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Network Overview
- Total Nodes: {summary.get('total_nodes', 'N/A')}
- Total Edges: {summary.get('total_edges', 'N/A')}
- High Risk Nodes: {summary.get('high_risk_nodes', 'N/A')}
- Isolated Nodes: {summary.get('isolated_nodes', 'N/A')}
- Network Density: {summary.get('network_density', 'N/A'):.2%}
- Average Degree: {summary.get('average_degree', 'N/A'):.2f}

## Critical Findings
- Critical Bottlenecks: {summary.get('critical_bottlenecks', 'N/A')}
- Network Components: {summary.get('components', 'N/A')}

## Security Metrics
"""
        # Add security metrics for each node
        for node, metrics in analysis_data.get('security_metrics', {}).items():
            report += f"""
### Node: {node}
- Device Type: {metrics.get('device_type', 'unknown')}
- Risk Level: {metrics.get('connectivity_risk', 0) * 100:.1f}%
- Connections: {len(metrics.get('neighbors', []))}
- Is Endpoint: {'Yes' if metrics.get('is_endpoint') else 'No'}
"""

        # Add anomalies section
        report += "\n## Anomalies and Risk Assessment\n"
        for node, data in analysis_data.get('anomalies', {}).items():
            if data.get('risk_score', 0) > 50:  # Only show high-risk nodes
                report += f"""
### {node}
- Risk Score: {data.get('risk_score', 0):.1f}
- Anomaly Score: {data.get('anomaly_score', 0):.3f}
- Centrality: {data.get('Degree_Centrality', 0):.3f}
"""

        return report