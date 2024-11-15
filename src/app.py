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

# Add the project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

# Local imports
from scanner.scanner import NetworkScanner, ScanResult
from scanner.network_discovery import NetworkDiscovery
from analyzer.topology import TopologyAnalyzer
from analyzer.network_analysis import NetworkAnalyzer
from api.analysis import analysis_bp

app = Flask(__name__)   

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('src/data/logs/app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Register the blueprint
app.register_blueprint(analysis_bp)

# Initialize analyzer
try:
    analyzer = NetworkAnalyzer(data_dir='src/data')
    logger.info("Network analyzer initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize analyzer: {str(e)}")
    raise

@app.route('/api/analyze', methods=['POST'])
def analyze_network():
    """Analyze network based on scan results with comprehensive error handling"""
    try:
        # Validate input data
        if not request.is_json:
            logger.error("Request does not contain JSON data")
            return jsonify({'error': 'Request must be JSON'}), 400

        data = request.json
        if not data:
            logger.error("Empty JSON data received")
            return jsonify({'error': 'No scan data provided'}), 400

        scan_id = data.get('scan_id')
        if not scan_id:
            logger.error("No scan_id provided in request")
            return jsonify({'error': 'No scan ID provided'}), 400

        # Validate scan file path and existence
        scan_file = os.path.join('src', 'data', 'scans', f'{scan_id}.json')
        if not os.path.exists(scan_file):
            logger.error(f"Scan file not found: {scan_file}")
            return jsonify({'error': f'Scan results not found for ID: {scan_id}'}), 404

        # Load and validate scan results
        try:
            with open(scan_file, 'r') as f:
                scan_result = json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse scan results JSON: {str(e)}")
            return jsonify({'error': 'Invalid scan results format'}), 500
        except Exception as e:
            logger.error(f"Failed to read scan file: {str(e)}")
            return jsonify({'error': 'Failed to read scan results'}), 500

        # Validate required fields in scan_result
        required_fields = ['hosts', 'ports', 'services', 'vulnerabilities', 'os_matches', 'scan_stats']
        missing_fields = [field for field in required_fields if field not in scan_result]
        if missing_fields:
            logger.error(f"Scan results missing required fields: {missing_fields}")
            return jsonify({'error': f'Invalid scan results: missing {", ".join(missing_fields)}'}), 400

        # Create ScanResult object
        try:
            scan_result_obj = ScanResult(
                timestamp=scan_result.get('timestamp', datetime.now().isoformat()),
                scan_type=scan_result.get('scan_type', 'unknown'),
                hosts=scan_result['hosts'],
                ports=scan_result['ports'],
                services=scan_result['services'],
                vulnerabilities=scan_result['vulnerabilities'],
                os_matches=scan_result['os_matches'],
                scan_stats=scan_result['scan_stats']
            )
        except Exception as e:
            logger.error(f"Failed to create ScanResult object: {str(e)}")
            return jsonify({'error': 'Invalid scan results format'}), 400

        # Run analysis with error handling
        try:
            analysis_result = analyzer.analyze_network(scan_result_obj)
        except nx.NetworkXError as e:
            logger.error(f"NetworkX error during analysis: {str(e)}")
            return jsonify({'error': 'Network analysis error'}), 500
        except ValueError as e:
            logger.error(f"Value error during analysis: {str(e)}")
            return jsonify({'error': 'Invalid data for analysis'}), 400
        except Exception as e:
            logger.error(f"Unexpected error during analysis: {str(e)}", exc_info=True)
            return jsonify({'error': 'Analysis failed'}), 500

        # Generate analysis ID with consistent format
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")  # No microseconds
        analysis_id = f"analysis_{timestamp}"

        # Save analysis results
        try:
            analysis_dir = os.path.join('src', 'data', 'analysis')
            os.makedirs(analysis_dir, exist_ok=True)
            
            analysis_file = os.path.join(analysis_dir, f'{analysis_id}.json')
            logger.info(f"Saving analysis to: {analysis_file}")
            
            analysis_data = {
                'id': analysis_id,
                'scan_id': scan_id,
                'timestamp': datetime.now().isoformat(),
                'results': analysis_result
            }
            
            with open(analysis_file, 'w') as f:
                json.dump(analysis_data, f, indent=2, default=str)
            
            logger.info(f"Analysis results saved to {analysis_file}")
            
        except Exception as e:
            logger.error(f"Failed to save analysis results: {str(e)}")
            return jsonify({'error': 'Failed to save analysis results'}), 500

        return jsonify({
            'status': 'success',
            'analysis_id': analysis_id,
            'analysis': analysis_result,
            'timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Unhandled exception in analyze_network: {str(e)}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/analysis/<analysis_id>')
def get_analysis(analysis_id):
    """Get specific analysis results"""
    try:
        analysis_file = os.path.join('src', 'data', 'analysis', f'{analysis_id}.json')
        if not os.path.exists(analysis_file):
            return jsonify({'error': 'Analysis results not found'}), 404

        with open(analysis_file, 'r') as f:
            analysis = json.load(f)

        return jsonify(analysis)

    except Exception as e:
        logger.error(f"Error retrieving analysis: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500


# Initialize scanner
try:
    scanner = NetworkScanner(output_dir='src/data')
    logger.info("Scanner initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize scanner: {str(e)}")
    raise

def format_scan_result(result: ScanResult) -> Dict[str, Any]:
    """Format scan result for JSON response"""
    try:
        return {
            'timestamp': result.timestamp,
            'scan_type': result.scan_type,
            'hosts': result.hosts,
            'ports': result.ports,
            'services': result.services,
            'vulnerabilities': result.vulnerabilities,
            'os_matches': result.os_matches,
            'scan_stats': result.scan_stats,
            'summary': {
                'total_hosts': len(result.hosts),
                'active_hosts': len([h for h in result.hosts if h['status'] == 'up']),
                'total_ports': len(result.ports),
                'total_services': len(result.services),
                'total_vulnerabilities': len(result.vulnerabilities)
            }
        }
    except Exception as e:
        logger.error(f"Error formatting scan result: {str(e)}")
        raise

@app.route('/')
def home():
    try:
        return render_template('index.html')
    except Exception as e:
        logger.error(f"Error rendering template: {str(e)}")
        return str(e), 500

@app.route('/api/scan', methods=['POST'])
def start_scan():
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        target = data.get('target')
        scan_type = data.get('scan_type', 'quick')

        if not target:
            return jsonify({'error': 'No target specified'}), 400

        logger.info(f"Starting {scan_type} scan on target: {target}")
        
        # Generate unique scan ID
        scan_id = str(uuid4())
        
        # Execute scan based on type
        if scan_type == 'quick':
            results = scanner.quick_scan(target)
        elif scan_type == 'basic':
            results = scanner.basic_scan(target)
        elif scan_type == 'full':
            results = scanner.full_scan(target)
        elif scan_type == 'vulnerability':
            results = scanner.vulnerability_scan(target)
        elif scan_type == 'stealth':
            results = scanner.stealth_scan(target)
        else:
            return jsonify({'error': 'Invalid scan type'}), 400

        # Format results
        formatted_results = format_scan_result(results)
        
        # Add scan ID and timestamp to results
        formatted_results['scan_id'] = scan_id
        formatted_results['timestamp'] = datetime.now().isoformat()
        
        # Save results to file
        results_dir = os.path.join('src', 'data', 'scans')
        os.makedirs(results_dir, exist_ok=True)
        
        result_file = os.path.join(results_dir, f'{scan_id}.json')
        with open(result_file, 'w') as f:
            json.dump(formatted_results, f, indent=2)
        
        logger.info(f"Scan completed successfully. Found {len(results.hosts)} hosts")
        logger.debug(f"Detailed results: {formatted_results}")
        
        return jsonify(formatted_results)

    except Exception as e:
        logger.error(f"Scan failed: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/results')
def get_results():
    try:
        results_dir = os.path.join('src', 'data', 'scans')
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

@app.route('/api/status')
def get_status():
    """Get current scanner status"""
    try:
        return jsonify({
            'status': 'ready',
            'last_scan': None,  # You can implement last scan tracking if needed
            'uptime': 'active'
        })
    except Exception as e:
        logger.error(f"Error getting status: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/network/stats')
def get_network_stats():
    """Get current network statistics"""
    try:
        stats = analyzer.generate_network_stats()
        vulnerability_score = analyzer.calculate_vulnerability_score()
        
        return jsonify({
            'status': 'success',
            'statistics': stats,
            'vulnerability_score': vulnerability_score,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error getting network stats: {str(e)}")
        return jsonify({'error': str(e)}), 500    
    
@app.route('/api/networks')
def get_networks():
    """Get available networks for scanning"""
    try:
        networks = NetworkDiscovery.get_local_networks()
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


@app.route('/api/network/visualization')
def get_network_visualization():
    """Get network visualization data"""
    try:
        viz_file = os.path.join('src', 'data', 'analysis', 'network_visualization.png')
        if os.path.exists(viz_file):
            return send_file(viz_file, mimetype='image/png')
        else:
            return jsonify({'error': 'Visualization not found'}), 404
    except Exception as e:
        logger.error(f"Error getting visualization: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Add new endpoint
@app.route('/api/topology/<scan_id>')
def get_topology(scan_id):
    """Get network topology data for visualization"""
    try:
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

        # Generate topology data
        analyzer = TopologyAnalyzer()
        topology_data = analyzer.create_network_graph(scan_result)
        
        return jsonify(topology_data)

    except Exception as e:
        logger.error(f"Error generating topology: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/analysis/<analysis_id>/report', methods=['GET'])
def get_analysis_report(analysis_id):
    """Get the executive report for a specific analysis"""
    try:
        # Set up directories
        analysis_dir = os.path.join('src', 'data', 'analysis')
        reports_dir = os.path.join('src', 'data', 'reports')
        os.makedirs(analysis_dir, exist_ok=True)
        os.makedirs(reports_dir, exist_ok=True)

        # Clean up the analysis ID
        base_id = analysis_id.split('.')[0]  # Remove any file extension
        timestamp_part = base_id.split('analysis_')[-1][:12]  # Get YYYYMMDDHHMMSS part
        clean_id = f"analysis_{timestamp_part}"
        
        # Try different file patterns
        possible_files = [
            os.path.join(analysis_dir, f'{analysis_id}.json'),
            os.path.join(analysis_dir, f'{clean_id}.json')
        ]
        
        logger.info(f"Looking for analysis files with patterns: {possible_files}")
        existing_files = os.listdir(analysis_dir)
        logger.info(f"Available files in analysis directory: {existing_files}")

        # Find the first matching file that exists
        analysis_file = None
        for file_path in possible_files:
            if os.path.exists(file_path):
                analysis_file = file_path
                logger.info(f"Found matching analysis file: {file_path}")
                break

        if not analysis_file:
            # Try to find the file by matching timestamp portion
            for existing_file in existing_files:
                if timestamp_part in existing_file:
                    analysis_file = os.path.join(analysis_dir, existing_file)
                    logger.info(f"Found matching analysis file by timestamp: {analysis_file}")
                    break

        if not analysis_file:
            logger.error(f"Analysis not found for ID: {analysis_id}")
            return jsonify({
                'error': 'Analysis not found',
                'details': {
                    'requested_id': analysis_id,
                    'attempted_patterns': [
                        analysis_id,
                        clean_id,
                        f"*{timestamp_part}*"
                    ],
                    'existing_files': existing_files
                }
            }), 404

        # Load and validate analysis data
        try:
            with open(analysis_file, 'r') as f:
                analysis_data = json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in analysis file: {str(e)}")
            return jsonify({'error': 'Corrupt analysis file'}), 500
        except Exception as e:
            logger.error(f"Error reading analysis file: {str(e)}")
            return jsonify({'error': 'Failed to read analysis file'}), 500

        # Generate report
        try:
            report = analyzer.generate_executive_report(analysis_data)
        except AttributeError:
            logger.warning("Executive report generator not available, using basic report")
            report = generate_basic_report(analysis_data)
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            return jsonify({'error': 'Failed to generate report'}), 500

        # Save report
        try:
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            report_filename = f'report_{clean_id}_{timestamp}.md'
            report_path = os.path.join(reports_dir, report_filename)
            
            with open(report_path, 'w') as f:
                f.write(report)
                
            logger.info(f"Report saved to {report_path}")
            
            return jsonify({
                'status': 'success',
                'report': report,
                'report_file': report_filename
            })
            
        except Exception as e:
            logger.error(f"Error saving report: {str(e)}")
            # Still return the report even if saving failed
            return jsonify({
                'status': 'partial_success',
                'report': report,
                'error': 'Failed to save report file'
            })

    except Exception as e:
        logger.error(f"Unhandled exception in get_analysis_report: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'Internal server error',
            'details': str(e)
        }), 500
    
# Add this route to your app.py
@app.route('/favicon.ico')
def favicon():
    return send_file(
        os.path.join(app.root_path, 'static', 'favicon.ico'),
        mimetype='image/vnd.microsoft.icon'
    )
    
def generate_basic_report(analysis_data):
    """Generate a basic report if the full report generation fails"""
    try:
        results = analysis_data.get('results', {})
        summary = results.get('summary', {})
        
        report = [
            "# Network Analysis Report",
            f"\nAnalysis Date: {analysis_data.get('timestamp', 'N/A')}",
            "\n## Summary",
            f"- Total Nodes: {summary.get('total_nodes', 'N/A')}",
            f"- High Risk Nodes: {summary.get('high_risk_nodes', 'N/A')}",
            f"- Components: {summary.get('components', 'N/A')}",
            "\n## Details",
        ]
        
        # Add any available security metrics
        security_metrics = results.get('security_metrics', {})
        if security_metrics:
            report.append("\n### Security Metrics")
            for node, metrics in security_metrics.items():
                report.append(f"\nNode: {node}")
                report.append(f"- Type: {metrics.get('device_type', 'Unknown')}")
                report.append(f"- Risk Level: {metrics.get('risk_level', 'Unknown')}")
        
        # Add any available anomalies
        anomalies = results.get('anomalies', {})
        if anomalies:
            report.append("\n### Anomalies")
            for node, data in anomalies.items():
                report.append(f"\nNode: {node}")
                report.append(f"- Risk Score: {data.get('risk_score', 'N/A')}")
        
        return "\n".join(report)
        
    except Exception as e:
        logger.error(f"Error generating basic report: {e}")
        return "Error generating report"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050, debug=True)