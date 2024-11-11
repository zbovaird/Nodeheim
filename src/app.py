# src/app.py
from flask import Flask, render_template, jsonify, request
import sys
import os
import json
import logging
from typing import Dict, Any
from datetime import datetime
from scanner.network_discovery import NetworkDiscovery
from analyzer.topology import TopologyAnalyzer
import networkx as nx
from uuid import uuid4
from datetime import datetime

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.scanner.scanner import NetworkScanner, ScanResult

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

# Add to your imports
from analyzer.topology import TopologyAnalyzer

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050, debug=True)