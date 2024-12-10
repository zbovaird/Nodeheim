#!/usr/bin/env python
"""
Nodeheim Connector
Main interface for network discovery and analysis operations.
Implements standardized Splunk action types for interoperability.
"""

import os
import sys
import json
import logging
from datetime import datetime

# Add lib directory to path for dependencies
app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
lib_path = os.path.join(app_root, 'lib')
if lib_path not in sys.path:
    sys.path.append(lib_path)

import splunk.Intersplunk as si
import network_scanner
import network_analyzer
import network_comparison

class NodeheimConnector:
    """Main connector class for Nodeheim operations"""
    
    def __init__(self):
        """Initialize the connector"""
        self.logger = logging.getLogger('splunk.nodeheim.connector')
        self.setup_logging()
        self.load_metadata()
    
    def setup_logging(self):
        """Configure logging"""
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    def load_metadata(self):
        """Load app metadata"""
        metadata_path = os.path.join(app_root, 'metadata', 'app.json')
        try:
            with open(metadata_path, 'r') as f:
                self.metadata = json.load(f)
            self.logger.info("Loaded metadata from %s", metadata_path)
        except Exception as e:
            self.logger.error("Failed to load metadata: %s", str(e))
            self.metadata = {}
    
    def handle_discover_hosts(self, args):
        """Handle host discovery operations"""
        try:
            scanner = network_scanner.NetworkScanner()
            results = scanner.scan(
                target=args.get('target'),
                options=args.get('options', '-sn'),
                source=args.get('source', 'direct')
            )
            return {
                'status': 'success',
                'results': results,
                'timestamp': datetime.utcnow().isoformat(),
                'contains': ['ip', 'time']
            }
        except Exception as e:
            self.logger.error("Host discovery failed: %s", str(e))
            return {
                'status': 'error',
                'message': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def handle_investigate_network(self, args):
        """Handle network investigation operations"""
        try:
            analyzer = network_analyzer.NetworkAnalyzer()
            results = analyzer.analyze(scan_id=args.get('scan_id'))
            return {
                'status': 'success',
                'topology': results,
                'timestamp': datetime.utcnow().isoformat(),
                'contains': ['network_topology']
            }
        except Exception as e:
            self.logger.error("Network investigation failed: %s", str(e))
            return {
                'status': 'error',
                'message': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def handle_compare_networks(self, args):
        """Handle network comparison operations"""
        try:
            comparator = network_comparison.NetworkComparator()
            results = comparator.compare(
                scan_id_1=args.get('scan_id_1'),
                scan_id_2=args.get('scan_id_2')
            )
            return {
                'status': 'success',
                'differences': results,
                'timestamp': datetime.utcnow().isoformat(),
                'contains': ['network_changes']
            }
        except Exception as e:
            self.logger.error("Network comparison failed: %s", str(e))
            return {
                'status': 'error',
                'message': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def handle_request(self, action, args):
        """Main request handler"""
        # Map standard action types to handlers
        handlers = {
            'discover_hosts': self.handle_discover_hosts,
            'investigate_network': self.handle_investigate_network,
            'compare_networks': self.handle_compare_networks
        }
        
        # Check if action exists in metadata
        if not self.metadata.get('actions'):
            self.logger.error("No actions defined in metadata")
            return {
                'status': 'error',
                'message': 'No actions defined in metadata',
                'timestamp': datetime.utcnow().isoformat()
            }
        
        # Validate action exists
        if action not in handlers:
            self.logger.error("Unknown action: %s", action)
            return {
                'status': 'error',
                'message': f'Unknown action: {action}',
                'timestamp': datetime.utcnow().isoformat()
            }
        
        # Get action metadata
        action_meta = next((a for a in self.metadata['actions'] if a['name'] == action), None)
        if not action_meta:
            self.logger.error("Action metadata not found: %s", action)
            return {
                'status': 'error',
                'message': f'Action metadata not found: {action}',
                'timestamp': datetime.utcnow().isoformat()
            }
        
        # Validate required parameters
        for param_name, param_meta in action_meta.get('parameters', {}).items():
            if param_meta.get('required', False) and param_name not in args:
                return {
                    'status': 'error',
                    'message': f'Missing required parameter: {param_name}',
                    'timestamp': datetime.utcnow().isoformat()
                }
        
        # Handle the request
        return handlers[action](args)

def main():
    """Main entry point"""
    try:
        # Get Splunk command arguments
        keywords, options = si.getKeywordsAndOptions()
        
        # Initialize connector
        connector = NodeheimConnector()
        
        # Determine action from command name or options
        action = options.get('action', 'discover_hosts')
        
        # Handle request
        results = connector.handle_request(action, options)
        
        # Output results to Splunk
        if results['status'] == 'success':
            si.outputResults([results])
        else:
            si.generateErrorResults(results['message'])
            
    except Exception as e:
        si.generateErrorResults(str(e))

if __name__ == "__main__":
    main() 