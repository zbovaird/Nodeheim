import splunk.Intersplunk  # type: ignore
import sys
import os
import json
from scanner.scanner import scan_network as run_network_scan

def scan_network(args):
    try:
        # Parse arguments
        subnet = args[0] if args else "192.168.1.0/24"
        scan_type = args[1] if len(args) > 1 else "basic_scan"
        
        # Create sample data for testing
        sample_data = [{
            'host': f'192.168.1.{i}',
            'type': 'host',
            'status': 'up',
            'connections': [
                {'target': f'192.168.1.{i+1}', 'type': 'network', 'latency': 1}
            ]
        } for i in range(1, 5)]
        
        # Run scan
        scan_results = run_network_scan(sample_data)
        
        # Convert to Splunk events
        events = []
        for node in scan_results.get('nodes', []):
            event = {
                'host': node['id'],
                'source': 'nodeheim:scanner',
                'sourcetype': 'nodeheim:scan',
                '_time': scan_results.get('timestamp'),
                '_raw': json.dumps(node),
                'subnet': subnet,
                'scan_type': scan_type,
                'type': node['attributes'].get('type', ''),
                'status': node['attributes'].get('status', '')
            }
            events.append(event)
            
        return events
        
    except Exception as e:
        splunk.Intersplunk.generateErrorResults(str(e))
        return None

if __name__ == '__main__':
    try:
        # Get arguments from Splunk
        results, dummyresults, settings = splunk.Intersplunk.getOrganizedResults()
        args = sys.argv[1:]
        
        # Run scan
        events = scan_network(args)
        
        # Output results
        if events:
            splunk.Intersplunk.outputResults(events)
            
    except Exception as e:
        splunk.Intersplunk.generateErrorResults(str(e)) 