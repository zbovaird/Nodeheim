#!/usr/bin/env python3
import sys
import os

# Add the app's bin directory to the Python path
app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
bin_path = os.path.join(app_root, 'bin')
if bin_path not in sys.path:
    sys.path.insert(0, bin_path)

import splunk.Intersplunk  # type: ignore
import json
from datetime import datetime
from analyzer.topology import create_network_topology
from analyzer.network_analysis import analyze_network

def analyze_scan_results(results):
    try:
        # Process the most recent scan
        if not results:
            return [{'error': 'No scan results to analyze'}]

        # Parse the raw scan data
        scan_data = []
        for result in results:
            scan_data.append(json.loads(result.get('_raw', '{}')))

        # Create network topology
        topology = create_network_topology({'nodes': scan_data})
        
        # Analyze the network
        metrics = analyze_network(topology)
        
        # Create analysis event
        analysis_event = {
            'source': 'nodeheim:analysis',
            'sourcetype': 'nodeheim:analysis',
            '_time': datetime.now().timestamp(),
            'metrics': metrics
        }

        return [analysis_event]

    except Exception as e:
        splunk.Intersplunk.generateErrorResults(str(e))
        return None

if __name__ == '__main__':
    try:
        results, dummyresults, settings = splunk.Intersplunk.getOrganizedResults()
        events = analyze_scan_results(results)
        if events:
            splunk.Intersplunk.outputResults(events)
    except Exception as e:
        splunk.Intersplunk.generateErrorResults(str(e)) 