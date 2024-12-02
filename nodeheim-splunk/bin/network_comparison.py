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
import networkx as nx
from datetime import datetime
from analyzer.topology import create_network_topology
from analyzer.network_analysis import compare_networks

def compare_network_scans(results, timespan):
    try:
        # Group results by scan time
        scans = {}
        for result in results:
            scan_time = result.get('_time')
            if scan_time not in scans:
                scans[scan_time] = []
            scans[scan_time].append(json.loads(result.get('_raw', '{}')))

        # Sort scans by time
        sorted_scans = sorted(scans.items())
        if len(sorted_scans) < 2:
            return [{'error': 'Need at least 2 scans to compare'}]

        # Get latest two scans
        before_time, before_data = sorted_scans[-2]
        after_time, after_data = sorted_scans[-1]

        # Create network graphs
        G_before = create_network_topology({'nodes': before_data})
        G_after = create_network_topology({'nodes': after_data})

        # Compare networks
        comparison = compare_networks(G_before, G_after)
        
        # Create comparison event
        comparison_event = {
            'source': 'nodeheim:comparison',
            'sourcetype': 'nodeheim:comparison',
            '_time': datetime.now().timestamp(),
            'before_time': before_time,
            'after_time': after_time,
            'comparison': comparison
        }

        return [comparison_event]

    except Exception as e:
        splunk.Intersplunk.generateErrorResults(str(e))
        return None

if __name__ == '__main__':
    try:
        results, dummyresults, settings = splunk.Intersplunk.getOrganizedResults()
        timespan = sys.argv[1] if len(sys.argv) > 1 else "24h"
        events = compare_network_scans(results, timespan)
        if events:
            splunk.Intersplunk.outputResults(events)
    except Exception as e:
        splunk.Intersplunk.generateErrorResults(str(e)) 