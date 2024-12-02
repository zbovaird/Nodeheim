#!/usr/bin/env python3
import sys
import os

# Add the app's bin directory to the Python path
app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
bin_path = os.path.join(app_root, 'bin')
if bin_path not in sys.path:
    sys.path.insert(0, bin_path)

# Add Splunk's Python paths
splunk_home = os.environ.get('SPLUNK_HOME', '/opt/splunk')
python_paths = [
    os.path.join(splunk_home, 'lib', 'python3.7', 'site-packages'),
    os.path.join(splunk_home, 'lib', 'python3.9', 'site-packages'),
    os.path.join(splunk_home, 'lib', 'python3', 'site-packages'),
    os.path.join(splunk_home, 'lib', 'python'),
]

for path in python_paths:
    if os.path.exists(path) and path not in sys.path:
        sys.path.append(path)

try:
    import splunk.Intersplunk  # type: ignore
    from scanner.scanner import scan_network, format_splunk_event
except ImportError as e:
    import logging
    logging.error(f"Import error: {str(e)}")
    logging.error(f"sys.path: {sys.path}")
    raise

def run_scan(args):
    try:
        # Parse arguments
        subnet = args[0] if args else "192.168.1.0/24"
        scan_type = args[1] if len(args) > 1 else "basic_scan"
        
        # Run network scan
        scan_results = scan_network(subnet, scan_type == "full_scan")
        
        # Format results as Splunk events
        events = format_splunk_event(scan_results)
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
        events = run_scan(args)
        
        # Output results
        if events:
            splunk.Intersplunk.outputResults(events)
            
    except Exception as e:
        splunk.Intersplunk.generateErrorResults(str(e))