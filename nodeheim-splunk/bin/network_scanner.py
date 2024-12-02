#!/usr/bin/env python3
import sys
import os
import logging

# Set up logging
log_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'var', 'log', 'nodeheim_scanner.log')
logging.basicConfig(filename=log_file, level=logging.DEBUG,
                   format='%(asctime)s %(levelname)s %(message)s')

# Add the app's bin directory to the Python path
app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
bin_path = os.path.join(app_root, 'bin')
if bin_path not in sys.path:
    sys.path.insert(0, bin_path)

import splunk.Intersplunk  # type: ignore
from scanner.scanner import scan_network, format_splunk_event

def run_scan(args):
    try:
        logging.info(f"Starting scan with args: {args}")
        
        # Parse arguments
        subnet = args[0] if args else "192.168.1.0/24"
        scan_type = args[1] if len(args) > 1 else "basic_scan"
        
        logging.info(f"Scanning subnet: {subnet} with type: {scan_type}")
        
        # Run network scan
        scan_results = scan_network(subnet, scan_type == "full_scan")
        
        logging.info(f"Scan completed. Results: {scan_results}")
        
        # Format results as Splunk events
        events = format_splunk_event(scan_results)
        
        logging.info(f"Formatted {len(events)} events")
        return events
        
    except Exception as e:
        logging.error(f"Error in run_scan: {str(e)}", exc_info=True)
        splunk.Intersplunk.generateErrorResults(str(e))
        return None

if __name__ == '__main__':
    try:
        logging.info("Script started")
        
        # Get arguments from Splunk
        results, dummyresults, settings = splunk.Intersplunk.getOrganizedResults()
        args = sys.argv[1:]
        
        logging.info(f"Received args from Splunk: {args}")
        
        # Run scan
        events = run_scan(args)
        
        # Output results
        if events:
            logging.info(f"Outputting {len(events)} events")
            splunk.Intersplunk.outputResults(events)
        else:
            logging.warning("No events to output")
            
    except Exception as e:
        logging.error(f"Error in main: {str(e)}", exc_info=True)
        splunk.Intersplunk.generateErrorResults(str(e)) 