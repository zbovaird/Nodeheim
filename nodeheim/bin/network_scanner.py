#!/usr/bin/env python
"""
Nodeheim Network Scanner
Performs network scanning operations for the Nodeheim Splunk app.
Uses only non-privileged scan types for basic functionality.
"""

import sys
import os

# Add our app's lib directory to the Python path
app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
lib_path = os.path.join(app_root, 'lib')
sys.path.insert(0, lib_path)

import logging
import time
from datetime import datetime
import ipaddress
import json
import nmap
import splunk.Intersplunk
import splunk.mining.dcutils as dcu

# Set up logging
logger = dcu.getLogger()

def setup_logging():
    """Configure logging for the command"""
    try:
        logging.root
        logging.root.addHandler(logging.StreamHandler())
        # Set log level from configuration or default to INFO
        log_level = os.environ.get('SPLUNK_HOME', 'INFO')
        logging.root.setLevel(log_level)
    except Exception as e:
        # If logging setup fails, continue but note the error
        sys.stderr.write(f"Logging setup failed: {str(e)}\n")

class SplunkNmapError(Exception):
    """Custom exception for Nmap scanning errors."""
    pass

def validate_options(options):
    """Validate command options"""
    validated = {}
    # Target is required
    if 'target' not in options:
        validated['target'] = '127.0.0.1/32'  # Default to localhost
    else:
        try:
            # Validate IP/network format
            ipaddress.ip_network(options['target'])
            validated['target'] = options['target']
        except ValueError:
            raise SplunkNmapError(f"Invalid target format: {options['target']}")
    
    # Scan options
    validated['options'] = options.get('options', '-sn')
    if not validated['options'].startswith('-'):
        raise SplunkNmapError("Scan options must start with '-'")
    
    return validated

def scan_network(target, options=None):
    """
    Perform network scan using nmap
    Returns: List of discovered hosts
    """
    try:
        logger.info(f"Starting network scan of {target} with options {options}")
        nm = nmap.PortScanner()
        scan_args = '-sn' if not options else options  # Default to ping scan
        nm.scan(hosts=target, arguments=scan_args)
        hosts = nm.all_hosts()
        logger.info(f"Scan complete. Found {len(hosts)} hosts")
        return hosts
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        raise SplunkNmapError(f"Scan failed: {str(e)}")

def process_results(hosts):
    """Process scan results into Splunk events"""
    events = []
    for host in hosts:
        # Create event with required fields
        event = {
            '_time': time.time(),
            'host': host,
            'status': 'up',
            'source': 'nodeheim_scan',
            'sourcetype': 'nodeheim:scan:result',
            '_raw': f"Host discovered: {host}"
        }
        events.append(event)
    return events

def main():
    """Main entry point for the command"""
    try:
        setup_logging()
        logger.info("Nodeheim scan command starting")
        
        # Get Splunk search results and settings
        results, dummyresults, settings = splunk.Intersplunk.getOrganizedResults()
        
        # Get and validate command options
        keywords, options = splunk.Intersplunk.getKeywordsAndOptions()
        logger.debug(f"Received options: {options}")
        
        # Validate options
        validated_options = validate_options(options)
        
        # Perform the scan
        hosts = scan_network(
            validated_options['target'], 
            validated_options['options']
        )
        
        # Process results
        events = process_results(hosts)
        
        # Output results to Splunk
        logger.info(f"Outputting {len(events)} events")
        splunk.Intersplunk.outputResults(events)
        
    except SplunkNmapError as e:
        logger.error(f"Command failed with SplunkNmapError: {str(e)}")
        splunk.Intersplunk.generateErrorResults(str(e))
    except Exception as e:
        logger.error(f"Command failed with unexpected error: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        splunk.Intersplunk.generateErrorResults(f"Unexpected error: {str(e)}")

if __name__ == '__main__':
    main()