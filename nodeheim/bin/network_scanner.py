#!/opt/splunk/bin/python3
import sys
import os
import logging
from datetime import datetime
import ipaddress
import subprocess
import json

# Configure logging to stderr
logging.basicConfig(
    stream=sys.stderr,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s"
)

def scan_network(subnet, scan_type="basic"):
    """Scan the network and return results."""
    try:
        network = ipaddress.ip_network(subnet)
        results = []
        
        for ip in network.hosts():
            ip_str = str(ip)
            
            # Basic ping scan
            ping_result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip_str],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            if ping_result.returncode == 0:
                result = {
                    "_raw": f"Host discovered: {ip_str}",
                    "_time": datetime.now().timestamp(),
                    "host": "nodeheim_scanner",
                    "source": "nodeheim:scan",
                    "sourcetype": "nodeheim:scan",
                    "event_type": "host_discovery",
                    "status": "up",
                    "ip_address": ip_str,
                    "scan_type": scan_type,
                    "subnet": subnet
                }
                results.append(result)
                logging.debug("Found active host: %s", ip_str)
                
        return results
    except Exception as e:
        logging.error("Error in scan_network: %s", str(e))
        raise

def main():
    try:
        logging.debug("Script starting at: %s", datetime.now())

        # Check if running in test mode
        if len(sys.argv) > 1 and sys.argv[1] == "--test":
            print("Test mode: Script loaded successfully")
            return

        # Import Splunk libraries
        import splunk.Intersplunk
        logging.debug("Successfully imported splunk.Intersplunk")

        # Get the keywords and options from Splunk
        keywords, options = splunk.Intersplunk.getKeywordsAndOptions()
        logging.debug("Keywords: %s, Options: %s", keywords, options)

        # Get any results that were passed in
        results, dummyresults, settings = splunk.Intersplunk.getOrganizedResults()
        logging.debug("Got %d results from input", len(results))

        # Get subnet and scan type from options
        subnet = options.get("subnet", "192.168.1.0/24")
        scan_type = options.get("scan_type", "basic")
        
        logging.debug("Starting scan of subnet %s with type %s", subnet, scan_type)
        scan_results = scan_network(subnet, scan_type)
        logging.debug("Scan complete. Found %d hosts", len(scan_results))

        # Output the results
        splunk.Intersplunk.outputResults(scan_results)
        logging.debug("Successfully output scan results")

    except Exception as e:
        logging.error("Fatal error: %s", str(e))
        import traceback
        logging.error("Traceback: %s", traceback.format_exc())
        if len(sys.argv) > 1 and sys.argv[1] == "--test":
            print(f"Error: {str(e)}")
        else:
            import splunk.Intersplunk
            splunk.Intersplunk.generateErrorResults(str(e))
        sys.exit(1)
    finally:
        logging.debug("Script completed at: %s", datetime.now())

if __name__ == "__main__":
    main()