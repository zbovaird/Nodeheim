"""
Nodeheim Network Scanner
Performs network scanning operations for the Nodeheim Splunk app.
Uses only non-privileged scan types for basic functionality.
"""

import sys
import os
import logging
from datetime import datetime
import ipaddress
import json
import nmap
import splunk.Intersplunk  # type: ignore
import splunk.auth  # type: ignore

# Configure logging
logger = logging.getLogger('splunk.nodeheim.network_scanner')

class SplunkNmapError(Exception):
    """Custom exception for Nodeheim nmap errors."""
    pass

class NetworkScanner:
    def __init__(self):
        self.nm = None
        self._check_capabilities()
        
    def _check_capabilities(self):
        """Check if we have the required capabilities to run nmap."""
        try:
            # Check if we're running with sufficient privileges
            capabilities = splunk.auth.getCapabilities()
            
            required_caps = ['network_scan', 'raw_exec']
            missing_caps = [cap for cap in required_caps if cap not in capabilities]
            
            if missing_caps:
                raise SplunkNmapError(f"Missing required capabilities: {', '.join(missing_caps)}")
            
            self.nm = nmap.PortScanner()
                
        except Exception as e:
            logger.error(f"Failed to initialize scanner: {str(e)}")
            raise SplunkNmapError(f"Scanner initialization failed: {str(e)}")
        
    def scan_network(self, subnet, scan_type="basic"):
        """
        Scan the network using nmap with non-privileged scan types.
        
        Scan Types:
        - basic: Simple host discovery using -sn (no port scanning)
        - connect: TCP connect scan (-sT) - most basic port scan
        - version: Version detection on common ports (-sV)
        """
        try:
            if not self.nm:
                raise SplunkNmapError("Scanner not properly initialized. Check capabilities and permissions.")
                
            # Validate subnet
            try:
                network = ipaddress.ip_network(subnet)
            except ValueError as e:
                raise SplunkNmapError(f"Invalid subnet format: {str(e)}")
                
            results = []
            
            # Configure scan based on type
            if scan_type == "basic":
                arguments = "-sn"  # Simple ping scan
            elif scan_type == "connect":
                arguments = "-sT -F"  # TCP connect scan on common ports
            elif scan_type == "version":
                arguments = "-sT -sV -F"  # Version detection on common ports
            else:
                raise SplunkNmapError(f"Invalid scan type: {scan_type}. Valid types are: basic, connect, version")
                
            logger.debug(f"Starting nmap scan of {subnet} with arguments: {arguments}")
            try:
                self.nm.scan(hosts=str(network), arguments=arguments)
            except nmap.PortScannerError as e:
                raise SplunkNmapError(f"Nmap scan failed: {str(e)}")
            
            # Process results
            for host in self.nm.all_hosts():
                host_data = self.nm[host]
                
                result = {
                    "_raw": f"Host discovered: {host}",
                    "_time": datetime.now().timestamp(),
                    "host": os.uname().nodename if os.name != "nt" else os.environ.get("COMPUTERNAME", "unknown"),
                    "source": "nodeheim:scan",
                    "sourcetype": "nodeheim:scan",
                    "event_type": "host_discovery",
                    "status": "up" if host_data.state() == "up" else "down",
                    "ip_address": host,
                    "scan_type": scan_type,
                    "subnet": subnet
                }
                
                # Add version detection results if available
                if scan_type == "version" and "tcp" in host_data:
                    open_ports = {}
                    for port, data in host_data["tcp"].items():
                        if data["state"] == "open":
                            open_ports[str(port)] = {
                                "name": data.get("name", "unknown"),
                                "product": data.get("product", ""),
                                "version": data.get("version", ""),
                                "extrainfo": data.get("extrainfo", "")
                            }
                    result["open_ports"] = open_ports
                
                # Add basic port info for connect scan
                elif scan_type == "connect" and "tcp" in host_data:
                    result["open_ports"] = [port for port, data in host_data["tcp"].items() 
                                          if data["state"] == "open"]
                
                results.append(result)
                logger.debug(f"Found host: {host} - Status: {result['status']}")
                
            return results
            
        except SplunkNmapError:
            # Re-raise SplunkNmapError as is
            raise
        except Exception as e:
            # Wrap unexpected errors
            raise SplunkNmapError(f"Unexpected error during network scan: {str(e)}")

def main():
    try:
        logger.debug("Script starting at: %s", datetime.now())
        scanner = NetworkScanner()

        # Check if running in test mode
        if len(sys.argv) > 1 and sys.argv[1] == "--test":
            print("Test mode: Script loaded successfully")
            return

        # Get the keywords and options from Splunk
        keywords, options = splunk.Intersplunk.getKeywordsAndOptions()
        logger.debug("Keywords: %s, Options: %s", keywords, options)

        # Get any results that were passed in
        results, dummyresults, settings = splunk.Intersplunk.getOrganizedResults()
        logger.debug("Got %d results from input", len(results))

        # Get subnet and scan type from options
        subnet = options.get("subnet", "192.168.1.0/24")
        scan_type = options.get("scan_type", "basic")
        
        logger.debug("Starting scan of subnet %s with type %s", subnet, scan_type)
        scan_results = scanner.scan_network(subnet, scan_type)
        logger.debug("Scan complete. Found %d hosts", len(scan_results))

        # Output the results
        splunk.Intersplunk.outputResults(scan_results)
        logger.debug("Successfully output scan results")

    except SplunkNmapError as e:
        logger.error(str(e))
        splunk.Intersplunk.generateErrorResults(str(e))
    except Exception as e:
        logger.error("Fatal error: %s", str(e))
        import traceback
        logger.error("Traceback: %s", traceback.format_exc())
        splunk.Intersplunk.generateErrorResults(f"Unexpected error: {str(e)}")
    finally:
        logger.debug("Script completed at: %s", datetime.now())

if __name__ == "__main__":
    main()