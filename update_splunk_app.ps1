# Create necessary directories if they don't exist
mkdir -Force splunk_app_files/bin | Out-Null
mkdir -Force splunk_app_files/default/data/ui/nav | Out-Null
mkdir -Force splunk_app_files/default/data/ui/views | Out-Null
mkdir -Force splunk_app_files/lib/scanner | Out-Null

# Copy scanner.py to lib/scanner
Copy-Item "src/scanner/scanner.py" -Destination "splunk_app_files/lib/scanner/" -Force

# Create network_scanner.py
@"
import splunk.Intersplunk
import sys
import os
import json
import nmap
from datetime import datetime
from scanner.scanner import NetworkScanner

# Add the lib directory to Python path
app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
lib_path = os.path.join(app_root, 'lib')
sys.path.append(lib_path)

def scan_network(args):
    try:
        subnet = args[0] if args else "192.168.1.0/24"
        scan_type = args[1] if len(args) > 1 else "basic_scan"
        
        scanner = NetworkScanner()
        scan_results = scanner.run_scan(subnet, scan_type)
        
        # Convert to Splunk events
        events = []
        for host in scan_results.get('hosts', []):
            event = {
                'host': host.get('ip_address'),
                'source': 'nodeheim:scanner',
                'sourcetype': 'nodeheim:scan',
                '_time': scan_results.get('timestamp'),
                '_raw': json.dumps(host),
                'subnet': subnet,
                'scan_type': scan_type,
                'hostname': host.get('hostname', ''),
                'os': host.get('os_info', {}).get('os_match', ''),
                'ports': host.get('ports', []),
                'services': host.get('services', [])
            }
            events.append(event)
            
        return events
        
    except Exception as e:
        splunk.Intersplunk.generateErrorResults(str(e))
        return None

if __name__ == '__main__':
    try:
        results, dummyresults, settings = splunk.Intersplunk.getOrganizedResults()
        args = sys.argv[1:]
        events = scan_network(args)
        if events:
            splunk.Intersplunk.outputResults(events)
    except Exception as e:
        splunk.Intersplunk.generateErrorResults(str(e))
"@ | Out-File -Encoding UTF8 splunk_app_files/bin/network_scanner.py

# Create network_analyzer.py
@"
import splunk.Intersplunk
import sys
import os
import json
import networkx as nx
from datetime import datetime

def analyze_network(results):
    try:
        # Create network graph from scan results
        G = nx.Graph()
        
        # Add nodes and their properties
        for result in results:
            host = result.get('host')
            hostname = result.get('hostname')
            ports = result.get('ports', [])
            services = result.get('services', [])
            os_info = result.get('os')
            
            # Add node with attributes
            G.add_node(host, 
                      hostname=hostname,
                      ports=ports,
                      services=services,
                      os=os_info)
        
        # Calculate network metrics
        metrics = {
            'total_hosts': len(G.nodes()),
            'total_connections': len(G.edges()),
            'density': nx.density(G),
            'average_degree': sum(dict(G.degree()).values()) / G.number_of_nodes() if G.number_of_nodes() > 0 else 0,
            'centrality': nx.degree_centrality(G),
            'betweenness': nx.betweenness_centrality(G),
            'clustering': nx.clustering(G)
        }
        
        analysis_results = {
            'source': 'nodeheim:analysis',
            'sourcetype': 'nodeheim:analysis',
            '_time': datetime.now().timestamp(),
            'metrics': metrics,
            'network_structure': {
                'is_connected': nx.is_connected(G),
                'components': len(list(nx.connected_components(G))),
                'diameter': nx.diameter(G) if nx.is_connected(G) else -1
            }
        }
        
        return [analysis_results]
        
    except Exception as e:
        splunk.Intersplunk.generateErrorResults(str(e))
        return None

if __name__ == '__main__':
    try:
        results, dummyresults, settings = splunk.Intersplunk.getOrganizedResults()
        events = analyze_network(results)
        if events:
            splunk.Intersplunk.outputResults(events)
    except Exception as e:
        splunk.Intersplunk.generateErrorResults(str(e))
"@ | Out-File -Encoding UTF8 splunk_app_files/bin/network_analyzer.py

# Create app.conf
@"
[install]
is_configured = 0
state = enabled

[package]
id = nodeheim-splunk
check_for_updates = 1

[ui]
is_visible = 1
label = Nodeheim Network Analysis

[launcher]
author = Your Name
description = Network Discovery and Analysis Tool for Splunk
version = 1.0.0
"@ | Out-File -Encoding UTF8 splunk_app_files/default/app.conf

# Create commands.conf
@"
[nodeheim_scan]
filename = network_scanner.py
enableheader = true
outputheader = true
requires_srinfo = true
supports_getinfo = true
supports_rawargs = true

[nodeheim_analyze]
filename = network_analyzer.py
enableheader = true
outputheader = true
requires_srinfo = true
supports_getinfo = true
supports_rawargs = true
"@ | Out-File -Encoding UTF8 splunk_app_files/default/commands.conf

# Create navigation menu
@"
<nav search_view="search">
  <view name="network_analysis" default="true"/>
  <collection label="Network Analysis">
    <view name="network_analysis" label="Network Discovery"/>
  </collection>
</nav>
"@ | Out-File -Encoding UTF8 splunk_app_files/default/data/ui/nav/default.xml

# Create dashboard
@"
<?xml version="1.0" encoding="UTF-8"?>
<dashboard version="2.0">
  <label>Network Analysis</label>
  <description>Network discovery and analysis dashboard</description>
  
  <row>
    <panel>
      <title>Network Scan</title>
      <input type="dropdown" token="subnet">
        <label>Subnet</label>
        <choice value="192.168.1.0/24">192.168.1.0/24</choice>
        <choice value="10.0.0.0/24">10.0.0.0/24</choice>
        <default>192.168.1.0/24</default>
      </input>
      <input type="dropdown" token="scan_type">
        <label>Scan Type</label>
        <choice value="basic_scan">Basic Scan</choice>
        <choice value="full_scan">Full Scan</choice>
        <default>basic_scan</default>
      </input>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>Network Metrics</title>
      <table>
        <search>
          <query>| nodeheim_scan $subnet$ $scan_type$ | nodeheim_analyze | table metrics.*</query>
          <earliest>-15m</earliest>
          <latest>now</latest>
        </search>
      </table>
    </panel>
  </row>

  <row>
    <panel>
      <title>Host Details</title>
      <table>
        <search>
          <query>| nodeheim_scan $subnet$ $scan_type$ | table host hostname os ports services</query>
          <earliest>-15m</earliest>
          <latest>now</latest>
        </search>
      </table>
    </panel>
  </row>
</dashboard>
"@ | Out-File -Encoding UTF8 splunk_app_files/default/data/ui/views/network_analysis.xml

# Copy everything to the Splunk container
docker cp splunk_app_files/. splunk_free:/opt/splunk/etc/apps/nodeheim-splunk/

# Set permissions and restart Splunk
docker exec -u root splunk_free chown -R splunk:splunk /opt/splunk/etc/apps/nodeheim-splunk/
docker exec -u root splunk_free chmod -R 755 /opt/splunk/etc/apps/nodeheim-splunk/
docker exec -u root splunk_free /opt/splunk/bin/splunk restart --accept-license --answer-yes --no-prompt
