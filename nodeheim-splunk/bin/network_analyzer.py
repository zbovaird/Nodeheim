import splunk.Intersplunk  # type: ignore
import networkx as nx
import json
from analyzer.topology import create_network_topology, analyze_topology
from analyzer.network_analysis import analyze_network as analyze_net

def analyze_network(results):
    try:
        # Create network graph from results
        hosts = []
        for result in results:
            host_data = json.loads(result.get('_raw', '{}'))
            hosts.append(host_data)
            
        scan_data = {'hosts': hosts}
        G = create_network_topology(scan_data)
        
        # Run analysis
        metrics = analyze_topology(G)
        network_metrics = analyze_net(G)
        
        # Create analysis event
        analysis_event = {
            'source': 'nodeheim:analysis',
            'sourcetype': 'nodeheim:analysis',
            'metrics': metrics,
            'network_metrics': network_metrics
        }
        
        return [analysis_event]
        
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