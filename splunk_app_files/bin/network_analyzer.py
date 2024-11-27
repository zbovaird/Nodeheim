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
            
            # Add edges based on network proximity and shared services
            for other_result in results:
                other_host = other_result.get('host')
                if host != other_host:
                    other_services = set(other_result.get('services', []))
                    services_set = set(services)
                    if services_set.intersection(other_services):
                        G.add_edge(host, other_host)
        
        # Calculate network metrics
        metrics = {
            'total_hosts': len(G.nodes()),
            'total_connections': len(G.edges()),
            'density': nx.density(G),
            'average_degree': sum(dict(G.degree()).values()) / G.number_of_nodes() if G.number_of_nodes() > 0 else 0,
            'centrality': {
                node: round(score, 3) 
                for node, score in nx.degree_centrality(G).items()
            },
            'betweenness': {
                node: round(score, 3) 
                for node, score in nx.betweenness_centrality(G).items()
            },
            'clustering': {
                node: round(score, 3) 
                for node, score in nx.clustering(G).items()
            }
        }
        
        # Identify critical nodes
        critical_nodes = []
        avg_betweenness = sum(metrics['betweenness'].values()) / len(G.nodes()) if G.nodes() else 0
        
        for node in G.nodes():
            degree = G.degree(node)
            betweenness = metrics['betweenness'][node]
            if degree > metrics['average_degree'] or betweenness > avg_betweenness:
                critical_nodes.append({
                    'node': node,
                    'hostname': G.nodes[node]['hostname'],
                    'degree': degree,
                    'betweenness': round(betweenness, 3),
                    'services': G.nodes[node]['services']
                })
        
        # Calculate spectral properties
        try:
            laplacian = nx.laplacian_matrix(G).todense()
            eigenvalues = sorted(nx.laplacian_spectrum(G))
            spectral_metrics = {
                'spectral_radius': float(max(abs(eigenvalues))),
                'algebraic_connectivity': float(eigenvalues[1]) if len(eigenvalues) > 1 else 0,
                'spectral_gap': float(eigenvalues[1] - eigenvalues[0]) if len(eigenvalues) > 1 else 0
            }
        except:
            spectral_metrics = {
                'spectral_radius': 0,
                'algebraic_connectivity': 0,
                'spectral_gap': 0
            }
        
        analysis_results = {
            'source': 'nodeheim:analysis',
            'sourcetype': 'nodeheim:analysis',
            '_time': datetime.now().timestamp(),
            'metrics': metrics,
            'critical_nodes': critical_nodes,
            'spectral_metrics': spectral_metrics,
            'network_structure': {
                'is_connected': nx.is_connected(G),
                'components': len(list(nx.connected_components(G))),
                'diameter': nx.diameter(G) if nx.is_connected(G) else -1,
                'average_path_length': nx.average_shortest_path_length(G) if nx.is_connected(G) else -1
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
