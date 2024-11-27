import splunk.Intersplunk
import sys
import os
import json
import networkx as nx
from datetime import datetime

def create_topology_visualization(results):
    try:
        # Create network graph from scan results
        G = nx.Graph()
        
        # Add nodes and their properties
        for result in results:
            host = result.get('host')
            hostname = result.get('hostname', '')
            ports = result.get('ports', [])
            services = result.get('services', [])
            os_info = result.get('os', '')
            
            # Create node label
            label = f"{host}\n{hostname}" if hostname else host
            
            # Add node with attributes
            G.add_node(host, 
                      label=label,
                      hostname=hostname,
                      ports=ports,
                      services=services,
                      os=os_info)
        
        # Add edges based on network proximity and shared services
        nodes = list(G.nodes())
        for i in range(len(nodes)):
            for j in range(i + 1, len(nodes)):
                node1, node2 = nodes[i], nodes[j]
                services1 = set(G.nodes[node1].get('services', []))
                services2 = set(G.nodes[node2].get('services', []))
                
                if services1.intersection(services2):
                    # Calculate edge weight based on shared services
                    weight = len(services1.intersection(services2))
                    G.add_edge(node1, node2, weight=weight)
        
        # Calculate node positions using force-directed layout
        pos = nx.spring_layout(G)
        
        # Create visualization data
        nodes_data = []
        for node in G.nodes():
            node_data = {
                'id': node,
                'label': G.nodes[node]['label'],
                'x': float(pos[node][0]),
                'y': float(pos[node][1]),
                'size': len(G.nodes[node].get('services', [])) + 5,
                'attributes': {
                    'hostname': G.nodes[node].get('hostname', ''),
                    'os': G.nodes[node].get('os', ''),
                    'services': G.nodes[node].get('services', []),
                    'ports': G.nodes[node].get('ports', [])
                }
            }
            nodes_data.append(node_data)
        
        edges_data = []
        for edge in G.edges(data=True):
            source, target, data = edge
            edge_data = {
                'id': f"{source}-{target}",
                'source': source,
                'target': target,
                'weight': data.get('weight', 1)
            }
            edges_data.append(edge_data)
        
        # Calculate network metrics for visualization
        metrics = {
            'total_nodes': len(G.nodes()),
            'total_edges': len(G.edges()),
            'density': nx.density(G),
            'average_degree': sum(dict(G.degree()).values()) / G.number_of_nodes() if G.number_of_nodes() > 0 else 0,
            'diameter': nx.diameter(G) if nx.is_connected(G) else -1,
            'average_path_length': nx.average_shortest_path_length(G) if nx.is_connected(G) else -1
        }
        
        # Create visualization event
        visualization_event = {
            'source': 'nodeheim:topology',
            'sourcetype': 'nodeheim:topology',
            '_time': datetime.now().timestamp(),
            'nodes': nodes_data,
            'edges': edges_data,
            'metrics': metrics,
            '_raw': json.dumps({
                'nodes': nodes_data,
                'edges': edges_data,
                'metrics': metrics
            })
        }
        
        return [visualization_event]
        
    except Exception as e:
        splunk.Intersplunk.generateErrorResults(str(e))
        return None

if __name__ == '__main__':
    try:
        results, dummyresults, settings = splunk.Intersplunk.getOrganizedResults()
        events = create_topology_visualization(results)
        if events:
            splunk.Intersplunk.outputResults(events)
    except Exception as e:
        splunk.Intersplunk.generateErrorResults(str(e))
