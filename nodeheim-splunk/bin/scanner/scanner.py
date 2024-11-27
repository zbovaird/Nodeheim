import json
import networkx as nx
from datetime import datetime

def scan_network(data):
    """Scan network and create topology data"""
    timestamp = datetime.now().isoformat()
    topology = {
        'timestamp': timestamp,
        'nodes': [],
        'edges': []
    }
    
    # Process input data to create network topology
    for item in data:
        node = {
            'id': item.get('host', ''),
            'attributes': {
                'type': item.get('type', ''),
                'status': item.get('status', '')
            }
        }
        topology['nodes'].append(node)
        
        # Add connections as edges
        for conn in item.get('connections', []):
            edge = {
                'source': item['host'],
                'target': conn['target'],
                'attributes': {
                    'type': conn.get('type', ''),
                    'latency': conn.get('latency', 0)
                }
            }
            topology['edges'].append(edge)
    
    return topology 