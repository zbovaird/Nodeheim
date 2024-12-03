import logging

def scan_network(subnet, full_scan=False):
    """
    Basic network scan function that returns test data
    """
    logging.debug(f"Scanning subnet: {subnet}, full_scan: {full_scan}")
    # Return test data
    return [{
        'ip': '192.168.1.1',
        'status': 'up',
        'ports': [80, 443]
    }]

def format_splunk_event(scan_results):
    """
    Format scan results as Splunk events
    """
    logging.debug("Formatting scan results")
    events = []
    for result in scan_results:
        event = {
            'source': 'nodeheim:scan',
            'sourcetype': 'nodeheim:scan',
            '_time': None,
            'host': result.get('ip', 'unknown'),
            'status': result.get('status', 'unknown'),
            'ports': result.get('ports', [])
        }
        events.append(event)
    return events 