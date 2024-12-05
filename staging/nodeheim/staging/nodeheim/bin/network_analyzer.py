#!/usr/bin/env python3
import sys
import os
import logging
from typing import List, Dict, Any, Optional

# Add the app's bin directory to the Python path
app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
bin_path = os.path.join(app_root, 'bin')
if bin_path not in sys.path:
    sys.path.insert(0, bin_path)

import splunk.Intersplunk  # type: ignore
import json
from datetime import datetime
from analyzer.topology import create_network_topology
from analyzer.network_analysis import analyze_network, compare_networks

# Set up logging
log_dir = os.path.join(app_root, 'var', 'log')
os.makedirs(log_dir, exist_ok=True)
logging.basicConfig(
    filename=os.path.join(log_dir, 'network_analyzer.log'),
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def analyze_scan_results(results: List[Dict[str, Any]], 
                        settings: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """
    Analyze network scan results and generate insights
    
    Args:
        results: List of scan results from Splunk
        settings: Splunk command settings
        
    Returns:
        List of analysis events or None if error occurs
    """
    try:
        logging.info("Starting network analysis")
        
        if not results:
            logging.warning("No scan results to analyze")
            return [{'error': 'No scan results to analyze'}]

        # Parse the raw scan data
        scan_data = []
        for result in results:
            try:
                scan_data.append(json.loads(result.get('_raw', '{}')))
            except json.JSONDecodeError as e:
                logging.error(f"Failed to parse scan result: {e}")
                continue

        if not scan_data:
            logging.warning("No valid scan data found")
            return [{'error': 'No valid scan data found'}]

        # Create network topology
        logging.info("Creating network topology")
        topology = create_network_topology({'nodes': scan_data})
        
        # Analyze the network
        logging.info("Analyzing network")
        metrics = analyze_network(topology)
        
        # Check for previous analysis for comparison
        previous_results = get_previous_analysis(settings)
        if previous_results:
            logging.info("Comparing with previous analysis")
            previous_topology = create_network_topology({'nodes': previous_results})
            comparison = compare_networks(previous_topology, topology)
            metrics['comparison'] = comparison

        # Create analysis event
        analysis_event = {
            'source': 'nodeheim:analysis',
            'sourcetype': 'nodeheim:analysis',
            '_time': datetime.now().timestamp(),
            'metrics': metrics
        }

        # Add summary metrics for quick reference
        summary = create_summary_metrics(metrics)
        analysis_event['summary'] = summary

        logging.info("Analysis completed successfully")
        return [analysis_event]

    except Exception as e:
        logging.error(f"Analysis failed: {str(e)}", exc_info=True)
        splunk.Intersplunk.generateErrorResults(str(e))
        return None

def get_previous_analysis(settings: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get previous analysis results for comparison"""
    try:
        # Implementation depends on how you want to store/retrieve previous results
        # This could query Splunk's index, a local cache, or a database
        return []
    except Exception as e:
        logging.error(f"Failed to get previous analysis: {str(e)}")
        return []

def create_summary_metrics(metrics: Dict[str, Any]) -> Dict[str, Any]:
    """Create a summary of the most important metrics"""
    try:
        summary = {
            'total_nodes': metrics.get('basic_metrics', {}).get('total_nodes', 0),
            'total_edges': metrics.get('basic_metrics', {}).get('total_edges', 0),
            'critical_nodes': len(metrics.get('critical_nodes', {}).get('articulation_points', [])),
            'network_segments': metrics.get('security_metrics', {}).get('segmentation_metrics', {}).get('number_of_segments', 0),
            'external_facing_nodes': metrics.get('security_metrics', {}).get('exposure_metrics', {}).get('external_facing_nodes', 0),
            'bottlenecks': len(metrics.get('vulnerability_metrics', {}).get('bottlenecks', {}).get('high_load_nodes', []))
        }
        
        # Add risk assessment
        risk_level = assess_risk_level(metrics)
        summary['risk_level'] = risk_level
        
        return summary
    except Exception as e:
        logging.error(f"Failed to create summary metrics: {str(e)}")
        return {}

def assess_risk_level(metrics: Dict[str, Any]) -> str:
    """Assess overall network risk level based on metrics"""
    try:
        risk_score = 0
        
        # Factor in various metrics to calculate risk
        security_metrics = metrics.get('security_metrics', {})
        vuln_metrics = metrics.get('vulnerability_metrics', {})
        
        # Check external exposure
        exposure = security_metrics.get('exposure_metrics', {})
        if exposure.get('external_facing_nodes', 0) > 5:
            risk_score += 2
        
        # Check network segmentation
        segmentation = security_metrics.get('segmentation_metrics', {})
        if segmentation.get('number_of_segments', 0) < 2:
            risk_score += 2
        
        # Check connectivity
        connectivity = vuln_metrics.get('connectivity_metrics', {})
        if connectivity.get('min_node_connectivity', 0) < 2:
            risk_score += 1
        
        # Determine risk level
        if risk_score >= 4:
            return 'HIGH'
        elif risk_score >= 2:
            return 'MEDIUM'
        else:
            return 'LOW'
            
    except Exception as e:
        logging.error(f"Failed to assess risk level: {str(e)}")
        return 'UNKNOWN'

if __name__ == '__main__':
    try:
        results, dummyresults, settings = splunk.Intersplunk.getOrganizedResults()
        events = analyze_scan_results(results, settings)
        if events:
            splunk.Intersplunk.outputResults(events)
    except Exception as e:
        logging.error(f"Script execution failed: {str(e)}", exc_info=True)
        splunk.Intersplunk.generateErrorResults(str(e)) 