from flask import jsonify
import os
import json
import logging
from datetime import datetime
from . import analysis_bp  # Import the blueprint from __init__.py instead of creating it

# Configure logging
logger = logging.getLogger(__name__)

@analysis_bp.route('/api/analysis/list')
def list_analyses():
    """List all available analysis results with proper data extraction"""
    try:
        analysis_dir = os.path.join('src', 'data', 'analysis')
        if not os.path.exists(analysis_dir):
            return jsonify([])

        analyses = []
        for file in os.listdir(analysis_dir):
            if file.endswith('.json'):
                with open(os.path.join(analysis_dir, file), 'r') as f:
                    try:
                        analysis = json.load(f)
                        # Extract data from nested structure
                        results = analysis.get('results', {})
                        summary = results.get('summary', {})
                        
                        analyses.append({
                            'id': analysis.get('id', file.replace('.json', '')),
                            'timestamp': analysis.get('timestamp'),
                            'summary': {
                                'total_nodes': summary.get('total_nodes', 0),
                                'high_risk_nodes': summary.get('high_risk_nodes', 0),
                                'isolated_nodes': summary.get('isolated_nodes', 0),
                                'components': summary.get('components', 0)
                            }
                        })
                    except json.JSONDecodeError:
                        logger.error(f"Invalid JSON in analysis file: {file}")
                        continue

        # Sort analyses by timestamp in descending order
        return jsonify(sorted(analyses, key=lambda x: x['timestamp'], reverse=True))

    except Exception as e:
        logger.error(f"Error listing analyses: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500