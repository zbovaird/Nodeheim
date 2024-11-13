from flask import Blueprint

# Create the blueprint here instead of in list.py
analysis_bp = Blueprint('analysis', __name__)

# Import routes after creating blueprint
from . import list  # This avoids the circular import

# Export the blueprint
__all__ = ['analysis_bp']