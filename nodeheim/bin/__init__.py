"""
Nodeheim Splunk App
Network scanning and analysis tool for Splunk Enterprise.
"""

import os
import sys
import logging
from datetime import datetime

# Add the app's lib directory to the Python path
app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
lib_path = os.path.join(app_root, 'lib')
if lib_path not in sys.path:
    sys.path.append(lib_path)

# Configure logging to use Splunk's logging system
def setup_logger():
    logger = logging.getLogger('splunk.nodeheim')
    # Let Splunk handle the logging configuration
    return logger

logger = setup_logger()

# App configuration - read from app.conf
APP_NAME = "nodeheim"
# Version should be read from app.conf, this is just a fallback
APP_VERSION = "1.0.3" 