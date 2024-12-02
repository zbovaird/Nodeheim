"""
Nodeheim Splunk App
Network scanning and analysis tool for Splunk Enterprise.
"""

import os
import sys

# Add the bin directory to the Python path
bin_path = os.path.dirname(os.path.abspath(__file__))
if bin_path not in sys.path:
    sys.path.append(bin_path)

# Import version from app.conf
APP_NAME = "nodeheim-splunk"
VERSION = "1.0.0" 