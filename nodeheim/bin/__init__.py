"""
Nodeheim Splunk App
Network scanning and analysis tool for Splunk Enterprise.
"""

import os
import sys
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    filename="/opt/splunk/var/log/splunk/nodeheim_debug.log",
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s"
)

# App configuration
APP_NAME = "nodeheim"
APP_VERSION = "1.0.3" 