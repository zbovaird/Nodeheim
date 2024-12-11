#!/bin/bash
set -e

# Start Splunk temporarily to install dependencies
/opt/splunk/bin/splunk start --accept-license --answer-yes --no-prompt
/opt/splunk/bin/splunk cmd python3 -m pip install python-nmap psutil
/opt/splunk/bin/splunk stop

# Start Splunk in foreground
exec /opt/splunk/bin/splunk start --accept-license --answer-yes --no-prompt --foreground 