#!/bin/bash

# Create log directories
mkdir -p /opt/splunk/etc/apps/nodeheim/var/log
touch /opt/splunk/etc/apps/nodeheim/var/log/scanner.log
touch /opt/splunk/etc/apps/nodeheim/var/log/network.log

# Set permissions
chown -R splunk:splunk /opt/splunk/etc/apps/nodeheim
chmod -R 755 /opt/splunk/etc/apps/nodeheim/bin/*.py
chmod -R 644 /opt/splunk/etc/apps/nodeheim/var/log/*

# Install Python dependencies
cd /opt/splunk/etc/apps/nodeheim
/opt/splunk/bin/python3.9 -m pip install -r requirements.txt

# Create local directory and configuration
mkdir -p /opt/splunk/etc/apps/nodeheim/local

# Create inputs.conf
cat > /opt/splunk/etc/apps/nodeheim/local/inputs.conf << EOL
[monitor://$SPLUNK_HOME/etc/apps/nodeheim/var/log/scanner.log]
sourcetype = nodeheim:scanner
index = main
disabled = 0

[monitor://$SPLUNK_HOME/etc/apps/nodeheim/var/log/network.log]
sourcetype = nodeheim:network
index = main
disabled = 0

[script://$SPLUNK_HOME/etc/apps/nodeheim/bin/network_scanner.py]
sourcetype = nodeheim:scan
index = main
interval = 300
disabled = 1
python.version = python3

[script://$SPLUNK_HOME/etc/apps/nodeheim/bin/network_analyzer.py]
sourcetype = nodeheim:analysis
index = main
interval = 600
disabled = 1
python.version = python3
EOL

# Set permissions for local directory
chown -R splunk:splunk /opt/splunk/etc/apps/nodeheim/local
chmod 644 /opt/splunk/etc/apps/nodeheim/local/*.conf

# Enable the receiving port for forwarder data
/opt/splunk/bin/splunk enable listen 9997 -auth admin:password123

# Configure forwarding
/opt/splunk/bin/splunk add forward-server localhost:9997 -auth admin:password123

# Restart Splunk to apply changes
/opt/splunk/bin/splunk restart