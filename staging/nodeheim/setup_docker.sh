#!/bin/bash

# Create log directories in the app
mkdir -p /opt/splunk/etc/apps/nodeheim-splunk/var/log
touch /opt/splunk/etc/apps/nodeheim-splunk/var/log/scanner.log
touch /opt/splunk/etc/apps/nodeheim-splunk/var/log/network.log

# Set permissions
chown -R splunk:splunk /opt/splunk/etc/apps/nodeheim-splunk
chmod -R 755 /opt/splunk/etc/apps/nodeheim-splunk/bin/*.py
chmod -R 644 /opt/splunk/etc/apps/nodeheim-splunk/var/log/*

# Enable the receiving port for forwarder data
/opt/splunk/bin/splunk enable listen 9997 -auth admin:password123

# Configure forwarding
/opt/splunk/bin/splunk add forward-server localhost:9997 -auth admin:password123

# Install required Python packages
cd /opt/splunk/etc/apps/nodeheim-splunk
python3 -m pip install -r requirements.txt --target=/opt/splunk/lib/python3.9/site-packages/ --upgrade

# Configure inputs
mkdir -p /opt/splunk/etc/apps/nodeheim-splunk/local

# Add inputs configuration
cat > /opt/splunk/etc/apps/nodeheim-splunk/local/inputs.conf << EOL
[monitor://$SPLUNK_HOME/etc/apps/nodeheim-splunk/var/log/scanner.log]
sourcetype = nodeheim:scanner
index = main
disabled = false

[monitor://$SPLUNK_HOME/etc/apps/nodeheim-splunk/var/log/network.log]
sourcetype = nodeheim:network
index = main
disabled = false

[monitor:///var/log/*]
sourcetype = syslog
index = main
disabled = false

[script://$SPLUNK_HOME/etc/apps/nodeheim-splunk/bin/network_scanner.py]
sourcetype = nodeheim:scan
interval = 300
index = main
disabled = false

[script://$SPLUNK_HOME/etc/apps/nodeheim-splunk/bin/network_analyzer.py]
sourcetype = nodeheim:analysis
interval = 300
index = main
disabled = false
EOL

# Set proper permissions on configuration files
chown -R splunk:splunk /opt/splunk/etc/apps/nodeheim-splunk/local
chmod 644 /opt/splunk/etc/apps/nodeheim-splunk/local/*.conf

# Restart Splunk to apply changes
/opt/splunk/bin/splunk restart