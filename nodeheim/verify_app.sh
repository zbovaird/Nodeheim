#!/bin/bash

# Create required directories
mkdir -p /opt/splunk/etc/apps/nodeheim/var/log
mkdir -p /opt/splunk/etc/apps/nodeheim/local

# Create log files
touch /opt/splunk/etc/apps/nodeheim/var/log/scanner.log
touch /opt/splunk/etc/apps/nodeheim/var/log/network.log

# Set ownership
chown -R splunk:splunk /opt/splunk/etc/apps/nodeheim

# Set permissions
chmod -R 755 /opt/splunk/etc/apps/nodeheim/bin
chmod -R 644 /opt/splunk/etc/apps/nodeheim/default/*.conf
chmod -R 644 /opt/splunk/etc/apps/nodeheim/local/*.conf
chmod -R 644 /opt/splunk/etc/apps/nodeheim/metadata/default.meta
chmod 644 /opt/splunk/etc/apps/nodeheim/test_data.log
chmod -R 755 /opt/splunk/etc/apps/nodeheim/var/log

# Verify Python dependencies
/opt/splunk/bin/python3.9 -m pip list | grep -E "networkx|splunk-sdk|matplotlib|numpy"

# Verify file structure
echo "Verifying file structure..."
ls -la /opt/splunk/etc/apps/nodeheim/

# Verify log files
echo "Verifying log files..."
ls -l /opt/splunk/etc/apps/nodeheim/test_data.log
cat /opt/splunk/etc/apps/nodeheim/test_data.log

# Restart Splunk
/opt/splunk/bin/splunk restart 