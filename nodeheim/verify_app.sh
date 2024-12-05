#!/bin/bash

# Create necessary directories
mkdir -p /opt/splunk/etc/apps/nodeheim-splunk/var/log
mkdir -p /opt/splunk/etc/apps/nodeheim-splunk/local

# Create log files
touch /opt/splunk/etc/apps/nodeheim-splunk/var/log/scanner.log
touch /opt/splunk/etc/apps/nodeheim-splunk/var/log/network.log

# Set proper ownership
chown -R splunk:splunk /opt/splunk/etc/apps/nodeheim-splunk

# Set proper permissions
chmod -R 755 /opt/splunk/etc/apps/nodeheim-splunk/bin
chmod -R 644 /opt/splunk/etc/apps/nodeheim-splunk/default/*.conf
chmod -R 644 /opt/splunk/etc/apps/nodeheim-splunk/local/*.conf
chmod -R 644 /opt/splunk/etc/apps/nodeheim-splunk/metadata/default.meta
chmod 644 /opt/splunk/etc/apps/nodeheim-splunk/test_data.log
chmod -R 755 /opt/splunk/etc/apps/nodeheim-splunk/var/log

# Verify Python is available
which python3

# List installed Python packages
pip3 list

# Check Splunk app directory
ls -la /opt/splunk/etc/apps/nodeheim-splunk/

# Check specific files
echo "Checking test_data.log:"
ls -l /opt/splunk/etc/apps/nodeheim-splunk/test_data.log
cat /opt/splunk/etc/apps/nodeheim-splunk/test_data.log

# Restart Splunk
/opt/splunk/bin/splunk restart 