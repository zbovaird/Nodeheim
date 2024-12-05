#!/bin/bash

# Create log directory
mkdir -p /var/log/nodeheim

# Download and install Splunk Universal Forwarder
wget -O splunkforwarder-9.1.2-b6b9c8185839.tgz 'https://download.splunk.com/products/universalforwarder/releases/9.1.2/linux/splunkforwarder-9.1.2-b6b9c8185839.tgz'
tar xvzf splunkforwarder-9.1.2-b6b9c8185839.tgz -C /opt

# Copy our app files
mkdir -p /opt/splunkforwarder/etc/apps/nodeheim-splunk
cp -r bin default /opt/splunkforwarder/etc/apps/nodeheim-splunk/

# Set permissions
chown -R splunk:splunk /opt/splunkforwarder
chmod -R 755 /opt/splunkforwarder/etc/apps/nodeheim-splunk/bin/*.py
chmod -R 755 /var/log/nodeheim

# Start the forwarder
/opt/splunkforwarder/bin/splunk start --accept-license --answer-yes --no-prompt --seed-passwd password123

# Configure forwarder to connect to Splunk instance
/opt/splunkforwarder/bin/splunk add forward-server localhost:9997 -auth admin:password123

# Enable the boot-start
/opt/splunkforwarder/bin/splunk enable boot-start

# Restart to apply changes
/opt/splunkforwarder/bin/splunk restart 