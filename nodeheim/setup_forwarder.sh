#!/bin/bash

# Install Splunk Universal Forwarder
wget -O splunkforwarder.tgz 'https://download.splunk.com/products/universalforwarder/releases/9.1.1/linux/splunkforwarder-9.1.1-64e843ea36b1-Linux-x86_64.tgz'
tar xzf splunkforwarder.tgz -C /opt
rm splunkforwarder.tgz

# Start Splunk and accept license
/opt/splunkforwarder/bin/splunk start --accept-license --answer-yes --no-prompt --seed-passwd Password123

# Copy app files
mkdir -p /opt/splunkforwarder/etc/apps/nodeheim
cp -r bin default /opt/splunkforwarder/etc/apps/nodeheim/

# Set permissions
chmod -R 755 /opt/splunkforwarder/etc/apps/nodeheim/bin/*.py

# Configure forwarding
/opt/splunkforwarder/bin/splunk add forward-server splunk:9997 -auth admin:Password123

# Restart Splunk
/opt/splunkforwarder/bin/splunk restart