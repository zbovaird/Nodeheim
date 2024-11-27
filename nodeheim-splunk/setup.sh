#!/bin/bash

# Install required Python packages
pip3 install splunk-sdk networkx matplotlib numpy

# Create app directory structure
mkdir -p /opt/splunk/etc/apps/nodeheim-splunk/bin
mkdir -p /opt/splunk/etc/apps/nodeheim-splunk/default/data/ui/views
mkdir -p /opt/splunk/etc/apps/nodeheim-splunk/default/data/ui/nav
mkdir -p /opt/splunk/etc/apps/nodeheim-splunk/appserver/templates

# Copy files
cp -r bin/* /opt/splunk/etc/apps/nodeheim-splunk/bin/
cp -r default/* /opt/splunk/etc/apps/nodeheim-splunk/default/
cp -r appserver/* /opt/splunk/etc/apps/nodeheim-splunk/appserver/

# Set permissions
chmod -R 755 /opt/splunk/etc/apps/nodeheim-splunk/bin/*.py
chown -R splunk:splunk /opt/splunk/etc/apps/nodeheim-splunk

# Restart Splunk
/opt/splunk/bin/splunk restart 