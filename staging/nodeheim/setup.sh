#!/bin/bash

# Set up error handling
set -e
echo "Starting Nodeheim setup..."

# Get Splunk Python path
SPLUNK_PYTHON="/opt/splunk/bin/python3.9"
if [ ! -f "$SPLUNK_PYTHON" ]; then
    echo "Error: Splunk Python not found at $SPLUNK_PYTHON"
    exit 1
fi

# Install required Python packages from lib directory
echo "Installing required Python packages..."
APP_DIR="/opt/splunk/etc/apps/nodeheim"
cd "$APP_DIR/lib"
for package in *.whl *.tar.gz; do
    if [ -f "$package" ]; then
        echo "Installing $package..."
        "$SPLUNK_PYTHON" -m pip install --no-deps "$package"
    fi
done

# Create app directory structure
echo "Creating app directory structure..."
mkdir -p "$APP_DIR/bin"
mkdir -p "$APP_DIR/default/data/ui/views"
mkdir -p "$APP_DIR/default/data/ui/nav"
mkdir -p "$APP_DIR/appserver/templates"
mkdir -p "$APP_DIR/var/log"

# Copy files
echo "Copying app files..."
cp -r bin/* "$APP_DIR/bin/"
cp -r default/* "$APP_DIR/default/"
cp -r appserver/* "$APP_DIR/appserver/"

# Set permissions
echo "Setting permissions..."
chmod -R 755 "$APP_DIR/bin/*.py"
chown -R splunk:splunk "$APP_DIR"
chmod 755 "$APP_DIR/var/log"

echo "Setup complete. Restarting Splunk..."
# Restart Splunk
/opt/splunk/bin/splunk restart

echo "Nodeheim setup finished successfully." 