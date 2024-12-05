#!/bin/bash

# Set version
VERSION="1.0.0"
APP_NAME="nodeheim"

# Clean up any existing packages
rm -f ${APP_NAME}-${VERSION}.tar.gz ${APP_NAME}-${VERSION}.spl

# Create a clean staging directory
STAGING_DIR="staging/${APP_NAME}"
rm -rf staging
mkdir -p "${STAGING_DIR}"

# Copy required files and directories
cp -r bin "${STAGING_DIR}/"
cp -r default "${STAGING_DIR}/"
cp -r local "${STAGING_DIR}/"
cp -r appserver "${STAGING_DIR}/"
cp -r metadata "${STAGING_DIR}/"

# Copy app.manifest and README
cp app.manifest "${STAGING_DIR}/"

# Create README
cat > "${STAGING_DIR}/README.txt" << EOF
Nodeheim Network Analysis App for Splunk
Version ${VERSION}

This app provides network scanning and analysis capabilities for Splunk Enterprise.

Requirements:
- Splunk Enterprise 8.0 or later
- Python 3.7 or later
- Required Python packages (installed automatically):
  - splunk-sdk
  - networkx
  - matplotlib
  - numpy

Installation:
1. Install via Splunk Web:
   - Navigate to Apps > Manage Apps
   - Click "Install app from file"
   - Upload this .spl file
   - Restart Splunk

2. Manual Installation:
   - Extract this .spl file to $SPLUNK_HOME/etc/apps/
   - Restart Splunk

Configuration:
No additional configuration required.

Support:
For support, please contact your.email@example.com
EOF

# Create the package
cd staging
tar -czf "../${APP_NAME}-${VERSION}.tar.gz" "${APP_NAME}"
cd ..

# Create the Splunk app package (.spl is just a renamed .tar.gz)
cp "${APP_NAME}-${VERSION}.tar.gz" "${APP_NAME}-${VERSION}.spl"

# Clean up
rm -rf staging

echo "Package created: ${APP_NAME}-${VERSION}.spl" 