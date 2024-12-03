# PowerShell script to update Splunk app locally for Docker environment

$APP_NAME = "nodeheim-splunk"
$APP_SOURCE = ".\nodeheim-splunk"

# Check if Docker container is running
Write-Host "Checking Docker container status..."
$container = docker ps --filter "name=splunk" --format "{{.Names}}"

if (-not $container) {
    Write-Host "Error: Splunk container not found. Please make sure it's running."
    exit 1
}

Write-Host "Found Splunk container: $container"

# Copy app files to container
Write-Host "Copying app files to container..."
docker cp $APP_SOURCE $container":/opt/splunk/etc/apps/"

# Set comprehensive permissions
Write-Host "Setting permissions..."
docker exec -u root $container bash -c @'
    # Set app permissions
    chown -R splunk:splunk /opt/splunk/etc/apps/$APP_NAME
    chmod -R 755 /opt/splunk/etc/apps/$APP_NAME/bin
    find /opt/splunk/etc/apps/$APP_NAME/bin -name "*.py" -exec chmod 755 {} \;
    
    # Set configuration file permissions
    find /opt/splunk/etc/apps/$APP_NAME/default -name "*.conf" -exec chmod 644 {} \;
    find /opt/splunk/etc/apps/$APP_NAME/local -name "*.conf" -exec chmod 644 {} \;
    
    # Create and set log directory permissions
    mkdir -p /opt/splunk/etc/apps/$APP_NAME/var/log
    mkdir -p /opt/splunk/var/log/splunk
    touch /opt/splunk/var/log/splunk/nodeheim_debug.log
    chown splunk:splunk /opt/splunk/var/log/splunk/nodeheim_debug.log
    chmod 644 /opt/splunk/var/log/splunk/nodeheim_debug.log
    chown -R splunk:splunk /opt/splunk/etc/apps/$APP_NAME/var/log
    chmod -R 755 /opt/splunk/etc/apps/$APP_NAME/var/log
    
    # Set specific Python file permissions
    chmod 755 /opt/splunk/etc/apps/$APP_NAME/bin/network_scanner.py
    chmod 755 /opt/splunk/etc/apps/$APP_NAME/bin/network_analyzer.py
    chmod 755 /opt/splunk/etc/apps/$APP_NAME/bin/network_comparison.py
    
    # Clear command cache
    rm -rf /opt/splunk/var/run/splunk/search_command_cache/*
'@

# Restart Splunk
Write-Host "Restarting Splunk..."
docker exec -u root $container bash -c "/opt/splunk/bin/splunk restart"

Write-Host "Update complete. Please verify the app is working correctly."