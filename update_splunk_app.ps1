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

# Copy files to container
docker cp ./nodeheim-splunk/. splunk:/opt/splunk/etc/apps/nodeheim-splunk/

# Fix permissions inside container
docker exec -u root splunk bash -c '
    # Set base permissions for app directory
    chown -R splunk:splunk /opt/splunk/etc/apps/nodeheim-splunk
    chmod -R 755 /opt/splunk/etc/apps/nodeheim-splunk

    # Set specific permissions for different file types
    find /opt/splunk/etc/apps/nodeheim-splunk/bin -type f -name "*.py" -exec chmod 755 {} \;
    find /opt/splunk/etc/apps/nodeheim-splunk -type f -name "*.conf" -exec chmod 644 {} \;
    find /opt/splunk/etc/apps/nodeheim-splunk/metadata -type f -exec chmod 644 {} \;
    find /opt/splunk/etc/apps/nodeheim-splunk/static -type f -exec chmod 644 {} \;

    # Ensure directories are executable
    find /opt/splunk/etc/apps/nodeheim-splunk -type d -exec chmod 755 {} \;

    # Set specific directory permissions
    chmod 755 /opt/splunk/etc/apps/nodeheim-splunk/bin
    chmod 755 /opt/splunk/etc/apps/nodeheim-splunk/default
    chmod 755 /opt/splunk/etc/apps/nodeheim-splunk/local
    chmod 755 /opt/splunk/etc/apps/nodeheim-splunk/metadata

    # Fix permissions for key Splunk directories
    chown -R splunk:splunk /opt/splunk/var/run/splunk
    chmod -R 755 /opt/splunk/var/run/splunk
    chown -R splunk:splunk /opt/splunk/var/log/splunk
    chmod -R 755 /opt/splunk/var/log/splunk
'

# Restart Splunk
docker exec -u root splunk /opt/splunk/bin/splunk restart

Write-Host "Update complete. Please verify the app is working correctly."