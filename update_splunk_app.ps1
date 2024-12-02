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

# Set permissions in container
Write-Host "Setting permissions..."
docker exec -u root $container bash -c "chown -R splunk:splunk /opt/splunk/etc/apps/$APP_NAME && chmod -R 755 /opt/splunk/etc/apps/$APP_NAME/bin/*.py"

# Create log directory
Write-Host "Creating log directory..."
docker exec -u root $container bash -c "mkdir -p /opt/splunk/etc/apps/$APP_NAME/var/log && chown splunk:splunk /opt/splunk/etc/apps/$APP_NAME/var/log"

# Restart Splunk in container
Write-Host "Restarting Splunk..."
docker exec -u root $container bash -c "/opt/splunk/bin/splunk restart"

Write-Host "App update complete. Please check Splunk logs for any errors."
Write-Host "To view logs, use: docker exec $container cat /opt/splunk/var/log/splunk/splunkd.log"
