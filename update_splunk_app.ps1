# PowerShell script to update Splunk app locally for Docker environment

$APP_NAME = "nodeheim"
$APP_VERSION = "1.0.2"
$APP_SOURCE = ".\nodeheim"

# Create package
Write-Host "Creating package..."
Remove-Item -Force "$APP_NAME-$APP_VERSION.*" -ErrorAction SilentlyContinue
Remove-Item -Force -Recurse staging -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path staging/$APP_NAME
Copy-Item -Recurse $APP_SOURCE/* staging/$APP_NAME/
Compress-Archive -Path staging/$APP_NAME -DestinationPath "$APP_NAME-$APP_VERSION.zip" -Force
Rename-Item -Force "$APP_NAME-$APP_VERSION.zip" "$APP_NAME-$APP_VERSION.spl"

# Check if Docker container is running
Write-Host "Checking Docker container status..."
$container = docker ps --filter "name=splunk" --format "{{.Names}}"

if (-not $container) {
    Write-Host "Error: Splunk container not found. Please make sure it's running."
    exit 1
}

Write-Host "Found Splunk container: $container"

# Copy package to container
Write-Host "Copying package to container..."
docker cp "$APP_NAME-$APP_VERSION.spl" splunk:/tmp/

# Install package
Write-Host "Installing package..."
docker exec -u splunk splunk /opt/splunk/bin/splunk install app "/tmp/$APP_NAME-$APP_VERSION.spl" -update 1 -auth admin:Password123

# Fix permissions inside container
docker exec -u root splunk bash -c "
    chown -R splunk:splunk /opt/splunk/etc/apps/$APP_NAME
    chmod -R 755 /opt/splunk/etc/apps/$APP_NAME
    find /opt/splunk/etc/apps/$APP_NAME/bin -type f -name '*.py' -exec chmod 755 {} \;
    find /opt/splunk/etc/apps/$APP_NAME -type f -name '*.conf' -exec chmod 644 {} \;
"

# Restart Splunk
Write-Host "Restarting Splunk..."
docker exec -u root splunk /opt/splunk/bin/splunk restart

Write-Host "Update complete. Please verify the app is working correctly."