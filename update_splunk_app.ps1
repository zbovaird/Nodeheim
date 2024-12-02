# PowerShell script to update Splunk app locally

# Configuration
$SPLUNK_HOME = "C:\Program Files\Splunk"
$APP_NAME = "nodeheim-splunk"
$APP_SOURCE = ".\nodeheim-splunk"

# Create necessary directories
$appPath = Join-Path $SPLUNK_HOME "etc\apps\$APP_NAME"
Write-Host "Creating app directories..."
New-Item -ItemType Directory -Force -Path $appPath | Out-Null
New-Item -ItemType Directory -Force -Path "$appPath\bin" | Out-Null
New-Item -ItemType Directory -Force -Path "$appPath\local" | Out-Null
New-Item -ItemType Directory -Force -Path "$appPath\default" | Out-Null
New-Item -ItemType Directory -Force -Path "$appPath\var\log" | Out-Null

# Copy app files
Write-Host "Copying app files..."
Copy-Item -Path "$APP_SOURCE\bin\*" -Destination "$appPath\bin" -Recurse -Force
Copy-Item -Path "$APP_SOURCE\default\*" -Destination "$appPath\default" -Recurse -Force
Copy-Item -Path "$APP_SOURCE\local\*" -Destination "$appPath\local" -Recurse -Force
Copy-Item -Path "$APP_SOURCE\appserver\*" -Destination "$appPath\appserver" -Recurse -Force

# Set file permissions
Write-Host "Setting file permissions..."
$acl = Get-Acl "$SPLUNK_HOME"
Get-ChildItem -Path $appPath -Recurse | ForEach-Object {
    Set-Acl -Path $_.FullName -AclObject $acl
}

# Verify Python files are accessible
Write-Host "Verifying Python files..."
$pythonFiles = @(
    "network_scanner.py",
    "network_analyzer.py",
    "network_comparison.py"
)

foreach ($file in $pythonFiles) {
    $filePath = Join-Path "$appPath\bin" $file
    if (Test-Path $filePath) {
        Write-Host "Found $file"
        # Make sure file is readable and executable
        $fileAcl = Get-Acl $filePath
        $fileAcl.SetAccessRuleProtection($false, $true)
        Set-Acl -Path $filePath -AclObject $fileAcl
    } else {
        Write-Host "Warning: $file not found"
    }
}

# Restart Splunk
Write-Host "Restarting Splunk..."
& "$SPLUNK_HOME\bin\splunk.exe" restart

Write-Host "App update complete. Please check Splunk logs for any errors."
Write-Host "Log location: $SPLUNK_HOME\var\log\splunk"
