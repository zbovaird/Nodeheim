# Create log directory
New-Item -ItemType Directory -Force -Path "C:\ProgramData\nodeheim\logs"

# Download Splunk Universal Forwarder for Windows
$splunkUrl = "https://download.splunk.com/products/universalforwarder/releases/9.1.2/windows/splunkforwarder-9.1.2-b6b9c8185839-x64-release.msi"
$installerPath = "$env:TEMP\splunkforwarder.msi"
Invoke-WebRequest -Uri $splunkUrl -OutFile $installerPath

# Install Splunk Universal Forwarder
Start-Process msiexec.exe -ArgumentList "/i `"$installerPath`" AGREETOLICENSE=Yes SPLUNKUSERNAME=admin SPLUNKPASSWORD=password123 /quiet" -Wait

# Wait for installation to complete
Start-Sleep -Seconds 30

# Copy our app files
$splunkAppsPath = "C:\Program Files\SplunkUniversalForwarder\etc\apps\nodeheim-splunk"
New-Item -ItemType Directory -Force -Path $splunkAppsPath
Copy-Item -Path "bin" -Destination "$splunkAppsPath\" -Recurse -Force
Copy-Item -Path "default" -Destination "$splunkAppsPath\" -Recurse -Force

# Configure forwarder
$splunkCmd = "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe"
& $splunkCmd add forward-server localhost:9997 -auth admin:password123
& $splunkCmd enable boot-start

# Restart Splunk forwarder
Stop-Service SplunkForwarder
Start-Service SplunkForwarder

Write-Host "Splunk Universal Forwarder has been installed and configured."
Write-Host "Log directory: C:\ProgramData\nodeheim\logs"
Write-Host "App directory: $splunkAppsPath" 