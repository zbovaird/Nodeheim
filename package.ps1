# Clean up any existing packages
Remove-Item -Force nodeheim-1.0.3.* -ErrorAction SilentlyContinue
Remove-Item -Force -Recurse staging -ErrorAction SilentlyContinue

# Create staging directory
New-Item -ItemType Directory -Path staging/nodeheim -Force

# Create lib directory if it doesn't exist
New-Item -ItemType Directory -Path nodeheim/lib -Force -ErrorAction SilentlyContinue

# Download required Python packages if not already present
if (-not (Test-Path "nodeheim/lib/*.whl")) {
    Write-Host "Downloading Python packages..."
    pip download -d nodeheim/lib networkx matplotlib numpy splunk-sdk ipaddress
}

# Copy files to staging
Copy-Item -Recurse nodeheim/* staging/nodeheim/

# Create package
Compress-Archive -Path staging/nodeheim -DestinationPath nodeheim-1.0.3.zip -Force
Rename-Item -Force nodeheim-1.0.3.zip nodeheim-1.0.3.spl

Write-Host "Package created: nodeheim-1.0.3.spl" 