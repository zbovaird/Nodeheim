# Docker Test Environment Setup for Nodeheim
Write-Host "Setting up Docker test environment for Nodeheim..."

# Ensure we're in the right directory
Set-Location $PSScriptRoot

# Stop and remove existing container if it exists
Write-Host "Cleaning up any existing test containers..."
docker stop nodeheim_test_splunk 2>$null
docker rm nodeheim_test_splunk 2>$null

# Start Splunk container
Write-Host "Starting Splunk container..."
docker-compose -f docker-compose.test.yml up -d

# Wait for Splunk to be ready
Write-Host "Waiting for Splunk to be ready..."
$ready = $false
$attempts = 0
$maxAttempts = 30

while (-not $ready -and $attempts -lt $maxAttempts) {
    $attempts++
    Write-Host "Checking Splunk readiness (attempt $attempts/$maxAttempts)..."
    
    try {
        $result = docker exec nodeheim_test_splunk /opt/splunk/bin/splunk status
        if ($result -match "splunkd is running") {
            $ready = $true
        }
    } catch {
        Start-Sleep -Seconds 10
    }
}

if (-not $ready) {
    Write-Host "Error: Splunk failed to start properly"
    exit 1
}

# Install dependencies in Splunk's Python environment
Write-Host "Installing Python dependencies..."
docker exec nodeheim_test_splunk /opt/splunk/bin/splunk cmd python3 -m pip install python-nmap --target=/opt/splunk/etc/apps/nodeheim/lib/

# Verify command registration
Write-Host "Verifying command registration..."
docker exec nodeheim_test_splunk /opt/splunk/bin/splunk cmd btool commands list --debug

# Run tests
Write-Host "Running tests..."
docker exec nodeheim_test_splunk /opt/splunk/bin/splunk cmd python3 /opt/splunk/etc/apps/nodeheim/bin/splunk_test.py

# Check Splunk logs for errors
Write-Host "Checking Splunk logs..."
docker exec nodeheim_test_splunk cat /opt/splunk/var/log/splunk/splunkd.log | Select-String -Pattern "ERROR"

Write-Host "Test environment setup complete. Access Splunk at http://localhost:8000"
Write-Host "Username: admin"
Write-Host "Password: Password123" 