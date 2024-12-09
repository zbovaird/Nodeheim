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

# Install dependencies
Write-Host "Installing Python dependencies..."
docker exec nodeheim_test_splunk pip install python-nmap

# Install nmap
Write-Host "Installing nmap..."
docker exec nodeheim_test_splunk apt-get update
docker exec nodeheim_test_splunk apt-get install -y nmap

# Run tests
Write-Host "Running tests..."
docker exec nodeheim_test_splunk python /opt/splunk/etc/apps/nodeheim/bin/splunk_test.py --splunk-home=/opt/splunk --app-package=/opt/splunk/etc/apps/nodeheim/nodeheim-1.0.4.spl

# Get test results
$testResult = $LASTEXITCODE

# Clean up
Write-Host "Cleaning up..."
docker-compose -f docker-compose.test.yml down

# Exit with test result
exit $testResult 