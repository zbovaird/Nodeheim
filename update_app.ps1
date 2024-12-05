# Define paths
$sourcePath = ".\nodeheim\bin\network_scanner.py"
$splunkPath = "C:\Program Files\Splunk\etc\apps\nodeheim"
$binPath = Join-Path $splunkPath "bin"
$defaultPath = Join-Path $splunkPath "default"

# Create necessary directories
if (-not (Test-Path $binPath)) {
    New-Item -ItemType Directory -Path $binPath -Force
}
if (-not (Test-Path $defaultPath)) {
    New-Item -ItemType Directory -Path $defaultPath -Force
}

# Copy the script
Copy-Item -Path $sourcePath -Destination $binPath -Force

# Create commands.conf
$commandsConf = @"
[nodeheim_scan]
filename = network_scanner.py
type = python
local = true
python.version = python3
generating = true
enableheader = true
outputheader = true
requires_srinfo = true
supports_getinfo = true
supports_rawargs = true
chunked = false
streaming = false
retainsevents = true
"@

$commandsConf | Out-File -FilePath (Join-Path $defaultPath "commands.conf") -Encoding UTF8 -Force

# Set permissions
$scriptPath = Join-Path $binPath "network_scanner.py"
$acl = Get-Acl $scriptPath
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone","FullControl","Allow")
$acl.SetAccessRule($accessRule)
Set-Acl $scriptPath $acl

Write-Host "Script and commands.conf updated successfully. Please restart Splunk to apply changes."