# Working Splunk Configuration Guide

## Port Configuration

### Port Overview
- **8000**: Splunk Web Interface (Docker)
  - Purpose: Web access to Splunk Enterprise
  - Access: http://localhost:8000
  - Credentials: admin/Password123

- **8089**: Splunk Management Port (Docker)
  - Purpose: Internal Splunk management/API
  - Used by: Docker container

- **8090**: Universal Forwarder Management Port
  - Purpose: Management interface for Universal Forwarder
  - Configured in: web.conf
  - Note: Moved from 8089 to avoid conflict with Docker

- **9997**: Data Forwarding/Receiving
  - Purpose: Receives data from Universal Forwarders
  - Direction: UF → Docker Splunk
  - Configuration: Configured in both container and UF

## Configuration Files

### Universal Forwarder Configuration

1. **outputs.conf** (Path: C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf)
```
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = localhost:9997
```

2. **inputs.conf** (Path: C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf)
```
[WinEventLog://Security]
disabled = 0
index = windows

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
renderXml = 1
index = windows
```

3. **web.conf** (Path: C:\Program Files\SplunkUniversalForwarder\etc\system\local\web.conf)
```
[settings]
mgmtHostPort = 8090
```

## Nodeheim App Configuration

### App Setup
1. **Mount App Directory**
   - App is mounted to container at: /opt/splunk/etc/apps/nodeheim
   - Configured in docker-compose.test.yml:
     ```yaml
     volumes:
       - ./:/opt/splunk/etc/apps/nodeheim:rw
     ```

2. **Required Dependencies**
   - Python 3.7+
   - nmap package (installed in container)
   - psutil package (installed in container)

3. **App Configuration Files**
   - **app.conf**: Basic app settings and metadata
   - **commands.conf**: Command definitions for nodeheim_scan
   - **inputs.conf**: Network scanning inputs
   - **limits.conf**: Resource limits for Free Edition

4. **Command Usage**
   ```spl
   | nodeheim-scan source=direct target="192.168.1.0/24"
   ```
   Options:
   - source=direct/import
   - target=CIDR notation
   - options=scan options
   - cache=true/false

### Free Edition Optimizations
- Local processing mode enabled
- Resource usage limits configured
- Progressive scanning enabled
- Data caching implemented

## Setup Steps

1. **Docker Container Setup**
   - Start Docker Desktop
   - Run container:
     ```
     docker-compose -f docker-compose.test.yml up -d
     ```
   - Wait for initialization (~30 seconds)
   - Verify web access: http://localhost:8000

2. **Index Creation**
   - Access Splunk Web Interface
   - Go to Settings > Indexes
   - Create new index named "windows"
   - Set index type to "Events"

3. **Configure Receiving**
   - Go to Settings > Forwarding and receiving
   - Click "Configure receiving"
   - Add receiving port 9997

4. **Universal Forwarder Configuration**
   - Create/edit outputs.conf
   - Create/edit inputs.conf
   - Create/edit web.conf
   - Restart forwarder:
     ```
     splunk.exe stop
     splunk.exe start --accept-license --answer-yes --no-prompt
     ```

5. **Verify Configuration**
   - Check forward-server status:
     ```
     splunk.exe list forward-server
     ```
   - Should show: "Active forwards: localhost:9997"
   - Search for events:
     ```
     index=windows sourcetype=WinEventLog:Security
     ```

6. **Verify Nodeheim**
   - Check app appears in Splunk Web
   - Verify command registration:
     ```
     | typeahead nodeheim
     ```
   - Test basic scan:
     ```
     | nodeheim-scan source=direct target="127.0.0.1/32"
     ```

## Troubleshooting

1. **Port Conflicts**
   - Check for processes using ports:
     ```
     netstat -ano | findstr :PORT_NUMBER
     ```
   - Kill conflicting processes:
     ```
     taskkill /F /PID PID_NUMBER
     ```

2. **Forwarder Connection**
   - Verify outputs.conf configuration
   - Check Splunk receiving configuration
   - Restart Universal Forwarder
   - Check splunkd.log for errors

3. **Docker Issues**
   - Restart Docker Desktop
   - Remove and recreate container
   - Verify port mappings with `docker ps`

4. **Nodeheim Issues**
   - Check btool output for command registration
   - Verify Python dependencies in container
   - Check app logs in Splunk Web
   - Verify nmap installation in container