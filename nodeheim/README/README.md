# Nodeheim - Network Discovery for Splunk

Nodeheim is a Splunk app that provides network discovery and analysis capabilities using nmap. It allows you to scan and monitor your network infrastructure directly from Splunk.

## Requirements

- Splunk Enterprise 8.0 or later
- Python 3.7 or later
- nmap 7.80 or later
- python-nmap 0.7.1 or later

## Installation

1. Install nmap on your Splunk search head:
   - **Windows**: Download and install from [nmap.org](https://nmap.org)
   - **Linux**: `sudo apt-get install nmap` or `sudo yum install nmap`

2. Install the app:
   - Via Splunk Web:
     1. Navigate to "Manage Apps"
     2. Click "Install app from file"
     3. Upload the `nodeheim-VERSION.spl` file
   - Via CLI:
     ```bash
     $SPLUNK_HOME/bin/splunk install app nodeheim-VERSION.spl
     ```

3. Restart Splunk

## Configuration

1. Verify nmap installation:
   ```bash
   nmap --version
   ```

2. Configure capabilities in `authorize.conf`:
   ```ini
   [capability::network_scan]
   [capability::raw_exec]
   ```

3. Assign capabilities to roles in `authorize.conf`:
   ```ini
   [role_admin]
   network_scan = enabled
   raw_exec = enabled
   ```

## Usage

### Basic Network Discovery
```spl
| nodeheim_scan subnet="192.168.1.0/24"
```

### TCP Port Scanning
```spl
| nodeheim_scan subnet="192.168.1.0/24" scan_type="connect"
```

### Service Version Detection
```spl
| nodeheim_scan subnet="192.168.1.0/24" scan_type="version"
```

## Scan Types

1. **basic** (default)
   - Simple host discovery
   - No port scanning
   - Fastest and least intrusive

2. **connect**
   - TCP connect scan
   - Scans common ports
   - More detailed but slower

3. **version**
   - Service version detection
   - Most detailed information
   - Slowest scan type

## Security Considerations

- All scan types use non-privileged operations
- No raw packet manipulation
- Scans are logged and auditable
- Access controlled via Splunk capabilities

## Troubleshooting

1. Check nmap installation:
   ```bash
   nmap --version
   ```

2. Verify Python environment:
   ```bash
   $SPLUNK_HOME/bin/splunk cmd python3 -c "import nmap"
   ```

3. Check Splunk logs:
   ```bash
   $SPLUNK_HOME/var/log/splunk/nodeheim_debug.log
   ```

## Support

For issues and feature requests, please visit our [GitHub repository](https://github.com/yourusername/nodeheim). 