# Nodeheim Test Plan

## Prerequisites

1. Splunk Enterprise 8.0 or later installed
2. Python 3.7 or later
3. nmap 7.80 or later installed
4. Administrative access to Splunk

## Test Environment Setup

1. Set SPLUNK_HOME environment variable:
   ```bash
   export SPLUNK_HOME=/opt/splunk  # Linux
   set SPLUNK_HOME=C:\Program Files\Splunk  # Windows
   ```

2. Install Python dependencies:
   ```bash
   $SPLUNK_HOME/bin/splunk cmd python3 -m pip install python-nmap>=0.7.1
   ```

## Automated Testing

Run the automated test suite:
```bash
python bin/splunk_test.py --splunk-home="$SPLUNK_HOME" --app-package="nodeheim-1.0.4.spl"
```

The test suite verifies:
1. Splunk installation and version
2. nmap installation and version
3. Python dependencies
4. App installation
5. Capability configuration
6. Basic network scan
7. TCP connect scan
8. Version detection scan
9. Log file analysis

## Manual Testing Steps

### 1. Installation Verification
- [ ] App appears in Splunk Web UI
- [ ] App navigation works
- [ ] No errors in Splunk Web console

### 2. Command Verification
Run each command and verify output format:

```spl
| nodeheim_scan subnet="127.0.0.1/32"
```
Expected fields:
- [ ] _raw
- [ ] _time
- [ ] host
- [ ] status
- [ ] ip_address
- [ ] scan_type
- [ ] subnet

### 3. Scan Type Testing
Test each scan type:
- [ ] Basic scan (`scan_type="basic"`)
- [ ] Connect scan (`scan_type="connect"`)
- [ ] Version scan (`scan_type="version"`)

### 4. Error Handling
Verify proper error messages for:
- [ ] Invalid subnet format
- [ ] Invalid scan type
- [ ] Missing capabilities
- [ ] Network access issues

### 5. Performance Testing
Test with different subnet sizes:
- [ ] Single host (/32)
- [ ] Small network (/28 - 16 hosts)
- [ ] Medium network (/24 - 256 hosts)

### 6. Security Testing
- [ ] Verify non-admin users can't run scans
- [ ] Verify scan logs are properly generated
- [ ] Check for sensitive information in logs
- [ ] Verify capability enforcement

### 7. Configuration Testing
- [ ] Verify app.conf settings are applied
- [ ] Test inputs.conf configurations
- [ ] Verify commands.conf settings

## Test Reporting

Document any issues found:
1. Issue description
2. Steps to reproduce
3. Expected vs actual behavior
4. Environment details
5. Log snippets

## Success Criteria

1. All automated tests pass
2. Manual verification steps complete
3. No errors in Splunk logs
4. Scan results are accurate
5. Performance is acceptable
6. Security controls work as expected

## Troubleshooting Guide

### Common Issues

1. nmap Not Found
   ```bash
   nmap --version
   ```
   Fix: Install nmap package

2. Python Dependencies
   ```bash
   $SPLUNK_HOME/bin/splunk cmd python3 -c "import nmap"
   ```
   Fix: Install python-nmap package

3. Permission Issues
   ```bash
   $SPLUNK_HOME/bin/splunk btool authorize list --debug
   ```
   Fix: Verify authorize.conf settings

### Log Locations

1. App Logs:
   ```
   $SPLUNK_HOME/var/log/splunk/nodeheim_debug.log
   ```

2. Splunk System Logs:
   ```
   $SPLUNK_HOME/var/log/splunk/splunkd.log
   ```

## Post-Test Cleanup

1. Remove test configurations:
   ```bash
   rm -f $SPLUNK_HOME/etc/system/local/authorize.conf
   ```

2. Restart Splunk:
   ```bash
   $SPLUNK_HOME/bin/splunk restart
   ``` 