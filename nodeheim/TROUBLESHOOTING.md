# Nodeheim Troubleshooting Guide

## Custom Command Not Found Issue

### Issue Description
When running the `nodeheim_scan` command in Splunk search, receiving error:
```
Unknown search command 'nodeheim'
```

### Environment
- Splunk Enterprise in Docker container
- App installed in `/opt/splunk/etc/apps/nodeheim/`
- Python 3.9
- App visible in Splunk Web UI

### Attempted Solutions

1. **Command Configuration Location** (Not Working)
   - Found command defined in `local/commands.conf` instead of `default/commands.conf`
   - Attempted to remove local config to use default
   - Reference: [Splunk Commands Configuration](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Commandsconf)

2. **Python Dependencies** (Partially Working)
   - Installed python-nmap package in container
   - Attempted to install in both system Python and Splunk's Python
   - Reference: [Custom Search Command Python Dependencies](https://docs.splunk.com/Documentation/Splunk/latest/AdvancedDev/CustomSearchScripts#Package_your_custom_command)

3. **Permission Issues** (In Progress)
   - Multiple permission errors in Splunk logs
   - Container showing issues with file access and ownership
   - Need to verify proper permissions for:
     - App directory
     - Python script
     - Splunk configuration files
   - Reference: [Splunk File Permissions](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Filepermissions)

### Current Status
- App is visible in Splunk Web UI
- Command script exists and has execute permissions
- Command configuration exists but may not be properly loaded
- Container has permission issues that need resolution

### Next Steps to Try
1. Review Splunk's [Custom Search Command Examples](https://docs.splunk.com/Documentation/Splunk/latest/AdvancedDev/CustomSearchScripts#Example_custom_search_commands)
2. Verify command registration using:
   ```
   $SPLUNK_HOME/bin/splunk cmd btool commands list --debug
   ```
3. Check Splunk's Python environment:
   ```
   $SPLUNK_HOME/bin/splunk cmd python3 -c "import splunk.Intersplunk; print('OK')"
   ```
4. Review app.conf settings for proper Python version specification
5. Consider rebuilding container with correct permissions from the start

### Docker-Specific Issues
1. Container Permission Problems
   - Container starting with incorrect user/group
   - File permission issues preventing Splunk from accessing configs
   - Need to align container user with Splunk user (41812:41812)

### Documentation Updates Needed
1. Add Docker deployment instructions to README.md
2. Update app.conf.spec with Python version requirements
3. Document custom command installation process
4. Add permission requirements for Docker deployment

### References
- [Splunk Custom Search Command Tutorial](https://docs.splunk.com/Documentation/Splunk/latest/AdvancedDev/CustomSearchScripts)
- [Splunk App Packaging](https://docs.splunk.com/Documentation/Splunk/latest/AdvancedDev/PackageApp)
- [Splunk Docker Deployment](https://docs.splunk.com/Documentation/Splunk/latest/Installation/DeployandrunSplunkEnterpriseinsideDockercontainers)
- [Commands.conf Specification](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Commandsconf) 

### Splunk Free Edition Limitations
1. **Custom Command Restrictions**
   - Splunk Free Edition has a 500MB/day indexing limit
   - Limited to a single user (admin)
   - No distributed search capabilities
   - Custom commands must be entirely self-contained
   - Cannot use external authentication

2. **Known Issues in Free Edition**
   - Custom commands may fail silently without proper error messages
   - Python SDK functionality might be limited
   - Real-time searches are restricted
   - Some REST API endpoints are not available

3. **Workarounds**
   - Use local-mode commands only (`local = true` in commands.conf)
   - Implement thorough error handling and logging
   - Keep data volumes under the 500MB/day limit
   - Use basic authentication only
   - Avoid distributed search dependencies

4. **Upgrade Considerations**
   - Document features that require Enterprise license
   - Test app functionality in both Free and Enterprise editions
   - Maintain separate configuration sets if needed
   - Consider graceful degradation for Enterprise-only features

### Workarounds for Splunk Free Edition Limitations

1. **Local Execution Strategy**
   - Set `local = true` for all commands in commands.conf
   - Run nmap scans directly on the Splunk server
   - Store scan results in local CSV lookups for faster access
   - Use file-based caching for frequent operations

2. **Memory Management**
   - Implement chunking in network_scanner.py
   - Process results in smaller batches
   - Use generators instead of lists
   - Clear memory explicitly after operations
   Example:
   ```python
   def scan_in_chunks(subnet, chunk_size=256):
       for i in range(0, len(hosts), chunk_size):
           chunk = hosts[i:i + chunk_size]
           yield scan_hosts(chunk)
   ```

3. **Performance Optimization**
   - Cache nmap results locally
   - Use lightweight scan options by default
   - Implement progressive scanning (basic scan first, detailed on demand)
   - Store frequently accessed data in KV store

4. **Alternative Storage Solutions**
   - Use CSV lookups for persistent storage
   - Leverage KV store for metadata
   - Implement file-based result caching
   - Use scheduled searches to maintain data

5. **Command Design Patterns**
   - Chain multiple simple commands instead of one complex command
   - Use generating commands for streaming results
   - Implement proper error handling with retries
   Example:
   ```python
   | nodeheim_scan subnet=192.168.1.0/24 mode=basic 
   | nodeheim_analyze 
   | nodeheim_report
   ```

6. **Resource Management**
   - Implement timeouts for all operations
   - Add backoff mechanisms for retries
   - Monitor memory usage actively
   - Clean up temporary files
   Example config:
   ```ini
   [nodeheim_scan]
   max_runtime = 300
   max_hosts_per_scan = 256
   cleanup_temp_files = true
   ```

7. **Testing and Validation**
   - Add health checks for system resources
   - Validate inputs before processing
   - Monitor command execution time
   - Log resource usage statistics

8. **User Experience**
   - Provide clear feedback on operation progress
   - Implement graceful degradation for heavy operations
   - Add status indicators for long-running scans
   - Cache previous results for quick access

### Custom Command Limitations in Splunk Free Edition

1. **Command Execution Environment**
   - Custom commands must run in local mode only (`local = true`)
   - No access to distributed search features
   - Limited memory allocation for command execution
   - Commands cannot spawn long-running processes

2. **Search Head Limitations**
   - Single instance only (no clustering)
   - No forwarding to indexers
   - Limited to searching local indexes
   - Maximum of 10 concurrent searches

3. **Python Environment Restrictions**
   - Must use Splunk's Python runtime
   - Limited access to external network resources
   - Restricted file system access
   - Memory constraints for Python processes

4. **Data Processing Limits**
   - Commands must respect 500MB/day indexing limit
   - Limited result set size
   - No real-time search capabilities
   - Restricted search time ranges

5. **Authentication & Authorization**
   - Single admin user only
   - No custom roles or capabilities
   - Basic authentication only
   - No external authentication support

6. **Debugging & Troubleshooting**
   - Limited logging capabilities
   - No remote debugging
   - Restricted access to some diagnostic endpoints
   - Limited performance metrics

7. **Common Issues & Solutions**
   - Command not found: Verify local=true in commands.conf
   - Memory errors: Reduce batch sizes and implement chunking
   - Timeout issues: Add proper timeout handling
   - Permission errors: Run with appropriate user context

### Implementation Checklist for Free Edition Optimizations

#### 1. Local Processing Setup
- [✅] Verify if direct network scanning is allowed in Free Edition
  - Confirmed: Allowed with non-privileged scans
  - Must use `-sn` (ping scan) by default
  - Need rate limiting and chunking
- [✅] Implement hybrid approach:
  - Direct scanning for small networks
  - CSV import for large networks
  - Caching of scan results
- [✅] Create local CSV lookup structure
  - Directory: `$SPLUNK_HOME/etc/apps/nodeheim/lookups`
  - Format: `network_scans_YYYYMMDD.csv`
  - Fields: host,status,last_scan,scan_type
- [✅] Implement file-based caching system
  - Cache location: `$SPLUNK_HOME/var/lib/splunk/nodeheim/cache`
  - TTL: 3600 seconds (configurable)
  - Format: JSON for easy processing
- [✅] Set up temp directory management
  - Location: `$SPLUNK_HOME/var/run/nodeheim`
  - Cleanup on startup and shutdown
  - Regular purge of old files

#### 2. Memory Management Implementation
- [✅] Add chunking to network_scanner.py
  - Set maxchunksize = 50000
  - Enabled chunked = true
  - Disabled streaming for better memory control
- [✅] Implement generator-based processing
  - Added yield statements for large datasets
  - Process results in batches
  - Added memory monitoring
- [✅] Add memory monitoring
  - Added psutil for memory tracking
  - Set warning thresholds (80%)
  - Set critical thresholds (90%)
  - Added garbage collection triggers
- [✅] Set up cleanup routines
  - Added file cleanup for cache
  - Added temp file purging
  - Added memory optimization
  - Added batch size adjustment

#### 3. Storage Implementation
- [✅] Create CSV lookup directory structure
  - Added LOOKUPS_DIR path
  - Created sample CSV format
  - Added import validation
- [✅] Set up KV store for metadata
  - Using file-based JSON cache instead
  - TTL-based expiration
  - Configurable settings
- [✅] Implement cache management system
  - Added cache validation
  - Added TTL checks
  - Added cleanup routines
- [✅] Create data retention policies
  - 7-day default retention
  - Configurable cleanup
  - Automatic purging
- [✅] Add data validation checks
  - CSV format validation
  - Cache integrity checks
  - Import data validation

#### 4. Command Optimization
- [✅] Break down complex operations
  - Added scan chunking
  - Added progressive processing
  - Added fallback modes
  - Added retry logic
- [✅] Add progress indicators
  - Added ProgressTracker class
  - Added scan progress logging
  - Added import progress tracking
  - Added cleanup status updates
- [✅] Implement timeout handling
  - Added operation timeouts
  - Added retry logic with backoff
  - Added graceful fallbacks
  - Added timeout decorator
- [✅] Add resource checks
  - Added ResourceMonitor class
  - Added CPU monitoring
  - Added disk space checks
  - Added memory optimization
- [✅] Create fallback modes
  - Added reduced functionality mode
  - Added slower scan options
  - Added emergency cleanup
  - Added graceful degradation

#### 5. Testing & Validation
- [ ] Test in clean Free Edition instance
  - Test direct scanning
  - Test CSV import
  - Test hybrid mode
  - Test fallback modes
- [ ] Verify all commands work locally
  - Test network scanning
  - Test data import
  - Test analysis
  - Test comparison
- [ ] Check resource usage
  - Monitor memory usage
  - Monitor CPU usage
  - Monitor disk usage
  - Check cleanup effectiveness
- [ ] Validate error handling
  - Test timeout scenarios
  - Test resource limits
  - Test network errors
  - Test file access errors
- [ ] Test data persistence
  - Verify cache functionality
  - Check data retention
  - Validate import/export
  - Test cleanup routines

#### 6. Documentation Updates
- [✅] Document Free Edition limitations
  - Added known constraints
  - Added workarounds
  - Added best practices
  - Added troubleshooting tips
- [✅] Add configuration examples
  - Added direct scan examples
  - Added CSV import examples
  - Added hybrid mode examples
  - Added resource tuning examples
- [✅] Update installation instructions
  - Added Free Edition setup
  - Added dependencies setup
  - Added permission setup
  - Added directory structure
- [✅] Add troubleshooting guides
  - Added common issues
  - Added error messages
  - Added resource problems
  - Added network issues
- [✅] Document fallback procedures
  - Added resource constraints
  - Added network issues
  - Added permission problems
  - Added data volume issues

## Common Issues

### 1. Resource Constraints

#### Memory Usage
- **Symptom**: "High memory usage" or "Critical memory usage" warnings
- **Solution**: 
  1. Reduce scan chunk size
  2. Enable caching
  3. Use CSV import for large networks
  4. Clear old cache files

#### CPU Usage
- **Symptom**: "High CPU usage" or "Critical CPU usage" warnings
- **Solution**:
  1. Use slower scan speeds (-T2)
  2. Reduce concurrent operations
  3. Schedule during off-peak hours
  4. Enable progressive scanning

#### Disk Space
- **Symptom**: "High disk usage" or "Critical disk usage" warnings
- **Solution**:
  1. Clear old cache files
  2. Reduce retention period
  3. Use CSV rotation
  4. Enable aggressive cleanup

### 2. Scan Performance

#### Slow Scans
- **Symptom**: Scans taking longer than expected
- **Solution**:
  1. Use smaller network chunks
  2. Enable caching
  3. Implement hybrid approach
  4. Optimize scan options

#### Timeout Issues
- **Symptom**: "Operation timed out" errors
- **Solution**:
  1. Increase timeout settings
  2. Reduce scan scope
  3. Use retry mechanism
  4. Enable fallback modes

### 3. Free Edition Specific

#### Command Limitations
- **Symptom**: Command not recognized or fails
- **Solution**:
  1. Use supported command syntax
  2. Check command registration
  3. Verify Python environment
  4. Use alternative approaches

#### Resource Management
- **Symptom**: Resource exhaustion in Free Edition
- **Solution**:
  1. Enable all optimization features
  2. Use minimal scan options
  3. Implement data rotation
  4. Monitor resource usage

## Best Practices

### 1. Scanning Strategy

#### Large Networks
1. Split into /24 subnets
2. Use CSV import for historical data
3. Enable caching
4. Implement progressive scanning

#### Resource Optimization
1. Monitor usage with ResourceMonitor
2. Use appropriate chunk sizes
3. Enable cleanup routines
4. Implement fallback modes

### 2. Data Management

#### Cache Management
1. Regular cleanup of old files
2. TTL-based expiration
3. Size-based rotation
4. Compression for storage

#### Import/Export
1. Use standardized CSV format
2. Implement data validation
3. Enable error handling
4. Use batch processing

## Error Messages

### Resource Errors
- `Critical memory usage`: Memory usage exceeded 90%
- `High CPU usage`: CPU usage exceeded 70%
- `Critical disk usage`: Disk usage exceeded 95%

### Operation Errors
- `Operation timed out`: Scan exceeded timeout limit
- `Import failed`: CSV import error
- `Scan failed`: Network scanning error
- `Processing failed`: Results processing error

## Configuration Examples

### Minimal Resource Usage
```spl
| nodeheim-scan source=direct target="192.168.1.0/24" options="-sn -T2" cache=true cache_ttl=7200
```

### CSV Import Mode
```spl
| nodeheim-scan source=import import_file="network_scan.csv" cache=true
```

### Progressive Scanning
```spl
| nodeheim-scan source=direct target="192.168.1.0/24" batch_size=100
```

## Diagnostic Commands

### Check Installation
```bash
$SPLUNK_HOME/bin/splunk cmd python3 -c "import nmap, psutil"
```

### Verify Permissions
```bash
$SPLUNK_HOME/bin/splunk btool nodeheim list --debug
```

### Check Resources
```bash
$SPLUNK_HOME/bin/splunk cmd python3 -c "import psutil; print(psutil.virtual_memory())"
```

## Support Resources

### Documentation
- README.md: Installation and usage
- commands.conf.spec: Command configuration
- limits.conf: Resource limits
- inputs.conf.spec: Input configuration

### Log Files
- nodeheim_debug.log: Debug information
- splunkd.log: Splunk daemon logs
- python.log: Python runtime logs

### Community
- GitHub Issues: Bug reports and features
- Splunk Answers: Community support
- Documentation Wiki: Extended guides