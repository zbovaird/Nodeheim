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