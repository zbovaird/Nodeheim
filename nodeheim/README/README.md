# Nodeheim - Network Discovery for Splunk

A Splunk app for network discovery and monitoring, optimized for both Free and Enterprise editions.

## Features

- Network discovery using non-privileged scans
- CSV data import for offline scanning
- Resource-optimized processing
- Automatic caching and data retention
- Progress tracking and monitoring
- Fallback modes for resource constraints

## Installation

1. Install via Splunk Web:
   - Navigate to "Manage Apps"
   - Click "Install app from file"
   - Upload the .spl file

2. Manual Installation:
   - Extract to `$SPLUNK_HOME/etc/apps/nodeheim`
   - Restart Splunk

## Requirements

- Splunk Free or Enterprise Edition
- Python 3.7+
- nmap package (will be installed automatically)
- psutil package (will be installed automatically)

## Usage

### Direct Network Scanning

```spl
| nodeheim-scan source=direct target="192.168.1.0/24"
```

Options:
- `source=direct` (default): Perform live network scan
- `target`: Network to scan (CIDR notation)
- `options`: Scan options (default: "-sn" for ping scan)
- `cache=true/false`: Enable/disable result caching (default: true)
- `cache_ttl`: Cache duration in seconds (default: 3600)

### CSV Import Mode

```spl
| nodeheim-scan source=import import_file="network_scan.csv"
```

Options:
- `source=import`: Import from CSV file
- `import_file`: CSV file in lookups directory
- `cache`: Enable/disable result caching
- `cache_ttl`: Cache duration

### Resource Optimization

The app automatically manages resources:
- Memory usage monitoring
- CPU usage tracking
- Disk space management
- Automatic cleanup of old data

### Fallback Modes

When resource constraints are detected:
1. Reduced chunk sizes
2. Slower scan speeds
3. Progressive processing
4. Automatic cleanup

## Free Edition Considerations

### Limitations
- Maximum scan size recommendations
- Resource usage guidelines
- Data retention periods
- Command timeout limits

### Best Practices
1. Use CSV import for large networks
2. Enable caching for repeated scans
3. Schedule scans during off-peak hours
4. Monitor resource usage

### Workarounds
1. Split large networks into smaller chunks
2. Use hybrid scanning approach
3. Implement local data retention
4. Utilize fallback modes

## Troubleshooting

See `TROUBLESHOOTING.md` for:
- Common issues and solutions
- Error message explanations
- Resource optimization tips
- Network scanning guidelines

## Support

- GitHub Issues: [Report bugs or request features]
- Documentation: See `README` directory
- Examples: See `lookups/sample_network_scan.csv`

## License

Apache License 2.0 