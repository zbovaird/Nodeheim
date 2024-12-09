#!/usr/bin/env python
"""
Nodeheim Network Scanner
Performs network scanning operations for the Splunk Nodeheim app.
Optimized for Free Edition with resource monitoring and fallback modes.
"""

import sys
import os
import csv
import json
import logging
import time
import psutil
import gc
import signal
from datetime import datetime
import ipaddress
import nmap
import threading
import shutil
import splunk.Intersplunk
import splunk.mining.dcutils as dcu

# Add our app's lib directory to the Python path
app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
lib_path = os.path.join(app_root, 'lib')
sys.path.insert(0, lib_path)

# Set up paths
LOOKUPS_DIR = os.path.join(app_root, 'lookups')
CACHE_DIR = os.path.join(os.environ.get('SPLUNK_HOME', ''), 'var', 'lib', 'splunk', 'nodeheim', 'cache')
TEMP_DIR = os.path.join(os.environ.get('SPLUNK_HOME', ''), 'var', 'run', 'nodeheim')

# Resource thresholds
MEMORY_WARNING_THRESHOLD = 80
MEMORY_CRITICAL_THRESHOLD = 90
CPU_WARNING_THRESHOLD = 70
CPU_CRITICAL_THRESHOLD = 85
DISK_WARNING_THRESHOLD = 85
DISK_CRITICAL_THRESHOLD = 95
BATCH_SIZE = 1000
DEFAULT_TIMEOUT = 300  # 5 minutes
MAX_RETRIES = 3

class TimeoutError(Exception):
    """Custom exception for operation timeouts."""
    pass

class ResourceError(Exception):
    """Custom exception for resource limit violations."""
    pass

def timeout_handler(signum, frame):
    """Signal handler for timeouts"""
    raise TimeoutError("Operation timed out")

class ProgressTracker:
    """Track progress of long-running operations"""
    def __init__(self, total=None, operation="Operation"):
        self.total = total
        self.current = 0
        self.operation = operation
        self.start_time = time.time()
        self.last_update = self.start_time
        self.update_interval = 5  # seconds

    def update(self, increment=1):
        """Update progress"""
        self.current += increment
        current_time = time.time()
        if current_time - self.last_update >= self.update_interval:
            if self.total:
                percentage = (self.current / self.total) * 100
                logger.info(f"{self.operation} progress: {percentage:.1f}% ({self.current}/{self.total})")
            else:
                logger.info(f"{self.operation} progress: {self.current} items processed")
            self.last_update = current_time

    def finish(self):
        """Mark operation as complete"""
        duration = time.time() - self.start_time
        logger.info(f"{self.operation} completed in {duration:.1f} seconds")

class ResourceMonitor:
    """Monitor system resources"""
    def __init__(self):
        self.process = psutil.Process()
    
    def check_resources(self):
        """Check all system resources"""
        try:
            # Memory check
            memory_percent = self.process.memory_percent()
            if memory_percent > MEMORY_CRITICAL_THRESHOLD:
                raise ResourceError(f"Critical memory usage: {memory_percent:.1f}%")
            elif memory_percent > MEMORY_WARNING_THRESHOLD:
                logger.warning(f"High memory usage: {memory_percent:.1f}%")
                gc.collect()
            
            # CPU check
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > CPU_CRITICAL_THRESHOLD:
                raise ResourceError(f"Critical CPU usage: {cpu_percent:.1f}%")
            elif cpu_percent > CPU_WARNING_THRESHOLD:
                logger.warning(f"High CPU usage: {cpu_percent:.1f}%")
                time.sleep(1)  # Brief pause
            
            # Disk check
            disk = psutil.disk_usage(CACHE_DIR)
            if disk.percent > DISK_CRITICAL_THRESHOLD:
                raise ResourceError(f"Critical disk usage: {disk.percent}%")
            elif disk.percent > DISK_WARNING_THRESHOLD:
                logger.warning(f"High disk usage: {disk.percent}%")
                cleanup_old_files(CACHE_DIR, max_age_days=1)  # Aggressive cleanup
            
            return True
        except Exception as e:
            logger.error(f"Resource check failed: {str(e)}")
            return False

def with_timeout(func):
    """Decorator to add timeout to functions"""
    def wrapper(*args, **kwargs):
        timeout = kwargs.pop('timeout', DEFAULT_TIMEOUT)
        
        def target(*args, **kwargs):
            result['value'] = func(*args, **kwargs)
        
        result = {'value': None}
        thread = threading.Thread(target=target, args=args, kwargs=kwargs)
        thread.daemon = True
        
        thread.start()
        thread.join(timeout)
        
        if thread.is_alive():
            raise TimeoutError(f"Operation timed out after {timeout} seconds")
        
        return result['value']
    
    return wrapper

def with_retry(func):
    """Decorator to add retry logic"""
    def wrapper(*args, **kwargs):
        retries = kwargs.pop('retries', MAX_RETRIES)
        for attempt in range(retries):
            try:
                return func(*args, **kwargs)
            except (TimeoutError, ResourceError) as e:
                if attempt == retries - 1:
                    raise
                logger.warning(f"Attempt {attempt + 1} failed: {str(e)}")
                time.sleep(2 ** attempt)  # Exponential backoff
    
    return wrapper

# Ensure directories exist
for directory in [LOOKUPS_DIR, CACHE_DIR, TEMP_DIR]:
    if not os.path.exists(directory):
        try:
            os.makedirs(directory)
        except Exception as e:
            sys.stderr.write(f"Failed to create directory {directory}: {str(e)}\n")

# Set up logging
logger = dcu.getLogger()

def setup_logging():
    """Configure logging for the command"""
    try:
        logging.root
        logging.root.addHandler(logging.StreamHandler())
        log_level = os.environ.get('SPLUNK_HOME', 'INFO')
        logging.root.setLevel(log_level)
    except Exception as e:
        sys.stderr.write(f"Logging setup failed: {str(e)}\n")

class SplunkNmapError(Exception):
    """Custom exception for Nmap scanning errors."""
    pass

def validate_options(options):
    """Validate command options"""
    validated = {}
    
    # Source type (direct or import)
    validated['source'] = options.get('source', 'direct')
    if validated['source'] not in ['direct', 'import']:
        raise SplunkNmapError("Invalid source type. Must be 'direct' or 'import'")
    
    # For direct scanning
    if validated['source'] == 'direct':
        if 'target' not in options:
            validated['target'] = '127.0.0.1/32'  # Default to localhost
        else:
            try:
                ipaddress.ip_network(options['target'])
                validated['target'] = options['target']
            except ValueError:
                raise SplunkNmapError(f"Invalid target format: {options['target']}")
        
        validated['options'] = options.get('options', '-sn')
        if not validated['options'].startswith('-'):
            raise SplunkNmapError("Scan options must start with '-'")
    
    # For import
    else:
        validated['import_file'] = options.get('import_file')
        if not validated['import_file']:
            raise SplunkNmapError("import_file is required when source='import'")
    
    # Common options
    validated['cache'] = options.get('cache', 'true').lower() == 'true'
    validated['cache_ttl'] = int(options.get('cache_ttl', 3600))
    validated['batch_size'] = int(options.get('batch_size', BATCH_SIZE))
    
    return validated

def get_cache_path(target=None, import_file=None):
    """Generate cache file path based on input"""
    if target:
        cache_key = f"scan_{target.replace('/', '_')}.json"
    else:
        cache_key = f"import_{os.path.basename(import_file)}.json"
    return os.path.join(CACHE_DIR, cache_key)

def check_cache(cache_path, ttl):
    """Check if valid cache exists"""
    try:
        if os.path.exists(cache_path):
            mtime = os.path.getmtime(cache_path)
            if time.time() - mtime < ttl:
                with open(cache_path, 'r') as f:
                    return json.load(f)
    except Exception as e:
        logger.warning(f"Cache read failed: {str(e)}")
    return None

def save_to_cache(cache_path, data):
    """Save results to cache"""
    try:
        with open(cache_path, 'w') as f:
            json.dump(data, f)
    except Exception as e:
        logger.warning(f"Cache write failed: {str(e)}")

@with_retry
@with_timeout
def scan_network_generator(target, options=None, resource_monitor=None):
    """Generator version of network scan using nmap"""
    try:
        logger.info(f"Starting network scan of {target} with options {options}")
        nm = nmap.PortScanner()
        scan_args = '-sn' if not options else options
        
        network = ipaddress.ip_network(target)
        total_hosts = network.num_addresses
        chunk_size = min(256, total_hosts)
        
        progress = ProgressTracker(total_hosts, "Network scan")
        
        for i in range(0, total_hosts, chunk_size):
            if resource_monitor and not resource_monitor.check_resources():
                chunk_size = max(32, chunk_size // 2)
                logger.warning(f"Reduced chunk size to {chunk_size} due to resource constraints")
            
            chunk_start = network[i]
            chunk_end = network[min(i + chunk_size - 1, total_hosts - 1)]
            chunk_target = f"{chunk_start}-{chunk_end}"
            
            logger.info(f"Scanning chunk: {chunk_target}")
            nm.scan(hosts=chunk_target, arguments=scan_args)
            
            for host in nm.all_hosts():
                progress.update()
                yield host
            
            nm = nmap.PortScanner()
        
        progress.finish()
            
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        raise SplunkNmapError(f"Scan failed: {str(e)}")

@with_retry
@with_timeout
def import_from_csv_generator(import_file, resource_monitor=None):
    """Generator version of CSV import"""
    try:
        import_path = os.path.join(LOOKUPS_DIR, import_file)
        if not os.path.exists(import_path):
            raise SplunkNmapError(f"Import file not found: {import_path}")
        
        # Count lines first for progress tracking
        with open(import_path, 'r') as f:
            total_lines = sum(1 for _ in f) - 1  # Subtract header
        
        progress = ProgressTracker(total_lines, "CSV import")
        
        with open(import_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if resource_monitor:
                    resource_monitor.check_resources()
                if 'host' in row:
                    progress.update()
                    yield row['host']
        
        progress.finish()
                
    except Exception as e:
        logger.error(f"Import failed: {str(e)}")
        raise SplunkNmapError(f"Import failed: {str(e)}")

@with_retry
def process_results_generator(host_generator, source_type, batch_size, resource_monitor=None):
    """Generator version of results processing"""
    batch = []
    try:
        progress = ProgressTracker(operation="Results processing")
        
        for host in host_generator:
            if resource_monitor:
                resource_monitor.check_resources()
            
            event = {
                '_time': time.time(),
                'host': host,
                'status': 'up',
                'source': f'nodeheim_scan_{source_type}',
                'sourcetype': 'nodeheim:scan:result',
                '_raw': f"Host discovered: {host}"
            }
            batch.append(event)
            progress.update()
            
            if len(batch) >= batch_size:
                yield batch
                batch = []
                
                if resource_monitor and not resource_monitor.check_resources():
                    batch_size = max(32, batch_size // 2)
                    logger.warning(f"Adjusted batch size to {batch_size}")
        
        if batch:
            yield batch
        
        progress.finish()
            
    except Exception as e:
        logger.error(f"Processing failed: {str(e)}")
        raise SplunkNmapError(f"Processing failed: {str(e)}")

def main():
    """Main entry point for the command"""
    try:
        setup_logging()
        logger.info("Nodeheim scan command starting")
        
        # Initialize resource monitor
        resource_monitor = ResourceMonitor()
        
        # Clean up old files
        cleanup_old_files(CACHE_DIR)
        cleanup_old_files(TEMP_DIR)
        
        results, dummyresults, settings = splunk.Intersplunk.getOrganizedResults()
        keywords, options = splunk.Intersplunk.getKeywordsAndOptions()
        logger.debug(f"Received options: {options}")
        
        validated_options = validate_options(options)
        
        # Check cache if enabled
        cache_path = get_cache_path(
            validated_options.get('target'),
            validated_options.get('import_file')
        )
        
        if validated_options['cache']:
            cached_results = check_cache(cache_path, validated_options['cache_ttl'])
            if cached_results:
                logger.info("Using cached results")
                splunk.Intersplunk.outputResults(cached_results)
                return
        
        # Get host generator based on source type
        try:
            if validated_options['source'] == 'direct':
                host_generator = scan_network_generator(
                    validated_options['target'],
                    validated_options['options'],
                    resource_monitor=resource_monitor
                )
            else:
                host_generator = import_from_csv_generator(
                    validated_options['import_file'],
                    resource_monitor=resource_monitor
                )
            
            # Process results in batches
            all_events = []
            for batch in process_results_generator(
                host_generator,
                validated_options['source'],
                validated_options['batch_size'],
                resource_monitor=resource_monitor
            ):
                all_events.extend(batch)
                
                # Output intermediate results if resources are constrained
                if resource_monitor and not resource_monitor.check_resources():
                    splunk.Intersplunk.outputResults(all_events)
                    all_events = []
            
            # Output any remaining results
            if all_events:
                splunk.Intersplunk.outputResults(all_events)
            
            # Cache final results if enabled
            if validated_options['cache'] and all_events:
                save_to_cache(cache_path, all_events)
            
        except (TimeoutError, ResourceError) as e:
            logger.error(f"Operation failed: {str(e)}")
            # Attempt fallback mode
            if validated_options['source'] == 'direct':
                logger.info("Falling back to reduced scan mode")
                validated_options['options'] = '-sn -T2'  # Slower, less aggressive scan
                host_generator = scan_network_generator(
                    validated_options['target'],
                    validated_options['options'],
                    resource_monitor=resource_monitor,
                    timeout=DEFAULT_TIMEOUT * 2
                )
                # Continue with reduced functionality...
            
    except SplunkNmapError as e:
        logger.error(f"Command failed with SplunkNmapError: {str(e)}")
        splunk.Intersplunk.generateErrorResults(str(e))
    except Exception as e:
        logger.error(f"Command failed with unexpected error: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        splunk.Intersplunk.generateErrorResults(f"Unexpected error: {str(e)}")
    finally:
        # Final cleanup
        gc.collect()

if __name__ == '__main__':
    main()