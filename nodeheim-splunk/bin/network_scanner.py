docker exec -u root -it splunk bash -c 'cat > /opt/splunk/etc/apps/nodeheim-splunk/bin/network_scanner.py' << 'EOL'
#!/usr/bin/env python3
import sys
import os
import logging
import signal
from datetime import datetime

# Configure logging
logging.basicConfig(
    filename='/opt/splunk/var/log/splunk/nodeheim_debug.log',
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s %(message)s'
)

def timeout_handler(signum, frame):
    logging.error("Script execution timed out after 10 seconds")
    sys.exit(1)

# Set timeout for 10 seconds
signal.signal(signal.SIGALRM, timeout_handler)
signal.alarm(10)

try:
    logging.debug("Script starting at: %s", datetime.now())
    
    # Add the app's bin directory to the Python path
    app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    bin_path = os.path.join(app_root, 'bin')
    if bin_path not in sys.path:
        sys.path.insert(0, bin_path)
    logging.debug("Added to sys.path: %s", bin_path)

    # Test event generation
    test_event = {
        'source': 'nodeheim:scan',
        'sourcetype': 'nodeheim:scan',
        '_time': datetime.now().timestamp(),
        'host': 'test_host',
        'status': 'test_successful'
    }
    
    # Import Splunk libraries
    try:
        import splunk.Intersplunk
        logging.debug("Successfully imported splunk.Intersplunk")
        splunk.Intersplunk.outputResults([test_event])
        logging.debug("Successfully output test event")
    except Exception as e:
        logging.error("Error with Splunk imports or output: %s", str(e))
        raise

except Exception as e:
    logging.error("Fatal error: %s", str(e))
    sys.exit(1)
finally:
    # Disable the alarm
    signal.alarm(0)
    logging.debug("Script completed at: %s", datetime.now())
EOL'