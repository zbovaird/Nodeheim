#!/usr/bin/env python3
import sys
import os
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    filename='/opt/splunk/var/log/splunk/nodeheim_debug.log',
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s %(message)s'
)

try:
    logging.debug("Comparison script starting at: %s", datetime.now())
    
    # Import Splunk libraries
    import splunk.Intersplunk
    logging.debug("Successfully imported splunk.Intersplunk")

    # Get the search results that were passed to us
    results, dummyresults, settings = splunk.Intersplunk.getOrganizedResults()
    logging.debug("Got %d results from Splunk", len(results))

    # Process the results (for now, just pass them through)
    for result in results:
        result['comparison_status'] = 'analyzed'
        
    # Output the results back to Splunk
    splunk.Intersplunk.outputResults(results)
    logging.debug("Successfully output comparison results")

except Exception as e:
    logging.error("Fatal error in comparison: %s", str(e))
    import traceback
    logging.error("Traceback: %s", traceback.format_exc())
    sys.exit(1)
finally:
    logging.debug("Comparison script completed at: %s", datetime.now())